"""Encrypted registry salt delivery using ordinary signed replies.

The /registry/salt route is a local R&D application route, not a standardized
KERI/ACDC route. It carries one recipient-encrypted salt; normal Revery verifies
the author's signatures, including group thresholds. There is no assignment
protocol, proof bundle, delivery ledger, acknowledgement, or private escrow.
"""
from .. import Vrsn_2_0
from ..core import Cipher, Encrypter, MtrDex, Prefixer, Diger, reply
from ..kering import ConfigurationError, ValidationError, UnverifiedReplyError
from .habbing import GroupHab
from .registry_custody import CustodyInfo

ROUTE = '/registry/salt'
ROUTES = frozenset((ROUTE,))


class RegistrySaltService:
    """Borrow registry, Keeper custody and Revery owners for one reply route."""

    def __init__(self, hby, rgy, custody, rvy):
        """Bind existing owners without opening stores or scheduling work.

        hby and rgy own accepted KEL/TEL evidence; custody owns encrypted local
        salts; rvy performs ordinary reply signature and threshold verification.
        """
        if rvy.db is not hby.db or custody.hby is not hby or custody.rgy is not rgy:
            raise ConfigurationError('salt sharing requires matching evidence and custody owners')
        self.hby, self.rgy, self.custody, self.rvy = hby, rgy, custody, rvy

    def register(self):
        """Install the local application route on the caller's ordinary Revery."""
        self.rvy.rtr.addRoute(ROUTE, self, suffix='RegistrySalt')

    def validate(self, body):
        """Validate the registry and addressed parties, independently of signatures.

        Return accepted inception and payload. The issuer may disclose to any
        explicit recipient. A recipient group may replicate to its own members;
        the receiving member validates that relationship from its local GroupHab.
        """
        data = body.sad.get('a')
        if (body.route != ROUTE or body.pvrsn != Vrsn_2_0 or not isinstance(data, dict)
                or set(data) != {'registry', 'recipient', 'target', 'cipher'}):
            raise ValidationError('invalid registry salt reply')
        try:
            for field, kind in (('registry', Diger), ('recipient', Prefixer), ('target', Prefixer)):
                if kind(qb64=data[field]).qb64 != data[field]:
                    raise ValueError
            cipher = Cipher(qb64=data['cipher'])
            if cipher.code != MtrDex.X25519_Cipher_Salt or cipher.qb64 != data['cipher']:
                raise ValueError
        except (ValueError, TypeError, KeyError):
            raise ValidationError('invalid encrypted salt or recipient') from None
        rip = self.rgy.store.seqEvent(data['registry'], 0)
        if rip is None or rip.ilk != 'rip':
            raise ValidationError('accepted registry inception is required before salt delivery')
        if body.pre not in (rip.israid, data['recipient']):
            raise ValidationError('salt reply must be signed by the issuer or recipient group')
        return rip, data

    def makeReply(self, hab, registry, recipient, *, target=None):
        """Build one encrypted reply for explicit caller signing and transport.

        hab is the issuer or a recipient group replicating its retained salt.
        registry names accepted inception; recipient is the logical recipient;
        target optionally selects its individual member's encryption key.
        No message is sent and no delivery state is created here.
        """
        target = target or recipient
        if self.hby.habByPre(hab.pre) is not hab:
            raise ValidationError('salt delivery requires a local author')
        kever = self.hby.kevers.get(target)
        if kever is None or len(kever.verfers) != 1:
            raise ValidationError('salt delivery requires a known individual encryption recipient')
        cipher = self.custody.sealRoot(registry, Encrypter(verkey=kever.verfers[0].qb64))
        body = reply(pre=hab.pre, route=ROUTE, data=dict(registry=registry,
            recipient=recipient, target=target, cipher=cipher.qb64), version=Vrsn_2_0)
        rip, _ = self.validate(body)
        if hab.pre != rip.israid and not isinstance(hab, GroupHab):
            raise ValidationError('nonissuer replication requires the recipient group')
        if isinstance(hab, GroupHab) and hab.pre == recipient and target not in hab.smids:
            raise ValidationError('replication target is not a current group member')
        return body

    def processReplyRegistrySalt(self, serder, diger, route, cigars=None, tsgs=None, **kwa):
        """Verify a signed reply, decrypt its addressed salt, and retain it locally.

        Revery supplies serder/diger/route and signature attachments. Its ordinary
        partial-signature escrow owns threshold completion. Missing registry or
        local keys are errors, not new application replay escrows. A transport
        sender may resend the same reply through ordinary delivery mechanisms.
        """
        rip, data = self.validate(serder)
        recipient = self.hby.habByPre(data['recipient'])
        author = self.hby.habByPre(serder.pre)
        if isinstance(recipient, GroupHab):
            member = recipient.mhab
            if data['target'] not in recipient.smids:
                raise ValidationError('salt target is not a local group member')
        else:
            member = recipient
            if serder.pre != rip.israid:
                raise ValidationError('individual recipient requires issuer authorization')
        addressed = member is not None and member.pre == data['target']
        if not addressed and author is None:
            raise ValidationError('salt reply is addressed to another local recipient')
        if not self.rvy.acceptReply(serder=serder, saider=diger, route=route,
                aid=serder.pre, cigars=cigars or [], tsgs=tsgs or []):
            raise UnverifiedReplyError('registry salt reply signatures are incomplete')
        if not addressed:
            return  # Local authors collect ordinary reply signatures without acquiring recipient custody.
        root = self.custody.openRoot(data['cipher'], member.kever.verfers[0])
        # Several local identities can share one vault's registry salt. Preserve
        # its existing storage metadata; reply authorization was checked above.
        existing = self.custody.db.custody.get((rip.said,))
        info = (CustodyInfo(**self.custody._load(rip.said).info) if existing is not None
                else CustodyInfo(rip.said, rip.israid, data['recipient']))
        prepared = self.custody.prepareRoot(info, root)
        with self.custody.db.env.begin(write=True) as txn:
            self.custody.retainPrepared(prepared, txn)
