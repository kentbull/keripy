"""Ultimate-recipient ESSR envelopes for an explicitly allowed reply profile.

Sealing uses the same libsodium Ed25519-to-X25519 sealed-box construction as
StreamPoster. Sealed boxes provide recipient confidentiality; the outer EXN
signature authenticates its sender. The inner reply retains its own authority.
"""
from dataclasses import asdict
import re

import pysodium

from ..core import Bexter, Counter, Codens, Diger, MtrDex, Prefixer, Texter
from ..kering import DecryptError, Kinds, ValidationError, Version, Vrsn_1_0
from ..peer import specialExchange
from ..spac import PayloadTyper, PayloadTypes
from .replying import parseReply


def envelope(hab, msg, recipient, verfer, *, version=Version, kind=Kinds.json,
             establishment=None):
    """Seal once to an authenticated individual key before choosing transport.

    The caller authenticates recipient/key membership. Optional establishment
    coordinates ``(sn, dig)`` bind the recipient's establishment event. Transport
    must carry these returned bytes with ESSR wrapping disabled.
    """
    if verfer.code not in (MtrDex.Ed25519, MtrDex.Ed25519N):
        raise ValidationError("Unsupported ESSR recipient key")
    q = dict(src=hab.pre, dest=recipient)
    if establishment is not None:
        sn, dig = establishment
        if isinstance(sn, bool) or not isinstance(sn, int) or sn < 0:
            raise ValidationError("Invalid ESSR recipient establishment sequence")
        Diger(qb64=dig)
        q.update(sn=f'{sn:x}', dig=dig, key=verfer.qb64)
    pubkey = pysodium.crypto_sign_pk_to_box_pk(verfer.raw)
    # Match StreamPoster._chunk: SCS type, authenticated source, and a complete
    # padding primitive precede the ordinary CESR payload inside the ciphertext.
    plain = (PayloadTyper(type=PayloadTypes.SCS).qb64b + hab.kever.prefixer.qb64b
             + Bexter(bext='').qb64b + bytes(msg))
    raw = pysodium.crypto_box_seal(plain, pubkey)
    texter = Texter(raw=raw)
    essr, _ = specialExchange(sender=hab.pre, route='/essr/req', modifiers=q,
                              diger=Diger(ser=raw, code=MtrDex.Blake3_256),
                              version=Vrsn_1_0, kind=kind)
    ims = hab.endorse(serder=essr, framed=True, gvrsn=version)
    ims.extend(Counter(Codens.ESSRPayloadGroup,
                       count=1 if version.major < 2 else len(texter.qb64b) // 4,
                       gvrsn=version).qb64b)
    ims.extend(texter.qb64b)
    return ims


class EssrReplyHandler:
    """Borrow the application Parser/Revery; accept only one allowed reply.

    Exchanger verifies the signed outer EXN and ciphertext digest before this
    handler runs. This handler never gives the outer sender inner authority.
    Applications must put secrets inside their own encrypted reply attributes:
    Revery's normal acceptance/escrow stores the inner reply serialization.
    """
    resource = '/essr/req'

    def __init__(self, hby, hab, parser, allowedRoutes):
        """Bind local ``hab`` in ``hby``, its borrowed ``parser`` and route set.

        ``allowedRoutes`` contains exact reply route strings. Returns no value;
        raises ValidationError for unsupported local keys or processor setup.
        """
        from .habbing import GroupHab, SignifyGroupHab

        if (isinstance(hab, (GroupHab, SignifyGroupHab)) or
                hby.habs.get(hab.pre) is not hab or
                len(hab.kever.verfers) != 1 or
                hab.kever.verfers[0].code not in (MtrDex.Ed25519, MtrDex.Ed25519N)):
            raise ValidationError("ESSR requires a local individual habitat with one Ed25519 key")
        if (parser.rvy is None or isinstance(allowedRoutes, (str, bytes)) or
                not allowedRoutes or
                any(not isinstance(route, str) or not route.startswith('/')
                    for route in allowedRoutes)):
            raise ValidationError("ESSR requires the application reply processor and allowed routes")
        self.hby = hby
        self.hab = hab
        self.parser = parser
        self.allowedRoutes = frozenset(allowedRoutes)

    def _verfer(self, serder):
        """Return the local recipient Verfer bound by outer ``serder``.

        Coordinates, when supplied, must name an accepted establishment event.
        Raises ValidationError if the signed sender, destination or key differs.
        """
        q = serder.ked['q']
        if q.get('src') != serder.pre or q.get('dest') != self.hab.pre:
            raise ValidationError("Invalid ESSR sender or recipient")
        fields = {'sn', 'dig', 'key'}
        if fields.intersection(q):
            if not fields.issubset(q):
                raise ValidationError("Incomplete ESSR recipient key binding")
            if not isinstance(q['sn'], str) or not re.fullmatch(r'0|[1-9a-f][0-9a-f]*', q['sn']):
                raise ValidationError("Invalid ESSR recipient establishment sequence")
            sn = int(q['sn'], 16)
            if self.hby.db.kels.getLast(keys=self.hab.pre, on=sn) != q['dig']:
                raise ValidationError("Unaccepted ESSR recipient establishment event")
            event = self.hby.db.evts.get(keys=(self.hab.pre, q['dig']))
            if event is None or not event.estive:
                raise ValidationError("Invalid ESSR recipient establishment event")
            _, verfers = self.hby.db.resolveVerifiers(
                pre=self.hab.pre, sn=sn, dig=q['dig'])
            if len(verfers) != 1 or verfers[0].qb64 != q['key']:
                raise ValidationError("Invalid ESSR recipient key binding")
        else:
            verfers = self.hab.kever.verfers
        if len(verfers) != 1 or verfers[0].code not in (MtrDex.Ed25519, MtrDex.Ed25519N):
            raise ValidationError("Unsupported ESSR recipient key")
        return verfers[0]

    def verify(self, serder, essr=None, **kwa):
        """Return whether signed outer ``serder`` addresses this ESSR receiver.

        ``essr`` is Exchanger's verified ciphertext; ``kwa`` contains unused
        transport attachments. Raises a static ValidationError on bad binding.
        """
        try:
            self._verfer(serder)
            return bool(essr)
        except Exception:
            raise ValidationError("Invalid ESSR reply envelope") from None

    def handle(self, serder, essr=None, **kwa):
        """Open ciphertext ``essr`` from outer ``serder`` and dispatch one reply.

        ``kwa`` holds unused outer attachments. Returns no acceptance receipt:
        borrowed domain handlers retain their normal authority and escrows.
        Errors exposed to Parser contain only static, nonsecret messages.
        """
        # No new key material or worker. Manager.decrypt uses the Keeper's
        # retained signing seed and existing authenticated Keeper decrypter.
        try:
            verfer = self._verfer(serder)
            if self.hab.mgr.aeid and self.hab.mgr.decrypter is None:
                raise DecryptError("ESSR recipient keystore is locked")
            plain = bytearray(self.hab.mgr.decrypt(qb64=essr, verfers=[verfer]))
            tag = self.parser.extract(plain, PayloadTyper)
            source = self.parser.extract(plain, Prefixer)
            self.parser.extract(plain, Bexter)
            if tag.type != PayloadTypes.SCS or source.qb64 != serder.pre:
                raise ValidationError("Invalid ESSR payload sender or type")
            parsed = parseReply(self.parser, plain, self.allowedRoutes)
        except DecryptError:
            raise ValidationError("ESSR recipient keystore is locked") from None
        except ValueError as ex:
            # Manager.decrypt has no typed missing-key exception. Preserve that
            # condition with a static message without exposing its key value.
            if str(ex).startswith("Missing prikey in db for pubkey="):
                raise ValidationError("ESSR recipient private key is unavailable") from None
            raise ValidationError("Unable to open ESSR reply") from None
        except Exception:
            raise ValidationError("Unable to open ESSR reply") from None
        try:
            # Preserve the owner's V2 allow/deny and KRAM path before Revery.
            self.parser.msgProcess(exts=asdict(parsed), kvy=self.parser.kvy,
                                   rvy=self.parser.rvy, tvy=None, exc=None, vry=None)
        except Exception:
            raise ValidationError("ESSR inner reply was not accepted") from None
