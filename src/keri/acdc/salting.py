"""Explicit encrypted copies of existing registry roots, using ordinary replies."""

from ..app.habbing import GroupHab, Hab
from ..core import Blinder, Cipher, Encrypter, MtrDex, Number, Prefixer, Salter, reply
from ..kering import AuthError, Ilks, Kinds, ValidationError, Vrsn_2_0
from .regeventing import vetAnchor, vetBlind


class RegistrySalt:
    """Transfer an existing root after explicit local approval and reply authentication.

    Register with ``Router.addRoute(Route, instance, attachments=True)``. The
    caller owns delivery and group approval of the exact returned reply bytes.
    A group coordinator prepares ciphertext; ordinary indexed signatures still
    supply the group's full threshold. There is no automatic issuance fallback.

    Receive approvals are process-local and disappear on restart/abandonment.
    Each approves one accepted BUP/opening against which the decrypted root is
    checked before immutable encrypted Keeper retention. Public TEL storage is
    unchanged; neither roots nor transfer records are added to it.
    """

    Route = "/registry/salt"

    def __init__(self, hab, rgy):
        if not isinstance(hab, (Hab, GroupHab)) or (
                isinstance(hab, GroupHab) and not isinstance(hab.mhab, Hab)):
            raise AuthError("registry transfer requires local signing and decryption habitats")
        if hab.db is not rgy.hby.db:
            raise ValueError("registry transfer requires the habitat's actual registry owner")
        self.hab, self.rgy = hab, rgy
        self.target = hab.mhab if isinstance(hab, GroupHab) else hab
        self._approvals = {}

    def _unlocked(self):
        mgr = self.hab.mgr
        if not (mgr.aeid and mgr.encrypter and mgr.decrypter):
            raise AuthError("registry transfer requires an encrypted unlocked Keeper")

    def _scope(self, registry, sender, recipient, target):
        """Verify accepted registry authority and current member-key contribution."""
        try:
            if any(Prefixer(qb64=aid).qb64 != aid for aid in (sender, recipient, target)):
                raise ValueError
        except Exception:
            raise ValidationError("invalid registry transfer identity") from None
        rip = self.rgy.store.seqEvent(registry, 0)
        head = self.rgy.store.headEvent(registry)
        if (rip is None or rip.said != registry or rip.ilk != Ilks.rip
                or head is None or head.ilk != Ilks.bup):
            raise ValidationError("root transfer requires an accepted registry update")
        vetAnchor(rip, db=self.hab.db, issuer=rip.israid)
        kevers = self.hab.db.kevers
        if any(aid not in kevers for aid in (sender, recipient, target)):
            raise ValidationError("registry transfer requires accepted party key state")
        if recipient != target:
            if kevers[target].fetchLatestContribTo(verfers=kevers[recipient].verfers) is None:
                raise ValidationError("encryption target is not a current group signing member")
        if sender != rip.israid and not (sender == recipient and recipient != target):
            raise ValidationError("only the issuer or recipient group may authorize this transfer")
        key = kevers[target].verfers[0]
        if key.code not in (MtrDex.Ed25519, MtrDex.Ed25519N):
            raise ValidationError("recipient encryption requires a current Ed25519 key")
        return key

    def _event(self, registry, said, proof):
        event = self.rgy.store.event(said)
        if event is None or event.said != said or event.ilk != Ilks.bup or event.sad['rd'] != registry:
            raise ValidationError("approval requires the exact registry BUP")
        accepted = self.rgy.store.seqSaider(registry, Number(numh=event.sad['n']).num)
        if accepted is None or accepted.qb64 != said:
            raise ValidationError("approval BUP is not accepted")
        rip = self.rgy.store.seqEvent(registry, 0)
        vetAnchor(event, db=self.hab.db, issuer=rip.israid)
        vetBlind(proof, blid=event.sad['b'])
        return event

    def approve(self, registry, sender, *, event, opening):
        """Approve receipt using an exact accepted event and already held opening.

        These are local evidence, not additional transfer wire fields. A BoundState
        opening is usable without guessing its Issuee coordinates or state.
        """
        self._unlocked()
        self._scope(registry, sender, self.hab.pre, self.target.pre)
        if not isinstance(opening, Blinder):
            raise ValidationError("approval requires a held opening")
        self._event(registry, event, opening)
        self._approvals[(registry, sender)] = (event, opening.qb64, opening.uuid)

    def abandon(self, registry, sender):
        """Revoke this process's receive approval; retained roots remain immutable."""
        self._approvals.pop((registry, sender), None)

    def prepare(self, registry, recipient, target, *, coordinator=None):
        """Return one signed encrypted reply, or a group member's partial reply.

        A group caller supplies its existing coordinator's exact accepted own KEL
        ``(sn, digest)``. Only that elected member prepares the ciphertext. Others
        explicitly approve and endorse the returned, unchanged reply body.
        """
        self._unlocked()
        key = self._scope(registry, self.hab.pre, recipient, target)
        if isinstance(self.hab, GroupHab):
            if coordinator is None or not self.hab.witnesser(sn=coordinator[0], dig=coordinator[1]):
                raise ValidationError("only the existing elected group coordinator prepares a root copy")
            if self.target.kever.fetchLatestContribTo(verfers=self.hab.kever.verfers) is None:
                raise ValidationError("group coordinator is no longer a current signing member")
        root = self.hab.mgr.getRegistryRoot(self.hab.pre, registry)
        if root is None:
            raise ValidationError("authorized registry root is unavailable")
        cipher = Encrypter(verkey=key.qb64).encrypt(prim=root)
        message = reply(pre=self.hab.pre, route=self.Route, pvrsn=Vrsn_2_0, kind=Kinds.json,
                        data=dict(registry=registry, recipient=recipient,
                                  target=target, cipher=cipher.qb64))
        return bytes(self.hab.endorse(message, gvrsn=Vrsn_2_0))

    def processReply(self, *, serder, diger, route, cigars=None, tsgs=None, attachments=None):
        """Authenticate current authorization before decrypting and retaining a root."""
        if (serder.ilk != Ilks.rpy or serder.pvrsn != Vrsn_2_0 or route != self.Route
                or serder.sad.get('r') != self.Route or not serder.verify()):
            raise ValidationError("invalid registry transfer reply")
        if attachments is None or any(value for key, value in attachments.items()
                                      if key not in ('sigers', 'local')):
            raise ValidationError("registry transfer carries unsupported attachments")
        data = serder.sad.get('a')
        if (not isinstance(data, dict) or set(data) != {'registry', 'recipient', 'target', 'cipher'}
                or any(not isinstance(value, str) for value in data.values())):
            raise ValidationError("invalid registry transfer scope")
        registry, sender = data['registry'], serder.pre
        approval = self._approvals.get((registry, sender))
        if approval is None or data['recipient'] != self.hab.pre or data['target'] != self.target.pre:
            raise ValidationError("registry transfer has no exact local approval")
        self._unlocked()
        key = self._scope(registry, sender, data['recipient'], data['target'])
        event, proof, uuid = approval
        event = self._event(registry, event, proof)
        try:
            cipher = Cipher(qb64=data['cipher'])
            if cipher.code != MtrDex.X25519_Cipher_Salt or cipher.qb64 != data['cipher']:
                raise ValueError
        except Exception:
            raise ValidationError("invalid encrypted Salt128 root") from None
        # BADA alone permits an older establishment without a prior reply. New
        # capability grants require the author's current accepted threshold.
        author = self.hab.db.kevers[sender]
        current = [group for group in tsgs or [] if group[0].qb64 == sender
                   and group[1].sn == author.lastEst.s and group[2].qb64 == author.lastEst.d]
        nontrans = [c for c in cigars or [] if c.verfer.qb64 == sender]
        if not current and not nontrans:
            raise ValidationError("registry transfer requires current author signatures")
        if not self.hab.rvy.acceptReply(serder=serder, saider=diger, route=route,
                                      aid=sender, cigars=nontrans, tsgs=current):
            return
        try:
            # Hab.decrypt expects sealed-box bytes, not the outer CESR encoding.
            plain = self.target.decrypt(cipher.raw, verfers=[key])
            root = Salter(qb64=plain)
            if root.code != MtrDex.Salt_128 or root.qb64b != plain:
                raise ValueError
        except Exception:
            raise ValidationError("root cannot be decrypted with the current target key") from None
        if Blinder.makeUUID(salt=root.qb64, sn=Number(numh=event.sad['n']).num) != uuid:
            raise ValidationError("root does not reproduce the approved accepted opening")
        self.hab.mgr.putRegistryRoot(self.hab.pre, registry, root)
