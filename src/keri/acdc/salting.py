"""Explicit encrypted copies of existing registry roots.

``RegistryRoot`` replicates held roots to individual members with ESSR
``exn`` messages (local profile). ``RegistrySalt`` is the earlier reply form.
"""

from ..app.habbing import GroupHab, Hab
from ..core import Blinder, Cipher, Encrypter, MtrDex, Number, Prefixer, Salter, reply
from ..kering import AuthError, Ilks, KeriError, Kinds, ValidationError, Vrsn_2_0
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
        """Return True only after authenticated retention, including an identical root.

        Incomplete reply authentication returns None without retaining a root.
        """
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
        return True


class RootRefused(ValidationError):
    """A stored registry-root copy that can never be retained as received."""


class RootUnverified(ValidationError):
    """A stored registry-root copy whose root cannot yet be verified locally."""


def rootExn(hab, recipient, gid, registry, root, *, event, td=None, kind=None):
    """Return one signed v2 ``/registry/root`` ESSR exchange carrying ``root``.

    Local profile, not an upstream KERI/ACDC or #1740 form. The individual
    ``hab`` signs a bare ``exn`` (``x``/``p`` empty) whose ``a`` is
    ``{essr, gid, rd}``: ``essr`` is the Blake3-256 digest of a libsodium
    sealed box to ``recipient``'s current first signing key, as
    ``StreamPoster._essrWrapper`` seals. The box holds the JSON field map
    ``{i, ri, gid, rd, s, e[, td]}``: sender, recipient, holder AID, registry,
    Salt128 root, one accepted BUP SAID and an optional ACDC SAID hint. The
    sealed box travels as one ESSR payload Texter. Callers apply policy first.

    Parameters:
        hab (Hab): individual sending habitat
        recipient (str): individual member AID that will decrypt the box
        gid (str): AID the root is held for (a group, or ``recipient``)
        registry (str): registry SAID
        root (Salter): Salt128 registry root
        event (str): one accepted BUP SAID of ``registry``
        td (str | None): optional ACDC SAID hint for commitment reproduction
        kind (str | None): serialization kind

    Returns:
        bytes: the framed exchange with signatures and ESSR payload
    """
    import json

    import pysodium

    from ..core import Codens, Counter, Diger, Texter, exchange

    if isinstance(hab, GroupHab) or not isinstance(hab, Hab):
        raise ValidationError("registry root copies are signed by an individual habitat")
    if not isinstance(root, Salter) or root.code != MtrDex.Salt_128:
        raise ValidationError("registry root must be a Salt128 primitive")
    verfer = hab.db.kevers[recipient].verfers[0]
    if verfer.code not in (MtrDex.Ed25519, MtrDex.Ed25519N):
        raise ValidationError("recipient encryption requires a current Ed25519 key")
    plain = dict(i=hab.pre, ri=recipient, gid=gid, rd=registry, s=root.qb64, e=event)
    if td:
        plain["td"] = td
    raw = pysodium.crypto_box_seal(json.dumps(plain, separators=(",", ":")).encode(),
                                   pysodium.crypto_sign_pk_to_box_pk(verfer.raw))
    texter = Texter(raw=raw)
    digest = Diger(ser=raw, code=MtrDex.Blake3_256)
    serder = exchange(sender=hab.pre, receiver=recipient, route=RegistryRoot.Route,
                      attributes=dict(essr=digest.qb64, gid=gid, rd=registry),
                      version=Vrsn_2_0, kind=kind if kind is not None else Kinds.json)
    signed = hab.endorse(serder, framed=True, gvrsn=Vrsn_2_0)
    atc = bytearray(signed[serder.size:])
    atc.extend(Counter(Codens.ESSRPayloadGroup, count=len(texter.qb64b) // 4,
                       version=Vrsn_2_0).qb64b)
    atc.extend(texter.qb64b)
    return serder.raw + bytes(Counter.enclose(qb64=bytes(atc), code=Codens.AttachmentGroup,
                                              version=Vrsn_2_0))


class RegistryRoot:
    """Replicate held registry roots to individual members by ESSR ``exn``.

    Local profile route ``/registry/root``; see ``rootExn`` for the wire.
    Register on the Habery's Exchanger with ``exc.addHandler``. ``verify``
    authorizes from the accepted KEL and TEL only, before anything persists:

    - recipient ``ri``: a local individual habitat that is a current signing
      member of ``gid`` (or is ``gid``, an individual holder) with a local
      group habitat for ``gid``;
    - sender ``i``: an individual AID, other than the recipient, that is a
      historical signing member of ``gid``, the registry issuer, or a
      historical signing member of the issuer group;
    - registry ``rd``: an accepted, issuer-anchored registry with a BUP head;
    - ``a.essr``: the Blake3-256 digest of the attached ESSR payload.

    Accepted copies persist in the Exchanger's ``exns``/``essrs`` stores with
    a Notifier note, so pending copies survive restart without a new ledger.
    Nothing is decrypted until ``receive``, the explicit receiver approval,
    which checks the plaintext binding and verifies the root against a held
    opening or by reproducing the BUP ``b`` commitment before retention.
    """

    Route = "/registry/root"
    Note = "/exn/registry/root"
    States = ("issued", "revoked")

    def __init__(self, hby, rgy, notifier=None):
        if rgy.hby is not hby:
            raise ValueError("registry root replication requires the Habery's registry owner")
        self.hby, self.rgy, self.notifier = hby, rgy, notifier
        self.resource = self.Route

    # policy

    def _historical(self, member, group):
        """True when ``member`` contributed to any accepted establishment of ``group``."""
        kevers = self.hby.db.kevers
        mkever, gkever = kevers.get(member), kevers.get(group)
        if mkever is None or gkever is None:
            return False
        for dig in self.hby.db.kels.getBackIter(keys=group, on=gkever.sn):
            event = self.hby.db.evts.get(keys=(group, dig))
            if (event is not None and event.estive
                    and mkever.fetchLatestContribTo(verfers=event.verfers) is not None):
                return True
        return False

    def _current(self, member, group):
        """True when ``member``'s latest contributing key is in ``group``'s current keys."""
        kevers = self.hby.db.kevers
        if member not in kevers or group not in kevers:
            return False
        return kevers[member].fetchLatestContribTo(verfers=kevers[group].verfers) is not None

    def registry(self, registry):
        """Return the accepted, issuer-anchored ``rip`` of ``registry``."""
        store = self.rgy.store
        rip, head = store.seqEvent(registry, 0), store.headEvent(registry)
        if (rip is None or rip.said != registry or rip.ilk != Ilks.rip
                or head is None or head.ilk != Ilks.bup):
            raise ValidationError("root replication requires an accepted registry update")
        vetAnchor(rip, db=self.hby.db, issuer=rip.israid)
        return rip

    def authorize(self, sender, recipient, gid, registry):
        """Raise ValidationError unless this KEL/TEL state authorizes the copy."""
        try:
            if any(Prefixer(qb64=aid).qb64 != aid for aid in (sender, recipient, gid)):
                raise ValueError
            from ..core import Saider
            if Saider(qb64=registry).qb64 != registry:
                raise ValueError
        except Exception:
            raise ValidationError("invalid registry root identity") from None
        rip = self.registry(registry)
        kevers = self.hby.db.kevers
        if any(aid not in kevers for aid in (sender, recipient, gid)):
            raise ValidationError("registry root replication requires accepted party key state")
        if sender == recipient:
            raise ValidationError("registry root sender and recipient must differ")
        if recipient != gid and not self._current(recipient, gid):
            raise ValidationError("recipient is not a current signing member of the holder")
        issuer = rip.israid
        if not (self._historical(sender, gid) or sender == issuer
                or self._historical(sender, issuer)):
            raise ValidationError("sender is not a historical holder member or registry issuer")
        if kevers[recipient].verfers[0].code not in (MtrDex.Ed25519, MtrDex.Ed25519N):
            raise ValidationError("recipient encryption requires a current Ed25519 key")
        return rip

    def newcomers(self, ghab, rotation):
        """Return current signing member AIDs added by one accepted group rotation.

        Members, not keys, are compared: a continuing member usually rotates
        its own key, so it contributes to both establishments. Candidates are
        the AIDs with accepted key state in this Habery.
        """
        if not isinstance(ghab, GroupHab) or ghab.db is not self.hby.db:
            raise ValidationError("newcomers require a local group habitat")
        pre, db = ghab.pre, self.hby.db
        event = db.evts.get(keys=(pre, rotation))
        if (event is None or event.ilk not in (Ilks.rot, Ilks.drt)
                or db.kels.getLast(keys=pre, on=event.sn) != rotation):
            raise ValidationError("newcomers require an accepted group rotation")
        prior = ghab.kvy.fetchEstEvent(pre, event.sn - 1)
        if prior is None:
            raise ValidationError("rotation has no accepted prior establishment")
        found = []
        for (aid,), _ in db.states.getTopItemIter():
            kever = db.kevers.get(aid)
            if aid == pre or kever is None:
                continue
            added = kever.fetchLatestContribTo(verfers=event.verfers)
            if (added is not None and kever.fetchLatestContribTo(verfers=prior.verfers) is None
                    and self._current(aid, pre)):
                found.append((added[1], aid))
        return [aid for _, aid in sorted(found)]

    def members(self, gid):
        """Return the current signing member AIDs of ``gid`` known to this Habery."""
        found = []
        for (aid,), _ in self.hby.db.states.getTopItemIter():
            if aid != gid and self._current(aid, gid):
                found.append((self.hby.db.kevers[aid].fetchLatestContribTo(
                    verfers=self.hby.db.kevers[gid].verfers)[1], aid))
        return [aid for _, aid in sorted(found)]

    def held(self, gid):
        """Return the registry SAIDs with a root retained locally for ``gid``."""
        return sorted(regid for (aid, regid), _ in self.hby.ks.rroots.getTopItemIter() if aid == gid)

    def witnesser(self, ghab, rotation):
        """True when ``ghab``'s local member is the elected sender for ``rotation``."""
        from ..app.habbing import _groupWitnesserSelection
        event = self.hby.db.evts.get(keys=(ghab.pre, rotation))
        if event is None:
            return False
        selection = _groupWitnesserSelection(ghab, sn=event.sn, dig=rotation)
        if selection is None:
            return False
        establishment, index = selection
        mine = ghab.mhab.kever.fetchLatestContribTo(verfers=establishment.verfers)
        return mine is not None and mine[1] == index

    # sending

    def prepare(self, hab, recipient, gid, registry, *, event=None, td=None):
        """Return one authorized copy of a root held locally for ``gid`` or the issuer.

        ``hab`` is the local individual sender. ``event`` defaults to the
        registry's accepted BUP head.
        """
        rip = self.authorize(hab.pre, recipient, gid, registry)
        root = None
        for holder in (gid, rip.israid):
            if holder in self.hby.habs:
                root = self.hby.mgr.getRegistryRoot(holder, registry)
                if root is not None:
                    break
        if root is None:
            raise ValidationError("no local root is held for this registry")
        bup = self._event(registry, event if event is not None
                          else self.rgy.store.headEvent(registry).said, rip)
        return rootExn(hab, recipient, gid, registry, root, event=bup.said, td=td)

    # receiving

    def _event(self, registry, said, rip=None):
        event = self.rgy.store.event(said) if isinstance(said, str) else None
        if event is None or event.said != said or event.ilk != Ilks.bup or event.sad['rd'] != registry:
            raise RootUnverified("root verification requires an accepted registry BUP")
        accepted = self.rgy.store.seqSaider(registry, Number(numh=event.sad['n']).num)
        if accepted is None or accepted.qb64 != said:
            raise RootUnverified("root verification BUP is not accepted")
        rip = rip if rip is not None else self.rgy.store.seqEvent(registry, 0)
        vetAnchor(event, db=self.hby.db, issuer=rip.israid)
        return event

    def _scope(self, serder, essr):
        """Check the outer exchange and authorize it; return (recipient hab, gid, rd)."""
        from ..core import Diger
        data = serder.ked.get('a')
        if (serder.pvrsn != Vrsn_2_0 or serder.ilk != Ilks.exn or serder.ked.get('r') != self.Route
                or serder.ked.get('x') or serder.ked.get('p') or serder.ked.get('q')
                or not isinstance(data, dict) or set(data) != {'essr', 'gid', 'rd'}
                or any(not isinstance(value, str) for value in data.values())):
            raise ValidationError("invalid registry root exchange")
        recipient = serder.ked.get('ri')
        hab = self.hby.habs.get(recipient)
        if isinstance(hab, GroupHab) or not isinstance(hab, Hab):
            raise ValidationError("registry root recipient is not a local individual habitat")
        gid, registry = data['gid'], data['rd']
        holder = self.hby.habs.get(gid)
        if gid != recipient and not (isinstance(holder, GroupHab) and holder.mhab.pre == recipient):
            raise ValidationError("registry root holder is not this member's local group")
        if not essr:
            raise ValidationError("registry root exchange requires an ESSR payload")
        digest = Diger(qb64=data['essr'])
        if digest.code != MtrDex.Blake3_256 or digest.qb64 != data['essr'] or not digest.verify(ser=essr):
            raise ValidationError("ESSR payload does not match its digest")
        self.authorize(serder.pre, recipient, gid, registry)
        return hab, gid, registry

    def verify(self, serder, attachments=None, essr=None, **kwa):
        """Authorize before the Exchanger persists; never decrypt here."""
        try:
            self._scope(serder, essr)
            return True
        except (KeriError, ValueError, KeyError, TypeError, AttributeError):
            return False

    def handle(self, serder, attachments=None, essr=None, **kwa):
        if self.notifier is not None:
            data = serder.ked['a']
            self.notifier.add(attrs=dict(r=self.Note, d=serder.said, i=serder.pre,
                                         ri=serder.ked['ri'], gid=data['gid'], rd=data['rd']))

    def _stored(self, said):
        serder = self.hby.db.exns.get(keys=(said,))
        if serder is None or serder.ked.get('r') != self.Route:
            raise ValidationError("no stored registry root copy")
        essr = b''.join(texter.raw for texter in self.hby.db.essrs.get(keys=(said,)))
        return serder, essr

    def _open(self, serder, essr):
        """Return (gid, rd, root, plaintext) after decrypting and binding the box."""
        import json
        hab, gid, registry = self._scope(serder, essr)
        mgr = hab.mgr
        if not (mgr.aeid and mgr.encrypter and mgr.decrypter):
            raise AuthError("registry root receipt requires an encrypted unlocked Keeper")
        try:
            plain = json.loads(hab.decrypt(ser=essr, verfers=hab.kever.verfers[:1]))
        except Exception:
            raise RootRefused("registry root cannot be decrypted with the current recipient key; "
                              "resend needed") from None
        if (not isinstance(plain, dict) or not {'i', 'ri', 'gid', 'rd', 's', 'e'} <= set(plain) <=
                {'i', 'ri', 'gid', 'rd', 's', 'e', 'td'}
                or any(not isinstance(value, str) for value in plain.values())
                or (plain['i'], plain['ri'], plain['gid'], plain['rd'])
                != (serder.pre, hab.pre, gid, registry)):
            raise RootRefused("registry root plaintext does not match its exchange")
        try:
            root = Salter(qb64=plain['s'])
            if root.code != MtrDex.Salt_128 or root.qb64 != plain['s']:
                raise ValueError
        except Exception:
            raise RootRefused("registry root is not a canonical Salt128") from None
        return gid, registry, root, plain

    def receive(self, said, *, event=None, opening=None):
        """Explicitly approve one stored copy; verify and retain its root.

        ``event`` overrides the sender's BUP hint; ``opening`` is a held
        Blinder for that BUP. Without one, a held opening in the registry
        store is used, else the BUP ``b`` commitment is reproduced from
        ``(uuid, td, ts)`` using the sender's ``td`` hint. Returns True on
        retention. RootRefused marks a copy that can never be retained;
        RootUnverified leaves it pending.
        """
        serder, essr = self._stored(said)
        gid, registry, root, plain = self._open(serder, essr)
        bup = self._event(registry, event if event is not None else plain['e'])
        sn, blid = Number(numh=bup.sad['n']).num, bup.sad['b']
        uuid = Blinder.makeUUID(salt=root.qb64, sn=sn)
        held = opening if opening is not None else self.rgy.store.opening(bup.said)
        if held is not None:
            if not isinstance(held, Blinder):
                raise ValidationError("held opening must be a Blinder")
            vetBlind(held, blid=blid)
            if held.uuid != uuid:
                raise RootUnverified("root does not reproduce the held opening")
        elif not self._reproduces(blid, uuid, plain.get('td', ''), gid):
            raise RootUnverified("root does not yet reproduce the registry commitment")
        retained = self.hby.mgr.getRegistryRoot(gid, registry)
        if retained is not None and retained.qb64 != root.qb64:
            raise RootRefused("a different root is already retained for this holder and registry")
        self.hby.mgr.putRegistryRoot(gid, registry, root)
        self._notes(said, read=True)
        return True

    def _reproduces(self, blid, uuid, td, gid):
        if Blinder.unblind(said=blid, uuid=uuid, acdc=td, states=self.States) is not None:
            return True
        kever = self.hby.db.kevers.get(gid)
        bounds = []
        if kever is not None:
            for sn in range(kever.sn + 1):
                dig = self.hby.db.kels.getLast(keys=gid, on=sn)
                if dig is not None:
                    bounds.append((sn, dig))
        return Blinder.unblind(said=blid, uuid=uuid, acdc=td, states=self.States,
                               bound=True, bounds=bounds) is not None

    def pending(self):
        """List stored copies to local recipients whose root is not yet retained.

        Each item has ``said, sender, recipient, gid, registry, dt``. With an
        unlocked Keeper a retained identical root resolves the copy; a
        different retained root is reported with ``error``.
        """
        items = []
        for (said,), serder in self.hby.db.exns.getTopItemIter():
            if serder.ked.get('r') != self.Route or serder.ked.get('ri') not in self.hby.habs:
                continue
            data = serder.ked.get('a') or {}
            gid, registry = data.get('gid'), data.get('rd')
            item = dict(said=said, sender=serder.pre, recipient=serder.ked['ri'], gid=gid,
                        registry=registry, dt=serder.ked.get('dt'))
            try:
                retained = self.hby.mgr.getRegistryRoot(gid, registry)
            except (KeriError, ValueError):
                retained = None
            if retained is not None:
                try:
                    _, _, root, _ = self._open(*self._stored(said))
                except (KeriError, ValueError) as error:
                    item['error'] = str(error)
                else:
                    if root.qb64 == retained.qb64:
                        continue
                    item['error'] = "a different root is already retained"
            items.append(item)
        return items

    def _notes(self, said, *, read=False):
        if self.notifier is None:
            return 0
        count = 0
        for _, note in list(self.notifier.noter.notes.getTopItemIter()):
            if note.attrs.get('r') == self.Note and note.attrs.get('d') == said:
                count += bool(self.notifier.mar(note.rid) if read else self.notifier.rem(note.rid))
        return count

    def dismiss(self, said):
        """Remove this copy's Notifier note; the exchange store is unchanged."""
        return self._notes(said)
