"""Derivation for the local IPEX DHKE profile.

This is not a standardized KERI key derivation. The caller must authenticate
the live Grant, participants and fresh registry scope before using these
primitives. Ephemeral private keys belong to that live operation, not Keeper.
"""

import hashlib
import struct

import pysodium
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..core import Matter, MtrDex, Prefixer, Saider, Salter


Domain = b"KERI/ipex/dhke/X25519-HKDF-SHA256-Salt128/v1"


def _canonical(qb64, klas):
    """Parse exactly one canonical qualified primitive, without trailing data."""
    if not isinstance(qb64, str) or not qb64:
        raise ValueError("expected a canonical CESR string")
    try:
        material = klas(qb64=qb64)
    except Exception:
        raise ValueError("invalid CESR material") from None
    if material.qb64 != qb64:
        raise ValueError("noncanonical or trailing CESR material")
    return material


def decodePublicKey(qb64):
    """Decode one CESR C X25519 public key; contributory checks occur in DH."""
    material = _canonical(qb64, Matter)
    if material.code != MtrDex.X25519 or len(material.raw) != 32:
        raise ValueError("expected a CESR X25519 public key")
    return material.raw


def generateKeyPair():
    """Return (private bytes, public qb64) for one fresh registry operation."""
    private = pysodium.randombytes(32)
    public = pysodium.crypto_scalarmult_curve25519_base(private)
    return private, Matter(raw=public, code=MtrDex.X25519).qb64


def deriveRoot(private, *, role, x, grant, registry, issuer, issuee,
               issuer_pk, issuee_pk):
    """Derive a Salt128 bound to the exact Grant, registry, parties and keys.

    ``role`` is the local party, either ``issuer`` or ``issuee``. The advertised
    key for that role must match the supplied 32-byte ephemeral private key.
    XIP identity ``x`` may differ from ``grant`` for Apply/Offer-first flows.
    Returns a Salter. Malformed input, mismatched local keys and noncontributory
    peer keys raise ValueError; no signing-key conversion or key storage occurs.
    """
    if role not in ("issuer", "issuee"):
        raise ValueError("role must be issuer or issuee")
    if not isinstance(private, (bytes, bytearray, memoryview)) or len(private) != 32:
        raise ValueError("expected a 32-byte ephemeral private key")
    private = bytes(private)
    for value in (x, grant, registry):
        _canonical(value, Saider)
    for value in (issuer, issuee):
        _canonical(value, Prefixer)
    issuerKey, issueeKey = decodePublicKey(issuer_pk), decodePublicKey(issuee_pk)
    own, peer = (issuerKey, issueeKey) if role == "issuer" else (issueeKey, issuerKey)
    if pysodium.crypto_scalarmult_curve25519_base(private) != own:
        raise ValueError("local ephemeral private and public keys do not match")
    try:
        shared = pysodium.crypto_scalarmult_curve25519(private, peer)
    except Exception:
        raise ValueError("noncontributory X25519 public key") from None
    if shared == bytes(32):
        raise ValueError("noncontributory X25519 public key")
    parts = [Domain, *(value.encode("ascii") for value in
                       (x, grant, registry, issuer, issuee, issuer_pk, issuee_pk))]
    info = b"".join(struct.pack(">I", len(part)) + part for part in parts)
    raw = HKDF(algorithm=hashes.SHA256(), length=16,
               salt=hashlib.sha256(Domain).digest(), info=info).derive(shared)
    return Salter(raw=raw, code=MtrDex.Salt_128)


class Dhke:
    """DH for explicitly approved pending Grants, with one custodian per party.

    The caller injects this instance as Kevery.qvy and registers it at
    /ipex/dhke on Revery's existing router. ``cues`` carries immutable signed
    bytes as {kin: 'query'|'reply'|'sign', dest: aid, msg: bytes}; 'sign' asks
    local members to review a proposal. The application owns delivery.
    JSON bodies preserve registry-keyed maps (native strict map labels cannot
    encode every registry ID). Attachments use the normal V2 CESR framing.
    Operations and retry bytes are process-local. A new instance authorizes
    nothing; it cannot recover an unfinished exchange's ephemeral keys.

    A local group explicitly names its already elected coordinator event and
    custodian. Only that member generates/derives keys; other members contribute
    ordinary signatures to its exact proposal. Own complete queries/replies
    return through the same Parser/KRAM/Revery threshold owners before a query
    becomes outstanding or a reply permits Keeper retention. No signature pool
    or recovery state belongs to this operation.
    """
    Route = "/ipex/dhke"

    def __init__(self, hab, exc):
        from collections import deque
        from ..app.habbing import GroupHab, Hab
        if (not isinstance(hab, (Hab, GroupHab)) or hab.db is not exc.hby.db
                or isinstance(hab, GroupHab) and not isinstance(hab.mhab, Hab)):
            raise ValueError("DH requires a local signing habitat and its Exchanger")
        self.hab, self.exc = hab, exc
        self.group = isinstance(hab, GroupHab)
        self.cues = deque()
        self._operations = {}

    def _unlocked(self):
        from ..kering import AuthError
        mgr = self.hab.mgr
        if not (mgr.aeid and mgr.encrypter and mgr.decrypter):
            raise AuthError("DH requires an encrypted, unlocked Keeper")

    def approve(self, grant, *, coordinator=None, custodian=None):
        """Select a pending Grant; group consent names its own (sn, SAID) and member.

        This local profile freezes the existing witnesser selection at approval.
        The issuee may choose its own accepted KEL event without a preceding
        Apply. Neither opposite-party signatures nor later signatures reelect it.
        """
        from ..kering import Ilks, ValidationError
        self._unlocked()
        for existing in self._operations.values():
            if existing["grant"] == grant:
                if ((coordinator is not None and coordinator != existing['coordinator'])
                        or (custodian is not None and custodian != existing['custodian'])):
                    raise ValidationError("DH coordinator and custodian are already frozen")
                self._live(existing)
                return existing["x"]
        message = self.exc.hby.db.epse.get((grant,))
        if message is None:
            raise ValidationError("DH requires a pending Grant")
        issuer, issuee = message.pre, message.ked.get("ri")
        if self.hab.pre not in (issuer, issuee) or issuer == issuee:
            raise ValidationError("local habitat is not a DH party")
        xid = message.said if message.ilk == Ilks.xip else message.ked.get("x")
        if xid in self._operations:
            raise ValidationError("another Grant is already selected for this transaction")
        from ..peer.exchanging import loadParsedNestedSubstreams
        bodies = tuple(nest.serder.raw for nest in loadParsedNestedSubstreams(self.exc.hby, grant))
        op = dict(grant=grant, raw=message.raw, bodies=bodies, x=xid, issuer=issuer, issuee=issuee,
                  registries=None, private={}, public={}, peer=None,
                  query=None, reply=None, proposal=None, contribution=None,
                  coordinator=None, custodian=None, election=None,
                  completed=False, abandoned=False)
        if self.group:
            from ..app.habbing import _groupWitnesserSelection
            if not isinstance(coordinator, tuple) or len(coordinator) != 2 or not custodian:
                raise ValidationError("group DH requires its own accepted coordinator and custodian")
            selection = _groupWitnesserSelection(self.hab, sn=coordinator[0], dig=coordinator[1])
            if selection is None:
                raise ValidationError("group coordinator event lacks accepted threshold evidence")
            establishment, index = selection
            op.update(coordinator=coordinator, custodian=custodian,
                      election=(establishment.said, index, establishment.verfers[index].qb64))
        elif coordinator is not None or custodian is not None:
            raise ValidationError("individual DH has no group coordinator")
        context = self._live(op)
        op["registries"] = context[1]
        self._roots(op)
        self._operations[xid] = op
        return xid

    def _custody(self, op, *, lead=False):
        """Recheck frozen election evidence and current membership without reelecting."""
        from ..core.eventing import verifySigs
        from ..kering import ValidationError
        if not self.group:
            return True
        sn, dig = op['coordinator']
        db = self.hab.db
        establishment = self.hab.kvy.fetchEstEvent(self.hab.pre, sn)
        event = db.evts.get(keys=(self.hab.pre, dig))
        member = db.kevers.get(op['custodian'])
        if (db.kels.getLast(keys=self.hab.pre, on=sn) != dig or event is None
                or event.pre != self.hab.pre or event.said != dig or event.sn != sn or establishment is None
                or establishment.said != op['election'][0] or member is None):
            raise ValidationError("frozen group coordinator evidence is unavailable")
        _, indices = verifySigs(event.raw, db.sigs.get(keys=(self.hab.pre, dig)), establishment.verfers)
        if not establishment.tholder.satisfy(indices) or op['election'][1] not in indices:
            raise ValidationError("frozen group coordinator signature evidence is unavailable")
        contribution = member.fetchLatestContribTo(verfers=establishment.verfers)
        if (contribution is None or contribution[1] != op['election'][1]
                or contribution[2].qb64 != op['election'][2]
                or member.fetchLatestContribTo(verfers=self.hab.kever.verfers) is None
                or self.hab.mhab.kever.fetchLatestContribTo(verfers=self.hab.kever.verfers) is None):
            raise ValidationError("frozen DH custodian or local member is no longer authorized")
        elected = self.hab.mhab.pre == op['custodian']
        if lead and not elected:
            raise ValidationError("only the frozen DH custodian may generate or derive keys")
        return elected

    def _pending(self, op):
        """Read the original pending operation without changing its lifecycle."""
        from ..help import helping
        from ..kering import ValidationError
        from ..peer.exchanging import loadParsedNestedSubstreams
        self._unlocked()
        self._custody(op)
        db = self.exc.hby.db
        message, deadline = db.epse.get((op["grant"],)), db.epsd.get((op["grant"],))
        if (op["abandoned"] or message is None or message.raw != op["raw"]
                or deadline is None or helping.nowUTC() >= deadline.datetime
                or db.exns.get((op["grant"],)) is not None
                or db.erpy.get((op["grant"],)) is not None):
            raise ValidationError("DH operation is unavailable, terminated or expired")
        nests = loadParsedNestedSubstreams(self.exc.hby, op["grant"])
        if tuple(nest.serder.raw for nest in nests) != op["bodies"]:
            raise ValidationError("pending disclosure differs from the approved Grant")
        return message, nests

    def _live(self, op):
        """Fresh issuance authorizes DH; losing freshness does not abandon it."""
        from ..kering import ValidationError
        self._pending(op)
        context = self.exc.pendingGrant(op["grant"], xid=op["x"],
                                        sender=op["issuer"], recipient=op["issuee"])
        if context is None or (op["registries"] is not None
                               and context[1] != op["registries"]):
            raise ValidationError("DH requires authenticated fresh registry scope")
        return context

    def _roots(self, op):
        from ..kering import ValidationError
        for registry in op["registries"]:
            retained = self.hab.mgr.getRegistryRoot(self.hab.pre, registry)
            if (retained is not None) != op["completed"]:
                raise ValidationError("registry root conflicts with this live DH operation")

    def start(self, grant):
        """Return the issuer query, initially a partial proposal for a group.

        Feed the ordinary full aggregate through Parser before sending a group's
        query to its peer. Repeats preserve keys and the already signed bytes.
        """
        from ..core import query
        from ..kering import Kinds, ValidationError, Vrsn_2_0
        xid = self.approve(grant)
        op = self._operations[xid]
        if self.hab.pre != op["issuer"]:
            raise ValidationError("only the issuer starts DH")
        self._custody(op, lead=True)
        self._roots(op)
        if op["query"] is None and op['proposal'] is None:
            for registry in op["registries"]:
                op["private"][registry], op["public"][registry] = generateKeyPair()
            message = query(pre=self.hab.pre, route=self.Route, replyRoute=self.Route,
                            query=dict(x=xid, pk=op["public"]), pvrsn=Vrsn_2_0, kind=Kinds.json)
            signed = bytes(self.hab.endorse(message, last=True, gvrsn=Vrsn_2_0))
            if self.group:
                op['proposal'], op['contribution'] = message.raw, signed
            else:
                op['query'] = signed
        return op["query"] or op['contribution']

    def _preflight(self, serder, field, role, *, own=False):
        from ..kering import ValidationError
        data = serder.ked.get(field)
        from ..kering import Vrsn_2_0
        if (not serder.verify() or serder.pvrsn != Vrsn_2_0 or serder.ked.get("r") != self.Route
                or not isinstance(data, dict) or set(data) != {"x", "pk"}
                or not isinstance(data["x"], str) or not isinstance(data["pk"], dict)):
            raise ValidationError("invalid DH message shape")
        op = self._operations.get(data["x"])
        if op is None:
            raise ValidationError("DH transaction has no local approval")
        self._live(op)
        sender = op[role] if own else op["issuer"] if role == "issuee" else op["issuee"]
        if self.hab.pre != op[role] or serder.pre != sender:
            raise ValidationError("wrong DH sender or local recipient")
        if set(data["pk"]) != set(op["registries"]):
            raise ValidationError("DH registry scope differs from the selected Grant")
        for public in data["pk"].values():
            decodePublicKey(public)
        if not own and op["peer"] is not None and op["peer"] != data["pk"]:
            raise ValidationError("conflicting DH public keys")
        self._roots(op)
        return op, data["pk"]

    def contribute(self, xid, proposal):
        """Explicitly sign one unchanged custodian proposal; never perform DH.

        The partial custodian signature authenticates only this review/signing
        action. Complete route thresholds still belong to KRAM and Revery.
        The caller transports/aggregates ordinary endorsements; no pool is kept.
        """
        from ..core import Parser
        from ..core.eventing import verifySigs
        from ..kering import Ilks, ValidationError, Vrsn_2_0
        if not self.group:
            raise ValidationError("DH contribution requires a local group member")
        ims = bytearray(proposal)
        parsed = Parser(version=Vrsn_2_0).parseOne(ims=ims, processive=False)
        if ims or parsed is None or any(value for key, value in vars(parsed).items()
                                       if key not in ('serder', 'sigers', 'tsgs', 'lsgs')):
            raise ValidationError("DH proposal must be one signed query or reply")
        message = parsed.serder
        if message.ilk not in (Ilks.qry, Ilks.rpy):
            raise ValidationError("DH proposal must be a query or reply")
        query = message.ilk == Ilks.qry
        op, public = self._preflight(message, 'q' if query else 'a',
                                     'issuer' if query else 'issuee', own=True)
        if op['x'] != xid or (query and message.sad.get('rr') != self.Route):
            raise ValidationError("DH proposal differs from the approved transaction")
        if not query and op['peer'] is None:
            raise ValidationError("group reply requires its authenticated peer query")
        if op['proposal'] is not None and op['proposal'] != message.raw:
            raise ValidationError("DH proposal body is already frozen")
        kever = self.hab.kever
        signatures = list(parsed.sigers)
        signatures.extend(siger for pre, sigers in parsed.lsgs if pre.qb64 == self.hab.pre
                          for siger in sigers)
        signatures.extend(siger for pre, number, diger, sigers in parsed.tsgs
                          if pre.qb64 == self.hab.pre and number.sn == kever.lastEst.s
                          and diger.qb64 == kever.lastEst.d for siger in sigers)
        _, indices = verifySigs(message.raw, signatures, kever.verfers)
        contribution = self.hab.db.kevers[op['custodian']].fetchLatestContribTo(verfers=kever.verfers)
        if contribution is None or contribution[1] not in indices:
            raise ValidationError("DH proposal lacks the frozen custodian's signature")
        signed = bytes(self.hab.endorse(message, last=query, gvrsn=Vrsn_2_0))
        op['proposal'], op['public'], op['contribution'] = message.raw, dict(public), signed
        return signed

    def _derive(self, op, peer, role):
        """Compute every root before any Keeper write, including low-order checks."""
        self._custody(op, lead=True)
        return {registry: deriveRoot(
            op["private"][registry], role=role, x=op["x"], grant=op["grant"],
            registry=registry, issuer=op["issuer"], issuee=op["issuee"],
            issuer_pk=op["public"][registry] if role == "issuer" else peer[registry],
            issuee_pk=peer[registry] if role == "issuer" else op["public"][registry])
            for registry in op["registries"]}

    def _retain(self, op, peer, roots):
        for registry, root in roots.items():
            self.hab.mgr.putRegistryRoot(self.hab.pre, registry, root)
        op["peer"] = dict(peer)
        op["completed"] = True
        op["private"].clear()

    def processQuery(self, serder, *, lsgs=None, tsgs=None, sigers=None, cigars=None, **kwa):
        """Authenticate the issuer independently of optional KRAM acceptance."""
        from ..core import messagize, reply
        from ..kering import Ilks, Kinds, MissingSignatureError, ValidationError, Vrsn_2_0
        from ..peer.exchanging import verifyQueryAttachments
        if serder.ilk != Ilks.qry or serder.ked.get("rr") != self.Route:
            raise ValidationError("invalid DH query or return route")
        own = self.group and serder.pre == self.hab.pre
        op, peer = self._preflight(serder, "q", 'issuer' if own else 'issuee', own=own)
        if own and op['proposal'] != serder.raw:
            raise ValidationError("own DH query lacks exact local proposal approval")
        if not verifyQueryAttachments(self.exc.hby, serder, lsgs=lsgs,
                                       tsgs=tsgs, sigers=sigers, cigars=cigars):
            raise MissingSignatureError("DH query lacks the issuer signature threshold")
        if own:
            groups = [group for group in tsgs or [] if group[0].qb64 == self.hab.pre]
            lasts = [group for group in lsgs or [] if group[0].qb64 == self.hab.pre]
            if op['query'] is None:
                op['query'] = bytes(messagize(serder, tsgs=groups,
                    lsgs=lasts if not groups else None,
                    sigers=sigers if not groups and not lasts else None, gvrsn=Vrsn_2_0))
            if self._custody(op):
                self.cues.append(dict(kin='query', dest=op['issuee'], msg=op['query']))
            return
        if self.group and not self._custody(op):
            op['peer'] = dict(peer)
            return  # Non-leads can now review the lead's reply; they never generate keys.
        if op["reply"] is None:
            if op['proposal'] is None:
                if not op["public"]:
                    for registry in op["registries"]:
                        op["private"][registry], op["public"][registry] = generateKeyPair()
                roots = self._derive(op, peer, "issuee")
                message = reply(pre=self.hab.pre, route=self.Route,
                                data=dict(x=op["x"], pk=op["public"]), pvrsn=Vrsn_2_0, kind=Kinds.json)
                signed = bytes(self.hab.endorse(message, gvrsn=Vrsn_2_0))
                if self.group:
                    op['proposal'], op['contribution'], op['peer'] = message.raw, signed, dict(peer)
                else:
                    self._retain(op, peer, roots)
                    op["reply"] = signed
            if self.group:
                self.cues.append(dict(kin='sign', dest=self.hab.pre, msg=op['contribution']))
                return
        self.cues.append(dict(kin="reply", dest=op["issuer"], msg=op["reply"]))

    def processReply(self, *, serder, diger, route, cigars=None, tsgs=None):
        """Verify the issuee reply through Revery before deriving or retaining."""
        from ..core import messagize
        from ..db import fetchTsgs
        from ..kering import Ilks, ValidationError, Vrsn_2_0
        if serder.ilk != Ilks.rpy or route != self.Route:
            raise ValidationError("invalid DH reply")
        own = self.group and serder.pre == self.hab.pre
        op, peer = self._preflight(serder, "a", 'issuee' if own else 'issuer', own=own)
        if own and (op['proposal'] != serder.raw or op['peer'] is None):
            raise ValidationError("own DH reply lacks exact local proposal approval")
        if not own and op["query"] is None:
            raise ValidationError("DH reply has no outstanding query")
        if not self.hab.rvy.acceptReply(serder=serder, saider=diger, route=route,
                                        aid=op["issuee"], cigars=cigars, tsgs=tsgs):
            return
        if own:
            if self._custody(op) and not op['completed']:
                self._retain(op, op['peer'], self._derive(op, op['peer'], 'issuee'))
            if op['reply'] is None:
                groups = [group for group in fetchTsgs(db=self.hab.db.tsgs, diger=diger)
                          if group[0].qb64 == self.hab.pre]
                op['reply'] = bytes(messagize(serder, tsgs=groups, gvrsn=Vrsn_2_0))
            if self._custody(op):
                self.cues.append(dict(kin='reply', dest=op['issuer'], msg=op['reply']))
        elif self._custody(op) and not op["completed"]:
            self._retain(op, peer, self._derive(op, peer, "issuer"))

    def finish(self, xid):
        """Complete this issuance's pending Grant from current issued openings.

        This is local evidence retry, not another KRAM acceptance. Only the
        current authenticated BUP may open the exact credential as 'issued'; a
        later placeholder or another state is deliberately unsupported here.
        Exchanger still owns all authentication, final validation and storage.
        """
        from ..core import Blinder, Number
        from ..kering import Ilks, ValidationError
        from ..peer.exchanging import verify
        from .regeventing import vetAnchor
        op = self._operations[xid]
        message, nests = self._pending(op)
        db = self.exc.hby.db
        if not op["completed"]:
            raise ValidationError("issuance has no completed DH operation")
        self._roots(op)
        tsgs, cigars = verify(self.exc.hby, message)
        seals = [(Prefixer(qb64=keys[1]), number, diger)
                 for keys, (number, diger) in db.ests.getTopItemIter(keys=(op["grant"], ""))]
        rgy = self.exc.routes["/ipex/grant"].rgy
        openings = []
        for nest in nests:
            node = nest.serder
            registry = node.sad.get("rd")
            if registry not in op["registries"]:
                continue
            head = rgy.store.headEvent(registry)
            if head is None or head.ilk != Ilks.bup:
                raise ValidationError("issued registry head is unavailable")
            vetAnchor(head, db=db, issuer=op["issuer"])
            root = self.hab.mgr.getRegistryRoot(self.hab.pre, registry)
            opening = Blinder.unblind(said=head.sad["b"],
                uuid=Blinder.makeUUID(salt=root.qb64, sn=Number(numh=head.sad["n"]).num),
                acdc=node.said, states=["issued"])
            if opening is None or opening.state != "issued" or opening.acdc != node.said:
                raise ValidationError("current registry head does not open this credential as issued")
            openings.append((nest, opening))
        if {nest.serder.sad["rd"] for nest, _ in openings} != set(op["registries"]):
            raise ValidationError("approved registry scope is absent from the pending disclosure")
        # No evidence is changed until every selected opening has verified.
        for nest, opening in openings:
            nest.bsqs.append(opening.data)
        return self.exc.processEvent(serder=message, tsgs=tsgs, cigars=cigars,
            ssts=seals, nests=nests, ptds=db.epath.get((op["grant"],)),
            essrs=db.essrs.get((op["grant"],)))

    def complete(self, xid):
        """Report readiness for issuance only while the selected Grant is live."""
        op = self._operations[xid]
        from ..peer.exchanging import verify
        message, _ = self._pending(op)
        verify(self.exc.hby, message)
        self._roots(op)
        return op["completed"]

    def abandon(self, xid):
        """Drop ephemeral private keys and refuse further use of this operation."""
        op = self._operations[xid]
        op["private"].clear()
        op["abandoned"] = True
