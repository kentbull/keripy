"""Live, explicitly approved IPEX presentation opening exchange.

This local profile shares the original Grant's scope and lifetime. It discloses
event-specific proofs only; it neither provisions roots nor widens a credential.
Applications own delivery, ordinary dependency acquisition and final Admit.
"""

from collections import deque

from ..core import (Blinder, BlindState, BoundState, Number, Parser,
                    Prefixer, SealSource, messagize, query, reply)
from ..core.parsing import MsgParseDom
from ..core.eventing import verifySigs
from ..db import fetchTsgs
from ..kering import (Ilks, Kinds, MissingOpeningError, MissingSignatureError, ValidationError,
                       Vrsn_2_0)
from ..peer.exchanging import (serializeParsedSubstream, verify, verifyAttachments,
                               verifyQueryAttachments)
from . import chaining
from ..recording import ExchangeRegistryStateRecord
from .regeventing import (_verifyAnchorCouple, vet, vetBlind, vetBound)


class Unblind:
    """Explicit unblind operation using existing query/reply authentication.

    Inject as Kevery.qvy and register Route with Revery's router using
    ``blinders=True, attachments=True``. ``states`` is the application's explicit
    vocabulary for ordinary root-derived proofs. Bound proofs require held material.
    ``cues`` supplies {kin: 'reply', dest, msg}; approval and retry bytes are
    process-local. A fresh instance has no approved unfinished operations.
    Group responders propose and contribute to one exact reply; Revery owns its
    threshold. Group requesters remain unsupported. Applications transport member
    proposals and the elected member's completed reply, never partial replies.
    """
    Route = "/ipex/unblind"

    def __init__(self, hab, exc, rgy, *, states):
        from ..app.habbing import GroupHab, Hab
        if (not isinstance(hab, (Hab, GroupHab))
                or isinstance(hab, GroupHab) and not isinstance(hab.mhab, Hab)
                or hab.db is not exc.hby.db
                or rgy.hby.db is not hab.db):
            raise ValueError("unblind requires one local signing habitat environment")
        handler = exc.routes.get("/ipex/grant")
        if handler is None or handler.rgy is not rgy:
            raise ValueError("unblind must use the registered Grant verifier's registry owner")
        if isinstance(states, str):
            raise ValueError("unblind states must be an explicit sequence of strings")
        states = tuple(states)
        if any(not isinstance(state, str) for state in states):
            raise ValueError("unblind states must be an explicit sequence of strings")
        self.hab, self.exc, self.rgy = hab, exc, rgy
        self.group = isinstance(hab, GroupHab)
        self.states = tuple(states)
        self.cues, self._operations = deque(), {}

    def approve(self, grant):
        """Approve one exact authenticated presentation without accepting it."""
        db = self.hab.db
        message = db.exns.get((grant,)) or db.epse.get((grant,))
        if message is None:
            raise ValidationError("unblind requires a retained Grant")
        xid = message.said if message.ilk == Ilks.xip else message.ked.get("x")
        existing = self._operations.get(xid)
        if existing is not None:
            if existing["grant"] != grant:
                raise ValidationError("another Grant is selected for this transaction")
            self._live(existing)
            return xid
        sender, recipient = message.pre, message.ked.get("ri")
        if self.group and self.hab.pre == recipient:
            raise ValidationError("group unblind requesters are not supported")
        if sender == recipient or self.hab.pre not in (sender, recipient):
            raise ValidationError("local habitat is not a presentation party")
        op = dict(grant=grant, x=xid, sender=sender, recipient=recipient,
                  raw=message.raw, bodies=None, scope=None, query=None, reply=None,
                  requested=None, selected=None, openings={}, requestedByPeer=False,
                  received=False, abandoned=False, proposal=None, contribution=None)
        _, nests, scope = self._live(op)
        op["bodies"] = tuple(nest.serder.raw for nest in nests)
        op["scope"] = scope
        self._operations[xid] = op
        return xid

    def _live(self, op):
        """Reauthenticate the original Grant, immutable view, scope and deadline."""
        context = self.exc.presentationContext(op["grant"], xid=op["x"],
            sender=op["sender"], recipient=op["recipient"])
        if op["abandoned"] or context is None:
            raise ValidationError("presentation is unavailable, terminated or expired")
        message, nests, scope = context
        if (message.raw != op["raw"] or op["scope"] is not None and
                (scope != op["scope"] or tuple(nest.serder.raw for nest in nests) != op["bodies"])):
            raise ValidationError("presentation differs from the approved Grant")
        return context

    def _operation(self, xid):
        """Require an approval retained by this process for any explicit action."""
        op = self._operations.get(xid)
        if op is None:
            raise ValidationError("unblind transaction has no local approval")
        return op

    @staticmethod
    def _parse(raw):
        """Read one complete serialized message without dispatching its effects."""
        ims = bytearray(raw)
        parsed = Parser(version=Vrsn_2_0).parseOneBare(ims=ims, processive=False)
        if ims:
            raise ValidationError("unexpected trailing message material")
        return parsed

    def _signed(self, message, *, nests=(), openings=()):
        """Attach selected evidence to the habitat's ordinary endorsement."""
        parsed = self._parse(self.hab.endorse(message, last=message.ilk == Ilks.qry,
                                             gvrsn=Vrsn_2_0))
        parsed.nests.extend(nests)
        for opening in openings:
            (parsed.bsss if opening.clan is BoundState else parsed.bsqs).append(opening.data)
        return bytes(serializeParsedSubstream(parsed))

    def start(self, grant):
        """Return the disclosee's frozen query with exact accepted public events."""
        xid = self.approve(grant)
        op = self._operations[xid]
        if self.hab.pre != op["recipient"]:
            raise ValidationError("only the disclosee starts unblind")
        if op["query"] is None:
            _, disclosure, _ = self._live(op)
            carried = self._carried(op, disclosure)
            requested, nests = {}, []
            for regid in op["scope"]:
                events = self._events(regid)
                missing, start = False, 0
                for index in range(len(events) - 1, -1, -1):
                    opening = carried.get(events[index].said)
                    if opening is None:
                        missing = True
                    elif self._checkOpening(op, events[index], opening, disclosure):
                        start = index + 1
                        break
                if not missing:
                    continue
                requested[regid] = []
                for event in events[start:]:
                    number, diger = self.rgy.store.anchor(event.said)
                    requested[regid].append(event.said)
                    nests.append(self._parse(messagize(event, nested=True,
                        bonds=[SealSource(s=number.snh, d=diger.qb64)], gvrsn=Vrsn_2_0)))
            if not requested:
                raise ValidationError("the Grant already carries the required current openings")
            message = query(pre=self.hab.pre, route=self.Route, replyRoute=self.Route,
                query=dict(x=xid, re=requested), pvrsn=Vrsn_2_0, kind=Kinds.json)
            op["requested"], op["query"] = requested, self._signed(message, nests=nests)
        self._current(op)
        return op["query"]

    def _current(self, op):
        """A new public head needs a new explicitly approved live operation."""
        for regid, saids in op["requested"].items():
            head = self.rgy.store.headEvent(regid)
            if head is None or head.said != saids[-1]:
                raise ValidationError("registry head changed after the unblind request")

    def _preflight(self, serder, field, local, *, own=False):
        """Bind a finite auxiliary body to the approved opposite-role peer."""
        data = serder.sad.get(field)
        if (not serder.verify() or serder.pvrsn != Vrsn_2_0
                or serder.sad.get("r") != self.Route or not isinstance(data, dict)
                or set(data) != {"x", "re"} or not isinstance(data["x"], str)
                or not isinstance(data["re"], dict) or field == "q" and not data["re"]):
            raise ValidationError("invalid unblind message shape")
        op = self._operation(data["x"])
        _, nests, scope = self._live(op)
        peer = "recipient" if local == "sender" else "sender"
        if self.hab.pre != op[local] or serder.pre != op[local if own else peer]:
            raise ValidationError("wrong unblind sender or local recipient")
        if not set(data["re"]).issubset(scope):
            raise ValidationError("unblind registry lies outside approved disclosure")
        for saids in data["re"].values():
            if (not isinstance(saids, list) or not saids
                    or any(not isinstance(said, str) for said in saids)
                    or len(set(saids)) != len(saids)):
                raise ValidationError("unblind events must be distinct nonempty lists")
        return op, data["re"], nests

    def _events(self, regid):
        """Read the accepted public update chain; escrowed bodies are excluded."""
        head = self.rgy.store.headEvent(regid)
        if head is None or head.ilk != Ilks.bup:
            raise ValidationError("accepted registry updates are unavailable")
        events = [self.rgy.store.seqEvent(regid, sn)
                  for sn in range(1, Number(numh=head.sad["n"]).num + 1)]
        if any(event is None for event in events):
            raise ValidationError("accepted registry chain is incomplete")
        return events

    def _carried(self, op, nests):
        """Index exact proofs already disclosed by this Grant, never inferred holdings."""
        carried = {}
        for nest in nests:
            regid = nest.serder.sad.get("rd")
            if regid not in op["scope"]:
                continue
            for data in [*nest.bsqs, *nest.bsss]:
                opening = Blinder(data=(BlindState(*data) if len(data) == 4 else BoundState(*data)),
                                    verify=False)
                for event in self._events(regid):
                    if opening.said == event.sad["b"]:
                        self._checkOpening(op, event, opening, nests)
                        carried[event.said] = opening
        return carried

    def _receiveEvents(self, requested, nests):
        """Verify all named public bodies before ordinary native TEL intake."""
        nests = [MsgParseDom(**nest) if isinstance(nest, dict) else nest for nest in nests]
        if [nest.serder.said for nest in nests] != [said for saids in requested.values() for said in saids]:
            raise ValidationError("nested events differ from the exact unblind request")
        offset = 0
        for regid, saids in requested.items():
            rip = self.rgy.store.seqEvent(regid, 0)
            head = self.rgy.store.headEvent(regid)
            if rip is None or head is None:
                raise ValidationError("query registry has no accepted inception")
            children = nests[offset:offset + len(saids)]
            offset += len(saids)
            first = Number(numh=children[0].serder.sad.get("n", "0")).num
            if first < 1 or first > Number(numh=head.sad["n"]).num + 1:
                raise ValidationError("query suffix has no accepted preceding registry prefix")
            prefix = [self.rgy.store.seqEvent(regid, sn) for sn in range(1, first)]
            if any(event is None for event in prefix):
                raise ValidationError("query suffix has no accepted preceding registry prefix")
            for sn, nest in enumerate(children, first):
                event = nest.serder
                if (event.ilk != Ilks.bup or event.sad["rd"] != regid
                        or Number(numh=event.sad["n"]).num != sn
                        or any(value for key, value in vars(nest).items()
                               if key not in ("serder", "sscs", "ssts", "local"))):
                    raise ValidationError("query must carry only contiguous public BUPs and sources")
                for pre, number, diger in [(rip.israid, *couple) for couple in nest.sscs] + [
                        (pre.qb64, number, diger) for pre, number, diger in nest.ssts]:
                    if pre != rip.israid or not _verifyAnchorCouple(event,
                            db=self.hab.db, issuer=pre, number=number, diger=diger):
                        raise ValidationError("query event has an unverified source")
                accepted = self.rgy.store.seqEvent(regid, sn)
                if accepted is not None and accepted.raw != event.raw:
                    raise ValidationError("query conflicts with accepted registry evidence")
            vet(rip, prefix + [nest.serder for nest in children], db=self.hab.db)
            if Number(numh=head.sad["n"]).num > first + len(saids) - 1:
                raise ValidationError("query requests superseded registry history")
        for nest in nests:
            if not self.rgy.processEvent(nest.serder, sscs=nest.sscs, ssts=nest.ssts):
                raise ValidationError("unblind event has not reached ordinary acceptance")

    def _checkOpening(self, op, event, opening, nests):
        """Verify the exact BLID, selected target and any historical Issuee bound."""
        target, state = vetBlind(opening, blid=event.sad["b"])
        credential = next((nest.serder for nest in nests if nest.serder.said == target), None)
        if (target or state) and target not in op["scope"][event.sad["rd"]]:
            raise ValidationError("opening targets an unrelated credential")
        vetBound(opening, acdc=credential, db=self.hab.db)
        return bool(target or state)

    def _held(self, op, event, nests):
        """Use exact held proofs or derive ordinary state from an explicit root."""
        opening = self.rgy.store.opening(event.said)
        if opening is None:
            for nest in nests:
                for data in [*nest.bsqs, *nest.bsss]:
                    candidate = Blinder(data=(BlindState(*data) if len(data) == 4 else BoundState(*data)),
                                        verify=False)
                    if candidate.said == event.sad["b"]:
                        opening = candidate
                        break
        if opening is None:
            root = self.hab.mgr.getRegistryRoot(self.hab.pre, event.sad["rd"])
            if root is not None:
                uuid = Blinder.makeUUID(salt=root.qb64, sn=Number(numh=event.sad["n"]).num)
                for target in op["scope"][event.sad["rd"]]:
                    opening = Blinder.unblind(event.sad["b"], uuid=uuid, acdc=target, states=self.states)
                    if opening is not None:
                        break
        if opening is None:
            raise MissingOpeningError("required exact event opening is unavailable")
        self._checkOpening(op, event, opening, nests)
        return opening

    def _minimum(self, op, requested, nests, resolve):
        """Return only requested proofs absent from the Grant's required current suffix."""
        carried = self._carried(op, nests)
        selected, openings = {}, {}
        for regid, saids in requested.items():
            suffix = []
            for event in reversed(self._events(regid)):
                opening = carried.get(event.said)
                if opening is None:
                    if event.said not in saids:
                        raise ValidationError("required older opening was neither carried nor requested")
                    opening = resolve(event)
                    suffix.append(event.said)
                    openings[opening.said] = opening
                if self._checkOpening(op, event, opening, nests):
                    break
            else:
                raise ValidationError("registry suffix contains no credential state")
            if suffix:
                selected[regid] = list(reversed(suffix))
        return selected, list(openings.values())

    def processQuery(self, serder, *, lsgs=None, tsgs=None, sigers=None, cigars=None, nests=None, **kwa):
        """Authenticate before accepting requested public evidence or disclosing."""
        if serder.ilk != Ilks.qry or serder.sad.get("rr") != self.Route:
            raise ValidationError("invalid unblind query or return route")
        if any(value for key, value in kwa.items() if key not in ("local", "source")):
            raise ValidationError("unblind query carries unsupported attachments")
        op, requested, disclosure = self._preflight(serder, "q", "sender")
        if not verifyQueryAttachments(self.exc.hby, serder, lsgs=lsgs,
                                       tsgs=tsgs, sigers=sigers, cigars=cigars):
            raise MissingSignatureError("unblind query lacks the disclosee signature threshold")
        if op["requested"] is not None and requested != op["requested"]:
            raise ValidationError("conflicting unblind request for this operation")
        self._receiveEvents(requested, nests or [])
        self._live(op)
        op["requested"] = {regid: list(saids) for regid, saids in requested.items()}
        op["requestedByPeer"] = True
        if not self.group:
            self.respond(op["x"])

    def respond(self, xid):
        """Retry this authenticated live request locally without replaying KRAM intake.

        Proofs may become available after receipt. The frozen request, exact
        approved Grant and original deadline remain required. Queue and return
        the same signed reply bytes on every successful individual attempt.
        Groups explicitly prepare a signing proposal after request receipt;
        repeated calls return that proposal or the completed aggregate. Only
        own-reply threshold processing emits the elected member's delivery cue.
        """
        op = self._operation(xid)
        _, disclosure, _ = self._live(op)
        if self.hab.pre != op["sender"] or not op["requestedByPeer"]:
            raise ValidationError("unblind has no authenticated peer request")
        self._current(op)
        if self.group and op['contribution'] is not None:
            return op['reply'] or op['contribution']
        if op["reply"] is None:
            selected, openings = self._minimum(op, op["requested"], disclosure,
                lambda event: self._held(op, event, disclosure))
            message = reply(pre=self.hab.pre, route=self.Route,
                data=dict(x=op["x"], re=selected), pvrsn=Vrsn_2_0, kind=Kinds.json)
            signed = self._signed(message, openings=openings)
            if self.group:
                op['proposal'], op['contribution'] = message.raw, signed
                self.cues.append(dict(kin='sign', dest=self.hab.pre, msg=signed))
                return signed
            op["reply"] = signed
        self.cues.append(dict(kin="reply", dest=op["recipient"], msg=op["reply"]))
        return op["reply"]

    def contribute(self, xid, proposal):
        """Approve one member's unchanged reply after the real peer request.

        Openings are independently verified against the selected current suffix;
        contributors need no root. This adds only the local indexed signature,
        never completes a threshold or authorizes a different proposal body.
        """
        if not self.group:
            raise ValidationError("unblind contribution requires a local group responder")
        parsed = self._parse(proposal)
        if (parsed.serder.ilk != Ilks.rpy or any(value for key, value in vars(parsed).items()
                if key not in ('serder', 'tsgs', 'bsqs', 'bsss'))):
            raise ValidationError("unblind proposal must be one signed reply with openings")
        op, selected, nests = self._preflight(parsed.serder, 'a', 'sender', own=True)
        if op['x'] != xid or not op['requestedByPeer']:
            raise ValidationError("group reply requires its authenticated peer query")
        self._current(op)
        if op['proposal'] is not None and op['proposal'] != parsed.serder.raw:
            raise ValidationError("unblind reply proposal is already frozen")
        kever = self.hab.kever
        if not parsed.tsgs:
            raise ValidationError("unblind proposal lacks a group member signature")
        for pre, number, diger, sigers in parsed.tsgs:
            if (pre.qb64 != self.hab.pre or number.sn != kever.lastEst.s
                    or diger.qb64 != kever.lastEst.d):
                raise ValidationError("unblind proposal has different group establishment keys")
            verified, _ = verifySigs(parsed.serder.raw, sigers, kever.verfers)
            if not verified or len(verified) != len(sigers):
                raise ValidationError("unblind proposal lacks valid member contributions")
        openings = self._replyOpenings(op, selected, nests, parsed.bsqs, parsed.bsss)
        minimum, _ = self._minimum(op, op['requested'], nests,
            lambda event: self._opening(openings, event))
        if selected != minimum:
            raise ValidationError("reply is not the minimum current-state suffix")
        if op['contribution'] is not None:
            retained = self._parse(op['contribution'])
            if serializeParsedSubstream(dict(vars(parsed), tsgs=[])) != serializeParsedSubstream(
                    dict(vars(retained), tsgs=[])):
                raise ValidationError("unblind reply proof bytes are already frozen")
        if op['contribution'] is None:
            # Carry the exact approved proof bytes; only our signature is new.
            local = self._parse(self.hab.endorse(parsed.serder, gvrsn=Vrsn_2_0))
            local.bsqs, local.bsss = parsed.bsqs, parsed.bsss
            op['proposal'] = parsed.serder.raw
            op['contribution'] = bytes(serializeParsedSubstream(local))
        return op['contribution']

    @staticmethod
    def _opening(openings, event):
        if event.said not in openings:
            raise ValidationError("reply lacks a required opening")
        return openings[event.said]

    def _replyOpenings(self, op, selected, nests, bsqs, bsss):
        """Validate candidate proof blocks without publishing or retaining them."""
        if not set(selected).issubset(op['requested']):
            raise ValidationError("unblind reply has no matching outstanding request")
        for regid, saids in selected.items():
            if any(said not in op['requested'][regid] for said in saids):
                raise ValidationError("reply names an event outside the request")
        seen, verified = set(), {}
        for data in [*(bsqs or []), *(bsss or [])]:
            opening = Blinder(data=(BlindState(*data) if len(data) == 4 else BoundState(*data)), verify=False)
            if opening.said in seen:
                raise ValidationError("duplicate unblind opening")
            seen.add(opening.said)
            matches = [self.rgy.store.event(said) for saids in selected.values() for said in saids
                       if self.rgy.store.event(said).sad['b'] == opening.said]
            if not matches:
                raise ValidationError("reply carries an excess opening")
            for event in matches:
                self._checkOpening(op, event, opening, nests)
                verified[event.said] = opening
        return verified

    def processReply(self, *, serder, diger, route, cigars=None, tsgs=None, bsqs=None, bsss=None,
                     attachments=None):
        """Keep only independently verified event proofs across partial replies."""
        if serder.ilk != Ilks.rpy or route != self.Route:
            raise ValidationError("invalid unblind reply")
        if attachments is None or any(value for key, value in attachments.items()
                if key not in ("bsqs", "bsss", "sigers", "local")):
            raise ValidationError("unblind reply carries unsupported attachments")
        own = self.group and serder.pre == self.hab.pre
        op, selected, nests = self._preflight(serder, "a", 'sender' if own else 'recipient', own=own)
        if own and (op['proposal'] != serder.raw or not op['requestedByPeer']):
            raise ValidationError("own unblind reply lacks exact local proposal approval")
        if not own and op["query"] is None:
            raise ValidationError("unblind reply has no matching outstanding request")
        self._current(op)
        verified = self._replyOpenings(op, selected, nests, bsqs, bsss)
        # No untrusted reply SAID owns this cache: each entry independently opens
        # one requested accepted event and is bound to the approved disclosure.
        op["openings"].update(verified)
        if not self.hab.rvy.acceptReply(serder, diger, route, op["sender"], cigars=cigars, tsgs=tsgs):
            return
        minimum, openings = self._minimum(op, op["requested"], nests,
            lambda event: self._opening(op['openings'], event))
        if selected != minimum:
            raise ValidationError("reply is not the minimum current-state suffix")
        op["selected"] = {regid: list(saids) for regid, saids in selected.items()}
        if own:
            groups = [group for group in fetchTsgs(db=self.hab.db.tsgs, diger=diger)
                      if group[0].qb64 == self.hab.pre]
            groups, _, _, _, _ = verifyAttachments(self.exc.hby, serder, tsgs=groups)
            if not groups:
                raise ValidationError("group reply lacks a verified signature threshold")
            if op['reply'] is None:
                frame = self._parse(messagize(serder, tsgs=groups, gvrsn=Vrsn_2_0))
                for opening in openings:
                    (frame.bsss if opening.clan is BoundState else frame.bsqs).append(opening.data)
                op['reply'] = bytes(serializeParsedSubstream(frame))
            # Ordinary verified signing-index leadership, independent of root custody.
            pre, number, digest, sigers = groups[0]
            _, verfers = self.hab.db.resolveVerifiers(pre=pre.qb64, sn=number.sn, dig=digest.qb64)
            contribution = self.hab.mhab.kever.fetchLatestContribTo(verfers=verfers)
            if contribution is not None and contribution[1] == min(siger.index for siger in sigers):
                self.cues.append(dict(kin='reply', dest=op['recipient'], msg=op['reply']))
            return
        op["received"] = True

    def complete(self, xid):
        """Report authenticated reply readiness within the original live request.

        Partial signatures are not completion. This is readiness to retry Grant
        verification for a recipient, or a threshold reply for a group responder;
        it is not a credential-state verdict or permission to Admit.
        """
        op = self._operation(xid)
        self._live(op)
        if op["requested"] is not None:
            self._current(op)
        return op['reply'] is not None if self.group else op["received"]

    def finish(self, xid):
        """Retry ordinary Grant verification with the authenticated minimal proofs."""
        op = self._operation(xid)
        db = self.hab.db
        retained = ([(bytes(key), bytes(raw)) for key, raw in db.getTopItemIter(
            db=db.enst.sdb, top=db.enst._tokey((op["grant"], "")))]
            if db.exns.get((op["grant"],)) is not None else None)
        message, nests, _ = self._live(op)
        if not op["received"]:
            raise ValidationError("unblind reply has not been authenticated and verified")
        self._current(op)
        for nest in nests:
            present = {data[0].qb64 for data in [*nest.bsqs, *nest.bsss]}
            for eventSaid in (said for saids in op["selected"].values() for said in saids):
                opening = op["openings"][eventSaid]
                if (self.rgy.store.event(eventSaid).sad["rd"] == nest.serder.sad.get("rd")
                        and (not opening.acdc or opening.acdc == nest.serder.said)
                        and opening.said not in present):
                    (nest.bsss if opening.clan is BoundState else nest.bsqs).append(opening.data)
                    present.add(opening.said)
        if retained is not None:
            # Ordinary intake treats the accepted Agree -> Grant link as a
            # second response. Check new proofs against that exact retained Grant.
            _, _, verdict, records = self.exc.reverifyGrant(op["grant"], nests=nests)
            if verdict is None or verdict.verdict != chaining.Verdicts.valid:
                return False
            self._retain(op, nests, retained, records)
            return True
        tsgs, cigars = verify(self.exc.hby, message)
        seals = [(Prefixer(qb64=keys[1]), number, diger)
                 for keys, (number, diger) in db.ests.getTopItemIter(keys=(op["grant"], ""))]
        return self.exc.processEvent(serder=message, tsgs=tsgs, cigars=cigars, ssts=seals,
            nests=nests, ptds=db.epath.get((op["grant"],)), essrs=db.essrs.get((op["grant"],)))

    def _retain(self, op, nests, retained, records):
        """Atomically retain verified proofs and their current observations."""
        self._live(op)
        self._current(op)
        updates = [(key, old, bytes(serializeParsedSubstream(nest)))
                   for (key, old), nest in zip(retained, nests, strict=True)]
        db = self.hab.db
        observations = [(db.exrs._tokey((op["grant"], said)), db.exrs._ser(
            ExchangeRegistryStateRecord(regid=record.regid, said=record.said,
                sn=record.sn, state=record.state, stamp=record.stamp)))
            for said, record in records.items()]
        with db.env.begin(write=True) as txn:
            if (txn.get(db.exns._tokey(op["grant"]), db=db.exns.sdb) != op["raw"]
                    or txn.get(db.erpy._tokey(op["grant"]), db=db.erpy.sdb) is not None):
                raise ValidationError("approved presentation is no longer live")
            for key, old, new in updates:
                if txn.get(key, db=db.enst.sdb) != old:
                    raise ValidationError("approved presentation evidence changed")
                txn.put(key, new, db=db.enst.sdb)
            for key, value in observations:
                txn.put(key, value, db=db.exrs.sdb)

    def abandon(self, xid):
        """Discard live proofs and unsent replies; delivered bytes belong to the caller."""
        op = self._operation(xid)
        pending = [cue for cue in self.cues if cue["msg"] != op["reply"]]
        self.cues.clear()
        self.cues.extend(pending)
        op["reply"] = None
        op["openings"].clear()
        op["abandoned"] = True
