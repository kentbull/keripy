"""Selected group issuance contributions inside one finite Admit invocation."""
from collections import deque
import json
from types import SimpleNamespace

from ... import Kinds, Vrsn_2_0
from ...acdc import chaining, ipexing, regeventing
from ...app import Multiplexor, multisigExn, multisigRpyExn
from ...core import (BlindState, Blinder, Parser, Prefixer, SealEvent, SerderACDC,
                     exchange, messagize)
from ...kering import ConfigurationError, ValidationError
from ...peer.exchanging import (loadParsedNestedSubstreams, serializeMessage,
                               serializeParsedSubstream, verify)


# This command's group coordination extension, not a standardized auxiliary route.
ProofRoute = '/multisig/ipex-proof'


class _Proposal:
    def __init__(self, owner, resource):
        self.owner, self.resource = owner, resource

    def verify(self, serder, attachments=None, nests=None):
        try:
            if self.resource == ProofRoute:
                return not attachments and self.owner.validateProof(serder, nests)
            return self.owner.validate(serder, nests)
        except (ValidationError, ValueError, KeyError, TypeError, AttributeError):
            return False

    def handle(self, serder, attachments=None, nests=None):
        owner = self.owner
        if self.resource == ProofRoute:
            owner.proof = serder.said
            return
        if self.resource == '/multisig/exn':
            owner.mux.add(serder, nests=nests)
        if serder.pre != owner.hab.mhab.pre:
            child = nests[0]['serder'] if isinstance(nests[0], dict) else nests[0].serder
            owner.queued[(serder.route, serder.pre)] = child.raw
            owner.pending.append(serder.said)


class GroupAdmission:
    """Borrow the command's live owners; never replay DH through the mux's Revery."""

    def __init__(self, owner, grant, xid, notifier):
        self.owner, self.grant, self.xid = owner, grant, xid
        self.hab, self.dh = owner.hab, owner.dh
        self.lead = self.hab.mhab.pre == owner.args.custodian
        self.deadline = owner.exc.exchangeDeadline(grant)
        owner.nativeDeadline = self.deadline
        self.pending, self.seen = deque(), set()
        self.queued = {}
        self.response = None
        self.transmitted = False
        self.proof = None
        self.original = loadParsedNestedSubstreams(owner.hby, grant.said)
        self.mux = Multiplexor(owner.hby, notifier, rgy=owner.rgy, replay=owner.psr)
        for route in ('/multisig/rpy', '/multisig/exn', ProofRoute):
            owner.exc.addHandler(_Proposal(self, route))

    def validateProof(self, wrapper, nests):
        """Authenticate coordination scope; native public proof verification happens before retry."""
        self.check()
        if (self.lead or self.owner.exc.complete(self.grant.said) or wrapper.pvrsn != Vrsn_2_0
                or wrapper.pre != self.owner.args.custodian
                or wrapper.pre not in self.hab.db.signingMembers(pre=self.hab.pre)
                or wrapper.sad['a'] != dict(gid=self.hab.pre, grant=self.grant.said)
                or len(nests) != 1):
            return False
        child = SimpleNamespace(**nests[0]) if isinstance(nests[0], dict) else nests[0]
        if child.serder.raw != self.grant.raw:
            return False
        nodes = [SimpleNamespace(**node) if isinstance(node, dict) else node for node in child.nests]
        if [node.serder.raw for node in nodes] != [node.serder.raw for node in self.original]:
            return False
        # Preserve the authenticated original issuer factors, not the transport member's authority.
        tsgs, cigars = verify(self.owner.hby, self.grant)
        seals = [SealEvent(i=Prefixer(qb64=keys[1]), s=number, d=diger)
                 for keys, (number, diger) in self.hab.db.ests.getTopItemIter(keys=(self.grant.said, ''))]
        saved = Parser(version=Vrsn_2_0).parseOneBare(ims=messagize(self.grant,
            tsgs=tsgs or None, cigars=cigars or None, bonds=seals or None, gvrsn=Vrsn_2_0), processive=False)
        auth = dict(vars(child), nests=[])
        if serializeParsedSubstream(auth) != serializeParsedSubstream(saved):
            return False
        for old, node in zip(self.original, nodes):
            unchanged = dict(vars(node), bsqs=old.bsqs, bsss=old.bsss)
            if serializeParsedSubstream(unchanged) != serializeParsedSubstream(old):
                return False
            if node.bsss != old.bsss or len(node.bsqs) != len(old.bsqs) + 1:
                return False
            if [Blinder(data=BlindState(*data), verify=False).qb64 for data in node.bsqs[:-1]] != [
                    Blinder(data=BlindState(*data), verify=False).qb64 for data in old.bsqs]:
                return False
            addition = Blinder(data=BlindState(*node.bsqs[-1]), verify=False)
            if addition.acdc != node.serder.said or addition.state != 'issued':
                return False
        return True

    def retryProof(self):
        if self.proof is None:
            return
        self.check()
        packet = self.hab.db.exns.get((self.proof,))
        child = loadParsedNestedSubstreams(self.owner.hby, self.proof)[0]
        if not self.validateProof(packet, [child]):
            raise ConfigurationError('group proof envelope no longer matches the selected pending Grant')
        # Evidence may arrive after its authenticated envelope; never infer acceptance from scheduling.
        for item in child.nests:
            node = SimpleNamespace(**item) if isinstance(item, dict) else item
            head = self.owner.rgy.store.headEvent(node.serder.regid)
            opening = Blinder(data=BlindState(*node.bsqs[-1]), verify=False)
            if head is None or head.ilk != 'bup' or head.sad['b'] != opening.said:
                return
            rip = self.owner.rgy.store.seqEvent(node.serder.regid, 0)
            updates = [self.owner.rgy.store.seqEvent(node.serder.regid, sn)
                       for sn in range(1, int(head.sad['n'], 16) + 1)]
            state = regeventing.vetBinds(rip, updates, db=self.hab.db,
                blinders=[Blinder(data=BlindState(*data), verify=False) for data in node.bsqs],
                target=node.serder.said, acdc=node.serder)
            regeventing.vetAnchor(head, db=self.hab.db, issuer=self.grant.pre)
            if state.said != head.said or state.state != 'issued':
                raise ConfigurationError('group proof does not verify the current issued registry head')
        deadline = self.owner.exc.exchangeDeadline(self.grant)
        self.check()
        protected = Parser(version=Vrsn_2_0, kvy=self.owner.hby.kvy,
            exc=self.owner.exc, rvy=self.owner.hby.rvy, rgy=self.owner.rgy, local=True)
        protected.parse(ims=serializeParsedSubstream(child), local=True)
        if self.owner.exc.exchangeDeadline(self.grant) != deadline:
            raise ConfigurationError('group proof retry changed the original Grant deadline')
        if not self.owner.exc.complete(self.grant.said):
            raise ConfigurationError('native verification did not accept the selected group Grant')
        self.current()
        self.proof = None

    def check(self):
        self.owner.check()
        if not self.owner.exc.complete(self.grant.said):
            self.dh.complete(self.xid)  # Also checks the unchanged pending disclosure and frozen custody.

    def validate(self, wrapper, nests):
        self.check()
        if wrapper.pvrsn != Vrsn_2_0:
            return False
        self.mux.validate(wrapper, nests=nests)
        child = nests[0]['serder'] if isinstance(nests[0], dict) else nests[0].serder
        if (child.pvrsn != Vrsn_2_0 or wrapper.sad['a']['gid'] != self.hab.pre or child.pre != self.hab.pre
                or wrapper.pre not in self.hab.db.signingMembers(pre=self.hab.pre)):
            return False
        queued = self.queued.get((wrapper.route, wrapper.pre))
        if queued is not None:
            return False  # One immutable proposal per member and phase; duplicates need no replay.
        if wrapper.route == '/multisig/rpy':
            return (not self.owner.exc.complete(self.grant.said)
                    and child.route == self.dh.Route and child.sad['a'].get('x') == self.xid)
        if (child.route != '/ipex/admit' or child.ilk != 'exn'
                or child.sad['p'] != self.grant.said or child.sad['x'] != self.xid
                or child.sad['ri'] != self.grant.pre or child.sad['a'] != dict(m=self.owner.args.message)):
            return False
        if self.response is not None:
            return child.raw == self.response.raw
        return not self.lead and wrapper.pre == self.owner.args.custodian

    def broadcast(self, raw, *, reply=False):
        self.check()
        factory = multisigRpyExn if reply else multisigExn
        kwa = dict(rpy=raw) if reply else dict(exn=raw)
        wrapper, atc = factory(self.hab, version=Vrsn_2_0, **kwa)
        if not reply:
            self.owner.psr.parse(ims=bytearray(wrapper.raw + atc), local=True)
        for member in self.hab.db.signingMembers(pre=self.hab.pre):
            if member != self.hab.mhab.pre:
                yield from self.owner.send(wrapper.raw + atc, member, topic='multisig')

    def proposals(self):
        for _ in range(len(self.pending)):
            self.check()
            said = self.pending.popleft()
            wrapper = self.hab.db.exns.get((said,))
            child = loadParsedNestedSubstreams(self.owner.hby, said)[0]
            key = (wrapper.pre, child.serder.said)
            if key in self.seen:
                continue
            if wrapper.route == '/multisig/rpy':
                # Only defer scheduling: native contribute still checks the authenticated query and custodian.
                if self.dh._operations[self.xid]['peer'] is None:
                    self.pending.append(said)
                    continue
                raw = serializeParsedSubstream(child)
                if self.lead:
                    self.owner.psr.parse(ims=bytearray(raw))
                else:
                    contribution = self.dh.contribute(self.xid, raw)
                    self.owner.psr.parse(ims=bytearray(raw))
                    self.owner.psr.parse(ims=bytearray(contribution), local=True)
                    yield from self.broadcast(contribution, reply=True)
            else:
                if not self.owner.exc.complete(self.grant.said):
                    self.pending.append(said)
                    continue
                self.current()
                if not self.lead:
                    self.response = child.serder
                    # Sign retained bytes. Only the elected lead constructed the Admit and its timestamp.
                    contribution = self.hab.endorse(child.serder, last=False,
                        framed=False, gvrsn=Vrsn_2_0)
                    yield from self.broadcast(contribution)
            self.seen.add(key)

    def current(self):
        self.check()
        _, _, verdict, observations = self.owner.exc.reverifyGrant(self.grant.said)
        if (verdict.verdict != chaining.Verdicts.valid or not observations
                or any(record.state != 'issued' for record in observations.values())):
            raise ConfigurationError('selected group Grant requires current verified issued state')

    def run(self):
        owner = self.owner
        while not owner.exc.complete(self.grant.said):
            self.check()
            while self.dh.cues:
                cue = self.dh.cues.popleft()
                if cue['kin'] == 'sign':
                    owner.psr.parse(ims=bytearray(cue['msg']), local=True)
                    yield from self.broadcast(cue['msg'], reply=True)
                    print(json.dumps(dict(grant=self.grant.said, xid=self.xid,
                        phase='group_dh_proposed', custodian=owner.args.custodian)), flush=True)
                else:
                    yield from owner.send(cue['msg'], cue['dest'])
            yield from self.proposals()
            self.retryProof()
            if self.lead and self.dh.complete(self.xid):
                registry = loadParsedNestedSubstreams(owner.hby, self.grant.said)[0].serder.regid
                head = owner.rgy.store.headEvent(registry)
                if head is not None and head.ilk == 'bup':
                    owner.finish(self.xid, self.grant.said)
                    self.current()
                    self.response, atc = ipexing.admit(self.hab, message=owner.args.message,
                        grant=self.grant, kind=Kinds.json, gvrsn=Vrsn_2_0)
                    # Public proofs let the nonlead verify the original issuer's Grant without any root or finish.
                    public = b''.join(owner.hby.db.clonePreIter(self.grant.pre, gvrsn=Vrsn_2_0))
                    public += b''.join(owner.evidence(SerderACDC(raw=raw), issuer=self.grant.pre)
                        for raw in owner.rgy.store.cloneTelIter(registry))
                    completed = Parser(version=Vrsn_2_0).parseOneBare(
                        ims=serializeMessage(owner.hby, self.grant.said), processive=False)
                    envelope = exchange(sender=self.hab.mhab.pre, route=ProofRoute,
                        attributes=dict(gid=self.hab.pre, grant=self.grant.said), version=Vrsn_2_0,
                        gvrsn=Vrsn_2_0, kind=Kinds.json)
                    proof = self.hab.mhab.endorse(envelope, last=False, framed=False,
                        gvrsn=Vrsn_2_0, nests=[serializeParsedSubstream(completed)])
                    for member in self.hab.db.signingMembers(pre=self.hab.pre):
                        if member != self.hab.mhab.pre:
                            yield from owner.send(public, member)
                            yield from owner.send(proof, member, topic='multisig')
                    yield from self.broadcast(self.response.raw + atc)
            yield owner.tock
        self.current()
        while self.response is None or not owner.exc.complete(self.response.said):
            self.check()
            yield from self.proposals()
            yield owner.tock
        self.current()
        raw = serializeMessage(owner.hby, self.response.said)
        owner.record(serializeMessage(owner.hby, self.grant.said) + raw)
        self.transmitted = owner.exc.lead(self.hab, self.response.said)
        if self.transmitted:
            yield from owner.send(raw, self.grant.pre)
        return self.response
