"""Finite member transport for one explicitly selected v2 IPEX Unblind operation."""
import json
from types import SimpleNamespace

from ... import Kinds, Vrsn_2_0
from ...acdc import chaining, ipexing
from ...app import Multiplexor, multisigExn, multisigQueryExn, multisigRpyExn
from ...core import BlindState, BoundState, Parser, messagize
from ...kering import ConfigurationError, KeriError
from ...peer.exchanging import serializeMessage, serializeParsedSubstream
from .presenting import currentIssued, xid


class _Proposal:
    def __init__(self, owner, resource):
        self.owner, self.resource = owner, resource

    def verify(self, serder, attachments=None, nests=None):
        try:
            return not attachments and self.owner.validate(serder, nests)
        except (KeriError, ValueError, KeyError, TypeError, AttributeError):
            return False

    def handle(self, serder, attachments=None, nests=None):
        self.owner.check()
        if serder.pre != self.owner.hab.mhab.pre:
            child = SimpleNamespace(**nests[0]) if isinstance(nests[0], dict) else nests[0]
            self.owner.pending[(serder.route, serder.pre)] = (serder, child)


class GroupUnblind:
    """The command queues authenticated wrappers; v2 IPEX owners verify every child.

    /multisig/qry is the core local coordination profile route, not an auxiliary
    protocol route. Its {gid, qry} commitment covers one ordinary v2 query substream.
    The selected proposer authors bytes only; v2 verified indices elect delivery.
    """
    def __init__(self, owner, grant, proposer, notifier, *, requester=False):
        self.owner, self.hab, self.grant = owner, owner.hab, grant
        self.requester, self.proposer = requester, proposer
        if proposer not in self.hab.db.signingMembers(pre=self.hab.pre):
            raise ConfigurationError('--unblind-proposer must select an accepted group signing member')
        if grant.route != '/ipex/grant' or grant.sad['a'].get('ax', [False])[0]:
            raise ConfigurationError('group Unblind requires an unanchored v2 IPEX presentation Grant')
        self.operation = owner.unblind.approve(grant.said)
        self.deadline = owner.exc.exchangeDeadline(grant)
        owner.grantDeadline = self.deadline
        self.author = self.hab.mhab.pre == proposer
        self.pending, self.frozen, self.contributed = {}, {}, set()
        self.response, self.finished, self.ready = None, False, False
        self.mux = Multiplexor(owner.hby, notifier, rgy=owner.rgy, replay=owner.psr)
        routes = ('/multisig/qry', '/multisig/exn') if requester else ('/multisig/rpy',)
        for route in routes:
            owner.exc.addHandler(_Proposal(self, route))
        self.check()

    def check(self):
        self.owner.check()
        if self.owner.exc.exchangeDeadline(self.grant) != self.deadline:
            raise ConfigurationError('group Unblind changed the original Grant deadline')
        if self.hab.db.erpy.get((self.grant.said,)) is None:
            self.owner.unblind.complete(self.operation)  # Rechecks Unblind scope and lifetime, not readiness.

    def validate(self, wrapper, nests):
        self.check()
        field = wrapper.route.rsplit('/', 1)[-1]
        if (wrapper.pvrsn != Vrsn_2_0 or len(nests or []) != 1
                or wrapper.pre not in self.hab.db.signingMembers(pre=self.hab.pre)):
            return False
        child = SimpleNamespace(**nests[0]) if isinstance(nests[0], dict) else nests[0]
        body = child.serder
        if (wrapper.sad['a'] != dict(gid=self.hab.pre, **{field: body.said})
                or body.pvrsn != Vrsn_2_0 or body.pre != self.hab.pre):
            return False
        self.mux.validate(wrapper, nests=nests)
        if field == 'exn':
            if (body.ilk != 'exn' or body.route != '/ipex/admit'
                    or body.sad['p'] != self.grant.said or body.sad['x'] != self.operation
                    or body.sad['ri'] != self.grant.pre or body.sad['a'] != dict(m=self.owner.args.message)):
                return False
            allowed = ('serder', 'tsgs', 'local')
        else:
            data = body.sad.get('q' if field == 'qry' else 'a', {})
            if body.ilk != field or body.route != self.owner.unblind.Route or data.get('x') != self.operation:
                return False
            allowed = ('serder', 'tsgs', 'lsgs', 'nests', 'local') if field == 'qry' else (
                'serder', 'tsgs', 'bsqs', 'bsss', 'local')
        if any(value for key, value in vars(child).items() if key not in allowed):
            return False
        frozen = self.frozen.get(field)
        return frozen is None or body.raw == frozen

    def broadcast(self, raw):
        self.check()
        child = Parser(version=Vrsn_2_0).parseOneBare(ims=bytearray(raw), processive=False)
        field = child.serder.ilk
        self.frozen[field] = child.serder.raw
        self.contributed.add(field)
        if field == 'qry':
            wrapper, atc = multisigQueryExn(self.hab, raw)
            wire = wrapper.raw + atc
        else:
            if field == 'rpy':
                # The existing wrapper builder expects ordinary body+attachments, not a nested stream.
                raw = messagize(child.serder, tsgs=child.tsgs,
                    bonds=[*(BlindState(*data) for data in child.bsqs),
                           *(BoundState(*data) for data in child.bsss)], gvrsn=Vrsn_2_0)
            factory = multisigExn if field == 'exn' else multisigRpyExn
            wrapper, atc = factory(self.hab, raw, version=Vrsn_2_0)
            wire = wrapper.raw + atc
        if field == 'exn':
            self.owner.psr.parse(ims=bytearray(wire), local=True)
            self.mux.add(wrapper, nests=[child])
        else:
            self.owner.psr.parse(ims=bytearray(raw), local=True)
        for member in self.hab.db.signingMembers(pre=self.hab.pre):
            if member != self.hab.mhab.pre:
                yield from self.owner.send(wire, member, topic='multisig')
        print(json.dumps(dict(grant=self.grant.said, xid=self.operation,
            phase='group_unblind_proposed', kind=field, proposer=self.proposer)), flush=True)

    def pump(self):
        self.check()
        unblind = self.owner.unblind
        # Readiness only schedules Unblind respond/contribute; those methods recheck all authority.
        requested = unblind._operations[self.operation]['requestedByPeer']
        if not self.requester and self.author and requested and 'rpy' not in self.contributed:
            unblind.respond(self.operation)
        for key, (wrapper, child) in list(self.pending.items()):
            field = child.serder.ilk
            if field not in self.frozen and wrapper.pre != self.proposer:
                continue
            if field == 'rpy' and not requested or field == 'exn' and not self.ready:
                continue
            self.check()
            if not self.validate(wrapper, [child]):
                del self.pending[key]  # A reordered contribution cannot replace the proposer's frozen body.
                continue
            raw = serializeParsedSubstream(child)
            if field == 'exn':
                currentIssued(self.owner.exc, self.grant.said)
                self.response = child.serder
                self.frozen[field] = child.serder.raw
                self.mux.add(wrapper, nests=[child])
                if field not in self.contributed:
                    yield from self.broadcast(self.hab.endorse(child.serder, framed=False, gvrsn=Vrsn_2_0))
            else:
                contribution = unblind.contribute(self.operation, raw)
                self.owner.psr.parse(ims=bytearray(raw))
                if field not in self.contributed:
                    yield from self.broadcast(contribution)
            del self.pending[key]
        if not self.requester and unblind.complete(self.operation) and not self.finished:
            unblind.finish(self.operation)  # Evidence completion never imposes an issued-state reply gate.
            self.finished = True
        while unblind.cues:
            self.check()
            cue = unblind.cues.popleft()
            if cue['kin'] == 'sign':
                yield from self.broadcast(cue['msg'])
            else:
                if cue['kin'] == 'reply' and not self.finished:
                    unblind.finish(self.operation)
                    self.finished = True
                yield from self.owner.send(cue['msg'], cue['dest'])

    def respond(self):
        try:
            while self.hab.db.erpy.get((self.grant.said,)) is None:
                yield from self.pump()
                yield self.owner.tock
            terminal = self.hab.db.erpy.get((self.grant.said,))
            response = self.hab.db.exns.get((terminal.qb64,))
            if response is None or response.route != '/ipex/admit':
                raise ConfigurationError('group presentation terminated without an accepted Admit')
            return response
        finally:
            self.owner.unblind.abandon(self.operation)

    def admit(self):
        owner, unblind = self.owner, self.owner.unblind
        try:
            needs = not owner.exc.complete(self.grant.said)
            if not needs:
                _, _, verdict, _ = owner.exc.reverifyGrant(self.grant.said)
                needs = verdict.verdict == chaining.Verdicts.unknown and verdict.retryable
            if needs:
                if self.author:
                    unblind.start(self.grant.said)
                while not unblind.complete(self.operation):
                    yield from self.pump()
                    yield owner.tock
                if not unblind.finish(self.operation) or not owner.exc.complete(self.grant.said):
                    raise ConfigurationError('v2 IPEX verification has not accepted the selected group presentation')
            currentIssued(owner.exc, self.grant.said)
            self.ready = True
            if self.author:
                self.response, atc = ipexing.admit(self.hab, message=owner.args.message,
                    grant=self.grant, kind=Kinds.json, gvrsn=Vrsn_2_0)
                yield from self.broadcast(self.response.raw + atc)
            while self.response is None or not owner.exc.complete(self.response.said):
                yield from self.pump()
                yield owner.tock
            self.check()
            currentIssued(owner.exc, self.grant.said)
            raw = serializeMessage(owner.hby, self.response.said)
            owner.record(raw, initial=True)
            transmitted = owner.exc.lead(self.hab, self.response.said)
            if transmitted:
                yield from owner.send(raw, self.grant.pre)
            print(json.dumps(dict(grant=self.grant.said, xid=xid(self.grant), admit=self.response.said,
                                  admitted=True, transmitted=transmitted)), flush=True)
        finally:
            unblind.abandon(self.operation)
