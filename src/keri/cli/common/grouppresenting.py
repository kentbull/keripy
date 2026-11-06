"""Explicit contributions to one exact group admitted-view presentation."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

from ... import Kinds, Vrsn_2_0
from ...acdc import ipexing
from ...app import Multiplexor, multisigExn
from ...core import Parser
from ...kering import ConfigurationError, KeriError
from ...peer.exchanging import loadParsedNestedSubstreams, serializeMessage, serializeParsedSubstream
from .credentialing import load, recipient
from .presenting import admitted, currentIssued, refresh, selected


class GroupPresentation:
    """Borrow the live parser; freshly selected wrappers authorize local child intake.

    Protected local intake retains native partial-auth escrow and its deadline;
    ordinary KRAM still aggregates signatures before threshold acceptance.
    """
    resource = '/multisig/exn'

    def __init__(self, owner, notifier):
        self.owner, self.args = owner, owner.args
        args = self.args
        if args.proposal and (args.derive or args.opening or args.proposal_output):
            raise ConfigurationError('contributors preserve packet proofs; --derive/--opening/--proposal-output are creator options')
        if not args.proposal and not args.proposal_output:
            raise ConfigurationError('group presentation creation requires --proposal-output')
        if args.proposal_output and (Path(args.proposal_output).exists()
                or args.output and Path(args.output).resolve() == Path(args.proposal_output).resolve()):
            raise ConfigurationError('proposal output already exists or conflicts with --output')
        self.source, nests = admitted(owner.hby, owner.hab, args.from_grant)
        if not args.refresh:
            currentIssued(owner.exc, self.source.said)
        elif not args.proposal:
            nests = refresh(owner.hab, owner.rgy, nests, openings=args.opening, derive=args.derive)
        self.nodes = selected(nests, args.disclose)
        if len(self.nodes) > 1 and args.plan is None:
            raise ConfigurationError('multiple disclosed nodes require explicit --plan')
        schema = self.nodes[0].serder.schema
        schema = schema.get('$id') if isinstance(schema, dict) else schema
        self.plan = load(args.plan) if args.plan is not None else [[[schema, '/', []]]]
        self.recipient = recipient(owner.hby, args.recipient)
        self.mux = Multiplexor(owner.hby, notifier, rgy=owner.rgy, replay=owner.psr)
        self.grant, self.proofs, self.handled, self.child = None, None, None, None
        owner.exc.addHandler(self)

    def verify(self, serder, attachments=None, nests=None):
        owner = self.owner
        owner.check()
        try:
            if attachments or serder.pvrsn != Vrsn_2_0:
                return False
            self.mux.validate(serder, nests=nests)
            child = nests[0]
            child = child if isinstance(child, dict) else vars(child)
            body = child['serder']
            if (body.raw != self.grant.raw or body.ilk != 'xip' or body.route != '/ipex/grant'
                    or body.pre != owner.hab.pre or body.sad['ri'] != self.recipient
                    or body.sad.get('p') or body.sad['q'] != dict(dp=self.plan)
                    or body.sad['a'] != dict(m=self.args.message, o=[self.nodes[0].serder.said])
                    or any(value for key, value in child.items() if key not in ('serder', 'tsgs', 'nests', 'local'))):
                return False
            nodes = [SimpleNamespace(**node) if isinstance(node, dict) else node
                     for node in child.get('nests') or []]
            if [node.serder.raw for node in nodes] != [node.serder.raw for node in self.nodes]:
                return False
            proofs = [serializeParsedSubstream(node) for node in nodes]
            if proofs != self.proofs:
                return False
            if self.args.refresh:
                refresh(owner.hab, owner.rgy, deepcopy(nodes), openings=(), derive=False)
            elif proofs != [serializeParsedSubstream(node) for node in self.nodes]:
                return False
            return True
        except (KeriError, ValueError, KeyError, TypeError, AttributeError):
            return False

    def handle(self, serder, attachments=None, nests=None):
        self.owner.check()
        self.mux.add(serder, nests=nests)
        self.handled = serder.said
        self.child = SimpleNamespace(**nests[0]) if isinstance(nests[0], dict) else nests[0]

    def accept(self, raw, *, local=False):
        stream = bytearray(raw)
        frame = Parser(version=Vrsn_2_0).parseOneBare(ims=stream, framed=True, processive=False)
        if (stream or frame.serder.pvrsn != Vrsn_2_0 or frame.serder.route != self.resource
                or len(frame.nests) != 1):
            raise ConfigurationError('--proposal requires one exact native /multisig/exn packet')
        self.handled = None
        self.owner.psr.parse(ims=bytearray(raw), local=local)
        if self.handled != frame.serder.said:
            raise ConfigurationError('proposal did not pass current authentication and selected admitted-view scope')
        if not self.owner.exc.complete(self.grant.said):
            # Fresh command consent permits escrow of this exact scoped child, never partial acceptance.
            protected = Parser(version=Vrsn_2_0, kvy=self.owner.hby.kvy,
                exc=self.owner.exc, rvy=self.owner.hby.rvy, rgy=self.owner.rgy, local=True)
            protected.parse(ims=serializeParsedSubstream(self.child), local=True)
        return self.child

    def freezeDeadline(self, *, required=False):
        deadline = self.owner.exc.exchangeDeadline(self.grant)
        if deadline is None and required:
            raise ConfigurationError('selected Grant has no authenticated KRAM lifetime')
        self.owner.nativeDeadline = deadline
        self.owner.check()

    def run(self):
        owner, args = self.owner, self.args
        if args.proposal:
            raw = Path(args.proposal).read_bytes()
            stream = bytearray(raw)
            packet = Parser(version=Vrsn_2_0).parseOneBare(ims=stream, framed=True, processive=False)
            if stream or len(packet.nests) != 1:
                raise ConfigurationError('--proposal requires one exact native /multisig/exn packet')
            self.grant = packet.nests[0].serder
            proposer = packet.serder.pre
            self.proofs = [serializeParsedSubstream(node) for node in packet.nests[0].nests]
            if owner.exc.exchangeDeadline(self.grant) is not None:
                self.freezeDeadline()
            child = self.accept(raw)
            self.freezeDeadline()
            signed = owner.hab.endorse(child.serder, last=False, framed=False,
                gvrsn=Vrsn_2_0, nests=self.proofs)
        else:
            proposer = owner.hab.mhab.pre
            self.proofs = [serializeParsedSubstream(node) for node in self.nodes]
            self.grant, atc = ipexing.grant(owner.hab, recp=self.recipient, message=args.message,
                origin=self.proofs[0], artifacts=self.proofs[1:] or None, modifiers=dict(dp=self.plan),
                kind=Kinds.json, gvrsn=Vrsn_2_0)
            signed = self.grant.raw + atc
        wrapper, watc = multisigExn(owner.hab, signed, version=Vrsn_2_0)
        raw = wrapper.raw + watc
        self.accept(raw, local=True)
        self.freezeDeadline()
        if args.proposal_output:
            with Path(args.proposal_output).open('xb') as output:
                output.write(raw)
        for member in owner.hab.db.signingMembers(pre=owner.hab.pre):
            if member != owner.hab.mhab.pre:
                yield from owner.send(raw, member, topic='multisig')
        print(json.dumps(dict(grant=self.grant.said, xid=self.grant.said, from_grant=self.source.said,
            phase='group_proposed', locally_accepted=owner.exc.complete(self.grant.said))), flush=True)
        while not owner.exc.complete(self.grant.said):
            owner.check()
            yield owner.tock
        owner.check()
        self.freezeDeadline(required=True)
        currentIssued(owner.exc, self.grant.said)
        if [serializeParsedSubstream(node) for node in loadParsedNestedSubstreams(owner.hby, self.grant.said)] != self.proofs:
            raise ConfigurationError('native accepted disclosure differs from the selected proposal proofs')
        raw = bytes(owner.hab.replay(gvrsn=Vrsn_2_0)) + serializeMessage(owner.hby, self.grant.said)
        coordination = None
        if args.respond_unblind:
            from .groupunblinding import GroupUnblind
            coordination = GroupUnblind(owner, self.grant, proposer, self.mux.notifier)
        owner.record(raw, initial=True)
        transmitted = owner.exc.lead(owner.hab, self.grant.said)
        if transmitted:
            yield from owner.send(raw, self.recipient)
        print(json.dumps(dict(grant=self.grant.said, xid=self.grant.said, locally_accepted=True,
            transmitted=transmitted)), flush=True)
        if coordination is not None:
            response = yield from coordination.respond()
            print(json.dumps(dict(grant=self.grant.said, xid=self.grant.said, admit=response.said,
                                  admitted=True, transmitted=transmitted)), flush=True)
