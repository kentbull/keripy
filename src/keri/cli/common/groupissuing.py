"""Explicit member consent for one fresh group issuance, through verified Admit."""
import json
from pathlib import Path
from types import SimpleNamespace

from ... import Kinds, Vrsn_2_0
from ...acdc import Registrar, ipexing, regeventing
from ...app import Multiplexor, multisigExn
from ...app.grouping import MultisigNotificationHandler
from ...core import Parser, SerderACDC, exchange, messagize
from ...kering import ConfigurationError, KeriError
from ...peer.exchanging import loadParsedNestedSubstreams, serializeParsedSubstream, verify
from .credentialing import recipient
from .negotiating import NativeNegotiation
from . import nativeanchoring


class _QueryProposal:
    resource = '/multisig/qry'  # Command coordination extension; the child is ordinary native DH.

    def __init__(self, operation):
        self.operation = operation

    def verify(self, serder, attachments=None, nests=None):
        try:
            operation = self.operation
            operation.owner.check()
            if attachments or operation.grant is None or len(nests or []) != 1:
                return False
            child = SimpleNamespace(**nests[0]) if isinstance(nests[0], dict) else nests[0]
            body = child.serder
            return (serder.pvrsn == Vrsn_2_0
                and serder.pre in operation.owner.hby.db.signingMembers(pre=operation.owner.hab.pre)
                and serder.sad['a'] == dict(gid=operation.owner.hab.pre, qry=body.said)
                and body.pvrsn == Vrsn_2_0 and body.ilk == 'qry'
                and body.pre == operation.owner.hab.pre and body.route == operation.owner.dh.Route
                and body.sad['q'].get('x') == (operation.grant.said if operation.grant.ilk == 'xip'
                                              else operation.grant.sad['x'])
                and (operation.query is None or body.raw == operation.query)
                and not any(value for key, value in vars(child).items()
                    if key not in ('serder', 'tsgs', 'lsgs', 'local')))
        except (KeriError, ValueError, KeyError, TypeError, AttributeError):
            return False

    def handle(self, serder, attachments=None, nests=None):
        if serder.pre != self.operation.owner.hab.mhab.pre:
            self.operation.pending[serder.pre] = (
                serder, SimpleNamespace(**nests[0]) if isinstance(nests[0], dict) else nests[0])


class GroupIssuance:
    """Proposal authorship grants no custody; native DH verifies the frozen election."""
    resource = '/multisig/exn'

    def __init__(self, owner, notifier, coordinator, custodian):
        self.owner, self.args = owner, owner.args
        self.coordinator, self.custodian = coordinator, custodian
        self.lead = owner.hab.mhab.pre == custodian
        args = self.args
        if bool(args.proposal) == bool(args.proposal_output):
            raise ConfigurationError('group Grant requires exactly one of --proposal or --proposal-output')
        if not args.proposal and not self.lead:
            raise ConfigurationError('only the existing elected custodian may create the group issuance proposal')
        if not self.lead and args.output:
            raise ConfigurationError('only the issuer custodian writes completed public issuance evidence')
        if args.authenticate or args.code or args.code_time is not None:
            raise ConfigurationError('group issuer witness authentication requires its group receipt owner')
        if args.proposal_output and (Path(args.proposal_output).exists()
                or args.output and Path(args.output).resolve() == Path(args.proposal_output).resolve()):
            raise ConfigurationError('proposal output already exists or conflicts with --output')
        self.body = SerderACDC(raw=Path(args.credential).read_bytes())
        self.recipient = recipient(owner.hby, args.recipient)
        if (self.body.raw != Path(args.credential).read_bytes() or not self.body.verify()
                or self.body.pvrsn != Vrsn_2_0 or self.body.ilk not in ('acm', 'act', 'acg')
                or self.body.israid != owner.hab.pre or self.body.iseaid != self.recipient):
            raise ConfigurationError('group public body must exactly match selected issuer and recipient')
        # Imported accepted RIPs intentionally have no managed Registry alias.
        rip = owner.rgy.store.headEvent(self.body.regid)
        if rip is None or rip.ilk != 'rip':
            raise ConfigurationError('group issuance requires a fresh accepted registry')
        regeventing.vetAnchor(rip, db=owner.hby.db, issuer=owner.hab.pre)
        self.registry = owner.rgy.regs.get(self.body.regid)
        if self.lead and self.registry is None:
            raise ConfigurationError('elected issuer custodian requires the managed local registry')
        self.prior, self.linked = None, {}
        if args.prior:
            prior = owner.hby.db.exns.get((args.prior,))
            if prior is None or prior.route not in ('/ipex/apply', '/ipex/agree'):
                raise ConfigurationError('--prior requires an exact accepted native Apply or Agree')
            self.prior = NativeNegotiation.prior(owner.hby, args.prior, prior.route)
            if self.prior.sad['a'].get('ax', [False])[0]:
                raise ConfigurationError('anchored prior is outside live group issuance')
            self.linked['apply' if prior.route == '/ipex/apply' else 'agree'] = self.prior
        schema = self.body.schema
        schema = schema.get('$id') if isinstance(schema, dict) else schema
        self.plan = [[]] if self.prior else [[[schema, '/', []]]]
        self.grant, self.handled, self.child, self.xid, self.query = None, None, None, None, None
        self.pending = {}
        self.mux = Multiplexor(owner.hby, notifier, rgy=owner.rgy, replay=owner.psr)
        owner.exc.addHandler(self)
        self.queryHandler = _QueryProposal(self)
        owner.exc.addHandler(self.queryHandler)
        owner.exc.addHandler(MultisigNotificationHandler('/multisig/bup', self.mux))

    def verify(self, serder, attachments=None, nests=None):
        try:
            self.owner.check()
            if attachments or serder.pvrsn != Vrsn_2_0:
                return False
            self.mux.validate(serder, nests=nests)
            child = SimpleNamespace(**nests[0]) if isinstance(nests[0], dict) else nests[0]
            grant = child.serder
            if (grant.raw != self.grant.raw or grant.pre != self.owner.hab.pre
                    or grant.route != '/ipex/grant' or grant.sad['ri'] != self.recipient
                    or grant.sad.get('p', '') != (self.prior.said if self.prior else '')
                    or grant.sad['q'] != dict(dp=self.plan)
                    or grant.sad['a'] != dict(m=self.args.message, o=[self.body.said])
                    or any(value for key, value in vars(child).items()
                        if key not in ('serder', 'tsgs', 'nests', 'local'))
                    or len(child.nests) != 1):
                return False
            node = SimpleNamespace(**child.nests[0]) if isinstance(child.nests[0], dict) else child.nests[0]
            return node.serder.raw == self.body.raw and not any(value for key, value in vars(node).items()
                if key not in ('serder', 'local'))
        except (KeriError, ValueError, KeyError, TypeError, AttributeError):
            return False

    def handle(self, serder, attachments=None, nests=None):
        self.owner.check()
        self.mux.add(serder, nests=nests)
        self.handled = serder.said
        self.child = SimpleNamespace(**nests[0]) if isinstance(nests[0], dict) else nests[0]

    def accept(self, raw, *, local=False):
        stream = bytearray(raw)
        packet = Parser(version=Vrsn_2_0).parseOneBare(ims=stream, framed=True, processive=False)
        if stream or packet.serder.route != self.resource or len(packet.nests) != 1:
            raise ConfigurationError('--proposal requires one exact native /multisig/exn Grant packet')
        self.handled = None
        self.owner.psr.parse(ims=bytearray(raw), local=local)
        if self.handled != packet.serder.said:
            raise ConfigurationError('proposal did not pass authentication and selected fresh issuance scope')
        protected = Parser(version=Vrsn_2_0, kvy=self.owner.hby.kvy, exc=self.owner.exc,
                           rvy=self.owner.hby.rvy, rgy=self.owner.rgy, local=True)
        protected.parse(ims=serializeParsedSubstream(self.child), local=True)
        return self.child

    def freezeDeadline(self):
        dater = self.owner.hby.db.epsd.get((self.grant.said,))
        if dater is None:
            raise ConfigurationError('selected group Grant has no original consent deadline')
        self.owner.nativeDeadline = dater.datetime
        self.owner.check()

    def broadcastQuery(self, raw):
        owner = self.owner
        child = Parser(version=Vrsn_2_0).parseOneBare(ims=bytearray(raw), processive=False)
        self.query = child.serder.raw
        wrapper = exchange(sender=owner.hab.mhab.pre, route='/multisig/qry',
            attributes=dict(gid=owner.hab.pre, qry=child.serder.said),
            version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)
        wire = owner.hab.mhab.endorse(wrapper, framed=False, gvrsn=Vrsn_2_0,
                                     nests=[serializeParsedSubstream(child)])
        owner.psr.parse(ims=bytearray(raw), local=True)
        for member in owner.hby.db.signingMembers(pre=owner.hab.pre):
            if member != owner.hab.mhab.pre:
                yield from owner.send(wire, member, topic='multisig')
        print(json.dumps(dict(grant=self.grant.said, xid=self.xid, phase='group_dh_proposed',
                              custodian=self.custodian)), flush=True)

    def run(self, background):
        owner, args = self.owner, self.args
        if args.proposal:
            raw = Path(args.proposal).read_bytes()
            stream = bytearray(raw)
            packet = Parser(version=Vrsn_2_0).parseOneBare(ims=stream, framed=True, processive=False)
            if stream or len(packet.nests) != 1:
                raise ConfigurationError('--proposal requires one exact native /multisig/exn Grant packet')
            self.grant = packet.nests[0].serder
            if owner.hby.db.epsd.get((self.grant.said,)) is not None:
                self.freezeDeadline()
            child = self.accept(raw)
            signed = owner.hab.endorse(child.serder, last=False, framed=False, gvrsn=Vrsn_2_0,
                                       nests=[serializeParsedSubstream(node) for node in child.nests])
        else:
            self.grant, atc = ipexing.grant(owner.hab, recp=self.recipient, message=args.message,
                origin=self.body, kind=Kinds.json, gvrsn=Vrsn_2_0, **self.linked)
            signed = self.grant.raw + atc
        wrapper, atc = multisigExn(owner.hab, signed, version=Vrsn_2_0)
        raw = wrapper.raw + atc
        self.accept(raw, local=True)
        self.freezeDeadline()
        if args.proposal_output:
            with Path(args.proposal_output).open('xb') as output:
                output.write(raw)
        for member in owner.hby.db.signingMembers(pre=owner.hab.pre):
            if member != owner.hab.mhab.pre:
                yield from owner.send(raw, member, topic='multisig')
        xid = self.grant.said if self.grant.ilk == 'xip' else self.grant.sad['x']
        print(json.dumps(dict(grant=self.grant.said, xid=xid, phase='group_proposed',
                              custodian=self.custodian)), flush=True)
        while owner.exc.pendingGrant(self.grant.said, xid=xid, sender=owner.hab.pre,
                                      recipient=self.recipient) is None:
            owner.check()
            yield owner.tock
        self.xid = owner.dh.approve(self.grant.said, coordinator=self.coordinator, custodian=self.custodian)
        if self.lead:
            tsgs, cigars = verify(owner.hby, self.grant)
            pending = messagize(self.grant, tsgs=tsgs or None, cigars=cigars or None,
                nests=[serializeParsedSubstream(node) for node in loadParsedNestedSubstreams(owner.hby, self.grant.said)],
                gvrsn=Vrsn_2_0)
            initial = owner.public(self.registry.regk) + pending
            owner.record(initial, initial=True)
            yield from owner.send(initial, self.recipient)
            yield from self.broadcastQuery(owner.dh.start(self.grant.said))
        while not self.lead or not owner.dh.complete(self.xid):
            owner.check()
            for member, (packet, child) in list(self.pending.items()):
                if not self.queryHandler.verify(packet, nests=[child]):
                    del self.pending[member]
                    continue
                raw = serializeParsedSubstream(child)
                if self.lead:
                    owner.psr.parse(ims=bytearray(raw))
                else:
                    contribution = owner.dh.contribute(self.xid, raw)
                    owner.psr.parse(ims=bytearray(raw))
                    yield from self.broadcastQuery(contribution)
                    print(json.dumps(dict(grant=self.grant.said, xid=self.xid,
                        phase='contributed', contributed=True, admitted=False, registry_issued=False)), flush=True)
                    # This invocation already consumed exact Grant consent. Leave
                    # other proposals for the subsequent explicit BUP join.
                    for keys, note in list(self.mux.notifier.noter.notes.getTopItemIter()):
                        packet = owner.hby.db.exns.get((note.attrs.get('d', ''),))
                        if (packet is not None and packet.route == self.resource
                                and packet.sad['a'] == dict(gid=owner.hab.pre, exn=self.grant.said)):
                            self.mux.notifier.noter.notes.rem(keys=keys)
                    return  # Release the store for explicit multisig join of the BUP.
                del self.pending[member]
            while owner.dh.cues:
                cue = owner.dh.cues.popleft()
                yield from owner.send(cue['msg'], cue['dest'])
            yield owner.tock
        _, event = Registrar(owner.rgy).issue(self.registry, acdc=self.body,
            salt=owner.hab.mgr.getRegistryRoot(owner.hab.pre, self.registry.regk).qb64)
        yield from nativeanchoring.groupAnchor(owner, self.registry, event, self.mux, background,
                                               grant=self.grant.said)
        owner.finish(self.xid, self.grant.said)
        published = owner.public(self.registry.regk)
        owner.record(published)
        yield from owner.send(published, self.recipient)
        while owner.hby.db.erpy.get((self.grant.said,)) is None:
            owner.check()
            yield owner.tock
        response = owner.hby.db.exns.get((owner.hby.db.erpy.get((self.grant.said,)).qb64,))
        if response is None or response.route != '/ipex/admit' or not owner.exc.complete(response.said):
            raise ConfigurationError('selected group Grant terminated without a verified Admit')
        print(json.dumps(dict(grant=self.grant.said, xid=self.xid, admit=response.said,
                              registry_issued=True, admitted=True, transmitted=True)), flush=True)
