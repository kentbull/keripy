"""Exact held-view preparation and independent issuer consent for a new Grant."""
from pathlib import Path
from types import SimpleNamespace

from .credentialing import load, recipient
from .presenting import admitted, selected, xid
from ... import Kinds, Vrsn_2_0
from ...acdc import chaining, ipexing
from ...core import Parser, Prefixer, SealEvent, messagize
from ...help import nowUTC
from ...kering import ConfigurationError
from ...peer.exchanging import loadParsedNestedSubstreams, serializeParsedSubstream, verify


def frame(raw):
    stream = bytearray(raw)
    item = Parser(version=Vrsn_2_0).parseOneBare(ims=stream, framed=True, processive=False)
    if (item is None or stream or item.serder.pvrsn != Vrsn_2_0 or item.serder.route != '/ipex/grant'
            or item.serder.ilk not in ('xip', 'exn') or item.serder.sad['a'].get('ax', [False])[0]
            or any(value for key, value in vars(item).items()
                   if key not in ('serder', 'tsgs', 'cigars', 'ssts', 'nests', 'local'))):
        raise ConfigurationError('expected one unanchored native Grant with unchanged public nested evidence')
    return item


def wire(item):
    return messagize(item.serder, tsgs=item.tsgs or None, cigars=item.cigars or None,
        bonds=[SealEvent(*seal) for seal in item.ssts] or None,
        nests=[serializeParsedSubstream(node) for node in item.nests] or None, gvrsn=Vrsn_2_0)


def nodes(item):
    return [serializeParsedSubstream(node) for node in item.nests]


def protected(owner, raw):
    Parser(version=Vrsn_2_0, kvy=owner.hby.kvy, exc=owner.exc,
        rvy=owner.hby.rvy, rgy=owner.rgy, local=True).parse(ims=bytearray(raw), local=True)


def retained(owner, said):
    message = owner.hby.db.exns.get((said,)) or owner.hby.db.epse.get((said,))
    deadline = owner.hby.db.epsd.get((said,))
    if (message is None or deadline is None or owner.hby.db.erpy.get((said,)) is not None
            or nowUTC() >= deadline.datetime):
        raise ConfigurationError('prepared Grant is unavailable, terminated or past its original native deadline')
    tsgs, cigars = verify(owner.hby, message)
    seals = [(Prefixer(qb64=keys[1]), number, diger)
             for keys, (number, diger) in owner.hby.db.ests.getTopItemIter(keys=(said, ''))]
    item = SimpleNamespace(serder=message, tsgs=tsgs, cigars=cigars, ssts=seals,
        nests=loadParsedNestedSubstreams(owner.hby, said))
    return item, deadline


def context(owner, item):
    """Require native auxiliary authorization for every selected registry-backed node."""
    result = owner.exc.presentationContext(item.serder.said, xid=xid(item.serder),
        sender=item.serder.pre, recipient=item.serder.sad['ri'])
    expected = {}
    for node in item.nests:
        expected.setdefault(node.serder.regid, set()).add(node.serder.said)
    expected.pop('', None)
    expected.pop(None, None)
    if (not expected or result is None or set(result[2]) != set(expected)
            or any(set(result[2][key]) != value for key, value in expected.items())):
        raise ConfigurationError('exact Grant lacks complete native issuer endorsement and presentation scope')
    return result


def factors(item):
    return ({('tsg', pre.qb64, number.sn, diger.qb64, sig.qb64)
             for pre, number, diger, sigs in item.tsgs for sig in sigs}
            | {('cigar', cigar.verfer.qb64, cigar.qb64) for cigar in item.cigars}
            | {('seal', pre.qb64, number.sn, diger.qb64) for pre, number, diger in item.ssts})


class SelectedPreparation:
    """No operation ledger: the exact native outgoing body and original epsd must exist."""
    def __init__(self, owner):
        self.owner, self.args = owner, owner.args
        self.source, nests = admitted(owner.hby, owner.hab, self.args.from_grant)
        self.nests = selected(nests, self.args.disclose)
        if len(self.nests) > 1 and self.args.plan is None:
            raise ConfigurationError('multiple disclosed nodes require explicit --plan')
        schema = self.nests[0].serder.schema
        schema = schema.get('$id') if isinstance(schema, dict) else schema
        self.plan = load(self.args.plan) if self.args.plan is not None else [[[schema, '/', []]]]
        self.recipient = recipient(owner.hby, self.args.recipient)

    def capture(self, said):
        item, deadline = retained(self.owner, said)
        message = item.serder
        if (message.pvrsn != Vrsn_2_0 or message.ilk != 'xip' or message.route != '/ipex/grant'
                or message.pre != self.owner.hab.pre or message.sad['ri'] != self.recipient
                or message.sad.get('p') or message.sad['q'] != dict(dp=self.plan)
                or message.sad['a'] != dict(m=self.args.message, o=[self.nests[0].serder.said])
                or nodes(item) != [serializeParsedSubstream(node) for node in self.nests]):
            raise ConfigurationError('prepared Grant differs from the exact selected admitted view and parties')
        self.owner.nativeDeadline = deadline.datetime
        self.owner.check()
        return item, deadline.dts

    def prepare(self):
        _, _, verdict, records = self.owner.exc.reverifyGrant(self.source.said)
        if (not (verdict.verdict == chaining.Verdicts.valid
                 or verdict.verdict == chaining.Verdicts.unknown and verdict.retryable)
                or any(record.state != 'issued' for record in records.values())):
            raise ConfigurationError('preparation requires issued state or retryable unknown current evidence')
        streams = [serializeParsedSubstream(node) for node in self.nests]
        message, atc = ipexing.grant(self.owner.hab, recp=self.recipient, message=self.args.message,
            origin=streams[0], artifacts=streams[1:] or None, modifiers=dict(dp=self.plan),
            kind=Kinds.json, gvrsn=Vrsn_2_0)
        raw = message.raw + atc
        protected(self.owner, raw)
        item, deadline = self.capture(message.said)
        if item.serder.raw != message.raw:
            raise ConfigurationError('native retention changed the prepared Grant')
        return item, raw, deadline

    def resume(self):
        # Capture existing native state BEFORE any input is imported; missing preparation cannot be recreated.
        original, deadline = self.capture(self.args.resume)
        if not self.args.input:
            raise ConfigurationError('--resume requires the exact independently endorsed Grant input')
        inputs = []
        for filename in self.args.input:
            candidate = frame(Path(filename).read_bytes())
            if (candidate.serder.raw != original.serder.raw or nodes(candidate) != nodes(original)
                    or not factors(original).issubset(factors(candidate))):
                raise ConfigurationError('resume permits authentication additions to the exact prepared Grant only')
            inputs.append(wire(candidate))
        for raw in inputs:
            self.owner.check()
            protected(self.owner, raw)
        final, current = self.capture(original.serder.said)
        if current != deadline:
            raise ConfigurationError('resume changed the original native Grant deadline')
        context(self.owner, final)
        operation = self.owner.unblind.approve(final.serder.said)
        try:
            raw = wire(final)
            # Register FINAL endorsed bytes with the ordinary conversation owner before any delivery.
            self.owner.psr.parse(ims=bytearray(raw), local=True)
            checked, current = self.capture(final.serder.said)
            if current != deadline or nodes(checked) != nodes(original):
                raise ConfigurationError('outgoing registration changed the prepared Grant or original deadline')
            context(self.owner, checked)
        except BaseException:
            self.owner.unblind.abandon(operation)
            raise
        return final.serder, raw, operation


def endorse(owner):
    args = owner.args
    item = frame(Path(args.grant).read_bytes())
    message = item.serder
    if (message.said != args.said or message.pre != recipient(owner.hby, args.sender)
            or message.sad['ri'] != recipient(owner.hby, args.recipient)):
        raise ConfigurationError('endorsement must select the exact Grant SAID, sender and recipient')
    registry_nodes = [node for node in item.nests if node.serder.regid]
    if not registry_nodes:
        raise ConfigurationError('endorsement requires selected registry-backed nodes')
    for node in registry_nodes:
        rip = owner.rgy.store.seqEvent(node.serder.regid, 0)
        if (rip is None or rip.israid != owner.hab.pre or node.serder.israid != owner.hab.pre):
            raise ConfigurationError('mixed-issuer scope is unsupported; every selected registry must belong to this issuer')
    protected(owner, wire(item))
    saved, _ = retained(owner, message.said)
    if saved.serder.raw != message.raw or nodes(saved) != nodes(item):
        raise ConfigurationError('native retention differs from the selected Grant')
    owner.check()
    addition = frame(owner.hab.endorse(message, framed=False, gvrsn=Vrsn_2_0))
    item.tsgs.extend(addition.tsgs)
    item.cigars.extend(addition.cigars)
    raw = wire(item)
    protected(owner, raw)
    saved, _ = retained(owner, message.said)
    context(owner, saved)
    owner.check()
    with Path(args.output).open('xb') as output:
        output.write(raw)
    return message
