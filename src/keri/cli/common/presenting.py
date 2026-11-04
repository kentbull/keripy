"""Exact admitted-view presentation and explicit live Unblind admission."""
import base64
from copy import deepcopy
from dataclasses import asdict
import json
import math
from pathlib import Path
from time import monotonic
from types import SimpleNamespace

from hio.base import doing

from . import setupHby
from . import evidencing
from .credentialing import load, recipient
from .issuing import NativeIssuance
from .negotiating import NativeNegotiation
from ... import Kinds, Vrsn_2_0
from ...acdc import Regery, chaining, ipexing, regeventing
from ...acdc.regbasing import RegBaser
from ...acdc.registering import RegistryStore
from ...acdc.unblinding import Unblind
from ...app import GroupHab, MailboxDirector, Notifier, SignifyHab, SignifyGroupHab
from ...core import Blinder, BlindState, BoundState, Kevery, Kramer, Number, Parser, SerderACDC, messagize
from ...db import Baser
from ...help import nowUTC
from ...kering import ConfigurationError, KeriError
from ...peer import Exchanger
from ...peer.exchanging import loadParsedNestedSubstreams, serializeParsedSubstream, verify


def xid(message):
    return message.said if message.ilk == 'xip' else message.sad['x']


def admitted(hby, hab, said):
    """Select accepted authenticated history, including this local party's consent."""
    grant = NativeNegotiation.prior(hby, said, '/ipex/grant')
    terminal = hby.db.erpy.get((said,))
    admission = NativeNegotiation.prior(hby, terminal.qb64 if terminal else None, '/ipex/admit')
    if (grant.sad['ri'] != hab.pre or admission.pre != hab.pre
            or admission.sad['ri'] != grant.pre or admission.sad['p'] != grant.said
            or xid(admission) != xid(grant)):
        raise ConfigurationError('--from-grant requires this local recipient\'s exact accepted Admit')
    if grant.sad['a'].get('ax', [False])[0]:
        raise ConfigurationError('anchored presentation profiles are not supported')
    return grant, loadParsedNestedSubstreams(hby, said)


def selected(nests, paths):
    """Narrow only the supplied origin; native Compactor cannot hydrate hidden leaves."""
    if not paths:
        return nests
    if any(not path.startswith('a/') for path in paths):
        raise ConfigurationError('--disclose accepts only held origin a/... paths')
    node = nests[0].serder
    if not isinstance(node.sad.get('a'), dict):
        raise ConfigurationError('--disclose requires a held attribute map')
    sector = node.sectionCompactor('a', deepcopy(node.sad['a']), kind=node.kind)
    sector.compact(paths=paths, root='a')
    sad = deepcopy(node.sad)
    sad['a'] = sector.partials[tuple(paths)].mad
    narrowed = SerderACDC(sad=sad, kind=node.kind, makify=True)
    if narrowed.said != node.said or not narrowed.verify():
        raise ConfigurationError('native disclosure changed the credential commitment')
    nests[0].serder = narrowed
    return nests


def currentIssued(exc, said):
    message, nests, verdict, observations = exc.reverifyGrant(said)
    if (verdict.verdict != chaining.Verdicts.valid or not observations
            or any(record.state != 'issued' for record in observations.values())):
        raise ConfigurationError('presentation requires current verified issued state')
    return message, nests


def opening(raw):
    """Parse exactly one native opening; no salt or event inference from a file."""
    wire = raw.decode()
    for clan in (BlindState, BoundState):
        try:
            candidate = Blinder(clan=clan, qb64=wire)
        except (KeriError, ValueError, TypeError):
            continue
        if candidate.qb64 == wire:
            return candidate
    raise ConfigurationError('--opening requires exactly one complete CESR state opening')


def refresh(hab, rgy, nests, *, openings, derive):
    """Verify explicit current proofs against native accepted history, changing copies only."""
    supplied = [opening(Path(filename).read_bytes()) for filename in openings]
    used = set()
    for nest in nests:
        node = nest.serder
        if not node.regid:
            continue
        rip, head = rgy.store.seqEvent(node.regid, 0), rgy.store.headEvent(node.regid)
        if rip is None or head is None:
            raise ConfigurationError('proof refresh requires accepted native registry history')
        updates = [rgy.store.seqEvent(node.regid, sn)
                   for sn in range(1, Number(numh=head.sad['n']).num + 1)]
        if any(event is None for event in updates):
            raise ConfigurationError('proof refresh requires contiguous accepted registry history')
        proofs = [Blinder(data=clan(*data), verify=False)
                  for clan, groups in ((BlindState, nest.bsqs), (BoundState, nest.bsss)) for data in groups]
        for proof in supplied:
            if any(proof.said == event.sad['b'] for event in updates):
                proofs.append(proof)
                used.add(proof.qb64)
        if derive:
            if (hab.pre not in (node.israid, node.iseaid) or not hab.mgr.aeid
                    or not hab.mgr.encrypter or not hab.mgr.decrypter):
                raise ConfigurationError('derivation requires this local party\'s encrypted unlocked Keeper')
            root = hab.mgr.getRegistryRoot(hab.pre, node.regid)
            if root is None:
                raise ConfigurationError('no authorized retained root for the selected registry')
            for event in reversed(updates):
                if any(proof.said == event.sad['b'] for proof in proofs):
                    continue
                proof = Blinder.unblind(event.sad['b'], salt=root.qb64,
                    sn=Number(numh=event.sad['n']).num, acdc=node.said, states=('issued', 'revoked'))
                if proof is None:
                    proof = Blinder.unblind(event.sad['b'], salt=root.qb64,
                        sn=Number(numh=event.sad['n']).num, acdc='', states=('',))
                if proof is None:
                    raise ConfigurationError('ordinary derivation cannot open this event; supply --opening (bound derivation is unsupported)')
                proofs.append(proof)
        unique = {proof.qb64: proof for proof in proofs}
        state = regeventing.vetBinds(rip, updates, db=hab.db, blinders=unique.values(),
                                     target=node.said, acdc=node)
        if state.state != 'issued':
            raise ConfigurationError('presentation requires current verified issued state')
        nest.bsqs = [proof.data for proof in unique.values() if proof.clan is BlindState]
        nest.bsss = [proof.data for proof in unique.values() if proof.clan is BoundState]
    if used != {proof.qb64 for proof in supplied}:
        raise ConfigurationError('--opening includes evidence outside the selected registry histories')
    return nests


class NativePresentation(NativeIssuance):
    """Borrow finite transport while native Unblind owns every auxiliary decision."""
    def check(self):
        if self.tyme >= self.deadline or (getattr(self, 'clockDeadline', None) is not None
                                         and monotonic() >= self.clockDeadline):
            raise TimeoutError('native presentation did not complete before --timeout')
        if getattr(self, 'nativeDeadline', None) is not None and nowUTC() >= self.nativeDeadline:
            raise TimeoutError('presentation reached its original native Grant deadline')

    def intake(self, raw, *, local=False):
        NativeNegotiation.intake(self.psr, self.exc, raw, local=local, presentation=True)

    def send(self, raw, dest, *, topic='credential'):
        # Unblind returns a nested stream; StreamPoster accepts body + attachments.
        stream = bytearray(raw)
        parsed = Parser(version=Vrsn_2_0).parseOneBare(ims=stream, processive=False)
        if parsed.serder.route == Unblind.Route:
            if stream:
                raise ConfigurationError('expected one native Unblind stream')
            raw = messagize(parsed.serder, sigers=parsed.sigers or None,
                tsgs=parsed.tsgs or None, lsgs=parsed.lsgs or None, cigars=parsed.cigars or None,
                bonds=[*(BlindState(*data) for data in parsed.bsqs),
                       *(BoundState(*data) for data in parsed.bsss)] or None,
                nests=[serializeParsedSubstream(nest) for nest in parsed.nests] or None,
                gvrsn=Vrsn_2_0)
        yield from super().send(raw, dest, topic=topic)

    def run(self, tymth, tock=0.03125, **kwa):
        self.wind(tymth)
        self.tock = tock
        yield tock
        args = self.args
        evidenceSource = evidencing.settings(args)
        prepare, resume = getattr(args, 'prepare', False), getattr(args, 'resume', None)
        staged = prepare or resume or self.verb == 'endorse'
        if not args.deliver and not (prepare or self.verb == 'endorse'):
            raise ConfigurationError('live native presentation requires explicit --deliver')
        if (prepare or self.verb == 'endorse') and (not args.output or args.deliver):
            raise ConfigurationError('preparation and endorsement require --output without --deliver')
        if staged and (getattr(args, 'refresh', False) or getattr(args, 'derive', False)
                       or getattr(args, 'opening', None) or getattr(args, 'proposal', None)
                       or getattr(args, 'proposal_output', None)):
            raise ConfigurationError('prepare/endorse/resume preserve held proofs; refresh and group proposal options are unsupported')
        if prepare and args.respond_unblind or resume and not args.respond_unblind:
            raise ConfigurationError('--prepare cannot approve Unblind; --resume requires --respond-unblind')
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ConfigurationError('--timeout must be finite and positive')
        if getattr(args, 'time', None):
            raise ConfigurationError('live presentation uses the native current timestamp')
        if args.output and Path(args.output).exists():
            raise ConfigurationError('output already exists')
        if (self.verb == 'present' and (args.opening or args.derive) and not args.refresh):
            raise ConfigurationError('--opening and --derive require explicit --refresh')
        self.deadline = self.tyme + args.timeout
        if staged:
            self.clockDeadline = monotonic() + args.timeout
        self.hby = setupHby(name=args.name, base=args.base, bran=args.bran, version=Vrsn_2_0)
        self.rgy, notifier, background, operation = None, None, [], None
        try:
            self.hab = self.hby.habByName(args.alias)
            if (self.hab is None or not self.hab.accepted
                    or isinstance(self.hab, (SignifyHab, SignifyGroupHab))):
                raise ConfigurationError('presentation requires an accepted local signer')
            group = isinstance(self.hab, GroupHab)
            if staged and group:
                raise ConfigurationError('prepare/endorse/resume require an individual local signer')
            if group and evidenceSource is not None:
                raise ConfigurationError('group signed observer acquisition is outside this presentation profile')
            if not group and getattr(args, 'unblind_proposer', None):
                raise ConfigurationError('--unblind-proposer requires a local group signer')
            if not group and (getattr(args, 'proposal', None) or getattr(args, 'proposal_output', None)):
                raise ConfigurationError('presentation proposal options require a local group signer')
            self.rgy = Regery(hby=self.hby, name=args.name, base=args.base)
            notifier = Notifier(self.hby)
            self.exc = Exchanger(hby=self.hby, handlers=[])
            ipexing.loadHandlers(self.hby, self.exc, notifier, rgy=self.rgy)
            self.unblind = Unblind(self.hab, self.exc, self.rgy, states=('issued', 'revoked', ''))
            if self.unblind is not None:
                self.hby.rtr.addRoute(Unblind.Route, self.unblind, blinders=True, attachments=True)
            kvy = Kevery(db=self.hby.db, rvy=self.hby.rvy, exc=self.exc, qvy=self.unblind,
                lax=True, local=False, direct=False, kramer=Kramer(db=self.hby.db, cf=self.hby.cf))
            mbx = MailboxDirector(hby=self.hby, topics=['/receipt', '/replay', '/credential', '/multisig'],
                exc=self.exc, kvy=kvy, rvy=self.hby.rvy, rgy=self.rgy,
                version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)
            self.psr = mbx.parser
            if not resume:
                for filename in args.input:
                    self.intake(Path(filename).read_bytes())
            if self.verb == 'endorse':
                from .disclosing import endorse
                message = endorse(self)
                print(json.dumps(dict(grant=message.said, xid=xid(message), endorsed=True,
                                      output=args.output, transmitted=False)), flush=True)
                return
            if group:
                background.append(mbx)
                self.extend(background)
                if self.verb == 'present':
                    from .grouppresenting import GroupPresentation
                    yield from GroupPresentation(self, notifier).run()
                else:
                    from .groupunblinding import GroupUnblind
                    message = self.hby.db.exns.get((args.said,)) or self.hby.db.epse.get((args.said,))
                    if message is None or message.route != '/ipex/grant' or message.sad['ri'] != self.hab.pre:
                        raise ConfigurationError('--said requires the exact native presentation Grant for this recipient')
                    coordination = GroupUnblind(self, message, args.unblind_proposer, notifier, requester=True)
                    yield from coordination.admit()
                return
            if self.verb == 'present':
                if prepare:
                    from .disclosing import SelectedPreparation
                    selection = SelectedPreparation(self)
                    item, raw, deadline = selection.prepare()
                    self.check()
                    self.record(raw, initial=True)
                    print(json.dumps(dict(grant=item.serder.said, xid=xid(item.serder),
                        from_grant=selection.source.said, phase='prepared', prepared=True,
                        deadline=deadline, transmitted=False)), flush=True)
                    return
                if resume:
                    from .disclosing import SelectedPreparation
                    selection = SelectedPreparation(self)
                    message, endorsed, operation = selection.resume()
                    recp = selection.recipient
                    raw = bytes(self.hab.replay(gvrsn=Vrsn_2_0)) + endorsed
                else:
                    source, nests = admitted(self.hby, self.hab, args.from_grant)
                    if args.refresh:
                        nests = refresh(self.hab, self.rgy, nests, openings=args.opening, derive=args.derive)
                    else:
                        currentIssued(self.exc, source.said)
                    nests = selected(nests, args.disclose)
                    if len(nests) > 1 and args.plan is None:
                        raise ConfigurationError('multiple disclosed nodes require explicit --plan')
                    plan = load(args.plan) if args.plan is not None else None
                    streams = [serializeParsedSubstream(nest) for nest in nests]
                    recp = recipient(self.hby, args.recipient)
                    message, atc = ipexing.grant(self.hab, recp=recp, message=args.message,
                        origin=streams[0], artifacts=streams[1:] or None,
                        modifiers=dict(dp=plan) if plan is not None else None,
                        kind=Kinds.json, gvrsn=Vrsn_2_0)
                    self.intake(message.raw + atc, local=True)
                    if args.respond_unblind:
                        operation = self.unblind.approve(message.said)
                    raw = bytes(self.hab.replay(gvrsn=Vrsn_2_0)) + message.raw + atc
                print(json.dumps(dict(grant=message.said, xid=xid(message), phase='selected',
                                      from_grant=args.from_grant)), flush=True)
                self.record(raw, initial=True)
                background.append(mbx)
                self.extend(background)
                yield from self.send(raw, recp)
                if not args.respond_unblind:
                    print(json.dumps(dict(grant=message.said, xid=xid(message), transmitted=True)), flush=True)
                    return
                while self.hby.db.erpy.get((message.said,)) is None:
                    self.check()
                    while self.unblind.cues:
                        cue = self.unblind.cues.popleft()
                        if cue['kin'] == 'reply':
                            # Verify the real frozen response before sending; issuer-state policy remains the receiver's.
                            self.unblind.finish(operation)
                        yield from self.send(cue['msg'], cue['dest'])
                    yield tock
                terminal = self.hby.db.erpy.get((message.said,))
                response = self.hby.db.exns.get((terminal.qb64,))
                if response is None or response.route != '/ipex/admit':
                    raise ConfigurationError('presentation terminated without an accepted Admit')
            else:
                message = self.hby.db.exns.get((args.said,)) or self.hby.db.epse.get((args.said,))
                if (message is None or message.route != '/ipex/grant'
                        or message.sad['ri'] != self.hab.pre):
                    raise ConfigurationError('--said requires the exact native presentation Grant for this recipient')
                if message.sad['a'].get('ax', [False])[0]:
                    raise ConfigurationError('anchored presentation profiles are not supported')
                operation = self.unblind.approve(message.said)
                print(json.dumps(dict(grant=message.said, xid=operation, phase='selected')), flush=True)
                background.append(mbx)
                self.extend(background)
                context = self.exc.presentationContext(message.said, xid=operation,
                    sender=message.pre, recipient=self.hab.pre)
                if context is None:
                    raise ConfigurationError('selected presentation context is unavailable')
                yield from evidencing.acquire(self, context[2], self.unblind, operation, evidenceSource)
                # Readiness never substitutes for the current issued-state gate.
                needs_unblind = not self.exc.complete(message.said)
                if not needs_unblind:
                    _, _, verdict, _ = self.exc.reverifyGrant(message.said)
                    needs_unblind = verdict.verdict == chaining.Verdicts.unknown and verdict.retryable
                    if not needs_unblind:
                        currentIssued(self.exc, message.said)
                if needs_unblind:
                    yield from self.send(self.unblind.start(message.said), message.pre)
                    while not self.unblind.complete(operation):
                        self.check()
                        yield tock
                    if not self.unblind.finish(operation) or not self.exc.complete(message.said):
                        raise ConfigurationError('native verification has not accepted the selected presentation')
                    print(json.dumps(dict(grant=message.said, xid=operation, phase='unblind_verified')),
                          flush=True)
                self.unblind.complete(operation)
                currentIssued(self.exc, message.said)
                response, atc = ipexing.admit(self.hab, message=args.message, grant=message,
                                             kind=Kinds.json, gvrsn=Vrsn_2_0)
                self.intake(response.raw + atc, local=True)
                self.record(response.raw + atc, initial=True)
                yield from self.send(response.raw + atc, message.pre)
            print(json.dumps(dict(grant=message.said, xid=xid(message), admit=response.said,
                                  admitted=True, transmitted=True)), flush=True)
        finally:
            self.remove(background)
            if operation is not None:
                self.unblind.abandon(operation)
            if notifier is not None:
                notifier.noter.close()
            if self.rgy is not None:
                self.rgy.close()
            self.hby.close()


class NativeInspection(doing.Doer):
    """Open only public evidence stores, with LMDB enforcing read-only access."""
    def __init__(self, args):
        self.args = args
        super().__init__()

    def recur(self, tyme):
        args = self.args
        db = Baser(name=args.name, base=args.base, reopen=True, readonly=True)
        baser = None
        try:
            hby = SimpleNamespace(db=db)
            message = db.exns.get((args.said,)) or db.epse.get((args.said,))
            if message is None or message.route != '/ipex/grant' or message.pvrsn != Vrsn_2_0:
                raise ConfigurationError('--said requires an exact retained native Grant')
            verify(hby, message)
            nests = loadParsedNestedSubstreams(hby, message.said)
            terminal = db.erpy.get((message.said,))
            deadline = db.epsd.get((message.said,))
            result = dict(said=message.said, grant=message.sad,
                accepted=db.exns.get((message.said,)) is not None,
                deadline=deadline.dts if deadline else None,
                terminal=terminal.qb64 if terminal else None,
                disclosure=[dict(said=nest.serder.said, body=nest.serder.sad,
                    raw_b64=base64.b64encode(nest.serder.raw).decode(),
                    evidence_b64=base64.b64encode(serializeParsedSubstream(nest)).decode()) for nest in nests],
                observations={keys[1]: asdict(record) for keys, record in
                              db.exrs.getTopItemIter(keys=(message.said,))})
            if args.current:
                baser = RegBaser(name=args.name, base=args.base, reopen=True, readonly=True)
                rgy = SimpleNamespace(store=RegistryStore(baser))
                exc = Exchanger(hby=hby, handlers=[])
                ipexing.loadHandlers(hby, exc, None, rgy=rgy)
                try:
                    _, _, verdict, records = exc.reverifyGrant(message.said)
                    result['current'] = dict(verdict=verdict._asdict(),
                        observations={said: record._asdict() for said, record in records.items()})
                except KeriError as error:
                    result['current'] = dict(error=type(error).__name__, reason=str(error))
            print(json.dumps(result))
            return True
        finally:
            if baser is not None:
                baser.close()
            db.close()
