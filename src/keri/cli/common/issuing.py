"""Finite, explicitly selected individual native issuance over existing mailboxes."""
import json
import math
from pathlib import Path

from hio.base import doing

from . import evidencing, nativeanchoring, sending, parseVersion, setupHby
from .credentialing import recipient
from .negotiating import NativeNegotiation
from .witnessing import witnessAuths
from ... import Kinds, Vrsn_1_0, Vrsn_2_0
from ...acdc import Regery, Registrar, ipexing, regeventing
from ...acdc.dhking import Dhke
from ...app import (GroupHab, Keeper, MailboxDirector, Notifier,
                    SignifyHab, SignifyGroupHab)
from ...core import Kevery, Kramer, Parser, SealSource, SerderACDC, messagize
from ...kering import ConfigurationError
from ...help import nowUTC
from ...peer import Exchanger
from ...peer.exchanging import loadParsedNestedSubstreams, serializeParsedSubstream, verify


def options(parser):
    parser.add_argument('--version', type=parseVersion, default=Vrsn_1_0)
    parser.add_argument('--input', action='append', default=[], help='signed public KEL/TEL/IPEX CESR intake')
    parser.add_argument('--output', help='exclusive-create public evidence file; never contains registry roots')
    parser.add_argument('--deliver', action='store_true', help='explicitly submit through recipient endpoints/mailboxes')
    parser.add_argument('--timeout', type=float, default=120.0, help='finite whole-operation wait; preserves the native deadline')


def legacy(args):
    if (args.input or args.output or args.deliver or args.timeout != 120.0
            or any(getattr(args, field, None) for field in
                   ('credential', 'prior', 'issue', 'authenticate', 'code', 'code_time', 'unblind',
                    'evidence_url', 'evidence_ca', 'evidence_hostname', 'coordinator', 'custodian',
                    'unblind_proposer', 'proposal', 'proposal_output', 'consent_lifetime'))):
        raise ConfigurationError('native issuance options require --version 2.0')


class NativeIssuance(doing.DoDoer):
    """Keep DH ephemeral keys alive until witnessed issuance and explicit Admit.

    Native Regery, Exchanger, DH and the ordinary KEL receipt/delegation owners
    decide acceptance. No operation can be resumed by opening a fresh process.
    """
    def __init__(self, args, verb):
        self.args, self.verb = args, verb
        super().__init__(doers=[doing.doify(self.run)])

    def check(self):
        if self.tyme >= self.deadline:
            raise TimeoutError('native issuance did not complete before --timeout')
        if getattr(self, 'nativeDeadline', None) is not None and nowUTC() >= self.nativeDeadline:
            raise TimeoutError('selected group issuance reached its original native deadline')

    def intake(self, raw, *, local=False):
        NativeNegotiation.intake(self.psr, self.exc, raw, local=local, issuance=True)

    def finish(self, xid, grant):
        if not self.dh.finish(xid) or not self.exc.complete(grant):
            raise ConfigurationError('native verification has not accepted the selected Grant')

    def evidence(self, event, *, issuer=None):
        sn, said = regeventing.vetAnchor(event, db=self.hby.db, issuer=issuer or self.hab.pre)
        return messagize(event, bonds=[SealSource(s=f'{sn:x}', d=said)], gvrsn=Vrsn_2_0)

    def public(self, registry):
        return bytes(self.hab.replay(gvrsn=Vrsn_2_0)) + b''.join(
            self.evidence(SerderACDC(raw=raw)) for raw in self.rgy.store.cloneTelIter(registry))

    def record(self, raw, *, initial=False):
        if self.args.output:
            with Path(self.args.output).open('xb' if initial else 'ab') as output:
                output.write(raw)

    def send(self, raw, dest, *, topic='credential'):
        """Deliver selected public bytes within this command's finite lifecycle."""
        yield from sending.send(self, raw, dest, topic=topic)

    def run(self, tymth, tock=0.03125, **kwa):
        self.wind(tymth)
        self.tock = tock
        yield tock
        args = self.args
        evidenceSource = evidencing.settings(args)
        if not args.deliver:
            raise ConfigurationError('live native issuance requires explicit --deliver')
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ConfigurationError('--timeout must be finite and positive')
        if args.time:
            raise ConfigurationError('live native issuance uses the native current timestamp')
        if args.output and Path(args.output).exists():
            raise ConfigurationError('output already exists')
        if self.verb == 'grant' and (not args.issue or not args.credential or args.said):
            raise ConfigurationError('native Grant requires --credential and --issue, without legacy --said')
        # Never upgrade an unencrypted store implicitly through a global passcode.
        keeper = Keeper(name=args.name, base=args.base, reopen=True)
        try:
            if not keeper.gbls.get('aeid'):
                raise ConfigurationError('live native issuance requires an encrypted Keeper')
        finally:
            keeper.close()
        self.deadline = self.tyme + args.timeout
        self.hby = setupHby(name=args.name, base=args.base, bran=args.bran, version=Vrsn_2_0)
        self.rgy, notifier, background, xid = None, None, [], None
        try:
            self.hab = self.hby.habByName(args.alias)
            if (self.hab is None or not self.hab.accepted
                    or isinstance(self.hab, (SignifyHab, SignifyGroupHab))
                    or isinstance(self.hab, GroupHab) and self.hab.mhab is None):
                raise ConfigurationError('live native issuance requires an accepted local signer')
            group = isinstance(self.hab, GroupHab)
            coordinator, custodian = getattr(args, 'coordinator', None), getattr(args, 'custodian', None)
            if group:
                event = self.hby.db.evts.get((self.hab.pre, coordinator)) if coordinator else None
                if event is None or not custodian:
                    raise ConfigurationError('group issuance requires --coordinator accepted event SAID and --custodian member AID')
                coordinator = (event.sn, event.said)
                if evidenceSource is not None:
                    raise ConfigurationError('group signed observer queries are outside this issuance profile')
            elif coordinator or custodian:
                raise ConfigurationError('--coordinator and --custodian require a group issuance recipient')
            self.rgy = Regery(hby=self.hby, name=args.name, base=args.base)
            notifier = Notifier(self.hby)
            self.exc = Exchanger(hby=self.hby, handlers=[])
            consent = getattr(args, 'consent_lifetime', None)
            if group and self.verb == 'grant':
                if consent is None or not math.isfinite(consent) or consent <= 0:
                    raise ConfigurationError('group Grant requires finite positive --consent-lifetime seconds')
                # Explicit command policy precedes the first partial Grant intake.
                # Native put-only epsd and configured KRAM remain authoritative.
                self.exc.TimeoutPSE = consent
            elif consent is not None or any(getattr(args, field, None) for field in ('proposal', 'proposal_output')):
                raise ConfigurationError('proposal and consent lifetime options require a group Grant')
            ipexing.loadHandlers(self.hby, self.exc, notifier, rgy=self.rgy)
            self.dh = Dhke(self.hab, self.exc)
            self.hby.rtr.addRoute(Dhke.Route, self.dh)
            kvy = Kevery(db=self.hby.db, rvy=self.hby.rvy, exc=self.exc, qvy=self.dh,
                         lax=True, local=False, direct=False,
                         kramer=Kramer(db=self.hby.db, cf=self.hby.cf))
            mbx = MailboxDirector(hby=self.hby, topics=['/receipt', '/replay', '/credential', '/delegate', '/multisig'],
                exc=self.exc, kvy=kvy, rvy=self.hby.rvy, rgy=self.rgy,
                version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)
            self.psr = mbx.parser
            for filename in args.input:
                self.intake(Path(filename).read_bytes())
            background.append(mbx)
            if group and self.verb == 'grant':
                from .groupissuing import GroupIssuance
                self.extend(background)
                operation = GroupIssuance(self, notifier, coordinator, custodian)
                try:
                    yield from operation.run(background)
                finally:
                    if operation.xid is not None:
                        self.dh.abandon(operation.xid)
                return
            if self.verb == 'grant':
                bodyraw = Path(args.credential).read_bytes()
                body = SerderACDC(raw=bodyraw)
                recp = recipient(self.hby, args.recipient)
                if (body.raw != bodyraw or body.pvrsn != Vrsn_2_0 or not body.verify()
                        or body.ilk not in ('acm', 'act', 'acg') or body.israid != self.hab.pre
                        or body.iseaid != recp or body.regid not in self.rgy.regs):
                    raise ConfigurationError('native public body must exactly match issuer, recipient and local registry')
                registry = self.rgy.regs[body.regid]
                rip = self.rgy.store.headEvent(registry.regk)
                if rip is None or rip.ilk != 'rip':
                    raise ConfigurationError('live issuance requires a fresh accepted registry')
                regeventing.vetAnchor(rip, db=self.hby.db, issuer=self.hab.pre)
                prior, linked = None, {}
                if args.prior:
                    prior = self.hby.db.exns.get((args.prior,))
                    if prior is None or prior.route not in ('/ipex/apply', '/ipex/agree'):
                        raise ConfigurationError('--prior requires an exact accepted native Apply or Agree')
                    prior = NativeNegotiation.prior(self.hby, args.prior, prior.route)
                    if prior.sad['a'].get('ax', [False])[0]:
                        raise ConfigurationError('anchored Agree is outside live individual issuance')
                    linked['apply' if prior.route == '/ipex/apply' else 'agree'] = prior
                auths = witnessAuths(self.hab.kever.wits, authenticate=args.authenticate,
                                    codes=args.code, codeTime=args.code_time)
                message, atc = ipexing.grant(self.hab, recp=recp, message=args.message,
                    origin=body, kind=Kinds.json, gvrsn=Vrsn_2_0, **linked)
                self.intake(message.raw + atc, local=True)
            else:
                message = self.hby.db.epse.get((args.said,))
                if message is None or message.route != '/ipex/grant' or message.sad['ri'] != self.hab.pre:
                    raise ConfigurationError('--said requires the exact pending native Grant for this recipient')
                recp = message.pre
            nests = loadParsedNestedSubstreams(self.hby, message.said)
            if message.sad['a'].get('ax', [False])[0]:
                raise ConfigurationError('anchored Grant is outside live individual issuance')
            if len(nests) != 1:
                raise ConfigurationError('live issuance supports exactly one disclosed registry node')
            xid = self.dh.approve(message.said, coordinator=coordinator, custodian=custodian)
            admission = None
            if group:
                from .groupadmitting import GroupAdmission
                admission = GroupAdmission(self, message, xid, notifier)
            print(json.dumps(dict(grant=message.said, xid=xid, recipient=message.sad['ri'],
                                  phase='selected', registry_issued=False)), flush=True)
            self.extend(background)
            if self.verb == 'grant':
                initial = self.public(registry.regk) + message.raw + atc
                self.record(initial, initial=True)
                yield from self.send(initial, recp)
                yield from self.send(self.dh.start(message.said), recp)
            else:
                tsgs, cigars = verify(self.hby, message)
                self.record(messagize(message, tsgs=tsgs or None, cigars=cigars or None,
                    nests=[bytearray(serializeParsedSubstream(nest)) for nest in nests],
                    gvrsn=Vrsn_2_0), initial=True)
            if admission is not None:
                response = yield from admission.run()
                print(json.dumps(dict(grant=message.said, xid=xid, admit=response.said,
                    registry_issued=True, admitted=True, transmitted=admission.transmitted,
                    contributed=True)), flush=True)
                return
            while True:
                self.check()
                while self.dh.cues:
                    cue = self.dh.cues.popleft()
                    yield from self.send(cue['msg'], cue['dest'])
                if self.dh.complete(xid):
                    break
                yield tock
            print(json.dumps(dict(grant=message.said, xid=xid, phase='dh_complete')), flush=True)
            if self.verb == 'grant':
                _, event = Registrar(self.rgy).issue(registry, acdc=body,
                    salt=self.hab.mgr.getRegistryRoot(self.hab.pre, registry.regk).qb64)
                yield from nativeanchoring.anchor(self, registry, event, auths, background)
                self.finish(xid, message.said)
                print(json.dumps(dict(grant=message.said, xid=xid, phase='registry_witnessed')),
                      flush=True)
                published = self.public(registry.regk)
                self.record(published)
                yield from self.send(published, recp)
                while self.hby.db.erpy.get((message.said,)) is None:
                    self.check()
                    yield tock
                response = self.hby.db.exns.get((self.hby.db.erpy.get((message.said,)).qb64,))
                if response is None or response.route != '/ipex/admit':
                    raise ConfigurationError('selected Grant terminated without Admit')
            else:
                registry = nests[0].serder.regid
                while self.rgy.store.headEvent(registry).ilk == 'rip':
                    self.check()
                    yield tock
                yield from evidencing.acquire(self, [registry], self.dh, xid, evidenceSource)
                self.finish(xid, message.said)
                response, atc = ipexing.admit(self.hab, message=args.message, grant=message,
                                             kind=Kinds.json, gvrsn=Vrsn_2_0)
                self.intake(response.raw + atc, local=True)
                self.record(response.raw + atc)
                yield from self.send(response.raw + atc, recp)
            print(json.dumps(dict(grant=message.said, xid=xid, admit=response.said,
                                  registry_issued=True, admitted=True, transmitted=True)), flush=True)
        finally:
            self.remove(background)
            if xid is not None:
                self.dh.abandon(xid)
            if notifier is not None:
                notifier.noter.close()
            if self.rgy is not None:
                self.rgy.close()
            self.hby.close()
