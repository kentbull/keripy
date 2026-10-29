"""ACDC v2 IPEX command composition using retained exchange evidence and core proofs."""
from contextlib import ExitStack
from dataclasses import asdict, replace
import json
import math
from pathlib import Path
from urllib.parse import urlsplit

import falcon
from hio.base import doing
from hio.core import http

from keri import Vrsn_1_0, Vrsn_2_0, Kinds
from keri.acdc.registraring import Registrar
from keri.acdc import ipexing
from keri.acdc.regeventing import issuerRegistry
from keri.acdc.sectioning import SectionBaser, Sectioner
from keri.app import GroupHab, Notifier
from keri.app.acdc_v2_grouping import AcdcV2GroupCoordinator
from keri.app.credential_disclosing import boundEvent, registryProof
from keri.app.credentialing import Wallet
from keri.app.registry_custody import RegistryCustody
from keri.app.httping import CESR_CONTENT_TYPE, CESR_ATTACHMENT_HEADER
from keri.app.indirecting import createHttpServer
from keri.app.evidencing import EvidenceContext, signedQuery, KEL_DEPENDENCIES
from keri.core import Compactor, Counter, Diger, GenDex, Number, Parser, SerderACDC, Serdery, messagize
from keri.kering import (ConfigurationError, ExtractionError, MissingChainError,
                         MissingSchemaError, ValidationError)
from keri.peer import exchanging
from keri.db import openLMDB
from keri.cli.common import acdc_v2, cesr_sending
from keri.cli.common.public_evidence import ObserverConnection, observerOptions, verifiedRegistryResponse


class Notices:
    """Adapt core notification calls when retained evidence drives CLI results.

    This adapter owns no notification database. Receiving a notification is not
    wallet consent, protocol acceptance, or transport acknowledgement."""
    def add(self, attrs):
        """Ignore transient attrs; CLI decisions read the verified retained EXNs.

        Return None and create no notification store or acceptance side effect."""
        pass


class Peer:
    """Share core proof processors between command intake and explicit admission.

    The caller owns identity, registry, and independent section stores.
    The peer composes verification and escrow processing; it grants no automatic
    wallet consent and does not weaken the ACDC v2 KRAM requirement."""
    def __init__(self, hby, rgy, sections, *, graphPolicy=None):
        """Share section evidence and ACDC v2 IPEX verification policy across intake and admission.

        Args:
            hby (Habery): Authenticated local identity and KEL/EXN evidence.
            rgy (Regery): ACDC v2 registry evidence owner.
            sections (SectionBaser): Independently received section store; caller
                owns closing it, including across CLI invocations/reopen.
            graphPolicy: Optional explicit graph validity/averaging policy.

        Returns:
            None
        """
        self.hby, self.rgy = hby, rgy
        self.evidence = EvidenceContext(hby, reger=rgy.baser)
        self.exc = exchanging.Exchanger(hby, handlers=[])
        self.scy = Sectioner(db=hby.db, sections=sections)
        self.verification = ipexing.loadHandlers(hby, self.exc, Notices(), rgy,
                                                  graphPolicy=graphPolicy, sections=sections)
        self.parser = Parser(kvy=self.evidence.kvy, rgy=self.evidence.rever,
                             exc=self.exc, scy=self.scy, version=Vrsn_2_0, local=False)

    def ingest(self, raw):
        """Process complete CESR-framed ACDC v2 IPEX messages and report EXN acceptance.

        Copy raw before incremental framing so the caller's bytes are unchanged.
        Dispatch through the normal KEL, registry, section, and exchange processors;
        only concrete retained dependency errors remain for escrow retry. Return a
        list of exchange SAIDs with their current core accepted flags. Incomplete
        framing raises ConfigurationError; other proof failures propagate. Neither
        intake nor acceptance records wallet consent or claims delivery."""
        # Independent input streams retain the v2 default; their own GVCs may
        # select another genus without changing the next request's default.
        self.parser.version = Vrsn_2_0
        ims = bytearray(raw)
        grants = []
        while ims:
            size = len(ims)
            dom = self.parser.parseOne(ims=ims, processive=False)
            if dom is None or dom.serder is None or len(ims) >= size:
                raise ConfigurationError('incomplete ACDC v2 IPEX stream')
            if dom.serder.ilk == 'exn':
                grants.append(dom.serder.said)
            try:
                self.parser.msgProcess(asdict(dom), kvy=self.evidence.kvy,
                    rgy=self.evidence.rever, exc=self.exc, scy=self.scy,
                    tvy=None, vry=None, rvy=None)
            except KEL_DEPENDENCIES + (MissingChainError, MissingSchemaError):
                # The concrete core processor retained this exact dependency;
                # unrelated proof or framing failures must still propagate.
                pass
        self.process()
        return [{'exchange': said, 'accepted': self.exc.complete(said)} for said in grants]

    def process(self):
        """Retry the shared KEL, registry, and exchange dependency escrows.

        Return None; core processors determine which retained evidence can advance.
        Scheduling this method does not manufacture observer freshness or admission."""
        self.evidence.kvy.processEscrows()
        self.evidence.rever.processEscrows()
        self.exc.processEscrow()


def options(parser, *, send=False):
    """Add shared ACDC v2 IPEX intake, evidence, group, and delivery arguments.

    parser is mutated in place and returns no result. send additionally exposes
    an explicit HTTP(S)/TCP endpoint. ACDC v2 selection remains opt-in; observer
    synchronization, public file handoff, and group proposals are explicit inputs,
    not switches that disable core verification."""
    acdc_v2.options(parser)
    parser.add_argument('--input', help='receive signed CESR evidence before this operation')
    parser.add_argument('--observer', help='configured ACDC v2 observer URL')
    observerOptions(parser)
    parser.add_argument('--registry', action='append', default=[], help='registry SAID to synchronize from observer')
    parser.add_argument('--output', help='create a CESR message file without overwriting')
    parser.add_argument('--timeout', type=float, default=10.0)
    parser.add_argument('--proposal', help='approve this exact member-signed group IPEX proposal')
    parser.add_argument('--proposal-output', help='write a signed member proposal instead of network fanout')
    if send:
        parser.add_argument('--endpoint', help='recipient HTTP(S) intake URL or tcp://host:port')


class ExchangeDoer(doing.DoDoer):
    """Own one ACDC v2 IPEX action or a long-lived authenticated intake service.

    Keep protocol acceptance, explicit wallet admission, and direct transport
    completion distinct. Open only the capabilities required by the selected
    operation and cancel scheduled child work before their store contexts exit."""
    def __init__(self, args, verb):
        """Retain parsed args and verb and schedule one cooperative operation.

        No stores or sockets open here. run later owns their lifetime and reports
        proof, policy, authentication, timeout, and file errors through the CLI."""
        self.args, self.verb = args, verb
        super().__init__(doers=[doing.doify(self.run)])

    def request(self, url, body, *, cafilepath=None, certedhost=None, redirectable=True):
        """Yield through bounded direct delivery of exact CESR body bytes to url.

        Use this command's timeout and child ownership. Return the checked HTTP
        response or a TCP send-buffer marker; neither is authenticated receiver
        acceptance. Network, timeout, and invalid-endpoint errors propagate after
        shared transport cleanup."""
        return (yield from cesr_sending.send(self, url, body, self.args.timeout,
            cafilepath=cafilepath, certedhost=certedhost, redirectable=redirectable))

    def run(self, tymth, tock=0.03125, **kwa):
        """Execute one IPEX verb or serve intake with explicit capability owners.

        ``tymth`` and ``tock`` drive cooperative scheduling. Retained holder
        presentations and issuer grants need no custody unless --derive explicitly
        selects it. All child work is cancelled before stores close.
        Verification failures propagate without recording consent or delivery.
        """
        self.wind(tymth)
        self.tock = tock
        yield tock
        args = self.args
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ConfigurationError('--timeout must be positive and finite')
        policy = ObserverConnection.fromArgs(args, args.observer if args.registry else None)
        derives = getattr(args, 'derive', False)
        with (acdc_v2.openedRegistry(args) as (hby, rgy),
              openLMDB(cls=SectionBaser, name=args.name, base=args.base, temp=False) as sections,
              ExitStack() as activity):
            hab = hby.habByName(args.alias)
            if hab is None:
                raise ConfigurationError('unknown ACDC v2 IPEX alias')
            peer = Peer(hby, rgy, sections)
            custody = RegistryCustody(hby, rgy) if derives else None
            # Only authoring from a locally issued credential needs Reger.
            # Receive, negotiation, admission, retained presentation and proposal
            # approval use the peer's existing exchange evidence directly.
            wallet = None
            if self.verb in ('grant', 'offer') and not args.from_grant and not args.proposal:
                wallet = Wallet(hby, rgy, verification=peer.verification)
                activity.callback(wallet.close)
            # This command owns KRAM maintenance, including when a group shares
            # the peer's Kramer. Stop child work before the stores leave scope.
            self.extend([peer.evidence])
            activity.callback(self.remove, [peer.evidence])
            if getattr(args, 'refresh', False) and not args.from_grant:
                raise ConfigurationError('--refresh requires an admitted --from-grant')
            if (getattr(args, 'opening', []) or getattr(args, 'derive', False)) and args.from_grant and not args.refresh:
                raise ConfigurationError('new openings for a held grant require --refresh')
            group = None
            if isinstance(hab, GroupHab):
                # Group proposal/mailbox intake resolves the same schema evidence
                # as the peer's verifier without expanding retained disclosures.
                group = AcdcV2GroupCoordinator(hby, rgy, hab, peer.exc, Notifier(hby=hby),
                                    kramer=peer.evidence.kvy.kramer, scy=peer.scy)
                self.extend([group])
                activity.callback(self.remove, [group])
            elif args.proposal or args.proposal_output:
                raise ConfigurationError('group proposal options require a GroupHab alias')
            if args.input:
                peer.ingest(Path(args.input).read_bytes())
            for regid in args.registry:
                if not args.observer:
                    raise ConfigurationError('--registry synchronization requires --observer')
                if urlsplit(args.observer).scheme not in ('http', 'https'):
                    raise ConfigurationError('observer queries require an HTTP(S) endpoint')
                response = yield from self.request(args.observer, signedQuery(hab, 'tels', {'i': regid}),
                                                   **policy.clientOptions())
                head = verifiedRegistryResponse(peer.evidence, regid, response)
                peer.process()
            if self.verb == 'receive':
                app = falcon.App()
                intake = Intake(peer)
                app.add_route('/ingest', intake)
                app.add_route('/', intake)
                server = createHttpServer(args.host, args.port, app)
                owner = http.ServerDoer(server=server)
                self.extend([owner])
                try:
                    while True:
                        peer.process()
                        yield tock
                finally:
                    self.remove([owner])
                    server.close()
            elif args.proposal:
                raw = group.exchangeProposal(Path(args.proposal).read_bytes())
                proposed = Parser(version=Vrsn_2_0).parseOne(ims=bytearray(raw), processive=False)
                exn = proposed.serder
                self.checkProposal(exn, args)
            elif self.verb in ('grant', 'offer'):
                held = None
                if args.from_grant:
                    held = peer.verification.heldCredential(args.from_grant)
                    credential = held['credential']
                    artifacts = held['artifacts']
                else:
                    credential = Registrar(wallet.rgy).issuedCredential(wallet.reger, args.said)
                    artifacts = []
                if args.disclose:
                    if not isinstance(credential.sad.get('a'), dict):
                        raise ConfigurationError('attribute partial disclosure requires an expanded map')
                    block = Compactor(mad=dict(credential.sad['a']), makify=True, kind=credential.kind)
                    block.compact(paths=args.disclose, root='a')
                    partial = block.partials[tuple(args.disclose)].mad
                    sad = dict(credential.sad, a=dict(partial))
                    disclosed = SerderACDC(sad=sad, kind=credential.kind, makify=True)
                    if disclosed.said != credential.said:
                        raise ConfigurationError('disclosure changed the credential commitment')
                    credential = disclosed
                bonds = []
                if self.verb == 'offer':
                    origin = credential
                elif held is not None and not args.refresh:
                    # Reuse only the admitted grant's retained proof and view.
                    # Fuller cached sections must not enrich this disclosure.
                    if args.bound_event:
                        raise ConfigurationError('--bound-event requires --refresh for a held grant')
                    nodes = exchanging.loadParsedNestedSubstreams(hby, args.from_grant)
                    node = next(item for item in nodes if item.serder.said == credential.said)
                    origin = exchanging.serializeParsedSubstream(replace(node, serder=credential))
                elif held is not None:
                    nodes = exchanging.loadParsedNestedSubstreams(hby, args.from_grant)
                    node = next(item for item in nodes if item.serder.said == credential.said)
                    regid = issuerRegistry(credential)
                    if regid is None:
                        candidates = {prefix.qb64 for prefix, _, _ in node.ssts
                                      if rgy.store.seqEvent(prefix.qb64, 0) is not None}
                        if len(candidates) != 1:
                            raise ConfigurationError('held disclosure has no unique issuer registry reference')
                        regid = candidates.pop()
                    origin = self.registryOrigin(hby, rgy, credential, regid, custody=custody,
                        retained=peer.exc.routes['/ipex/grant']._blindProofs(node))
                elif regid := (issuerRegistry(credential) or
                               Registrar(wallet.rgy).issuedRecord(wallet.reger, credential.said).registry):
                    origin = self.registryOrigin(hby, rgy, credential, regid, custody=custody,
                        issued=Registrar(wallet.rgy).issuedRecord(wallet.reger, credential.said))
                else:
                    if credential.israid != hab.pre:
                        raise ConfigurationError('credential issuer proof is unavailable')
                    origin = messagize(credential, tsgs=[(hab.kever.prefixer,
                        Number(num=hab.kever.lastEst.s), Diger(qb64=hab.kever.lastEst.d),
                        hab.sign(credential.raw))], gvrsn=Vrsn_2_0)
                prior = self.prior(peer, args.prior) if args.prior else None
                if self.verb == 'offer':
                    exn, attachment = ipexing.offer(hab, args.message, origin=origin,
                        apply=prior, recp=args.recipient, dt=args.time,
                        modifiers={'dp': acdc_v2.load(args.plan)} if args.plan else None)
                else:
                    kwargs = {}
                    if prior is not None:
                        if prior.route not in ('/ipex/apply', '/ipex/agree'):
                            raise ConfigurationError('grant prior must be apply or agree')
                        kwargs[prior.route.rsplit('/', 1)[1]] = prior
                    if peer.verification.evaluateSelected(origin, artifacts) is not True:
                        raise ConfigurationError('credential graph is false or unresolved')
                    exn, attachment = ipexing.grant(hab, args.recipient, args.message,
                        origin=origin, artifacts=artifacts, dt=args.time, **kwargs)
            elif self.verb == 'apply':
                exn, attachment = ipexing.apply(hab, args.recipient, args.message,
                    modifiers={'dp': acdc_v2.load(args.plan)}, dt=args.time)
            elif self.verb in ('agree', 'spurn'):
                prior = self.prior(peer, args.said)
                if self.verb == 'agree':
                    exn, attachment = ipexing.agree(hab, args.message, prior, dt=args.time)
                else:
                    exn, attachment = ipexing.spurn(hab, args.message, prior, dt=args.time)
            elif self.verb == 'admit':
                grant = hby.db.exns.get((args.said,))
                if grant is None or not peer.exc.routes['/ipex/grant'].verifyAccepted(args.said):
                    raise ConfigurationError('grant has not passed ACDC v2 IPEX verification')
                if peer.verification.evaluateGrant(args.said) is not True:
                    raise ConfigurationError('credential graph is false or unresolved')
                exn, attachment = ipexing.admit(hab, args.message, grant, dt=args.time)
            else:
                raise ConfigurationError('unsupported ACDC v2 IPEX operation')
            if not args.proposal:
                raw = bytes(exn.raw + attachment)
            if group is not None:
                wrapper, attachments = group.approveExchange(raw)
                if args.proposal_output:
                    with Path(args.proposal_output).open('xb') as stream:
                        stream.write(bytes(hab.mhab.replay(gvrsn=Vrsn_2_0)) +
                                     bytes(hab.replay(gvrsn=Vrsn_2_0)) + wrapper.raw + attachments)
                else:
                    group.send(wrapper, attachments)
                deadline = self.tyme + args.timeout
                while not group.completeExchange(exn.said):
                    if self.tyme >= deadline:
                        raise TimeoutError(f'ACDC v2 group exchange {exn.said} is pending member approval or evidence')
                    group.process()
                    yield tock
                # Reconstruct the accepted threshold proof, including all
                # authenticated member signatures retained by Exchanger.
                raw = bytes(exchanging.serializeMessage(hby, exn.said))
            else:
                peer.ingest(raw)
            if not peer.exc.complete(exn.said):
                raise ConfigurationError('locally authored IPEX message is pending verification')
            # Group threshold/receipt waits do not preserve an earlier use verdict.
            if self.verb == 'grant' and exn.sad['a'].get('o'):
                if peer.verification.evaluateGrant(exn.said) is not True:
                    raise ConfigurationError('credential graph is false or unresolved')
            elif self.verb == 'admit':
                if peer.verification.evaluateGrant(exn.sad['p']) is not True:
                    raise ConfigurationError('credential graph is false or unresolved')
            if self.verb == 'admit':
                peer.verification.validateAdmission(args.said, exn.said, consent=True)
            if args.output:
                with Path(args.output).open('xb') as stream:
                    stream.write(bytes(hab.replay(gvrsn=Vrsn_2_0)) + raw)
            delivered = False
            if getattr(args, 'endpoint', None):
                yield from self.request(args.endpoint, bytes(hab.replay(gvrsn=Vrsn_2_0)) + raw)
                delivered = True
            print(json.dumps(dict(exchange=exn.said, accepted=True, transmitted=delivered,
                                  admitted=self.verb == 'admit')))

    def registryOrigin(self, hby, rgy, credential, regid, *, retained=(), custody=None, issued=None):
        """Return the credential stream with exact verified registry opening evidence.

        hby supplies accepted KEL evidence, rgy the accepted public TEL,
        credential the unchanged retained disclosure, and regid its issuer registry.
        custody optionally derives openings; issued optionally supplies the exact
        original issuer-bound coordinates. Held views need no issuer storage.
        retained contains received Blinders; --opening files add event-specific CESR
        Blinders, never salts. Only explicitly supplied custody derives missing openings.
        Walk from the accepted head through vacuous updates to the disclosed binding;
        common vetBlind/vetBound checks bind every opening before it is attached.
        An omitted issuer registry gets the exact binding event reference. Public
        updates use an explicitly empty foot, with no invented BLID. Return bytes;
        missing/conflicting capability or evidence raises ConfigurationError, while
        core opening/bound-proof failures and file errors propagate."""
        retained = list(retained)
        for path in getattr(self.args, 'opening', []):
            retained.append(acdc_v2.loadOpening(path))
        explicit = (boundEvent(hby, credential, self.args.bound_event)
                    if self.args.bound_event else {})

        def derive(update, target, state):
            """Apply the selected custody's existing bound coordinates to this event."""
            parameters = explicit
            if not parameters and issued is not None and issued.update == update.said and issued.bound:
                parameters = dict(bound=True, bsn=issued.bound['bn'], bd=issued.bound['bd'])
            if parameters and not target:
                parameters = dict(bound=True, bsn=0, bd='')
            return custody.derive(regid, update.sn, target, state, **parameters)

        return registryProof(hby, rgy, credential, regid, retained=retained,
                             derive=derive if custody is not None else None)

    def checkProposal(self, exn, args):
        """Refuse a group proposal that contradicts the explicit command selection.

        exn is the parsed proposed body and args supplies requested verb, recipient,
        credential/prior, disclosure plan, message, and timestamp. Return None when
        those supplied constraints match; raise ConfigurationError on mismatch or
        on disclosure-generation options that would rewrite the approved body.
        Threshold authentication and final acceptance remain the group's job."""
        if exn.route != '/ipex/' + self.verb:
            raise ConfigurationError('group proposal has a different IPEX operation')
        if getattr(args, 'recipient', None) and exn.sad['ri'] != args.recipient:
            raise ConfigurationError('group proposal has a different recipient')
        if self.verb in ('grant', 'offer') and exn.sad['a'].get('o') != [args.said]:
            raise ConfigurationError('group proposal has a different credential')
        prior = args.said if self.verb in ('agree', 'admit', 'spurn') else getattr(args, 'prior', None)
        if prior and exn.sad.get('p') != prior:
            raise ConfigurationError('group proposal has a different prior exchange')
        if getattr(args, 'plan', None) and exn.sad.get('q', {}).get('dp') != acdc_v2.load(args.plan):
            raise ConfigurationError('group proposal has a different disclosure plan')
        if args.message and exn.sad['a'].get('m') != args.message:
            raise ConfigurationError('group proposal has a different message')
        if args.time and exn.sad['dt'] != args.time:
            raise ConfigurationError('group proposal has a different timestamp')
        if (getattr(args, 'disclose', None) or getattr(args, 'from_grant', None)
                or getattr(args, 'bound_event', None)):
            raise ConfigurationError('proposal approval uses its exact disclosure; do not supply disclosure-generation options')

    @staticmethod
    def prior(peer, said):
        """Return a retained prior only after core route-specific revalidation.

        peer supplies its accepted EXNs and configured ACDC v2 IPEX handlers; said selects
        the exact prior. Missing acceptance, unknown routes, or failed semantic proof
        raise ConfigurationError. This lookup does not imply wallet admission."""
        message = peer.hby.db.exns.get((said,))
        if message is None or not peer.exc.complete(said):
            raise ConfigurationError('prior IPEX message is not accepted')
        handler = peer.exc.routes.get(message.route)
        if handler is None or not handler.verifyAccepted(said):
            raise ConfigurationError('prior IPEX message failed semantic verification')
        return message


class Intake:
    """Expose raw or detached-header CESR intake without changing signed bodies or granting consent."""
    def __init__(self, peer):
        """Retain the peer whose core processors own this endpoint's evidence.

        No separate parser, identity, or store is created by the HTTP adapter."""
        self.peer = peer

    @staticmethod
    def decode(raw, attachment, genus):
        """Reattach exact header bytes with their declared or body-metadata genus.

        Header form requires one bare serialized body. Full streams retain
        their original bytes and the peer's v2 default; their explicit GVCs
        remain authoritative within the stream. No JSON is reserialized."""
        if attachment is None and genus is None:
            return raw
        first = None
        if attachment is not None:
            remaining = bytearray(raw)
            first = Serdery().reap(ims=remaining, genus=GenDex.KERI, svrsn=Vrsn_2_0)
            if remaining:
                raise ValidationError('attachment-header body must contain exactly one message')
            raw += attachment.encode('ascii')
        selected = genus if genus is not None else str((first.gvrsn or first.pvrsn).major)
        if selected not in ('1', '2'):
            raise ValidationError('CESR-Genus must be 1 or 2')
        return Counter.makeGVC(Vrsn_1_0 if selected == '1' else Vrsn_2_0) + raw

    def on_post(self, req, rep):
        """Dispatch the request's bounded CESR bytes and return intake status 202.

        req and rep are Falcon request/response objects. Require application/cesr
        or raise HTTPUnsupportedMediaType; malformed detached-header framing
        raises HTTPBadRequest and core proof errors propagate through the
        framework. The JSON lists core exchange acceptance, not wallet consent
        or recipient delivery, and this adapter records no admission itself."""
        if (req.content_type or '').split(';')[0] != CESR_CONTENT_TYPE:
            raise falcon.HTTPUnsupportedMediaType()
        try:
            raw = self.decode(req.bounded_stream.read(), req.get_header(CESR_ATTACHMENT_HEADER),
                              req.get_header('CESR-Genus'))
        except (ExtractionError, ValidationError, ValueError) as error:
            raise falcon.HTTPBadRequest(description=str(error)) from error
        rep.media = self.peer.ingest(raw)
        rep.status = falcon.HTTP_202

    # StreamPoster uses PUT at the recipient endpoint root. Both methods enter
    # the same ACDC v2 verifier and neither implies wallet admission.
    on_put = on_post
