"""Native IPEX command composition using retained wallet views and core proofs."""
from contextlib import ExitStack
from dataclasses import asdict, replace
import json
import math
from pathlib import Path
from urllib.parse import urlsplit

import falcon
from hio.base import doing
from hio.core import http

from keri import Vrsn_2_0, Kinds
from keri.acdc import ipexing
from keri.acdc.regeventing import issuerRegistry
from keri.acdc.sectioning import SectionBaser, Sectioner
from keri.app import GroupHab, Notifier
from keri.app.native_grouping import NativeGroup
from keri.app.httping import CESR_CONTENT_TYPE
from keri.app.indirecting import createHttpServer
from keri.app.registrar.serving import Context as EvidenceContext, signedQuery, KEL_DEPENDENCIES
from keri.core import Codens, Compactor, Counter, Diger, Number, Parser, SealEvent, SerderACDC, messagize
from keri.kering import ConfigurationError, MissingChainError, MissingSchemaError
from keri.peer import exchanging
from keri.db import openLMDB
from keri.cli.common import native


class Notices:
    def add(self, attrs):
        pass


class Peer:
    def __init__(self, hby, rgy, wallet, sections, *, graphPolicy=None):
        """Share section evidence and native policy across intake and admission.

        Args:
            hby (Habery): Authenticated local identity and KEL/EXN evidence.
            rgy (Regery): Native registry evidence owner.
            wallet (Wallet): Inventory owner configured to use this peer's context.
            sections (SectionBaser): Independently received section store; caller
                owns closing it, including across CLI invocations/reopen.
            graphPolicy: Optional explicit graph validity/averaging policy.

        Returns:
            None
        """
        self.hby, self.rgy, self.wallet = hby, rgy, wallet
        self.evidence = EvidenceContext(hby, reger=rgy.baser)
        self.exc = exchanging.Exchanger(hby, handlers=[])
        self.scy = Sectioner(db=hby.db, sections=sections)
        wallet.verification = ipexing.loadHandlers(hby, self.exc, Notices(), rgy,
                                                  graphPolicy=graphPolicy, sections=sections)
        wallet.exc = self.exc
        self.parser = Parser(kvy=self.evidence.kvy, rgy=self.evidence.rever,
                             exc=self.exc, scy=self.scy, version=Vrsn_2_0, local=False)

    def ingest(self, raw):
        ims = bytearray(raw)
        grants = []
        while ims:
            size = len(ims)
            dom = self.parser.parseOne(ims=ims, processive=False)
            if dom is None or dom.serder is None or len(ims) >= size:
                raise ConfigurationError('incomplete native IPEX stream')
            if dom.serder.ilk == 'exn':
                grants.append(dom.serder.said)
            try:
                self.parser.msgProcess(asdict(dom), kvy=self.evidence.kvy,
                    rgy=self.evidence.rever, exc=self.exc, scy=self.scy,
                    tvy=None, vry=None, rvy=None)
            except KEL_DEPENDENCIES + (MissingChainError, MissingSchemaError):
                pass
        self.process()
        return [{'exchange': said, 'accepted': self.exc.complete(said)} for said in grants]

    def process(self):
        self.evidence.kvy.processEscrows()
        self.evidence.rever.processEscrows()
        self.exc.processEscrow()


def options(parser, *, send=False):
    native.options(parser)
    parser.add_argument('--input', help='receive signed CESR evidence before this operation')
    parser.add_argument('--observer', help='configured native observer URL')
    parser.add_argument('--registry', action='append', default=[], help='registry SAID to synchronize from observer')
    parser.add_argument('--output', help='create a CESR message file without overwriting')
    parser.add_argument('--timeout', type=float, default=10.0)
    parser.add_argument('--proposal', help='approve this exact member-signed group IPEX proposal')
    parser.add_argument('--proposal-output', help='write a signed member proposal instead of network fanout')
    if send:
        parser.add_argument('--endpoint', help='recipient CESR intake URL')


class ExchangeDoer(doing.DoDoer):
    def __init__(self, args, verb):
        self.args, self.verb = args, verb
        super().__init__(doers=[doing.doify(self.run)])

    def request(self, url, body):
        target = urlsplit(url)
        if target.scheme not in ('http', 'https') or not target.hostname:
            raise ConfigurationError('an HTTP(S) endpoint is required')
        client = http.clienting.Client(scheme=target.scheme, hostname=target.hostname,
            port=target.port or (443 if target.scheme == 'https' else 80))
        owner = http.clienting.ClientDoer(client=client)
        self.extend([owner])
        try:
            client.request(method='POST', path=target.path or '/', body=body,
                           headers={'Content-Type': CESR_CONTENT_TYPE})
            deadline = self.tyme + self.args.timeout
            while not client.responses and self.tyme < deadline:
                yield self.tock
            if not client.responses:
                raise TimeoutError('native IPEX HTTP request timed out')
            response = client.responses.popleft()
            if not 200 <= response['status'] < 300:
                raise ConfigurationError(f"native IPEX HTTP status {response['status']}")
            return response
        finally:
            self.remove([owner])
            client.close()

    def run(self, tymth, tock=0.03125, **kwa):
        self.wind(tymth)
        self.tock = tock
        yield tock
        args = self.args
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ConfigurationError('--timeout must be positive and finite')
        with (native.opened(args) as (hby, rgy, wallet),
              openLMDB(cls=SectionBaser, name=args.name, base=args.base, temp=False) as sections,
              ExitStack() as activity):
            hab = hby.habByName(args.alias)
            if hab is None:
                raise ConfigurationError('unknown native IPEX alias')
            peer = Peer(hby, rgy, wallet, sections)
            # This command owns KRAM maintenance, including when a group shares
            # the peer's Kramer. Stop child work before the stores leave scope.
            self.extend([peer.evidence])
            activity.callback(self.remove, [peer.evidence])
            if getattr(args, 'refresh', False) and not args.from_grant:
                raise ConfigurationError('--refresh requires an admitted --from-grant')
            group = None
            if isinstance(hab, GroupHab):
                # Group proposal/mailbox intake resolves the same schema evidence
                # as the peer's verifier without expanding retained disclosures.
                group = NativeGroup(hby, rgy, hab, peer.exc, Notifier(hby=hby),
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
                response = yield from self.request(args.observer, signedQuery(hab, 'tels', {'i': regid}))
                if response.get('headers', {}).get('observer-evidence-state') != 'fresh':
                    raise ConfigurationError('observer has no fresh evidence')
                result = peer.evidence.ingest(response['body'])
                if result['pending'] or result['rejected']:
                    raise ConfigurationError('observer evidence is incomplete or invalid')
                peer.process()
            if self.verb == 'receive':
                app = falcon.App()
                app.add_route('/ingest', Intake(peer))
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
                    held = wallet.heldCredential(args.from_grant)
                    credential = held['credential']
                    artifacts = held['artifacts']
                else:
                    credential = wallet.issuedCredential(args.said)
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
                    origin = self.registryOrigin(wallet, rgy, credential, regid,
                        retained=peer.exc.routes['/ipex/grant']._blindProofs(node))
                elif regid := (issuerRegistry(credential) or
                               wallet.db.issued.get((credential.said,)).registry):
                    origin = self.registryOrigin(wallet, rgy, credential, regid)
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
                        modifiers={'dp': native.load(args.plan)} if args.plan else None)
                else:
                    kwargs = {}
                    if prior is not None:
                        if prior.route not in ('/ipex/apply', '/ipex/agree'):
                            raise ConfigurationError('grant prior must be apply or agree')
                        kwargs[prior.route.rsplit('/', 1)[1]] = prior
                    exn, attachment = ipexing.grant(hab, args.recipient, args.message,
                        origin=origin, artifacts=artifacts, dt=args.time, **kwargs)
            elif self.verb == 'apply':
                exn, attachment = ipexing.apply(hab, args.recipient, args.message,
                    modifiers={'dp': native.load(args.plan)}, dt=args.time)
            elif self.verb in ('agree', 'spurn'):
                prior = self.prior(peer, args.said)
                if self.verb == 'agree':
                    exn, attachment = ipexing.agree(hab, args.message, prior, dt=args.time)
                else:
                    exn, attachment = ipexing.spurn(hab, args.message, prior, dt=args.time)
            elif self.verb == 'admit':
                grant = hby.db.exns.get((args.said,))
                if grant is None or not peer.exc.routes['/ipex/grant'].verifyAccepted(args.said):
                    raise ConfigurationError('grant has not passed native IPEX verification')
                exn, attachment = ipexing.admit(hab, args.message, grant, dt=args.time)
            else:
                raise ConfigurationError('unsupported native IPEX operation')
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
                        raise TimeoutError(f'native group exchange {exn.said} is pending member approval or evidence')
                    group.process()
                    yield tock
                # Reconstruct the accepted threshold proof, including all
                # authenticated member signatures retained by Exchanger.
                raw = bytes(exchanging.serializeMessage(hby, exn.said))
            else:
                peer.ingest(raw)
            if not peer.exc.complete(exn.said):
                raise ConfigurationError('locally authored IPEX message is pending verification')
            if self.verb == 'admit':
                wallet.recordAdmission(args.said, exn.said, consent=True)
            if args.output:
                with Path(args.output).open('xb') as stream:
                    stream.write(bytes(hab.replay(gvrsn=Vrsn_2_0)) + raw)
            delivered = False
            if getattr(args, 'endpoint', None):
                yield from self.request(args.endpoint, bytes(hab.replay(gvrsn=Vrsn_2_0)) + raw)
                delivered = True
            print(json.dumps(dict(exchange=exn.said, accepted=True, transmitted=delivered,
                                  admitted=self.verb == 'admit')))

    def registryOrigin(self, wallet, rgy, credential, regid, *, retained=()):
        """Open the known current history without changing the received ACDC view."""
        head = rgy.store.headEvent(regid)
        if head is None:
            raise ConfigurationError('registry evidence has not been acquired')
        explicit = (wallet.boundEvent(credential, self.args.bound_event)
                    if self.args.bound_event else {})
        issued = wallet.db.issued.get((credential.said,))
        bonds = []
        binding = None
        for ordinal in range(Number(numh=head.sad['n']).num, 0, -1):
            update = rgy.store.seqEvent(regid, ordinal)
            if update.ilk == 'upd':
                if update.sad['td']:
                    binding = update
                    break
                continue
            found = next((proof for proof in retained if proof.said == update.sad['b']), None)
            parameters = explicit
            if not parameters and issued is not None and issued.update == update.said and issued.bound:
                parameters = dict(bound=True, bsn=issued.bound['bn'], bd=issued.bound['bd'])
            if found is None:
                for target, state in ((credential.said, 'issued'), (credential.said, 'revoked'), ('', '')):
                    # A bound vacuous update has its specified empty coordinates.
                    args = (dict(bound=True, bsn=0, bd='') if parameters and not target
                            else parameters)
                    proof = wallet.derive(regid, ordinal, target, state, **args)
                    if proof.said == update.sad['b']:
                        found = proof
                        break
            if found is None:
                raise ConfigurationError('custody and explicit bound reference cannot open the current registry history')
            bonds.append(found.data)
            if found.acdc:
                binding = update
                break
        if binding is None:
            raise ConfigurationError('registry has no disclosed non-vacuous credential binding')
        if issuerRegistry(credential) is None:
            bonds.append(SealEvent(i=regid, s=binding.sad['n'], d=binding.said))
        # Mutual public updates authenticate through the declared registry;
        # their credential foot is explicitly empty, with no invented BLID.
        return (messagize(credential, bonds=bonds, gvrsn=Vrsn_2_0) if bonds else
                credential.raw + Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b)

    def checkProposal(self, exn, args):
        """Keep explicit CLI intent tied to the exact body being approved."""
        if exn.route != '/ipex/' + self.verb:
            raise ConfigurationError('group proposal has a different IPEX operation')
        if getattr(args, 'recipient', None) and exn.sad['ri'] != args.recipient:
            raise ConfigurationError('group proposal has a different recipient')
        if self.verb in ('grant', 'offer') and exn.sad['a'].get('o') != [args.said]:
            raise ConfigurationError('group proposal has a different credential')
        prior = args.said if self.verb in ('agree', 'admit', 'spurn') else getattr(args, 'prior', None)
        if prior and exn.sad.get('p') != prior:
            raise ConfigurationError('group proposal has a different prior exchange')
        if getattr(args, 'plan', None) and exn.sad.get('q', {}).get('dp') != native.load(args.plan):
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
        message = peer.hby.db.exns.get((said,))
        if message is None or not peer.exc.complete(said):
            raise ConfigurationError('prior IPEX message is not accepted')
        handler = peer.exc.routes.get(message.route)
        if handler is None or not handler.verifyAccepted(said):
            raise ConfigurationError('prior IPEX message failed semantic verification')
        return message


class Intake:
    def __init__(self, peer):
        self.peer = peer

    def on_post(self, req, rep):
        if (req.content_type or '').split(';')[0] != CESR_CONTENT_TYPE:
            raise falcon.HTTPUnsupportedMediaType()
        rep.media = self.peer.ingest(req.bounded_stream.read())
        rep.status = falcon.HTTP_202
