"""KLI composition for the experimental registry-salt reply capability.

The service owns authorization; this adapter selects explicit operator actions,
existing processors, and their bounded HIO lifetime. It never copies plaintext
roots to files or infers consent from an incoming request. Public proof imports
retain the normal KEL/TEL/reply and KRAM checks.
"""
from contextlib import ExitStack
from dataclasses import asdict
import json
import math
from pathlib import Path

import falcon
from hio.base import doing
from hio.core import http

from ... import Vrsn_2_0
from ...acdc.regeventing import Rever
from ...app import GroupHab, HaberyDoer, MailboxDirector, Notifier
from ...app.essring import EssrReplyHandler
from ...app.evidencing import KEL_DEPENDENCIES, ServiceConfig
from ...app.forwarding import StreamPoster
from ...app.grouping import Multiplexor, loadHandlers
from ...app.indirecting import createHttpServer
from ...app.registry_salt_service import RegistrySaltService, ROUTES
from ...app.registry_salt_state import RegistrySaltState
from ...core import Kramer, Parser, Pruner
from ...kering import ConfigurationError, MissingEntryError, UnverifiedReplyError
from ...peer import Exchanger
from . import acdc_v2, cesr_sending
from .acdc_v2_ipex import Intake
from .public_evidence import write


class SaltPeer:
    """Borrow stores and share one live processor set across file/mailbox/HTTP intake."""

    def __init__(self, hby, rgy, wallet, hab, notifier):
        """Compose the selected local member's optional salt service.

        Args: hby/rgy/wallet are caller-owned open stores, hab is the selected
            logical local habitat, notifier is the ordinary persistent notifier.
        Returns: an unscheduled peer. Its pruner and process method must run for
            the listener lifetime. No root is read or generated on construction.
        """
        self.hby, self.hab, self.rgy = hby, hab, rgy
        self.member = hab.mhab if isinstance(hab, GroupHab) else hab
        self.exc = Exchanger(hby, handlers=[])
        self.rever = Rever(db=hby.db, reger=rgy.baser)
        self.mux = Multiplexor(hby, notifier, exc=self.exc, rgy=self.rever)
        self.mux.kvy.kramer = Kramer(db=hby.db, cf=ServiceConfig(), cues=self.mux.kvy.cues)
        hby.kvy.kramer = self.mux.kvy.kramer
        self.pruner = Pruner(self.mux.kvy.kramer, tock=1.0)
        self.parser = Parser(kvy=self.mux.kvy, rvy=self.mux.rvy, rgy=self.rever,
                             exc=self.exc, version=Vrsn_2_0, local=False)
        loadHandlers(self.exc, self.mux)
        self.state = RegistrySaltState(wallet.custody)
        self.service = RegistrySaltService(hby, rgy, wallet, wallet.custody,
            self.state, self.parser, self.mux.rvy, exc=self.exc, mux=self.mux)
        self.service.register()
        self.exc.addHandler(EssrReplyHandler(hby, self.member, self.parser, ROUTES))

    def ingest(self, raw):
        """Verify complete CESR frames without treating transport intake as custody.

        Args: raw contains public evidence, signed replies or sealed envelopes.
        Returns: parsed message identities and routes, without acceptance claims.
        Raises: ConfigurationError for incomplete framing; authentication errors
            propagate unless the concrete processor retained a known dependency.
        """
        self.parser.version = Vrsn_2_0
        remaining, seen = bytearray(raw), []
        while remaining:
            size = len(remaining)
            parsed = self.parser.parseOne(ims=remaining, processive=False)
            if parsed is None or parsed.serder is None or len(remaining) >= size:
                raise ConfigurationError('registry-salt intake requires complete CESR frames')
            try:
                self.parser.msgProcess(asdict(parsed), kvy=self.mux.kvy,
                    rvy=self.mux.rvy, rgy=self.rever, exc=self.exc, tvy=None, vry=None)
            except KEL_DEPENDENCIES + (UnverifiedReplyError,):
                pass  # ordinary processors retain these exact dependencies
            seen.append(dict(said=parsed.serder.said, ilk=parsed.serder.ilk))
        self.process()
        return seen

    def process(self):
        """Advance existing escrows and accepted salt work without granting approval."""
        self.mux.kvy.processEscrows()
        self.rever.processEscrows()
        self.exc.processEscrow()
        self.service.process()

    def trust(self, path):
        """Validate an explicit operator roster file against accepted local history.

        path names a JSON object mapping logical AID to ordered member-AID list.
        This is local configuration, never a membership assertion from the wire.
        Returns None; invalid input/history raises before any local approval.
        """
        if path is None:
            return
        rosters = json.loads(Path(path).read_text())
        if not isinstance(rosters, dict):
            raise ConfigurationError('--rosters requires a logical-AID to ordered-member-list map')
        for party, members in rosters.items():
            self.service.trustRoster(party, members)


def command(args):
    """Return one caller-scheduled KLI action; perform no I/O while parsing args."""
    return [SaltDoer(args)]


class SaltDoer(doing.DoDoer):
    """Own one command's open stores, finite deliveries and optional listener."""

    def __init__(self, args):
        """Retain parsed operator arguments; defer stores and sockets until scheduled."""
        self.args = args
        super().__init__(doers=[doing.doify(self.run)])

    def _require(self, *names):
        """Reject missing action inputs before generating or endorsing any statement."""
        if any(getattr(self.args, name) is None for name in names):
            raise ConfigurationError('registry-salt operation is missing required named arguments: ' + ', '.join(names))

    def _body(self, peer):
        """Select one explicit service action and its exact unsigned body.

        peer supplies authenticated domain state. Returns (body, proposal SAID).
        This operator path is consent; network intake never invokes it.
        """
        args, service = self.args, peer.service
        match args.operation:
            case 'init':
                self._require('issuer', 'discloser')
                body = service.prepareInit(issuer=args.issuer, discloser=args.discloser,
                    party=peer.hab.pre, representative=peer.member.pre)
            case 'bind':
                self._require('init', 'registry')
                body = service.prepareBind(args.init, args.registry, peer.member.pre)
            case 'confirm':
                self._require('init', 'bind')
                body = service.prepareConfirm(args.init, args.bind)
            case 'assign':
                self._require('origin', 'party')
                body = service.prepareAssign(args.origin, args.party)
            case 'resume':
                self._require('init')
                body = service.resume(args.init, peer.member.pre)
            case 'approve':
                self._require('proposal')
                body = service.inspectProposal(args.proposal)
            case _:
                raise ConfigurationError('registry-salt operation does not author a reply')
        if body.pre != peer.hab.pre:
            raise ConfigurationError('registry-salt reply belongs to a different logical alias')
        return body, args.proposal if args.operation == 'approve' else None

    def _fanout(self, peer, outbound):
        """Start existing finite group delivery and return only owned child doers."""
        if outbound.proposal is None:
            return []
        children = []
        roster = peer.service.roster(peer.hab.pre)
        for member in roster.members:
            if member.aid == peer.member.pre:
                continue
            poster = StreamPoster(hby=peer.hby, hab=peer.member, recp=member.aid,
                                  topic='multisig', version=Vrsn_2_0)
            poster.send(outbound.proposal, attachment=outbound.attachments, gvrsn=Vrsn_2_0)
            children.extend(poster.deliver())
        return children

    def run(self, tymth, tock=0.0, **kwa):
        """Run the explicit action and release scheduled children before store closure.

        HIO supplies tymth/tock/kwa. Yield while quorum, transport or service work
        is pending. Exceptions propagate as CLI failure; success output describes
        exact proof retention or transport, never inferred remote custody.
        """
        self.wind(tymth)
        yield tock
        args = self.args
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ConfigurationError('--timeout must be positive and finite')
        with acdc_v2.opened(args, custody=True) as (hby, rgy, wallet), ExitStack() as activity:
            hab = hby.habByName(args.alias)
            if hab is None:
                raise ConfigurationError('registry-salt requires an existing local alias')
            notifier = Notifier(hby=hby)
            activity.callback(notifier.noter.close)
            peer = SaltPeer(hby, rgy, wallet, hab, notifier)
            mailbox = MailboxDirector(hby=hby, topics=['/receipt', '/multisig', '/replay', '/credential'],
                kvy=peer.mux.kvy, rvy=peer.mux.rvy, exc=peer.exc,
                version=Vrsn_2_0, gvrsn=Vrsn_2_0)
            mailbox.parser.rgy = peer.rever
            children = [HaberyDoer(habery=hby), peer.pruner, mailbox]
            self.extend(children)
            activity.callback(self.remove, children)
            for path in args.evidence:
                peer.ingest(Path(path).read_bytes())
            peer.trust(args.rosters)
            if args.input and args.operation != 'archive':
                peer.ingest(Path(args.input).read_bytes())
            if args.operation == 'serve':
                yield from self.serve(peer, activity)
                return
            if args.operation == 'status':
                self._require('registry')
                origin = peer.state.origin(args.registry)
                print(json.dumps(dict(registry=args.registry,
                    origin=asdict(origin) if origin else None,
                    custody_present=wallet.db.custody.get((args.registry,)) is not None,
                    deliveries=[asdict(row) for _, row in wallet.db.saltDeliveries.getTopItemIter()
                                if row.registry == args.registry])))
                return
            if args.operation == 'archive':
                self._require('input')
                body = peer.service.importProof(Path(args.input).read_bytes())
                print(json.dumps(dict(said=body.said, archived=True)))
                return
            if args.operation == 'import':
                self._require('input')
                print(json.dumps(dict(received=True)))
                return
            if args.operation == 'export':
                self._require('said', 'output')
                stream = peer.state.proof(args.said)
                if stream is None:
                    raise MissingEntryError('authenticated registry-salt proof is unavailable')
                print(json.dumps(dict(said=args.said, output=args.output, sha256=write(args.output, stream))))
                return
            body, proposal = self._body(peer)
            outbound = peer.service.approveReply(body, proposal=proposal)
            if args.proposal_output:
                if outbound.proposal is None:
                    raise ConfigurationError('--proposal-output requires a group alias')
                write(args.proposal_output, outbound.proposal.raw + outbound.attachments)
                print(json.dumps(dict(said=body.said, proposal=outbound.proposal.said,
                                      pending=peer.state.proof(body.said) is None)))
                return
            deliveries = self._fanout(peer, outbound)
            self.extend(deliveries)
            activity.callback(self.remove, deliveries)
            deadline = self.tyme + args.timeout
            while peer.state.proof(body.said) is None or any(not child.done for child in deliveries):
                peer.process()
                if self.tyme >= deadline:
                    if peer.state.proof(body.said) is None:
                        raise TimeoutError('registry-salt reply is pending exact group approval')
                    raise TimeoutError('registry-salt reply is authenticated but member fanout is pending')
                yield self.tock
            stream = peer.state.proof(body.said)
            if args.output:
                write(args.output, stream)
            transport = None
            if args.endpoint:
                # Quorum or witness work can outlive the original signed body's
                # applicable KRAM window. Never silently refresh its DH transcript.
                peer.service.checkLive(body)
                transport = yield from cesr_sending.send(self, args.endpoint, stream, args.timeout)
            print(json.dumps(dict(said=body.said, route=body.route, authenticated=True,
                                  submitted=transport is not None)))

    def serve(self, peer, activity):
        """Run HTTP intake and the durable worker under the command's one scheduler.

        peer supplies the shared Parser/Revery and source party; activity owns
        cleanup callbacks. No received request triggers logical-party approval.
        """
        from ...app.registry_salt_delivery import RegistrySaltDelivery

        peer.service.reconcileKnown(peer.hab.pre)
        establishment = peer.hab.kever.lastEst.d
        app = falcon.App()
        intake = Intake(peer)
        app.add_route('/', intake)
        app.add_route('/ingest', intake)
        server = createHttpServer(self.args.host, self.args.port, app)
        owners = [http.ServerDoer(server=server),
                  RegistrySaltDelivery(peer.service, source=peer.hab.pre)]
        self.extend(owners)
        activity.callback(self.remove, owners)
        while True:
            peer.process()
            if peer.hab.kever.lastEst.d != establishment:
                # KEL acceptance owns membership changes. Only afterwards may
                # existing entitlements queue the same root for new members.
                peer.service.reconcileKnown(peer.hab.pre)
                establishment = peer.hab.kever.lastEst.d
            yield self.tock
