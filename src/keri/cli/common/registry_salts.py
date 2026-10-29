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
from ...app.evidencing import EvidenceContext, KEL_DEPENDENCIES, ServiceConfig
from ...app.forwarding import StreamPoster
from ...app.grouping import Multiplexor, loadHandlers, replyProposal, endorseReply, multisigRpyExn
from ...app.indirecting import createHttpServer
from ...app.registry_custody import RegistryCustody
from ...app.registry_salt_service import RegistrySaltService, ROUTES
from ...core import Kramer, Parser, Pruner, Diger, messagize
from ...db import fetchTsgs
from ...kering import ConfigurationError, MissingEntryError, UnverifiedReplyError, ValidationError
from ...peer import Exchanger
from . import acdc_v2, cesr_sending
from .acdc_v2_ipex import Intake
from .public_evidence import write


class SaltPeer:
    """Borrow stores and share one live processor set across file/mailbox/HTTP intake."""

    def __init__(self, hby, rgy, custody, hab, notifier):
        """Compose the selected local member's optional salt service.

        Args: hby/rgy are caller-owned open stores; custody uses their Keeper, hab is the selected
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
        self.service = RegistrySaltService(hby, rgy, custody, self.mux.rvy)
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
        self.mux.rvy.processEscrowReply()


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

    def _reply(self, peer):
        """Sign the operator-selected reply or explicitly approve its retained proposal.

        Group signatures travel in ordinary multisig/rpy wrappers. There is no
        assignment event, salt activation record, or application delivery state.
        """
        args, service = self.args, peer.service
        if args.operation == 'approve':
            self._require('proposal')
            child = replyProposal(peer.hby, peer.exc, peer.mux, args.proposal,
                                  ghab=peer.hab, validate=service.validate)
            return endorseReply(peer.hby, peer.hab, child, validate=service.validate)
        self._require('registry', 'party')
        body = service.makeReply(peer.hab, args.registry, args.party, target=args.target)
        stream = peer.hab.endorse(body, gvrsn=Vrsn_2_0)
        if isinstance(peer.hab, GroupHab):
            proposal, attachments = multisigRpyExn(peer.hab, stream,
                version=Vrsn_2_0, gvrsn=Vrsn_2_0)
            return stream, proposal, attachments
        return stream, None, None

    def _fanout(self, peer, proposal, attachments):
        """Schedule ordinary finite member submissions under this command's owner."""
        children = []
        if proposal is not None:
            for member in peer.hab.smids:
                if member == peer.member.pre:
                    continue
                poster = StreamPoster(hby=peer.hby, hab=peer.member, recp=member,
                                      topic='multisig', version=Vrsn_2_0)
                poster.send(proposal, attachment=attachments, gvrsn=Vrsn_2_0)
                children.extend(poster.deliver() or [])
        return children

    def run(self, tymth, tock=0.0, **kwa):
        """Run the explicit action and release scheduled children before store closure.

        HIO supplies tymth/tock/kwa. Ordinary reply escrows collect the group
        signatures while the command owns finite member transport children.
        Output never infers remote custody from transport completion.
        """
        self.wind(tymth)
        yield tock
        args = self.args
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ConfigurationError('--timeout must be positive and finite')
        with acdc_v2.openedRegistry(args) as (hby, rgy), ExitStack() as activity:
            hab = hby.habByName(args.alias)
            if hab is None:
                raise ConfigurationError('registry-salt requires an existing local alias')
            notifier = Notifier(hby=hby)
            activity.callback(notifier.noter.close)
            peer = SaltPeer(hby, rgy, RegistryCustody(hby, rgy), hab, notifier)
            mailbox = MailboxDirector(hby=hby, topics=['/receipt', '/multisig', '/replay', '/credential'],
                kvy=peer.mux.kvy, rvy=peer.mux.rvy, exc=peer.exc,
                version=Vrsn_2_0, gvrsn=Vrsn_2_0)
            mailbox.parser.rgy = peer.rever
            children = [HaberyDoer(habery=hby), peer.pruner, mailbox]
            self.extend(children)
            activity.callback(self.remove, children)
            for path in args.evidence:
                peer.ingest(Path(path).read_bytes())
            if args.input:
                peer.ingest(Path(args.input).read_bytes())
            if args.operation == 'serve':
                yield from self.serve(peer, activity)
                return
            if args.operation == 'status':
                self._require('registry')
                print(json.dumps(dict(registry=args.registry,
                    custody_present=hby.ks.custody.get((args.registry,)) is not None)))
                return
            if args.operation == 'receive':
                self._require('input')
                print(json.dumps(dict(processed=True)))
                return
            if not (args.output or args.endpoint or args.proposal_output or getattr(args, 'deliver', False)):
                raise ConfigurationError('send/approve requires --output, --endpoint, --deliver or --proposal-output')
            stream, proposal, attachments = self._reply(peer)
            body = Parser(version=Vrsn_2_0).parseOne(ims=bytearray(stream), processive=False).serder
            peer.ingest(stream)
            if proposal is not None:
                peer.ingest(proposal.raw + attachments)
            if args.proposal_output:
                if proposal is None:
                    raise ConfigurationError('--proposal-output requires a group alias')
                write(args.proposal_output, proposal.raw + attachments)
                print(json.dumps(dict(said=body.said, proposal=proposal.said)))
                return
            deliveries = self._fanout(peer, proposal, attachments)
            self.extend(deliveries)
            activity.callback(self.remove, deliveries)
            deadline = self.tyme + args.timeout
            while True:
                peer.process()
                # Read normal Revery signature storage, then use its ordinary
                # threshold verification. A stored body alone may still be escrowed.
                diger = Diger(qb64=body.said)
                tsgs = list(fetchTsgs(db=hby.db.tsgs, diger=diger))
                cigars = []
                for verfer, cigar in hby.db.scgs.get(keys=(body.said,)):
                    cigar.verfer = verfer
                    cigars.append(cigar)
                if peer.mux.rvy.acceptReply(serder=body, saider=diger,
                        route=body.route, aid=body.pre, tsgs=tsgs, cigars=cigars):
                    stream = messagize(body, tsgs=tsgs or None, cigars=cigars or None,
                                       gvrsn=Vrsn_2_0)
                    break
                if self.tyme >= deadline:
                    raise TimeoutError('registry salt reply awaits the group signing threshold')
                yield self.tock
            if args.output:
                write(args.output, stream)
            if args.endpoint:
                yield from cesr_sending.send(self, args.endpoint, stream, args.timeout)
            if getattr(args, 'deliver', False):
                yield from self.deliver(peer, body, stream)
            print(json.dumps(dict(said=body.said,
                submitted=bool(args.endpoint or getattr(args, 'deliver', False)))))

    def deliver(self, peer, body, stream):
        """Submit accepted public evidence and this verified reply via ordinary routing.

        peer borrows identity/registry stores; body and stream are the exact
        operator-approved reply after ordinary threshold verification. Public
        replay precedes it so a new member can verify registry inception.
        Completion means submission, not remote custody. Timeout or transport
        failure propagates without a retry or a delivery-state record.
        """
        evidence = EvidenceContext(peer.hby, reger=peer.rgy.baser)
        raw = evidence.clone([body.sad['a']['registry']]) + bytes(stream)
        poster = StreamPoster(hby=peer.hby, hab=peer.member,
            recp=body.sad['a']['target'], topic='credential', version=Vrsn_2_0)
        children = poster.deliverStream(raw)
        if not children:
            raise ConfigurationError('registry salt recipient has no delivery route')
        self.extend(children)
        deadline = self.tyme + self.args.timeout
        try:
            while not all(child.done for child in children):
                if self.tyme >= deadline:
                    raise TimeoutError('registry salt submission timed out')
                yield self.tock
            if any(getattr(child, 'error', None) is not None for child in children):
                raise ConfigurationError('registry salt submission failed')
        finally:
            self.remove(children)

    def serve(self, peer, activity):
        """Run HTTP intake and ordinary protocol escrows under the command's one scheduler.

        peer supplies the shared Parser/Revery and source party; activity owns
        cleanup callbacks. No received request triggers logical-party approval.
        """
        app = falcon.App()
        intake = Intake(peer)
        app.add_route('/', intake)
        app.add_route('/ingest', intake)
        server = createHttpServer(self.args.host, self.args.port, app)
        owners = [http.ServerDoer(server=server)]
        self.extend(owners)
        activity.callback(self.remove, owners)
        while True:
            peer.process()
            yield self.tock
