"""ACDC v2 credential group composition using the existing KERI group owners."""
from hio.base import doing

from .. import Vrsn_2_0
from ..acdc.regeventing import Rever, vetBlind
from ..core import (Blinder, BlindState, BoundState, Codens, Counter, Diger,
                    Kramer, Number, Parser, Prefixer, Pruner, SerderKERI, messagize)
from ..kering import ConfigurationError, Ilks, MissingRegistryError, ValidationError
from ..peer.exchanging import serializeParsedSubstream
from .grouping import (Counselor, Multiplexor, loadHandlers,
                       multisigExn, multisigRipExn, multisigBupExn, validateRegistryAnchor)
from .habbing import GroupHab
from .indirecting import MailboxDirector
from .forwarding import StreamPoster
from .evidencing import ServiceConfig


class AcdcV2GroupCoordinator(doing.DoDoer):
    """Coordinate explicit approval, signatures, and fanout without new state.

    GroupHab owns signing, Multiplexor retains member approvals, Counselor owns
    KEL threshold/delegation/receipts, and Rever owns ACDC v2 registry TEL acceptance.
    Incoming proposals are retained until this member approves the exact body.
    No custody secret is generated, shared, or embedded by this coordinator.
    """
    def __init__(self, hby, rgy, ghab, exc, notifier, *, kramer=None, scy=None):
        """Compose group approval with shared registry and section evidence.

        Args:
            hby (Habery): Local member's KEL/EXN evidence owner.
            rgy (Regery): ACDC v2 registry evidence owner.
            ghab (GroupHab): Accepted local group identity requiring approvals.
            exc (Exchanger): Shared router with configured ACDC v2 IPEX semantics.
            notifier: Receiver of group proposal notices.
            kramer (Kramer | None): Shared replay/liveness owner, or create one.
                A supplied Kramer must have caller-owned scheduled pruning. When
                omitted, this coordinator schedules one Pruner for its own Kramer;
                removing the coordinator cancels that child maintenance work.
            scy (Sectioner | None): Caller-owned independent section processor.
                Its store must also be supplied to ACDC v2 IPEX handlers. Both
                direct proposals and mailbox intake use this same processor;
                caching sections never changes a retained grant disclosure.

        Returns:
            None

        Raises:
            ConfigurationError: GroupHab is absent or not locally accepted.
            ValidationError: The Exchanger already has conflicting group handlers.
        """
        if not isinstance(ghab, GroupHab) or not ghab.accepted:
            raise ConfigurationError('ACDC v2 group requires an accepted local GroupHab')
        self.hby, self.rgy, self.ghab, self.exc = hby, rgy, ghab, exc
        self.scy = scy
        self.rever = Rever(db=hby.db, reger=rgy.baser)
        self.mux = Multiplexor(hby, notifier, exc=exc, rgy=self.rever)
        self.mux.kvy.kramer = kramer if kramer is not None else Kramer(
            db=hby.db, cf=ServiceConfig(), cues=self.mux.kvy.cues)
        # Maintenance follows cache ownership. Shared caches are pruned by their
        # existing runtime owner, rather than once per coordinator using them.
        self.pruner = Pruner(self.mux.kvy.kramer, tock=1.0) if kramer is None else None
        loadHandlers(exc, self.mux)
        self.counselor = Counselor(hby=hby, version=Vrsn_2_0)
        self.mailbox = MailboxDirector(hby=hby,
            topics=['/receipt', '/multisig', '/replay', '/credential'],
            kvy=self.mux.kvy, exc=exc, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        self.mailbox.parser.rgy = self.rever
        self.mailbox.parser.scy = scy
        self.parser = Parser(kvy=self.mux.kvy, rgy=self.rever, exc=exc, scy=scy,
                             version=Vrsn_2_0, local=True)
        self.registry = RegistryApproval(hby, rgy, ghab, exc, self.mux,
                                         self.parser, self.counselor)
        doers = [self.counselor, self.mailbox, doing.doify(self.escrowDo)]
        if self.pruner is not None:
            doers.append(self.pruner)
        super().__init__(doers=doers)

    def process(self):
        """Advance group KEL, quorum, ACDC v2 registry TEL, and exchange dependency work.

            Returns:
                None. Only ordinary processors can accept evidence; delivery alone never
                creates local approval. Unexpected processor/storage errors propagate."""
        self.registry.process()

    def escrowDo(self, tymth, tock=0.03125, **kwa):
        """Schedule bounded group dependency passes for this coordinator's lifetime.

            Args:
                tymth: HIO scheduler clock supplied to this doer.
                tock (float): Recurrence interval returned at each cooperative yield.
                **kwa: Scheduler metadata unused by the escrow loop.

            Yields:
                float: Delay before the next process pass. Cancellation stops recurrence;
                    the enclosing coordinator owns its other child doers."""
        yield tock
        while True:
            self.process()
            yield tock

    def receive(self, stream):
        """Process member-authenticated evidence without implicitly approving it.

            Args:
                stream (bytes): KEL, independent sections, or signed proposal stream.

            Returns:
                None. Parsing and normal dependency processing retain verified proposals;
                explicit local approval is still required for wrapped exchange replay."""
        self.parser.parse(ims=bytearray(stream))
        self.process()

    def send(self, wrapper, attachments):
        """Fan out a signed proposal through each remote member's ordinary transport.

            Args:
                wrapper (SerderKERI): Member-signed group proposal EXN.
                attachments (bytes): Exact detached proposal evidence.

            Returns:
                None. Poster delivery doers join this coordinator and stop with it;
                transmission is not remote acceptance or local member consent."""
        for member in self.hby.db.signingMembers(pre=self.ghab.pre):
            if member == self.ghab.mhab.pre:
                continue
            poster = StreamPoster(hby=self.hby, hab=self.ghab.mhab, recp=member,
                                  topic='multisig', version=Vrsn_2_0)
            poster.send(serder=wrapper, attachment=attachments, gvrsn=Vrsn_2_0)
            self.extend(poster.deliver())

    def registryProposal(self, stream):
        """Inspect an authenticated exact registry proposal without signing it."""
        return self.registry.proposal(stream)

    def exchangeProposal(self, stream):
        """Authenticate one exact IPEX proposal and reconstruct its wrapped bytes.

            Args:
                stream (bytes): Member wrapper with preceding KEL evidence if needed.

            Returns:
                bytes: Original child exchange stream, retaining disclosed attachments.

            Raises:
                ValidationError: Wrapper count, authentication, or child structure fails.

            The returned child remains unapproved locally until approveExchange signs it."""
        parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(stream), processive=False) or []
        proposals = [dom for dom in parsed if dom.serder.ilk == Ilks.exn
                     and dom.serder.route == '/multisig/exn']
        if len(proposals) != 1:
            raise ValidationError('expected one ACDC v2 IPEX group proposal')
        self.receive(stream)
        proposal = proposals[0]
        if not self.exc.complete(proposal.serder.said):
            raise ValidationError('group exchange proposal is not authenticated')
        self.mux.validate(proposal.serder, nests=proposal.nests)
        return serializeParsedSubstream(proposal.nests[0])

    def approveRegistry(self, event, anchor=None, *, opening=None):
        """Explicitly approve one exact registry event through the shared signer."""
        return self.registry.approve(event, anchor, opening=opening)

    def approveExchange(self, stream):
        """Add this member's signature to one exact group EXN and retain its view.

            Args:
                stream (bytes): One group-authored exchange with exact nested evidence.

            Returns:
                tuple: Signed member proposal wrapper and its attachments.

            Raises:
                ValidationError: Input has multiple messages, is not EXN, or uses another AID.

            Parsing merges signatures through normal processors. This explicit consent
            does not bypass ACDC v2 IPEX semantics, missing sections, or group thresholds."""
        parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(stream), processive=False) or []
        if len(parsed) != 1:
            raise ValidationError('ACDC v2 group approval requires exactly one exchange')
        child = parsed[0]
        if child.serder.ilk != Ilks.exn or child.serder.pre != self.ghab.pre:
            raise ValidationError('exchange is not issued by this group')
        route = child.serder.route
        if (route == '/ipex/grant' and child.serder.sad['a'].get('o')) or route == '/ipex/admit':
            handler = self.exc.routes['/ipex/grant']
            verification = getattr(handler, 'acdcV2', handler).verification
            if route == '/ipex/grant':
                origins = child.serder.sad['a']['o']
                if (not isinstance(origins, list) or len(origins) != 1
                        or verification.evaluateDisclosure(origins[0], child.nests) is not True):
                    raise ValidationError('credential graph is false or unresolved')
            elif verification.evaluateGrant(child.serder.sad['p']) is not True:
                raise ValidationError('credential graph is false or unresolved')
        child.tsgs.append((self.ghab.kever.prefixer,
            Number(num=self.ghab.kever.lastEst.s), Diger(qb64=self.ghab.kever.lastEst.d),
            self.ghab.sign(child.serder.raw)))
        signed = serializeParsedSubstream(child)
        self.parser.parse(ims=bytearray(signed))
        wrapper, attachments = multisigExn(self.ghab, signed, version=Vrsn_2_0)
        self.receive(wrapper.raw + attachments)
        return wrapper, attachments

    def completeExchange(self, said):
        """Check ordinary Exchanger completion for one group child exchange.

            Args:
                said (str): Child exchange identifier, not its proposal wrapper SAID.

            Returns:
                bool: Whether its authenticated threshold and protocol workflow completed.
                Completion alone is not application graph authorization."""
        return self.exc.complete(said)


class RegistryApproval:
    """Approve exact native registry proposals using caller-owned group processors.

    This passive collaborator has no mailbox, scheduler, transport, or custody
    owner. GroupHab signs, Multiplexor records explicit consent, Counselor drives
    the group KEL, and Rever accepts the TEL against accepted controller evidence.
    """

    def __init__(self, hby, rgy, ghab, exc, mux, parser, counselor):
        """Borrow existing processors without opening stores or scheduling work.

        Args:
            hby (Habery): Local KEL and proposal evidence owner.
            rgy (Regery): Native registry store shared with the injected Rever.
            ghab (GroupHab): Accepted local group whose exact anchors may be signed.
            exc (Exchanger): Existing authenticated proposal router.
            mux (Multiplexor): Existing explicit-consent and child-replay owner.
            parser (Parser): Existing KEL, TEL, and EXN intake parser.
            counselor (Counselor): Existing group completion owner.
        """
        if not isinstance(ghab, GroupHab) or not ghab.accepted:
            raise ConfigurationError('registry approval requires an accepted local GroupHab')
        self.hby, self.rgy, self.ghab = hby, rgy, ghab
        self.exc, self.mux, self.parser, self.counselor = exc, mux, parser, counselor
        self.rever = mux.rgy
        if (self.rever is None or parser.rgy is not self.rever
                or parser.kvy is not mux.kvy):
            raise ConfigurationError('registry approval requires shared native KEL and TEL processors')

    def validateEvent(self, event):
        """Check event identity and accepted registry control before any signature.

        Missing accepted inception evidence raises MissingRegistryError so callers
        can retain the notification pending. A known foreign controller is invalid.
        Neither case authorizes signing a fresh local group anchor.
        """
        if (event.ilk not in (Ilks.rip, Ilks.bup) or event.pvrsn != Vrsn_2_0
                or not event.verify()):
            raise ValidationError('selected ACDC v2 group profile supports only valid rip and bup')
        if event.ilk == Ilks.rip:
            rip = event
        else:
            rip = self.rgy.store.seqEvent(event.sad['rd'], 0)
            if rip is None:
                raise MissingRegistryError('registry proposal needs accepted inception evidence')
        if rip.ilk != Ilks.rip or rip.sad['i'] != self.ghab.pre:
            raise ValidationError('registry proposal is controlled by a different group')

    def process(self):
        """Advance borrowed processors; acceptance remains their ordinary decision."""
        self.mux.kvy.processEscrows()
        self.counselor.processEscrows()
        self.rever.processEscrows()
        self.exc.processEscrow()

    def receive(self, stream):
        """Retain authenticated evidence without creating local approval."""
        self.parser.parse(ims=bytearray(stream), local=True)
        self.process()

    def proposal(self, stream):
        """Authenticate one exact registry proposal without signing its anchor.

            Args:
                stream (bytes): Signed group wrapper with proposed TEL and KEL bodies.

            Returns:
                tuple: Exact proposed registry event, controlling group anchor,
                    and optional explicitly disclosed event opening.

            Raises:
                ValidationError: Expected wrapper is absent, unauthenticated, or malformed.

            receive may retain authenticated evidence, but this read path adds no local
            signature and cannot substitute for approve."""
        parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(stream), processive=False) or []
        proposals = [dom for dom in parsed if dom.serder.ilk == Ilks.exn
                     and dom.serder.route in ('/multisig/rip', '/multisig/bup')]
        if len(proposals) != 1:
            raise ValidationError('expected one ACDC v2 registry proposal')
        self.receive(stream)
        proposal = proposals[0]
        if not self.exc.complete(proposal.serder.said):
            raise ValidationError('registry proposal is not authenticated')
        self.mux.validate(proposal.serder, nests=proposal.nests)
        tel = proposal.nests[0]
        proofs = ((tel.get('bsqs', []) + tel.get('bsss', [])) if isinstance(tel, dict)
                  else tel.bsqs + tel.bsss)
        if len(proofs) > 1:
            raise ValidationError('registry proposal carries multiple event openings')
        opening = None
        if proofs:
            clan = BlindState if len(proofs[0]) == 4 else BoundState
            opening = Blinder(data=clan(*proofs[0]))
            event = tel['serder'] if isinstance(tel, dict) else tel.serder
            vetBlind(opening, blid=event.sad.get('b', ''))
        children = tuple(nest['serder'] if isinstance(nest, dict) else nest.serder
                         for nest in proposal.nests)
        self.validateEvent(children[0])
        return children + (opening,)

    def approve(self, event, anchor=None, *, opening=None):
        """Sign the exact proposed TEL anchor and start ordinary threshold completion.

            Args:
                event (SerderACDC): ACDC v2 registry event this member explicitly approves.
                anchor (SerderKERI | None): Exact proposed group KEL event; None reuses
                    pending local work or authors a new suitable interaction/rotation.
                opening (Blinder | None): Explicit opening published with a ``bup``.

            Returns:
                tuple: Member proposal wrapper and detached attachments for fanout.

            Raises:
                ValidationError: Anchor identity/type/body does not exclusively seal event.

            Local retries reuse partial events rather than fork them. Acceptance still
            requires Counselor quorum/witness/delegation and normal Rever verification."""
        self.validateEvent(event)
        if opening is not None:
            if event.ilk != Ilks.bup or not isinstance(opening, Blinder):
                raise ValidationError('registry opening requires an exact bup proposal')
            vetBlind(opening, blid=event.sad['b'])
        seal = dict(s=event.sad['n'], d=event.said)
        if anchor is None:
            # A command retry reuses its partial event instead of forking it.
            sn = self.ghab.kever.sn + 1
            dig = self.hby.db.pses.getLast(keys=self.ghab.pre, on=sn)
            anchor = self.hby.db.evts.get((self.ghab.pre, dig)) if dig else None
            if anchor is None:
                author = self.ghab.rotate if self.ghab.kever.estOnly else self.ghab.interact
                stream = author(data=[seal], version=Vrsn_2_0, gvrsn=Vrsn_2_0)
                anchor = SerderKERI(raw=stream)
        validateRegistryAnchor(event, anchor, self.ghab.pre)
        if anchor.ilk in (Ilks.rot, Ilks.drt):
            stream = self.ghab.rotate(serder=anchor, smids=self.ghab.smids,
                rmids=self.ghab.rmids, gvrsn=Vrsn_2_0)
        else:
            stream = messagize(anchor, sigers=self.ghab.sign(anchor.raw), gvrsn=Vrsn_2_0)
        self.parser.parse(ims=bytearray(stream), local=True)
        tel = (messagize(event, bonds=[opening.data], gvrsn=Vrsn_2_0)
               if opening is not None else
               event.raw + Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b)
        self.rever.processEvent(event)
        propose = multisigRipExn if event.ilk == Ilks.rip else multisigBupExn
        wrapper, attachments = propose(self.ghab, tel, stream)
        self.receive(wrapper.raw + attachments)  # explicit local approval
        self.counselor.start(self.ghab, Prefixer(qb64=self.ghab.pre),
                             Number(num=anchor.sn), Diger(qb64=anchor.said))
        self.process()
        return wrapper, attachments
