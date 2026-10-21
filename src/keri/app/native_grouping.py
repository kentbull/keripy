"""Native credential group composition using the existing KERI group owners."""
from hio.base import doing

from .. import Vrsn_2_0
from ..acdc.regeventing import Rever
from ..core import (Codens, Counter, Diger, Kramer, Number, Parser, Prefixer,
                    SerderKERI, messagize)
from ..kering import ConfigurationError, Ilks, ValidationError
from ..peer.exchanging import serializeParsedSubstream
from .grouping import (Counselor, Multiplexor, loadHandlers,
                       multisigExn, multisigRegistryExn)
from .habbing import GroupHab
from .indirecting import MailboxDirector
from .forwarding import StreamPoster
from .registrar.serving import ServiceConfig


class NativeGroup(doing.DoDoer):
    """Coordinate explicit approval, signatures, and fanout without new state.

    GroupHab owns signing, Multiplexor retains member approvals, Counselor owns
    KEL threshold/delegation/receipts, and Rever owns native TEL acceptance.
    Incoming proposals are retained until this member approves the exact body.
    No custody secret is generated, shared, or embedded by this coordinator.
    """
    def __init__(self, hby, rgy, ghab, exc, notifier, *, kramer=None):
        if not isinstance(ghab, GroupHab) or not ghab.accepted:
            raise ConfigurationError('native group requires an accepted local GroupHab')
        self.hby, self.rgy, self.ghab, self.exc = hby, rgy, ghab, exc
        self.rever = Rever(db=hby.db, reger=rgy.baser)
        self.mux = Multiplexor(hby, notifier, exc=exc, rgy=self.rever)
        self.mux.kvy.kramer = kramer if kramer is not None else Kramer(
            db=hby.db, cf=ServiceConfig(), cues=self.mux.kvy.cues)
        loadHandlers(exc, self.mux)
        self.counselor = Counselor(hby=hby, version=Vrsn_2_0)
        self.mailbox = MailboxDirector(hby=hby,
            topics=['/receipt', '/multisig', '/replay', '/credential'],
            kvy=self.mux.kvy, exc=exc, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        self.mailbox.parser.rgy = self.rever
        self.parser = Parser(kvy=self.mux.kvy, rgy=self.rever, exc=exc,
                             version=Vrsn_2_0, local=True)
        super().__init__(doers=[self.counselor, self.mailbox, doing.doify(self.escrowDo)])

    def process(self):
        self.mux.kvy.processEscrows()
        self.counselor.processEscrows()
        self.rever.processEscrows()
        self.exc.processEscrow()

    def escrowDo(self, tymth, tock=0.03125, **kwa):
        yield tock
        while True:
            self.process()
            yield tock

    def receive(self, stream):
        """Accept a member-authenticated proposal; it does not imply approval."""
        self.parser.parse(ims=bytearray(stream))
        self.process()

    def send(self, wrapper, attachments):
        """Fan out one member proposal using the ordinary KERI transport owner."""
        for member in self.hby.db.signingMembers(pre=self.ghab.pre):
            if member == self.ghab.mhab.pre:
                continue
            poster = StreamPoster(hby=self.hby, hab=self.ghab.mhab, recp=member,
                                  topic='multisig', version=Vrsn_2_0)
            poster.send(serder=wrapper, attachment=attachments, gvrsn=Vrsn_2_0)
            self.extend(poster.deliver())

    def registryProposal(self, stream):
        """Read an authenticated remote proposal without granting local approval."""
        parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(stream), processive=False) or []
        proposals = [dom for dom in parsed if dom.serder.ilk == Ilks.exn
                     and dom.serder.route == '/multisig/registry']
        if len(proposals) != 1:
            raise ValidationError('expected one native registry proposal')
        self.receive(stream)
        proposal = proposals[0]
        if not self.exc.complete(proposal.serder.said):
            raise ValidationError('registry proposal is not authenticated')
        self.mux.validate(proposal.serder, nests=proposal.nests)
        return tuple(nest['serder'] if isinstance(nest, dict) else nest.serder
                     for nest in proposal.nests)

    def exchangeProposal(self, stream):
        """Authenticate an exact native IPEX proposal, including preceding KELs."""
        parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(stream), processive=False) or []
        proposals = [dom for dom in parsed if dom.serder.ilk == Ilks.exn
                     and dom.serder.route == '/multisig/exn']
        if len(proposals) != 1:
            raise ValidationError('expected one native IPEX group proposal')
        self.receive(stream)
        proposal = proposals[0]
        if not self.exc.complete(proposal.serder.said):
            raise ValidationError('group exchange proposal is not authenticated')
        self.mux.validate(proposal.serder, nests=proposal.nests)
        return serializeParsedSubstream(proposal.nests[0])

    def approveRegistry(self, event, anchor=None):
        """Sign the exact proposed anchor; accepted TEL state still awaits quorum."""
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
        if (anchor.pre != self.ghab.pre or anchor.ilk not in (Ilks.ixn, Ilks.rot, Ilks.drt)
                or anchor.sad.get('a') != [seal]):
            raise ValidationError('group proposal does not exclusively anchor the requested TEL')
        if anchor.ilk in (Ilks.rot, Ilks.drt):
            stream = self.ghab.rotate(serder=anchor, smids=self.ghab.smids,
                rmids=self.ghab.rmids, gvrsn=Vrsn_2_0)
        else:
            stream = messagize(anchor, sigers=self.ghab.sign(anchor.raw), gvrsn=Vrsn_2_0)
        self.parser.parse(ims=bytearray(stream))
        tel = event.raw + Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b
        self.rever.processEvent(event)
        wrapper, attachments = multisigRegistryExn(self.ghab, tel, stream)
        self.receive(wrapper.raw + attachments)  # explicit local approval
        self.counselor.start(self.ghab, Prefixer(qb64=self.ghab.pre),
                             Number(num=anchor.sn), Diger(qb64=anchor.said))
        self.process()
        return wrapper, attachments

    def approveExchange(self, stream):
        """Add this member's signature to the exact EXN and retain its disclosure."""
        parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(stream), processive=False) or []
        if len(parsed) != 1:
            raise ValidationError('native group approval requires exactly one exchange')
        child = parsed[0]
        if child.serder.ilk != Ilks.exn or child.serder.pre != self.ghab.pre:
            raise ValidationError('exchange is not issued by this group')
        child.tsgs.append((self.ghab.kever.prefixer,
            Number(num=self.ghab.kever.lastEst.s), Diger(qb64=self.ghab.kever.lastEst.d),
            self.ghab.sign(child.serder.raw)))
        signed = serializeParsedSubstream(child)
        self.parser.parse(ims=bytearray(signed))
        wrapper, attachments = multisigExn(self.ghab, signed, version=Vrsn_2_0)
        self.receive(wrapper.raw + attachments)
        return wrapper, attachments

    def completeExchange(self, said):
        return self.exc.complete(said)
