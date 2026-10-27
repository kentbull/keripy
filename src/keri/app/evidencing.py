"""Shared KEL and ACDC v2 registry TEL verification and cooperative maintenance composition.

Extracted from the qualified registrar adapter at KERIpy 64e14e08. This module
owns no HTTP routes, publisher/reader policy, or polling schedule. Services,
wallets and reporting applications share these ordinary core processors without
importing one another's application. Protocol acceptance remains in Rever.
"""
from dataclasses import asdict

from hio.base import doing

from keri import Vrsn_2_0
from keri.acdc.regbasing import RegBaser
from keri.acdc.regeventing import Rever, requireSupportedEvent
from keri.core import (BlindState, Blinder, BoundState, Kevery, Parser,
                       SerderACDC, Counter, Codens, Number, NumDex)
from keri.core.kraming import Kramer, Pruner
from keri.db.dbing import snKey
from keri.kering import (ConfigurationError, ValidationError, MissingSignatureError,
    MissingWitnessSignatureError, MissingDelegationError, OutOfOrderError,
    MissingDelegableApprovalError, UnverifiedReceiptError,
    UnverifiedWitnessReceiptError, UnverifiedTransferableReceiptError)


KEL_DEPENDENCIES = (MissingSignatureError, MissingWitnessSignatureError,
    MissingDelegationError, OutOfOrderError, MissingDelegableApprovalError,
    UnverifiedReceiptError, UnverifiedWitnessReceiptError, UnverifiedTransferableReceiptError)


class ServiceConfig:
    """Fixed, enabled KRAM policy for authenticated service requests."""

    def __init__(self, data=None):
        """Select a concrete enabled KRAM policy for authenticated service requests.

            Args:
                data (dict | None): Explicit KRAM settings; None uses service defaults.

            Returns:
                None. The service rejects disabled KRAM and denial exemptions.

            Raises:
                ConfigurationError: Configuration disables mandatory authentication."""
        self.data = data if data is not None else {
            'kram': {'enabled': True, 'denials': [],
                     'caches': {'~': [1000, 5000, 60000, 300000, 5000, 60000, 300000]}}}
        block = self.data.get('kram', {})
        if block.get('enabled') is not True or block.get('denials'):
            raise ConfigurationError('service requests require enabled KRAM without denial exemptions')

    def get(self):
        """Expose this service's concrete KRAM settings to Kramer.

            Returns:
                dict: The selected settings object; no network fetch or policy inference."""
        return self.data


def signedQuery(hab, route, query=None):
    """Create a fresh, signed KERI v2 service query with existing habitat keys.

        Args:
            hab: Authenticated signing habitat for the requester AID.
            route (str): Service query route, such as tels/bulk.
            query (dict | None): Query attributes; None supplies an empty map.

        Returns:
            bytes: Endorsed v2 CESR query stream with current request timestamp.

        Key/signing failures propagate. This helper conveys no registry salt."""
    from keri.core import query as makeQuery
    from keri.help import helping
    serder = makeQuery(pre=hab.pre, route=route, query=query or {},
                       stamp=helping.nowIso8601(), version=Vrsn_2_0)
    return bytes(hab.endorse(serder, last=True, framed=False, gvrsn=Vrsn_2_0))


class EvidenceContext(doing.DoDoer):
    """Own concrete remote KEL/ACDC v2 registry processors and their stores."""

    def __init__(self, hby, *, reger=None, config=None):
        """Compose public evidence intake with one owned KRAM maintenance runtime.

            Args:
                hby: Caller-owned Habery containing authenticated KEL and KRAM persistence.
                reger (RegBaser | None): Registry store, closed by this context's close().
                config (dict | None): Enabled KRAM settings accepted by ServiceConfig.

            Returns:
                None. Schedule the context for its entire service lifetime; its single
                Pruner and escrow child stop before the caller closes backing stores.

            Raises:
                ConfigurationError: Requested service policy disables required KRAM.

            KEL/ACDC v2 registry TEL acceptance remains in the shared processors. Reopening resumes
            persisted cache maintenance without deleting accepted evidence."""
        self.hby = hby
        self.cf = ServiceConfig(config)
        self.kvy = Kevery(db=hby.db, cf=self.cf, enableKram=True, lax=False, local=False)
        self.kvy.kramer = Kramer(db=hby.db, cf=self.cf, cues=self.kvy.cues)
        self.pruner = Pruner(self.kvy.kramer, tock=1.0)
        self.reger = reger if reger is not None else RegBaser(
            name=hby.name, base=hby.base, temp=hby.temp)
        self.rever = Rever(db=hby.db, reger=self.reger)
        self.store = self.rever.store
        self.evidence = EvidenceProcessor(hby, kvy=self.kvy, rever=self.rever)
        self.parser = self.evidence.parser
        super().__init__(doers=[self.pruner, doing.doify(self.escrowDo)])

    def ingest(self, raw):
        """Delegate public evidence intake to the borrowed-processor adapter."""
        return self.evidence.ingest(raw)

    def registries(self):
        """Return accepted registry identifiers from the shared evidence store."""
        return self.evidence.registries()

    def clone(self, regks=None, sn=0):
        """Export accepted scoped evidence; see EvidenceProcessor.clone."""
        return self.evidence.clone(regks=regks, sn=sn)

    def escrowDo(self, tymth=None, tock=0.0, **kwa):
        """Retry concrete KEL/TEL dependencies while this service is scheduled.

            Args:
                tymth: HIO scheduler clock injected on entry.
                tock (float): Cooperative recurrence delay.
                **kwa: Scheduler metadata unused by this loop.

            Yields:
                float: Delay between bounded processor passes. Cancellation stops retries;
                the sibling Pruner owns cache expiration rather than deleting evidence."""
        self.wind(tymth)
        yield tock
        while True:
            self.kvy.processEscrows()
            self.rever.processEscrows()
            yield tock

    def close(self):
        """Close the ACDC v2 registry store after child doers have stopped.

            Returns:
                None. Habery remains caller-owned; scheduling cancellation must precede
                this close so pruning/escrow work cannot access a closed environment."""
        self.reger.close()


class EvidenceProcessor:
    """Process public evidence using borrowed core verifiers, with no lifecycle.

    Services compose this with their KRAM/pruning owner; applications can reuse
    it alongside an existing vault scheduler. It never opens or closes stores,
    creates a Kramer, schedules a pruner, or implements a second TEL acceptor.
    """

    def __init__(self, hby, *, kvy, rever):
        """Bind the caller's strict KEL verifier and ACDC v2 registry TEL verifier.

        Args:
            hby: Caller-owned Habery whose database receives verified evidence.
            kvy: Existing nonlocal, nonlax Kevery for that database.
            rever: Existing Rever for the same KEL database and registry store.

        Raises:
            ConfigurationError: Verifier ownership or strictness does not match.

        The caller owns escrow scheduling and KRAM maintenance. Methods are
        moved unchanged from EvidenceContext at 9ca869f6.
        """
        if kvy.db is not hby.db or kvy.lax or kvy.local or rever.db is not hby.db:
            raise ConfigurationError('public evidence requires strict verifiers for one Habery')
        self.hby, self.kvy, self.rever = hby, kvy, rever
        self.reger, self.store = rever.reger, rever.store
        self.parser = Parser(kvy=kvy, rgy=rever, local=False, version=Vrsn_2_0)

    def ingest(self, raw):
        """Process public evidence and summarize final shared-processor outcomes.

            Args:
                raw (bytes): Complete or concatenated CESR KEL/ACDC v2 registry TEL evidence stream.

            Returns:
                dict: Accepted/pending/rejected counts and accepted per-registry heads.
                    Stream/framing failures are recorded as rejected stream entries.

            Recognized retained KEL dependencies permit continued intake; other failures
            stop this stream. Escrows run before classification so a staged sibling is
            not mistaken for acceptance. Unknown rival anchors remain pending; proven
            conflicts never replace the accepted chain. Conflict proof discovered while
            processing supporting KEL is retained locally, without inventing a TEL event
            in this batch's counters. Freshness is a separate observer policy."""
        ims = bytearray(raw)
        summary = dict(accepted={}, pending={}, rejected={}, heads={})
        events = []
        kelDependencies = []
        while ims:
            before = len(ims)
            try:
                dom = self.parser.parseOne(ims=ims, processive=False, local=False)
                if dom is None or dom.serder is None or len(ims) >= before:
                    raise ValidationError('invalid or incomplete evidence frame')
                serder = dom.serder
                if isinstance(serder, SerderACDC):
                    opening = self._opening(serder, dom)
                    self.rever.processEvent(serder, sscs=dom.sscs, ssts=dom.ssts)
                    if opening is not None:
                        self.store.retainOpening(serder, opening)
                    events.append(serder)
                else:
                    if serder.ilk not in ('icp', 'dip', 'rot', 'drt', 'ixn', 'rct'):
                        raise ValidationError('hosting intake accepts only public KEL/ACDC v2 registry TEL evidence')
                    self.parser.msgProcess(exts=asdict(dom), kvy=self.kvy, rgy=self.rever,
                                           tvy=None, exc=None, rvy=None, vry=None)
            except KEL_DEPENDENCIES as ex:
                # Only the concrete processor's retained dependency can justify
                # continuing. Invalid evidence and framing still terminate intake.
                if not isinstance(serder, SerderACDC) and self._kelPending(serder):
                    kelDependencies.append(serder)
                    continue
                summary['rejected']['stream'] = str(ex)
                break
            except Exception as ex:
                summary['rejected']['stream'] = str(ex)
                break
        self.kvy.processEscrows()
        self.rever.processEscrows()
        for event in kelDependencies:
            if self._kelPending(event):
                key = f'kel:{event.pre}'
                summary['pending'][key] = summary['pending'].get(key, 0) + 1
            elif self.hby.db.kels.getLast(keys=event.pre, on=event.sn) != event.said:
                summary['rejected'][f'kel:{event.pre}:{event.snh}'] = 'dependency was not accepted or retained'
        for event in events:
            regk = event.said if event.ilk == 'rip' else event.sad['rd']
            sn = Number(numh=event.sad['n']).num
            accepted = self.store.seqEvent(regk, sn)
            if accepted is not None and accepted.said == event.said:
                bucket = 'accepted'
            else:
                # Escrow membership distinguishes an unauthenticated rival from
                # a proven conflict even when another event occupies this slot.
                pending = any(event.said == said for escrow in (self.reger.maes, self.reger.ooes)
                              for (said,) in escrow.get(keys=regk, on=sn))
                bucket = 'pending' if pending else 'rejected'
            summary[bucket][regk] = summary[bucket].get(regk, 0) + 1
            if bucket == 'accepted':
                previous = summary['heads'].get(regk)
                if previous is None or Number(numh=self.store.event(previous).sad['n']).num < Number(numh=event.sad['n']).num:
                    summary['heads'][regk] = event.said
        return summary

    def _opening(self, event, dom):
        """Return one exact presented opening after event-specific validation.

        A ``bup`` without a disclosure remains legitimate private evidence.
        Once a disclosure is present, exactly one blind or bound opening must
        reproduce this event's BLID. Registry inception cannot carry one.
        """
        openings = [(BlindState, item) for item in dom.bsqs]
        openings.extend((BoundState, item) for item in dom.bsss)
        if event.ilk != 'bup':
            if openings:
                raise ValidationError('only a blinded update may carry a state opening')
            return None
        if not openings:
            return None
        if len(openings) != 1:
            raise ValidationError('blinded update must carry at most one public opening')
        clan, values = openings[0]
        opening = Blinder(data=clan(*values))
        old = self.store.opening(event.said)
        if old is not None and old != opening.qb64:
            raise ValidationError('different public opening is already retained for this event')
        # The store repeats this check at the write boundary. Doing it before
        # TEL processing prevents an invalid disclosure from staging a body.
        from keri.acdc.regeventing import vetBlind
        vetBlind(opening, blid=event.sad['b'])
        return opening

    def _kelPending(self, event):
        """Confirm that one exact KEL/receipt dependency remains durably escrowed.

            Args:
                event: Parsed KERI event or receipt whose processing raised a dependency.

            Returns:
                bool: Whether the concrete ordinary escrow retains this event identity.
                    Exception class alone is insufficient evidence of recoverable work."""
        db = self.hby.db
        if event.ilk != 'rct':
            if any(event.said in escrow.get(keys=event.pre, on=event.sn)
                   for escrow in (db.pses, db.pwes, db.pdes, db.ooes)):
                return True
            return event.said in db.delegables.get(keys=snKey(event.pre, event.sn))
        if any(said == event.said for said, _ in db.uwes.get(keys=event.pre, on=event.sn)):
            return True
        receipts = db.ures.get(keys=(event.pre, Number(num=event.sn, code=NumDex.Huge).qb64))
        receipts += db.vres.get(keys=snKey(event.pre, event.sn))
        return any(receipt[0].qb64 == event.said for receipt in receipts)

    def registries(self):
        """Enumerate only registries with an accepted ACDC v2 registry head.

            Returns:
                list[str]: Sorted registry SAIDs; staged inception bodies are excluded."""
        regks = []
        for keys, _ in self.reger.heads.getTopItemIter():
            regk = keys[0]
            try:
                for raw in self.store.cloneTelIter(regk):
                    requireSupportedEvent(SerderACDC(raw=raw))
            except ValidationError:
                continue
            regks.append(regk)
        return sorted(regks)

    def clone(self, regks=None, sn=0):
        """Clone accepted controller KEL evidence and selected accepted ACDC v2 registry TELs.

            Args:
                regks (Iterable[str] | None): Registry scope; None selects all accepted heads.
                sn (int): First TEL ordinal to include, while retaining supporting KELs.

            Returns:
                bytes: Supporting delegation/controller evidence followed by framed TELs.

            Raises:
                KeyError: Scope contains a registry without an accepted inception.

            Controller evidence is emitted once per issuer. Pending or conflicting body
            rows never acquire accepted ordinals merely because their anchors are known."""
        regks = self.registries() if regks is None else list(regks)
        kel, tel, issuers = bytearray(), bytearray(), set()
        for regk in regks:
            rip = self.store.seqEvent(regk, 0)
            if rip is None:
                raise KeyError(regk)
            accepted = [SerderACDC(raw=raw)
                        for raw in self.store.cloneTelIter(regk)]
            # Validate the entire accepted prefix before emitting any of it.
            # Low-level store iteration remains available for explicit history
            # inspection, including exact legacy upd bytes.
            for event in accepted:
                requireSupportedEvent(event)
            history = [event for event in accepted
                       if Number(numh=event.sad['n']).num >= sn]
            issuer = rip.sad['i']
            if issuer not in issuers:
                kever = self.hby.kevers[issuer]
                kel.extend(b''.join(self.hby.db.cloneDelegation(kever, gvrsn=Vrsn_2_0)))
                kel.extend(b''.join(self.hby.db.clonePreIter(pre=issuer, gvrsn=Vrsn_2_0)))
                issuers.add(issuer)
            for event in history:
                tel.extend(event.raw)
                opening = self.store.opening(event.said) if event.ilk == 'bup' else None
                if opening is None:
                    attachments = b''
                else:
                    candidates = []
                    for clan in (BlindState, BoundState):
                        try:
                            candidate = Blinder(clan=clan, qb64=opening)
                        except Exception:
                            continue
                        if candidate.qb64 == opening:
                            candidates.append(candidate)
                    if len(candidates) != 1:
                        raise ValidationError(
                            f'retained public opening is invalid for event {event.said}')
                    self.store.retainOpening(event, candidates[0])
                    attachments = Blinder.enclose(candidates)
                tel.extend(Counter.enclose(qb64=attachments,
                                           code=Codens.AttachmentGroup,
                                           version=Vrsn_2_0))
        return bytes(kel + tel)
