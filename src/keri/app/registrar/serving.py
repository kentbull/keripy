"""Authorized public-evidence hosting, adapted from kf-registrar (Apache-2.0).

The application routes and topology derive from keri-foundation/kf-registrar
bf14eac4d644275a13cbd3c5900cc2e4dd7c11d1. Registry acceptance belongs to Rever.
"""
from dataclasses import asdict

import falcon
from hio.base import doing
from hio.core import http

from keri import Vrsn_2_0
from keri.acdc.regbasing import RegBaser
from keri.acdc.regeventing import Rever
from keri.app.httping import CESR_CONTENT_TYPE
from keri.app.indirecting import createHttpServer
from keri.db.basing import BaserDoer
from keri.core import Kevery, Parser, SerderACDC, Counter, Codens, Number, NumDex
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
    """Create a fresh, signed native service query with existing habitat keys.

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


def authenticate(req, ctx, allowed, routes):
    """Authenticate one complete native query and enforce the service allowlist.

        Args:
            req: Falcon request carrying one signed CESR query in its bounded body.
            ctx (Context): Service holding enabled KRAM and authenticated KEL evidence.
            allowed (Collection[str]): Explicit requester AIDs permitted for this route.
            routes (Collection[str]): Query routes this endpoint accepts.

        Returns:
            tuple: Authenticated query Serder and its query-attribute map.

        Raises:
            falcon.HTTPError: Unsupported media, malformed/multiple messages, forbidden
                AID/route, unavailable authentication, or invalid/replayed evidence.

        Authorization alone cannot authenticate input. KRAM verifies the exact request
        and updates replay/liveness state before endpoint code consumes its payload."""
    if (req.content_type or '').split(';')[0].lower() != CESR_CONTENT_TYPE:
        raise falcon.HTTPUnsupportedMediaType()
    ims = bytearray(req.bounded_stream.read())
    if not ims:
        raise falcon.HTTPBadRequest(description='empty query')
    try:
        dom = Parser(version=Vrsn_2_0).parseOne(ims=ims, processive=False, local=False)
        if dom is None or dom.serder is None or ims:
            raise ValueError('expected exactly one complete signed query')
        serder = dom.serder
        if serder.ilk != 'qry' or serder.pvrsn != Vrsn_2_0:
            raise ValueError('expected a native signed query')
    except Exception as ex:
        raise falcon.HTTPBadRequest(description=str(ex)) from ex
    if serder.route not in routes or serder.pre not in allowed:
        raise falcon.HTTPForbidden(description='requester or route is not authorized')
    if not ctx.kvy.kramer or not ctx.kvy.kramer.enabled:
        raise falcon.HTTPServiceUnavailable(description='request authentication unavailable')
    try:
        kwa = {key: getattr(dom, key) for key in ('sigers', 'cigars', 'lsgs', 'tsgs', 'sscs', 'ssts')}
        if ctx.kvy.kramer.intake(serder, kwa) is None:
            raise ValueError('KRAM rejected request')
    except Exception as ex:
        raise falcon.HTTPUnauthorized(description=str(ex)) from ex
    qry = serder.sad.get('q')
    if not isinstance(qry, dict):
        raise falcon.HTTPBadRequest(description='query must be an object')
    return serder, qry


class Context(doing.DoDoer):
    """Own concrete remote KEL/native registry processors and their stores."""

    def __init__(self, hby, *, publishers=(), observers=(), reger=None, config=None):
        """Compose public evidence intake with one owned KRAM maintenance runtime.

            Args:
                hby: Caller-owned Habery containing authenticated KEL and KRAM persistence.
                publishers (Iterable[str]): Explicit AIDs allowed to publish public evidence.
                observers (Iterable[str]): Explicit AIDs allowed to retrieve bulk evidence.
                reger (RegBaser | None): Registry store, closed by this context's close().
                config (dict | None): Enabled KRAM settings accepted by ServiceConfig.

            Returns:
                None. Schedule the context for its entire service lifetime; its single
                Pruner and escrow child stop before the caller closes backing stores.

            Raises:
                ConfigurationError: Requested service policy disables required KRAM.

            KEL/native TEL acceptance remains in the shared processors. Reopening resumes
            persisted cache maintenance without deleting accepted evidence."""
        self.hby = hby
        self.publishers, self.observers = set(publishers), set(observers)
        self.cf = ServiceConfig(config)
        self.kvy = Kevery(db=hby.db, cf=self.cf, enableKram=True, lax=False, local=False)
        self.kvy.kramer = Kramer(db=hby.db, cf=self.cf, cues=self.kvy.cues)
        self.pruner = Pruner(self.kvy.kramer, tock=1.0)
        self.reger = reger if reger is not None else RegBaser(
            name=hby.name, base=hby.base, temp=hby.temp)
        self.rever = Rever(db=hby.db, reger=self.reger)
        self.store = self.rever.store
        self.parser = Parser(kvy=self.kvy, rgy=self.rever, local=False, version=Vrsn_2_0)
        self.app = falcon.App()
        self.app.add_route('/', BulkEnd(self))
        self.app.add_route('/ingest', IngestEnd(self))
        self.app.add_route('/health', HealthEnd())
        super().__init__(doers=[self.pruner, doing.doify(self.escrowDo)])

    def ingest(self, raw):
        """Process public evidence and summarize final shared-processor outcomes.

            Args:
                raw (bytes): Complete or concatenated CESR KEL/native TEL evidence stream.

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
                    self.rever.processEvent(serder, sscs=dom.sscs, ssts=dom.ssts)
                    events.append(serder)
                else:
                    if serder.ilk not in ('icp', 'dip', 'rot', 'drt', 'ixn', 'rct'):
                        raise ValidationError('hosting intake accepts only public KEL/native TEL evidence')
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
        """Enumerate only registries with an accepted native head.

            Returns:
                list[str]: Sorted registry SAIDs; staged inception bodies are excluded."""
        return sorted(keys[0] for keys, _ in self.reger.heads.getTopItemIter())

    def clone(self, regks=None, sn=0):
        """Clone accepted controller KEL evidence and selected accepted native TELs.

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
            issuer = rip.sad['i']
            if issuer not in issuers:
                kever = self.hby.kevers[issuer]
                kel.extend(b''.join(self.hby.db.cloneDelegation(kever, gvrsn=Vrsn_2_0)))
                kel.extend(b''.join(self.hby.db.clonePreIter(pre=issuer, gvrsn=Vrsn_2_0)))
                issuers.add(issuer)
            for raw in self.store.cloneTelIter(regk, sn=sn):
                tel.extend(raw)
                tel.extend(Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b)
        return bytes(kel + tel)

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
        """Close the native registry store after child doers have stopped.

            Returns:
                None. Habery remains caller-owned; scheduling cancellation must precede
                this close so pruning/escrow work cannot access a closed environment."""
        self.reger.close()


class HealthEnd:
    def on_get(self, req, rep):
        """Return service availability without claiming credential acceptance.

            Args:
                req: Falcon health request; body is unused.
                rep: Falcon response whose media is set to status ok.

            Returns:
                None. Health is not authorization, freshness, or a verification verdict."""
        rep.media = {'status': 'ok'}


class IngestEnd:
    def __init__(self, ctx):
        """Bind authorized public-evidence publication to one service context.

            Args:
                ctx (Context): Existing processor/runtime owner; endpoint never closes it.

            Returns:
                None."""
        self.ctx = ctx

    def on_post(self, req, rep):
        """Authenticate publication and classify the supplied public CESR stream.

            Args:
                req: Falcon request with an allowlisted signed tels/publish query.
                rep: Response receiving intake summary and 200/202/422 outcome status.

            Returns:
                None. Intake acknowledgement does not imply every dependency completed.

            Raises:
                falcon.HTTPError: Query authorization/authentication or stream field fails."""
        _, qry = authenticate(req, self.ctx, self.ctx.publishers, ('tels/publish',))
        raw = qry.get('stream')
        if not isinstance(raw, str) or not raw:
            raise falcon.HTTPBadRequest(description='q.stream must contain public CESR evidence')
        rep.media = self.ctx.ingest(raw.encode())
        rep.status = (falcon.HTTP_422 if rep.media['rejected'] else
                      falcon.HTTP_202 if rep.media['pending'] else falcon.HTTP_200)


class BulkEnd:
    def __init__(self, ctx):
        """Bind cache-only bulk retrieval to the existing evidence owner.

            Args:
                ctx (Context): Service owning accepted KEL/TEL records and allowlists.

            Returns:
                None. Endpoint creation schedules no network acquisition."""
        self.ctx = ctx

    def on_post(self, req, rep):
        """Authenticate registry-scoped bulk retrieval without credential lookup.

            Args:
                req: Falcon request containing an authorized tels/bulk or regs query.
                rep: Response receiving accepted evidence bytes and CESR content type.

            Returns:
                None. Query handling never authorizes or accelerates an observer pull.

            Raises:
                falcon.HTTPError: Invalid query/ordinal/scope, forbidden vcid, missing
                    accepted registry, or authentication/authorization failure."""
        _, qry = authenticate(req, self.ctx, self.ctx.observers, ('tels/bulk', 'regs'))
        if 'vcid' in qry:
            raise falcon.HTTPForbidden(description='credential queries are not served here')
        raw = qry.get('i')
        if raw is not None and not isinstance(raw, (str, list)):
            raise falcon.HTTPBadRequest(description='invalid registry scope')
        regks = [raw] if isinstance(raw, str) and raw else raw or None
        sn = qry.get('sn', 0)
        if not isinstance(sn, int) or sn < 0:
            raise falcon.HTTPBadRequest(description='sn must be a nonnegative integer')
        try:
            rep.data = self.ctx.clone(regks, sn=sn)
        except KeyError as ex:
            raise falcon.HTTPNotFound(description='unknown accepted registry') from ex
        rep.content_type = CESR_CONTENT_TYPE


def setup(hby, *, host='127.0.0.1', port=6632, keypath=None, certpath=None,
          cafilepath=None, **kwa):
    """Compose the registrar context and its HTTP/service persistence doers.

        Args:
            hby: Existing caller-owned Habery with controller evidence and keys.
            host (str): HTTP listening interface.
            port (int): HTTP listening port.
            keypath (str | None): Optional TLS private-key path.
            certpath (str | None): Optional TLS certificate path.
            cafilepath (str | None): Optional TLS CA path.
            **kwa: Context publisher/observer allowlists, registry store, and KRAM policy.

        Returns:
            tuple: Context and doers owning registry persistence, maintenance, and HTTP.

        Configuration/listener failures propagate. The caller schedules and cancels
        returned doers, then closes stores; setup alone is not a running service."""
    ctx = Context(hby, **kwa)
    server = createHttpServer(host=host, port=port, app=ctx.app,
                              keypath=keypath, certpath=certpath, cafilepath=cafilepath)
    return ctx, [BaserDoer(baser=ctx.reger), ctx, http.ServerDoer(server=server)]
