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
        self.data = data if data is not None else {
            'kram': {'enabled': True, 'denials': [],
                     'caches': {'~': [1000, 5000, 60000, 300000, 5000, 60000, 300000]}}}
        block = self.data.get('kram', {})
        if block.get('enabled') is not True or block.get('denials'):
            raise ConfigurationError('service requests require enabled KRAM without denial exemptions')

    def get(self):
        return self.data


def signedQuery(hab, route, query=None):
    """Construct a fresh signed CESR service query; callers retain no secret here."""
    from keri.core import query as makeQuery
    from keri.help import helping
    serder = makeQuery(pre=hab.pre, route=route, query=query or {},
                       stamp=helping.nowIso8601(), version=Vrsn_2_0)
    return bytes(hab.endorse(serder, last=True, framed=False, gvrsn=Vrsn_2_0))


def authenticate(req, ctx, allowed, routes):
    """Authenticate exactly one signed qry and its explicit service authorization."""
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
        """Compose authenticated intake, registry evidence, and cache maintenance.

        Args:
            hby: Habery owning KEL and KRAM persistence; caller closes it.
            publishers: AIDs authorized to publish public registry evidence.
            observers: AIDs authorized to retrieve hosted evidence.
            reger: Optional existing native registry store, closed by ``close``.
            config: Optional enabled KRAM policy accepted by ServiceConfig.

        Schedule this context as a child doer for its entire service lifetime.
        Its single pruner uses the same Kramer as intake; cancellation stops
        maintenance before the caller closes stores. Reopening resumes pruning
        persisted caches under the existing KRAM rules, without erasing evidence.
        """
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
        """Parse public evidence and summarize the shared Rever's final state.

        raw is a CESR stream of KEL/native TEL evidence. Returns accepted,
        pending and rejected counts with accepted heads. An occupied TEL slot
        does not reject a rival whose independent anchor is still pending;
        authenticated conflicts and invalid evidence remain rejected. Intake
        errors are reported in the rejected stream entry rather than raised.
        """
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
        """Check exact ordinary KEL/receipt escrow membership, not just exception type."""
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
        return sorted(keys[0] for keys, _ in self.reger.heads.getTopItemIter())

    def clone(self, regks=None, sn=0):
        """Clone accepted controller evidence followed by accepted native TELs."""
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
        self.wind(tymth)
        yield tock
        while True:
            self.kvy.processEscrows()
            self.rever.processEscrows()
            yield tock

    def close(self):
        self.reger.close()


class HealthEnd:
    def on_get(self, req, rep):
        rep.media = {'status': 'ok'}


class IngestEnd:
    def __init__(self, ctx):
        self.ctx = ctx

    def on_post(self, req, rep):
        _, qry = authenticate(req, self.ctx, self.ctx.publishers, ('tels/publish',))
        raw = qry.get('stream')
        if not isinstance(raw, str) or not raw:
            raise falcon.HTTPBadRequest(description='q.stream must contain public CESR evidence')
        rep.media = self.ctx.ingest(raw.encode())
        rep.status = (falcon.HTTP_422 if rep.media['rejected'] else
                      falcon.HTTP_202 if rep.media['pending'] else falcon.HTTP_200)


class BulkEnd:
    def __init__(self, ctx):
        self.ctx = ctx

    def on_post(self, req, rep):
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
    """Return the service context and ordinary HTTP server doer."""
    ctx = Context(hby, **kwa)
    server = createHttpServer(host=host, port=port, app=ctx.app,
                              keypath=keypath, certpath=certpath, cafilepath=cafilepath)
    return ctx, [BaserDoer(baser=ctx.reger), ctx, http.ServerDoer(server=server)]
