"""Sally-like application policy over native and legacy KERIpy verification.

Composition informed by Sally ed789de (Apache-2.0); cryptographic verification
remains in Exchanger, native IPEX/Rever, and legacy Tevery/Verifier.
"""
from dataclasses import asdict, dataclass, field
import math
import json
from urllib.parse import urlsplit

import falcon
from hio.base import doing
from hio.core import http

from keri import Vrsn_1_0, Vrsn_2_0, Kinds
from keri.acdc import Regery
from keri.acdc.regeventing import issuerRegistry
from keri.app import ipexing, agenting
from keri.app.dolly.projecting import project
from keri.app.httping import CESR_CONTENT_TYPE, CESR_ATTACHMENT_HEADER
from keri.app.indirecting import createHttpServer
from keri.app.registrar.serving import Context as EvidenceContext, signedQuery, KEL_DEPENDENCIES
from keri.core import Parser, SerderACDC, SerderKERI, Revery
from keri.db import dbing, koming
from keri.db.basing import BaserDoer
from keri.help import helping
from keri.kering import (ValidationError, MissingChainError, MissingSchemaError,
                         MissingRegistryError, MissingAnchorError)
from keri.peer import exchanging
from keri.vdr import verifying, eventing as legacyEventing


@dataclass
class Submission:
    grant: str
    registries: list = field(default_factory=list)
    state: str = 'pending'
    reason: str = ''
    payload: dict = field(default_factory=dict)
    delivered: bool = False


@dataclass
class Observation:
    observed: str
    head: str
    observer: str


@dataclass
class LegacyQuery:
    credential: str
    registry: str
    issuer: str
    started: str
    reply: str = ''


class DollyBaser(dbing.LMDBer):
    TailDirPath = 'keri/dolly'
    AltTailDirPath = '.keri/dolly'

    def reopen(self, **kwa):
        super().reopen(**kwa)
        self.submissions = koming.Komer(db=self, subkey='submissions.', klas=Submission)
        self.observed = koming.Komer(db=self, subkey='observed.', klas=Observation)
        self.legacyQueries = koming.Komer(db=self, subkey='legacy-queries.', klas=LegacyQuery)
        return self.opened


class Notices:
    def add(self, attrs):
        # Durable EXN state, not notification delivery, drives application work.
        pass


class Context(doing.DoDoer):
    def __init__(self, hby, hab, *, issuers, schemas, fields, required=(),
                 observer, webhook, maximumAge=15.0, timeout=5.0,
                 db=None, evidence=None, legacy=None, legacySources=(), graphPolicy=None):
        if any(not math.isfinite(value) or value <= 0 for value in (maximumAge, timeout)):
            raise ValueError('Dolly freshness and request timeouts must be finite and positive')
        self.hby, self.hab = hby, hab
        self.issuers, self.schemas = set(issuers), set(schemas)
        self.fields, self.required = dict(fields), tuple(required)
        self.observer, self.webhook = observer, webhook
        self.maximumAge, self.timeout = maximumAge, timeout
        self.legacySources = tuple(legacySources)
        self.db = db if db is not None else DollyBaser(name=hby.name, base=hby.base, temp=hby.temp)
        self.evidence = evidence if evidence is not None else EvidenceContext(hby)
        self.rgy = Regery(hby, name=hby.name, baser=self.evidence.reger)
        self.legacy = legacy if legacy is not None else verifying.Verifier(hby,
            reger=legacyEventing.Reger(name=hby.name, base=hby.base, temp=hby.temp))
        self.rvy = Revery(db=hby.db)
        self.evidence.kvy.rvy = self.rvy
        self.evidence.kvy.registerReplyRoutes(self.rvy.rtr)
        self.legacy.tvy.rvy = self.rvy
        self.legacy.tvy.registerReplyRoutes(self.rvy.rtr)
        self.inquisitor = agenting.WitnessInquisitor(hby=hby)
        self.exc = exchanging.Exchanger(hby, handlers=[])
        ipexing.loadHandlers(hby, self.exc, Notices(), self.rgy, graphPolicy=graphPolicy)
        self.native = self.exc.routes['/ipex/grant'].native
        self.app = falcon.App()
        self.app.add_route('/ingest', IntakeEnd(self))
        self.app.add_route('/', IntakeEnd(self))
        self.app.add_route('/health', HealthEnd())
        self.clients = set()
        super().__init__(doers=[self.inquisitor, doing.doify(self.workDo)])

    def _parser(self, version):
        return Parser(kvy=self.evidence.kvy, rgy=self.evidence.rever,
            tvy=self.legacy.tvy, vry=self.legacy, exc=self.exc, rvy=self.rvy,
            local=False, version=version)

    def ingest(self, raw, version=Vrsn_2_0):
        """Receive ordinary CESR; HTTP success only means intake, never acceptance."""
        parser, ims, received = self._parser(version), bytearray(raw), []
        while ims:
            size = len(ims)
            dom = parser.parseOne(ims=ims, processive=False, local=False)
            if dom is None or dom.serder is None or len(ims) >= size:
                raise ValidationError('incomplete credential evidence stream')
            serder = dom.serder
            if serder.ilk in ('vcp', 'vrt', 'iss', 'bis', 'rev', 'brv'):
                # Conventional TEL replay includes the registry inception again.
                # An exact accepted slot is already core-verified; a different
                # digest still goes through Tevery's conflict checks.
                if self.legacy.reger.tels.get(keys=serder.pre, on=serder.sn) == serder.said:
                    continue
            if serder.ilk == 'exn' and serder.route == '/ipex/grant':
                recipient = serder.sad.get('ri') if serder.pvrsn.major == 2 else serder.sad['a'].get('i')
                if recipient != self.hab.pre:
                    raise ValidationError('grant is addressed to a different disclosee')
                registries = sorted({regid for item in dom.nests
                                     if (regid := issuerRegistry(item.serder))})
                self.db.submissions.put((serder.said,), Submission(serder.said, registries))
                received.append(serder.said)
            try:
                parser.msgProcess(asdict(dom), kvy=self.evidence.kvy, rgy=self.evidence.rever,
                    tvy=self.legacy.tvy, vry=self.legacy, exc=self.exc, rvy=self.rvy)
            except KEL_DEPENDENCIES + (MissingChainError, MissingSchemaError):
                # Concrete core processors retain dependencies in their escrows.
                continue
        self.process()
        return [{'grant': said, 'state': self.db.submissions.get((said,)).state}
                for said in received]

    def fresh(self, regid):
        record = self.db.observed.get((regid,))
        head = self.rgy.store.head(regid)
        if (record is None or record.observer != self.observer
                or head is None or record.head != head.qb64):
            return False
        age = (helping.nowUTC() - helping.fromIso8601(record.observed)).total_seconds()
        return 0 <= age <= self.maximumAge

    def observe(self, regid, response):
        """Retain a configured observer report only after locally verifying its head."""
        headers = response.get('headers', {})
        if (response['status'] != 200 or headers.get('observer-evidence-state') != 'fresh'
                or headers.get('content-type', '').split(';')[0] != CESR_CONTENT_TYPE):
            return False
        stamp, head = headers.get('observer-observed-at'), headers.get('observer-registry-head')
        try:
            age = (helping.nowUTC() - helping.fromIso8601(stamp)).total_seconds()
        except (ValueError, TypeError):
            return False
        if not 0 <= age <= self.maximumAge:
            return False
        result = self.evidence.ingest(response['body'])
        accepted = self.rgy.store.head(regid)
        if (result['rejected'] or result['pending'] or accepted is None
                or accepted.qb64 != head or result['heads'].get(regid) != head):
            return False
        self.db.observed.pin((regid,), Observation(stamp, head, self.observer))
        return True

    def _nativeCredential(self, exn):
        # This reuses native semantic verification, including schema and graph.
        if not self.native.verifyAccepted(exn.said):
            raise ValidationError('native IPEX proof or semantics failed')
        nests = exchanging.loadParsedNestedSubstreams(self.hby, exn.said)
        origin = exn.sad['a']['o'][0]
        for nest in nests:
            credential = nest.serder
            declared = issuerRegistry(credential)
            registries = ({declared} if declared else {pre.qb64 for pre, _, _ in nest.ssts
                if pre.qb64 != credential.israid and pre.qb64 not in self.hby.kevers})
            for regid in registries:
                if not self.fresh(regid):
                    raise MissingChainError('observer evidence is missing or stale')
                state = self.native._vetRegistry(regid, self.native._blindProofs(nest),
                                                 credential.said, acdc=credential)
                if state is None or state.state != 'issued':
                    raise ValidationError('credential is not currently issued')
            for _, regid in self.native._presentationRegistries(credential) or []:
                if not self.fresh(regid):
                    raise MissingChainError('presentation registry observation is missing or stale')
        return next(nest.serder for nest in nests if nest.serder.said == origin)

    def _legacyCredential(self, exn):
        exchanging.verify(self.hby, exn)
        _, pathed = exchanging.cloneMessage(self.hby, exn.said)
        embeds = exn.sad.get('e', {})
        if 'acdc' not in embeds:
            raise ValidationError('legacy grant has no credential')
        parser = self._parser(Vrsn_1_0)
        credential = SerderACDC(sad=embeds['acdc'])
        for label in ('anc', 'iss', 'acdc'):
            if label not in embeds:
                continue
            serder = (SerderACDC if label == 'acdc' else SerderKERI)(sad=embeds[label])
            if label == 'iss' and self.legacy.reger.tels.get(keys=serder.pre, on=serder.sn) == serder.said:
                continue
            if label == 'acdc' and self.legacy.reger.saved.get((credential.said,)) is not None:
                continue
            try:
                parser.parseOne(ims=bytearray(serder.raw) + pathed.get(label, b''))
            except KEL_DEPENDENCIES + (MissingRegistryError, MissingAnchorError) as error:
                self._queryLegacy(credential)
                raise MissingChainError(str(error)) from error
        self.legacy.tvy.processEscrows()
        self.legacy.processEscrows()
        if self.legacy.reger.saved.get((credential.said,)) is None:
            raise MissingChainError('legacy credential verification is pending')
        tever = self.legacy.tevers.get(credential.regid)
        state = tever.vcState(credential.said) if tever else None
        if state is None or state.et not in ('iss', 'bis'):
            raise ValidationError('credential is not currently issued')
        observation = self.db.observed.get(('legacy', credential.said))
        if observation is not None and observation.head == state.d and observation.observer in self.legacySources:
            age = (helping.nowUTC() - helping.fromIso8601(observation.observed)).total_seconds()
            if 0 <= age <= self.maximumAge:
                return credential
        self._queryLegacy(credential)
        raise MissingChainError('legacy issuance is authentic; current TEL observation is not established')

    def _queryLegacy(self, credential):
        """Use conventional legacy TEL replay and TSN queries to configured sources."""
        if not self.legacySources:
            return
        previous = self.db.legacyQueries.get((credential.said,))
        if previous is not None:
            age = (helping.nowUTC() - helping.fromIso8601(previous.started)).total_seconds()
            if age < self.maximumAge:
                return
        record = LegacyQuery(credential.said, credential.regid, credential.israid, helping.nowIso8601())
        self.db.legacyQueries.pin((credential.said,), record)
        for route in ('tels', 'tsn'):
            self.inquisitor.telquery(ri=credential.regid, i=credential.said, pre=credential.israid,
                src=self.hab.pre, hab=self.hab, wits=list(self.legacySources), r=route,
                version=Vrsn_1_0, pvrsn=Vrsn_1_0, gvrsn=Vrsn_1_0, kind=Kinds.json)

    def _legacyReports(self):
        """Consume only core source-authenticated BADA-accepted credential TSNs.

        This is application freshness relative to the configured source's report,
        not cryptographic proof of global latest state or historical authority.
        """
        for keys, query in self.db.legacyQueries.getTopItemIter():
            for source in self.legacySources:
                current = self.legacy.reger.txnsb.current((query.credential, source))
                if current is None:
                    continue
                reply = self.legacy.reger.txnsb.serderdb.get((current.qb64,))
                if reply is None or reply.said == query.reply:
                    continue
                stamp = helping.fromIso8601(reply.sad['dt'])
                age = (helping.nowUTC() - stamp).total_seconds()
                if stamp < helping.fromIso8601(query.started) or not 0 <= age <= self.maximumAge:
                    continue
                state = self.legacy.tevers[query.registry].vcState(query.credential)
                if state is None or state.d != current.qb64:
                    continue
                self.db.observed.pin(('legacy', query.credential),
                    Observation(reply.sad['dt'], current.qb64, source))
                query.reply = reply.said
                self.db.legacyQueries.pin(keys, query)

    def process(self):
        self.evidence.kvy.processEscrows()
        self.evidence.rever.processEscrows()
        self.legacy.tvy.processEscrows()
        self.legacy.processEscrows()
        self.rvy.processEscrowReply()
        self._legacyReports()
        self.exc.processEscrow()
        for keys, record in self.db.submissions.getTopItemIter():
            if record.state != 'pending' or not self.exc.complete(record.grant):
                continue
            exn = self.hby.db.exns.get((record.grant,))
            try:
                credential = (self._nativeCredential(exn) if exn.pvrsn.major == 2
                              else self._legacyCredential(exn))
                schema = credential.sad.get('s')
                schema = schema.get('$id') if isinstance(schema, dict) else schema
                if credential.israid not in self.issuers or schema not in self.schemas:
                    raise ValidationError('issuer or schema is outside application policy')
                values, disclosure = project(credential, self.fields, self.required)
                record.payload = dict(schema='dolly.accepted-credential/v1',
                    decision='accepted', credential=credential.said, grant=exn.said,
                    issuer=credential.israid, presenter=exn.pre, verifier=self.hab.pre,
                    credentialSchema=schema, protocol=exn.pvrsn.major,
                    business=values, disclosure=disclosure, standing='issued',
                    acceptedAt=helping.nowIso8601())
                record.state, record.reason = 'accepted', ''
            except (MissingChainError, MissingSchemaError) as error:
                record.reason = str(error)
            except ValidationError as error:
                record.state, record.reason = 'rejected', str(error)
            self.db.submissions.pin(keys, record)

    def request(self, url, *, body=None, data=None):
        target = urlsplit(url)
        client = http.clienting.Client(scheme=target.scheme, hostname=target.hostname,
            port=target.port or (443 if target.scheme == 'https' else 80))
        doer = http.clienting.ClientDoer(client)
        self.clients.add(client)
        self.extend([doer])
        try:
            client.request(method='POST', path=target.path or '/', body=body, data=data,
                headers={'Content-Type': CESR_CONTENT_TYPE if body is not None else 'application/json'})
            deadline = self.tyme + self.timeout
            while not client.responses and self.tyme < deadline:
                yield self.tock
            return client.responses.popleft() if client.responses else None
        finally:
            self.remove([doer])
            client.close()
            self.clients.discard(client)

    def workDo(self, tymth=None, tock=0.03125, **kwa):
        self.wind(tymth)
        yield tock
        while True:
            registries = set()
            for _, record in self.db.submissions.getTopItemIter():
                if record.state != 'pending':
                    continue
                exn = (self.hby.db.exns.get((record.grant,))
                       or self.hby.db.epse.get((record.grant,)))
                if exn is None or exn.pvrsn.major != 2:
                    continue
                try:
                    # Missing TEL does not authorize unauthenticated fetch hints.
                    # Authentication and retained nests belong to core Exchanger.
                    exchanging.verify(self.hby, exn)
                except ValidationError:
                    continue
                for nest in exchanging.loadParsedNestedSubstreams(self.hby, exn.said):
                    if (regid := issuerRegistry(nest.serder)) and not self.fresh(regid):
                        registries.add(regid)
                    registries.update(regid for _, regid in
                        self.native._presentationRegistries(nest.serder) or []
                        if not self.fresh(regid))
                    # Nonissuer source triples are untrusted fetch hints until
                    # the core validates their exact accepted TEL event.
                    registries.update(pre.qb64 for pre, _, _ in nest.ssts
                        if pre.qb64 != nest.serder.israid and pre.qb64 not in self.hby.kevers
                        and not self.fresh(pre.qb64))
            for regid in sorted(registries):
                response = yield from self.request(self.observer,
                    body=signedQuery(self.hab, 'tels', {'i': regid}))
                if response is not None:
                    self.observe(regid, response)
            self.process()
            for keys, record in self.db.submissions.getTopItemIter():
                if record.state == 'accepted' and not record.delivered:
                    response = yield from self.request(self.webhook, data=record.payload)
                    if response is not None and 200 <= response['status'] < 300:
                        record.delivered = True
                        self.db.submissions.pin(keys, record)
            # Ordinary application retry; no distributed exactly-once promise.
            started = self.tyme
            while self.tyme < started + 1.0:
                yield tock

    def close(self):
        for client in tuple(self.clients):
            client.close()
        self.db.close()
        self.evidence.close()
        self.legacy.reger.close()


class IntakeEnd:
    def __init__(self, ctx):
        self.ctx = ctx

    def on_post(self, req, rep):
        if (req.content_type or '').split(';')[0] != CESR_CONTENT_TYPE:
            raise falcon.HTTPUnsupportedMediaType()
        raw = req.bounded_stream.read()
        try:
            attachment = req.get_header(CESR_ATTACHMENT_HEADER)
            first = None
            if attachment is not None:
                first = SerderKERI(sad=json.loads(raw))
                raw = first.raw + attachment.encode()
            elif raw.startswith(b'{'):
                first = SerderKERI(raw=raw)
            default = str((first.gvrsn or first.pvrsn).major) if first else '2'
            genus = req.get_header('CESR-Genus', default=default)
            if genus not in ('1', '2'):
                raise ValidationError('CESR-Genus must be 1 or 2')
            rep.media = self.ctx.ingest(raw,
                version=Vrsn_1_0 if genus == '1' else Vrsn_2_0)
        except (ValidationError, ValueError, TypeError) as error:
            raise falcon.HTTPBadRequest(description=str(error)) from error
        rep.status = falcon.HTTP_202

    on_put = on_post


class HealthEnd:
    def on_get(self, req, rep):
        rep.media = {'application': 'dolly', 'status': 'ready'}


def setup(hby, hab, *, host='127.0.0.1', port=6644, keypath=None, certpath=None,
          cafilepath=None, **kwa):
    context = Context(hby, hab, **kwa)
    server = createHttpServer(host=host, port=port, app=context.app,
                              keypath=keypath, certpath=certpath, cafilepath=cafilepath)
    return context, [BaserDoer(baser=context.db), BaserDoer(baser=context.evidence.reger),
                     BaserDoer(baser=context.legacy.reger), context, http.ServerDoer(server=server)]
