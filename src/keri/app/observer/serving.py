"""Cache-only queries and independent cooperative public-evidence synchronization.

Adapted from keri-foundation/kf-observer d6368aef9497452f5aa2a0657abe1adf5645c69b
(Apache-2.0). No presentation request can schedule or accelerate a registrar pull.
"""
from dataclasses import dataclass, field
from collections import deque
from math import isfinite
from urllib.parse import urlsplit

import falcon
from hio.base import doing
from hio.core import http

from keri.app.httping import CESR_CONTENT_TYPE
from keri.app.indirecting import createHttpServer
from keri.db.basing import BaserDoer
from keri.app.registrar.serving import Context as EvidenceContext
from keri.app.registrar.serving import HealthEnd, authenticate, signedQuery
from keri.db import dbing, koming
from keri.help import helping


@dataclass
class Observation:
    """Durable completed-pull time and exact accepted heads for one source URL.

        completed is receiver observation time, not issuer publication time. heads
        binds that observation to selected accepted registry histories."""
    completed: str = ''
    heads: dict = field(default_factory=dict)


class ObservationBaser(dbing.LMDBer):
    """Caller-owned LMDB persistence for completed source observations."""
    TailDirPath = 'keri/observer'
    AltTailDirPath = '.keri/observer'

    def reopen(self, **kwa):
        """Open durable source-URL observation records using ordinary LMDB options.

            Args:
                **kwa: LMDBer reopen/path settings.

            Returns:
                bool: Whether observation persistence is open. Storage failures propagate."""
        super().reopen(**kwa)
        self.observations = koming.Komer(db=self, subkey='observations.', klas=Observation)
        return self.opened


class Context(EvidenceContext):
    """Share authenticated evidence processing while separating source freshness.

        Freshness describes an independently completed configured-source pull. A
        presentation query can read that result but cannot trigger acquisition."""
    def __init__(self, hby, *, readers=(), observations=None, maximumAge=15.0,
                 urls=(), **kwa):
        """Compose observer evidence, source authorization, and freshness persistence.

            Args:
                hby: Caller-owned authenticated Habery.
                readers (Iterable[str]): Explicit AIDs allowed to query this observer cache.
                observations (ObservationBaser | None): Store closed by this context.
                maximumAge (float): Positive finite application freshness limit in seconds.
                urls (Iterable[str]): Current authoritative source URLs for completed pulls.
                **kwa: Shared EvidenceContext registry/KRAM configuration and allowlists.

            Returns:
                None. Existing evidence remains when source authority changes; old URLs
                cannot confer current freshness merely because their rows remain stored.

            Raises:
                ValueError: maximumAge is not positive and finite.
                ConfigurationError: Shared service authentication policy is invalid."""
        if not isfinite(maximumAge) or maximumAge <= 0:
            raise ValueError('maximum observation age must be finite and positive')
        super().__init__(hby, **kwa)
        self.readers = set(readers)
        self.maximumAge = maximumAge
        self.urls = frozenset(urls)
        self.observations = observations if observations is not None else ObservationBaser(
            name=hby.name, base=hby.base, temp=hby.temp)
        self.app = falcon.App()
        self.app.add_route('/', QueryEnd(self))
        self.app.add_route('/health', HealthEnd())

    def observe(self, url, raw):
        """Record freshness only after an independently acquired complete source scope.

            Args:
                url (str): Configured registrar source whose pull produced raw evidence.
                raw (bytes): Public CESR KEL/TEL stream processed by the shared intake.

            Returns:
                dict: Intake summary; unsuccessful/incomplete pulls retain the older row.

            Current-batch failures and unresolved unaccepted ordinals block completion.
            Old unanchored rivals at accepted slots cannot monopolize a later clean pull.
            A fresh selected chain does not certify absence of competing issuer evidence."""
        result = self.ingest(raw)
        # Only unresolved acceptance dependencies block subsequent clean pulls.
        # A raw rival cannot displace or monopolize its already accepted slot.
        pending = any(self.store.seqSaider(keys[0], sn) is None
                      for escrow in (self.reger.maes, self.reger.ooes)
                      for keys, sn, _ in escrow.getTopItemIter())
        previous = self.observations.observations.get((url,))
        heads = result['heads']
        complete = (not previous or set(previous.heads).issubset(heads))
        complete = complete and all(self.store.head(regk).qb64 == said
                                    for regk, said in heads.items())
        if (url in self.urls and not result['rejected'] and not result['pending']
                and not pending and complete):
            self.observations.observations.pin(
                keys=(url,), val=Observation(helping.nowIso8601(), heads))
        return result

    def close(self):
        """Close observation and native registry stores after runtime cancellation.

            Returns:
                None. The shared Habery remains caller-owned."""
        self.observations.close()
        super().close()


class QueryEnd:
    def __init__(self, ctx):
        """Bind authenticated cache queries to an existing observer.

            Args:
                ctx (Context): Evidence, allowlists, configured sources, and observations.

            Returns:
                None. Construction schedules no pull or other network work."""
        self.ctx = ctx

    def on_post(self, req, rep):
        """Serve authenticated registry evidence only with a current observation.

            Args:
                req: Falcon signed tels/tels/head query naming one registry and ordinal.
                rep: Response receiving accepted CESR bytes and observation/head headers.

            Returns:
                None. A cache query never schedules or accelerates acquisition.

            Raises:
                falcon.HTTPError: Authorization, malformed scope, absent/pending registry,
                    missing completed observation, or stale/future observation time.

            Source URL and exact accepted head must both match; retained old-source facts
            alone cannot authorize a freshness claim."""
        _, qry = authenticate(req, self.ctx, self.ctx.readers, ('tels', 'tels/head'))
        regk = qry.get('i')
        if not isinstance(regk, str) or not regk or 'vcid' in qry:
            raise falcon.HTTPBadRequest(description='q.i must identify one registry')
        if self.ctx.store.head(regk) is None:
            if any(keys[0] == regk for escrow in (self.ctx.reger.maes, self.ctx.reger.ooes)
                   for keys, _, _ in escrow.getTopItemIter()):
                raise falcon.HTTPServiceUnavailable(description='registry dependencies are pending')
            raise falcon.HTTPNotFound(description='unknown registry in local observer cache')
        sn = qry.get('sn', 0)
        if not isinstance(sn, int) or sn < 0:
            raise falcon.HTTPBadRequest(description='sn must be a nonnegative integer')
        observations = [record for url in self.ctx.urls
                        if (record := self.ctx.observations.observations.get((url,)))
                        and record.heads.get(regk) == self.ctx.store.head(regk).qb64]
        if not observations:
            raise falcon.HTTPServiceUnavailable(description='no completed observation for accepted head')
        completed = max(record.completed for record in observations)
        age = (helping.nowUTC() - helping.fromIso8601(completed)).total_seconds()
        if age < 0 or age > self.ctx.maximumAge:
            raise falcon.HTTPServiceUnavailable(description='cached observation is stale')
        # Every response includes the chain needed for local authentication.
        rep.data = self.ctx.clone([regk], sn=sn)
        rep.content_type = CESR_CONTENT_TYPE
        rep.set_header('Observer-Observed-At', completed)
        rep.set_header('Observer-Evidence-State', 'fresh')
        rep.set_header('Observer-Registry-Head', self.ctx.store.head(regk).qb64)


class RegistrarPuller(doing.DoDoer):
    """One cooperative full-scope request at a time, driven only by fixed cadence."""
    def __init__(self, hab, observer, urls, *, interval=5.0, timeout=5.0, tock=0.03125):
        """Compose independent cooperative full-scope polling on a fixed cadence.

            Args:
                hab: Authenticated requester habitat used to sign bulk queries.
                observer (Context): Receiver of evidence and completed observation records.
                urls (Iterable[str]): Sources polled sequentially, independently of queries.
                interval (float): Positive finite seconds between cycle starts.
                timeout (float): Positive finite per-source response deadline.
                tock (float): HIO cooperative recurrence interval.

            Returns:
                None. Only the most recent 32 transport/intake outcomes remain in memory.

            Raises:
                ValueError: Poll interval or timeout is not positive and finite."""
        if not isfinite(interval) or not isfinite(timeout) or interval <= 0 or timeout <= 0:
            raise ValueError('poll interval and timeout must be finite and positive')
        self.hab, self.observer = hab, observer
        self.urls, self.interval, self.timeout = tuple(urls), interval, timeout
        self.results = deque(maxlen=32)
        self.client = None
        super().__init__(doers=[doing.doify(self.pollDo)], tock=tock)

    def pollDo(self, tymth=None, tock=0.03125, **kwa):
        """Run one finite cooperative request at a time and close each HTTP client.

            Args:
                tymth: HIO scheduler clock used for deadlines and cadence.
                tock (float): Cooperative yield delay.
                **kwa: Scheduler metadata unused by the polling loop.

            Yields:
                float: Delay while awaiting responses or the next independent cycle.

            Only successful CESR responses enter observer processing. Timeout/status/
            content/transport failures become bounded result entries. finally removes
            each client doer and closes its connection, including on cancellation."""
        self.wind(tymth)
        yield tock
        while True:
            started = self.tyme
            for url in self.urls:
                target = urlsplit(url)
                client = http.clienting.Client(scheme=target.scheme or 'http',
                    hostname=target.hostname or '127.0.0.1',
                    port=target.port or (443 if target.scheme == 'https' else 80))
                doer = http.clienting.ClientDoer(client=client)
                self.client = client
                self.extend([doer])
                try:
                    client.request(method='POST', path=target.path or '/',
                        headers={'Content-Type': CESR_CONTENT_TYPE},
                        body=signedQuery(self.hab, 'tels/bulk'))
                    deadline = self.tyme + self.timeout
                    while not client.responses and self.tyme < deadline:
                        yield tock
                    if not client.responses:
                        self.results.append((url, 'timeout'))
                    else:
                        response = client.responses.popleft()
                        if response['status'] != 200:
                            self.results.append((url, 'http_error'))
                        elif (response.get('headers', {}).get('content-type', '').split(';')[0]
                              != CESR_CONTENT_TYPE):
                            self.results.append((url, 'invalid_content_type'))
                        else:
                            result = self.observer.observe(url, response['body'])
                            self.results.append((url, result))
                except Exception as ex:
                    self.results.append((url, {'transport_error': str(ex)}))
                finally:
                    self.remove([doer])
                    client.close()
                    self.client = None
            while self.tyme < started + self.interval:
                yield tock


def setup(hby, hab, *, urls=(), host='127.0.0.1', port=6633,
          interval=5.0, timeout=5.0, keypath=None, certpath=None,
          cafilepath=None, **kwa):
    """Compose an observer HTTP runtime and optional independent registrar puller.

        Args:
            hby: Existing caller-owned authenticated Habery.
            hab: Request-signing habitat for configured registrar pulls.
            urls (Iterable[str]): Independently polled authoritative registrar sources.
            host (str): HTTP listening interface.
            port (int): HTTP listening port.
            interval (float): Positive finite pull cycle interval.
            timeout (float): Positive finite per-source deadline.
            keypath (str | None): Optional TLS private key.
            certpath (str | None): Optional TLS certificate.
            cafilepath (str | None): Optional TLS CA file.
            **kwa: Context reader authorization, freshness age, stores, and KRAM policy.

        Returns:
            tuple: Context and persistence/maintenance/server/poller doers.

        Invalid policy, polling limits, and listener errors propagate. Returned doers
        require caller scheduling/cancellation before their stores are closed."""
    ctx = Context(hby, urls=urls, **kwa)
    server = createHttpServer(host=host, port=port, app=ctx.app,
                              keypath=keypath, certpath=certpath, cafilepath=cafilepath)
    doers = [BaserDoer(baser=ctx.reger), BaserDoer(baser=ctx.observations),
             ctx, http.ServerDoer(server=server)]
    if urls:
        doers.append(RegistrarPuller(hab, ctx, urls, interval=interval, timeout=timeout))
    return ctx, doers
