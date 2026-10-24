"""Reusable independent evidence observations and cooperative acquisition.

Extracted from the qualified observer at KERIpy 4b1078e0. Source observation is
an application freshness fact, never a protocol timestamp or global publication
claim. This module owns no routes or reader policy. The original KLI observer
and community service can share these exact scheduling and persistence rules.
"""
from dataclasses import dataclass, field
from collections import deque
from math import isfinite
from urllib.parse import urlsplit

from hio.base import doing
from hio.core import http
from keri.app.evidencing import EvidenceContext, signedQuery
from keri.app.httping import CESR_CONTENT_TYPE
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


class ObservedEvidence(EvidenceContext):
    """Share authenticated evidence processing while separating source freshness.

        Freshness describes an independently completed configured-source pull. A
        presentation query can read that result but cannot trigger acquisition."""
    def __init__(self, hby, *, observations=None, maximumAge=15.0,
                 urls=(), **kwa):
        """Compose observer evidence, source authorization, and freshness persistence.

            Args:
                hby: Caller-owned authenticated Habery.
                observations (ObservationBaser | None): Store closed by this context.
                maximumAge (float): Positive finite application freshness limit in seconds.
                urls (Iterable[str]): Current authoritative source URLs for completed pulls.
                **kwa: Shared EvidenceContext registry/KRAM configuration.

            Returns:
                None. Existing evidence remains when source authority changes; old URLs
                cannot confer current freshness merely because their rows remain stored.

            Raises:
                ValueError: maximumAge is not positive and finite.
                ConfigurationError: Shared service authentication policy is invalid."""
        if not isfinite(maximumAge) or maximumAge <= 0:
            raise ValueError('maximum observation age must be finite and positive')
        super().__init__(hby, **kwa)
        self.maximumAge = maximumAge
        self.urls = frozenset(urls)
        self.observations = observations if observations is not None else ObservationBaser(
            name=hby.name, base=hby.base, temp=hby.temp)

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
        """Close observation and ACDC v2 registry stores after runtime cancellation.

            Returns:
                None. The shared Habery remains caller-owned."""
        self.observations.close()
        super().close()


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
