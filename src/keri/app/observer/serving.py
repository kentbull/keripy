"""Compatible KLI observer composition over shared evidence capabilities.

Original service topology derives from kf-observer d6368aef. Source observations,
cooperative acquisition and cache-only queries are reusable library components;
this module retains the original application and setup contract.
"""
import falcon
from hio.core import http
from keri.app.evidencing import signedQuery
from keri.app.evidence_httping import HealthEnd, authenticate
from keri.app.evidence_observing import Observation, ObservationBaser, ObservedEvidence, RegistrarPuller
from keri.app.evidence_querying import QueryEnd
from keri.app.indirecting import createHttpServer
from keri.db.basing import BaserDoer


class Context(ObservedEvidence):
    """Bind the original observer HTTP routes and reader policy to shared state."""

    def __init__(self, hby, *, readers=(), **kwa):
        """Compose the compatible KLI service without changing verification.

        Parameters:
            hby: caller-owned Habery used for authentication and public evidence.
            readers: AIDs permitted to read the observer cache.
            **kwa: observation stores, freshness/source policy and evidence options;
                legacy publisher/observer allowlists remain accepted attributes.
        """
        self.publishers = set(kwa.pop('publishers', ()))
        self.observers = set(kwa.pop('observers', ()))
        super().__init__(hby, **kwa)
        self.readers = set(readers)
        self.app = falcon.App()
        self.app.add_route('/', QueryEnd(self))
        self.app.add_route('/health', HealthEnd())


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
