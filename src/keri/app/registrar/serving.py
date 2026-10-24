"""Authorized public-evidence hosting, adapted from kf-registrar (Apache-2.0).

Routes/topology derive from keri-foundation/kf-registrar bf14eac4. The original
KLI service remains supported. Shared verification now lives in evidencing;
legacy helper imports are re-exported here for existing application callers.
"""
import falcon
from hio.core import http

from keri.app.evidencing import (EvidenceContext, KEL_DEPENDENCIES,
                                 ServiceConfig, signedQuery)
from keri.app.evidence_httping import HealthEnd, authenticate
from keri.app.httping import CESR_CONTENT_TYPE
from keri.app.indirecting import createHttpServer
from keri.db.basing import BaserDoer


class Context(EvidenceContext):
    """Compose shared KEL and ACDC v2 registry verification with registrar HTTP publication policy."""

    def __init__(self, hby, *, publishers=(), observers=(), reger=None, config=None):
        """Bind publisher/observer allowlists and routes to the shared evidence owner.

        Args:
            hby: Caller-owned authenticated habitat environment.
            publishers: AIDs permitted to publish public evidence.
            observers: AIDs permitted to retrieve accepted registry evidence.
            reger: Optional registry store; close() retains its existing ownership.
            config: Enabled KRAM policy passed to the shared composition.

        The inherited pruner and escrow Doers retain their scheduling/lifetime.
        Application construction neither opens a socket nor accepts raw evidence.
        """
        super().__init__(hby, reger=reger, config=config)
        self.publishers, self.observers = set(publishers), set(observers)
        self.app = falcon.App()
        self.app.add_route('/', BulkEnd(self))
        self.app.add_route('/ingest', IngestEnd(self))
        self.app.add_route('/health', HealthEnd())


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
