"""HTTP adapters for shared native evidence authentication and availability.

Extracted without protocol changes from the qualified registrar adapter at
KERIpy 64e14e08. Applications choose routes and allowlists; these helpers bind
Falcon requests to the existing core KRAM verifier and provide health output.
"""
import falcon

from keri import Vrsn_2_0
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import Parser


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


class HealthEnd:
    def on_get(self, req, rep):
        """Return service availability without claiming credential acceptance.

            Args:
                req: Falcon health request; body is unused.
                rep: Falcon response whose media is set to status ok.

            Returns:
                None. Health is not authorization, freshness, or a verification verdict."""
        rep.media = {'status': 'ok'}
