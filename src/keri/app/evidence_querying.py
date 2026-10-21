"""HTTP cache-only evidence query contract shared by observer applications.

Moved unchanged from KERIpy 4b1078e0. Applications choose the reader allowlist,
current source URLs and maximum observation age. A request cannot initiate a pull.
"""
import falcon
from keri.app.evidence_httping import authenticate
from keri.app.httping import CESR_CONTENT_TYPE
from keri.help import helping

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
