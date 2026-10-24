"""Service scheduling must prune real authenticated caches across restart."""

import pytest
from falcon import testing
from hio.base import doing

from keri import Vrsn_2_0
from keri.acdc.regbasing import RegBaser
from keri.app.habbing import openHby
from keri.app.httping import CESR_CONTENT_TYPE
from keri.app.observer.serving import Context as Observer, ObservationBaser
from keri.app.registrar.serving import Context as Registrar, signedQuery
from keri.core import Parser


@pytest.mark.parametrize('service', ['registrar', 'observer'])
def test_service_pruner_expiry_restart_and_cancellation(service, tmp_path, fakeHelpingClock):
    """Authenticate a query, restart, then expire it through the service doer.

    ``service`` selects both production evidence owners. ``tmp_path`` supplies
    persistent Linux test stores; ``fakeHelpingClock`` advances receiver time
    without altering message authentication or inserting accepted cache rows.
    Cancelled work must leave stores usable; pruning must preserve verified KEL.
    """
    config = {'kram': {'enabled': True, 'denials': [],
              'caches': {'~': [1000, 5000, 60000, 300000, 5000, 60000, 300000]}}}

    def context(hby, requester):
        """Compose the selected service over persistent KRAM/TEL stores.

        Args:
            hby (Habery): Caller-owned identity and accepted KEL environment.
            requester (str): Authorized observer/reader AID for this service role.

        Returns:
            Registrar | Observer: Caller-owned context with the tested finite KRAM policy
            and, for Observer, a persistent observation store."""
        reger = RegBaser(name=service, headDirPath=str(tmp_path), temp=False)
        if service == 'registrar':
            return Registrar(hby, reger=reger, observers=[requester], config=config)
        observations = ObservationBaser(name=service, headDirPath=str(tmp_path), temp=False)
        return Observer(hby, reger=reger, readers=[requester], config=config,
                        observations=observations)

    with openHby(name='pruning-sender', version=Vrsn_2_0) as sender:
        hab = sender.makeHab(name='sender')
        route = 'tels/bulk' if service == 'registrar' else 'tels'
        raw = signedQuery(hab, route, {'i': hab.pre} if service == 'observer' else {})
        query = Parser(version=Vrsn_2_0).parseOne(ims=bytearray(raw), processive=False).serder
        key = (hab.pre, query.said)
        with openHby(name=service, headDirPath=str(tmp_path), temp=False,
                     version=Vrsn_2_0) as receiver:
            ctx = context(receiver, hab.pre)
            try:
                assert not ctx.ingest(hab.replay(gvrsn=Vrsn_2_0))['rejected']
                response = testing.TestClient(ctx.app).simulate_post('/', body=raw,
                    headers={'Content-Type': CESR_CONTENT_TYPE})
                assert response.status_code == (200 if service == 'registrar' else 404)
                cached = receiver.db.kramMSGC.get(key)
                assert cached is not None
                # Real scheduling leaves live entries alone and cancellation
                # stops maintenance without deleting the shared authenticated DB.
                doist = doing.Doist(tock=1.0)
                deeds = doist.enter(doers=[ctx])
                doist.recur(deeds=deeds)
                assert receiver.db.kramMSGC.get(key) == cached
                doist.exit(deeds=deeds)
                assert not ctx.deeds
                assert receiver.db.kramMSGC.get(key) == cached
            finally:
                ctx.close()

        fakeHelpingClock.advance(milliseconds=cached.d + cached.pml + 1)
        with openHby(name=service, headDirPath=str(tmp_path), temp=False,
                     version=Vrsn_2_0) as receiver:
            ctx = context(receiver, hab.pre)
            doist = doing.Doist(tock=1.0)
            deeds = None
            try:
                assert receiver.db.kramMSGC.get(key) == cached
                assert ctx.pruner.kramer is ctx.kvy.kramer
                assert ctx.doers.count(ctx.pruner) == 1
                deeds = doist.enter(doers=[ctx])
                doist.recur(deeds=deeds)
                assert receiver.db.kramMSGC.get(key) is None
                assert receiver.db.kels.getLast(keys=hab.pre, on=0) == hab.kever.serder.said
                # Removing the cache never makes the old signed message fresh.
                response = testing.TestClient(ctx.app).simulate_post('/', body=raw,
                    headers={'Content-Type': CESR_CONTENT_TYPE})
                assert response.status_code == 401
            finally:
                if deeds is not None:
                    doist.exit(deeds=deeds)
                ctx.close()
