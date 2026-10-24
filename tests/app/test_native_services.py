"""Native service proof acquisition uses real processors and cooperative sockets."""
import pytest
from falcon import testing
from hio.base import doing
from hio.core import http

from keri import Vrsn_2_0
from keri.acdc import regcept, acdcmap, blindate
from keri.app.habbing import openHby
from keri.app.evidencing import EvidenceContext
from keri.app.httping import CESR_CONTENT_TYPE
from keri.app.registrar.serving import Context as Registrar, signedQuery, ServiceConfig
from keri.app.observer.serving import Context as Observer, RegistrarPuller, ObservationBaser, Observation
from keri.core import Blinder, Counter, Codens, Parser, Diger, SerderKERI, SerderACDC, SealSource, messagize
from keri.kering import ConfigurationError


def native(*events):
    """Serialize native TEL bodies with complete empty attachment-group feet.

    Args:
        *events: Ordered native registry events to send to actual service intake.

    Returns:
        bytes: Concatenated exact bodies and prescribed v2 foot counters."""
    foot = Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b
    return b''.join(event.raw + foot for event in events)


def issue(hab):
    """Create a genuinely KEL-anchored native registry and blinded issuance.

    Args:
        hab (Hab): Controller creating both TEL and signed sealing key events.

    Returns:
        tuple[SerderACDC, SerderACDC]: Inception and issued update. Private openings
        are intentionally not returned because service acquisition hosts public proof."""
    rip = regcept(israid=hab.pre)
    hab.interact(data=[dict(s=rip.sad['n'], d=rip.said)])
    acdc = acdcmap(israid=hab.pre, regid=rip.said, attribute={'d': '', 'name': 'Test'})
    blinder = Blinder.blind(acdc=acdc.said, state='issued')
    update = blindate(regid=rip.said, prior=rip.said, blid=blinder.said)
    hab.interact(data=[dict(s=update.sad['n'], d=update.said)])
    return rip, update


def post(client, hab, route, query=None, path='/', suffix=b''):
    """Send one signed service query through Falcon's real request contract.

    Args:
        client (TestClient): Registrar or observer app under test.
        hab (Hab): Requester signing the query.
        route (str): Native service query resource.
        query (dict | None): Query attributes.
        path (str): HTTP route, default root.
        suffix (bytes): Deliberately appended framing material for hostile-input cases.

    Returns:
        Result: Falcon response, including status/body/headers for assertions."""
    return client.simulate_post(path, body=signedQuery(hab, route, query) + suffix,
                                headers={'Content-Type': CESR_CONTENT_TYPE})


@pytest.mark.parametrize("contextType", [EvidenceContext, Registrar])
def test_resolved_wrong_anchor_locator_is_not_dropped_at_service_intake(contextType):
    """Reject a false locator through shared and legacy contextType entry points.

    contextType selects neutral evidence processing or the compatible registrar
    application. A clean authentic replay must still succeed without poisoning.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with (openHby(name='locator-issuer', version=Vrsn_2_0) as issuer,
          openHby(name='locator-registrar', version=Vrsn_2_0) as registrar):
        hab = issuer.makeHab(name='issuer')
        rip, update = issue(hab)
        hab.interact(data=[{'unrelated': 'accepted KEL event'}])
        wrong = hab.kever.serder
        ctx = contextType(registrar)
        try:
            assert not ctx.ingest(hab.replay(gvrsn=Vrsn_2_0) + native(rip))['rejected']
            supplied = messagize(update, bonds=[SealSource(s=wrong.snh, d=wrong.said)],
                                 gvrsn=Vrsn_2_0)
            result = ctx.ingest(supplied)
            assert result['rejected'] and not result['accepted']
            assert ctx.store.headEvent(rip.said).said == rip.said
            assert ctx.store.event(update.said) is None
            # The bad unsigned hint is not retained as poison. Normal discovery
            # of the actual matching controller anchor still permits acceptance.
            result = ctx.ingest(native(update))
            assert not result['rejected'] and not result['pending']
            assert ctx.store.headEvent(rip.said).said == update.said
        finally:
            ctx.close()


def test_authorized_foreign_hosting_and_independent_cache(tmp_path):
    """Enforce signed service roles, independently acquire foreign KEL/TEL, and refuse stale/prefix/omitted-scope observations as freshness.

    Parameters:
        tmp_path: Pytest-owned persistent registry/observation directories for restart assertions.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with (openHby(name='service-issuer', temp=True, version=Vrsn_2_0) as issuer,
          openHby(name='service-registrar', temp=True, version=Vrsn_2_0) as registrar,
          openHby(name='service-observer', temp=True, version=Vrsn_2_0) as observer):
        controller = issuer.makeHab(name='controller')
        observerHab = observer.makeHab(name='observer')
        rip, update = issue(controller)
        reg = Registrar(registrar, publishers=[controller.pre], observers=[observerHab.pre])
        observations = ObservationBaser(name='observations', headDirPath=str(tmp_path), temp=False)
        obs = Observer(observer, readers=[controller.pre], observations=observations,
                       urls=['http://registrar/'])
        try:
            # Ordinary authenticated KEL bootstrap; never populate accepted native tables.
            assert not reg.ingest(controller.replay(gvrsn=Vrsn_2_0))['rejected']
            assert not reg.ingest(observerHab.replay(gvrsn=Vrsn_2_0))['rejected']
            assert not obs.ingest(controller.replay(gvrsn=Vrsn_2_0))['rejected']
            inner, cache = testing.TestClient(reg.app), testing.TestClient(obs.app)
            assert post(inner, observerHab, 'tels/publish', {'stream': 'x'}, '/ingest').status_code == 403
            assert post(inner, controller, 'tels/bulk').status_code == 403
            unsigned = Parser().parseOne(ims=bytearray(signedQuery(observerHab, 'tels/bulk')),
                                         processive=False).serder.raw
            empty = Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b
            assert inner.simulate_post('/', body=unsigned + empty,
                headers={'Content-Type': CESR_CONTENT_TYPE}).status_code == 401
            assert post(inner, observerHab, 'tels/bulk', suffix=signedQuery(observerHab, 'tels/bulk')).status_code == 400
            published = post(inner, controller, 'tels/publish',
                             {'stream': native(rip, update).decode()}, '/ingest')
            assert published.status_code == 200
            assert published.json['accepted'][rip.said] == 2
            assert not registrar.habByPre(controller.pre)
            assert reg.store.head(rip.said).qb64 == update.said
            # Queries have no registrar URL or pull owner and cannot create one.
            assert post(cache, controller, 'tels', {'i': rip.said}).status_code == 404
            bulk = post(inner, observerHab, 'tels/bulk')
            assert bulk.status_code == 200
            # A separate store acquires both accepted KEL and native TEL over the public contract.
            result = obs.observe('http://registrar/', bulk.content)
            assert not result['pending'] and not result['rejected']
            assert obs.store.head(rip.said).qb64 == update.said
            found = post(cache, controller, 'tels', {'i': rip.said})
            assert found.status_code == 200
            assert found.headers['Observer-Registry-Head'] == update.said
            assert found.headers['Observer-Observed-At']
            previous = observations.observations.get(('http://registrar/',))
            assert previous.heads == {rip.said: update.said}
            # An old valid prefix or omitted known scope is not a fresh
            # observation of the cached newer head.
            obs.observe('http://registrar/', native(rip))
            assert observations.observations.get(('http://registrar/',)) == previous
            obs.observe('http://registrar/', b'')
            assert observations.observations.get(('http://registrar/',)) == previous
            assert obs.observe('http://registrar/', b'invalid')['rejected']
            assert observations.observations.get(('http://registrar/',)) == previous
            observations.observations.pin(('http://registrar/',), Observation(
                '2000-01-01T00:00:00.000000+00:00', previous.heads))
            assert post(cache, controller, 'tels', {'i': rip.said}).status_code == 503
            observations.observations.pin(('http://registrar/',), previous)
            observations.close()
            observations.reopen()
            assert observations.observations.get(('http://registrar/',)) == previous
        finally:
            obs.close()
            reg.close()


def test_authentication_must_be_enabled():
    """Refuse service configuration that disables or denies mandatory KRAM query authentication.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with pytest.raises(ConfigurationError):
        ServiceConfig({'kram': {'enabled': False}})
    with pytest.raises(ConfigurationError):
        ServiceConfig({'kram': {'enabled': True, 'denials': [['qry']]}})


def test_reopened_observer_requires_observation_from_active_registrar_url(tmp_path):
    """Require a fresh observation from the active configured registrar URL after persistent observer reopen.

    Parameters:
        tmp_path: Pytest-owned persistent registry/observation directories for restart assertions.

    Returns:
        None. Assertions check the stated evidence boundary."""
    from keri.acdc.regbasing import RegBaser

    oldURL, newURL = 'http://registrar.old.test/', 'http://registrar.new.test/'
    with openHby(name='source-rotation-issuer', version=Vrsn_2_0) as issuer:
        controller = issuer.makeHab(name='issuer')
        rip, update = issue(controller)
        public = controller.replay(gvrsn=Vrsn_2_0) + native(rip, update)

        def context(hby, urls):
            """Reopen one persistent observer using the explicitly active registrar URLs.

            Args:
                hby (Habery): Caller-owned authenticated KEL environment.
                urls (Iterable[str]): Current allowed observation source URLs.

            Returns:
                Observer: Caller-owned service with persistent TEL and freshness stores."""
            return Observer(hby, readers=[reader], urls=urls,
                reger=RegBaser(name='source-rotation', headDirPath=str(tmp_path), temp=False),
                observations=ObservationBaser(name='source-rotation', headDirPath=str(tmp_path), temp=False))

        with openHby(name='source-rotation-reader', headDirPath=str(tmp_path), temp=False,
                     version=Vrsn_2_0) as receiver:
            hab = receiver.makeHab(name='reader')
            reader = hab.pre
            obs = context(receiver, [oldURL])
            try:
                assert not obs.observe(oldURL, public)['rejected']
                assert post(testing.TestClient(obs.app), hab, 'tels', {'i': rip.said}).status_code == 200
                previous = obs.observations.observations.get((oldURL,))
            finally:
                obs.close()

        # A new Habery and both reopened LMDB owners retain the accepted head
        # and old observation. Changing current source policy removes freshness.
        with openHby(name='source-rotation-reader', headDirPath=str(tmp_path), temp=False,
                     version=Vrsn_2_0) as receiver:
            hab = receiver.habByName('reader')
            obs = context(receiver, [newURL])
            try:
                cache = testing.TestClient(obs.app)
                assert obs.store.head(rip.said).qb64 == update.said
                assert obs.observations.observations.get((oldURL,)) == previous
                assert post(cache, hab, 'tels', {'i': rip.said}).status_code == 503
                assert not obs.observe(oldURL, public)['rejected']
                assert obs.observations.observations.get((oldURL,)) == previous
                assert post(cache, hab, 'tels', {'i': rip.said}).status_code == 503
                assert not obs.observe(newURL, public)['rejected']
                assert post(cache, hab, 'tels', {'i': rip.said}).status_code == 200
            finally:
                obs.close()


def test_pending_native_evidence_survives_reopen_and_remains_unservable(tmp_path):
    """Persist incomplete native evidence across restart without serving it as accepted or observed state.

    Parameters:
        tmp_path: Pytest-owned persistent registry/observation directories for restart assertions.

    Returns:
        None. Assertions check the stated evidence boundary."""
    from keri.acdc.regbasing import RegBaser
    with (openHby(name='pending-issuer', temp=True, version=Vrsn_2_0) as issuer,
          openHby(name='pending-observer', temp=True, version=Vrsn_2_0) as receiver):
        controller = issuer.makeHab(name='controller')
        reader = receiver.makeHab(name='reader')
        rip, update = issue(controller)
        reger = RegBaser(name='pending-reg', headDirPath=str(tmp_path), temp=False)
        obs = Observer(receiver, readers=[reader.pre], reger=reger, urls=['http://registrar/'])
        try:
            result = obs.observe('http://registrar/', native(rip, update))
            assert result['pending'] and not result['accepted']
            assert not obs.observations.observations.get(('http://registrar/',))
            assert post(testing.TestClient(obs.app), reader, 'tels', {'i': rip.said}).status_code == 503
            reger.close()
            reger.reopen()
            # Recreate the processor against reopened durable rows; no remembered batches.
            from keri.acdc.regeventing import Rever
            obs.rever = Rever(db=receiver.db, reger=reger)
            obs.store = obs.rever.store
            assert not obs.ingest(controller.replay(gvrsn=Vrsn_2_0))['rejected']
            assert obs.store.head(rip.said).qb64 == update.said
            # Dependency recovery alone does not pretend a complete new scope observation occurred.
            assert post(testing.TestClient(obs.app), reader, 'tels', {'i': rip.said}).status_code == 503
        finally:
            obs.close()


def test_cooperative_socket_poll_and_cancellation():
    """Run actual HTTP polling alongside a sentinel doer and cancel cleanly without blocking the scheduler.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with (openHby(name='socket-issuer', temp=True, version=Vrsn_2_0) as issuer,
          openHby(name='socket-reg', temp=True, version=Vrsn_2_0) as registrar,
          openHby(name='socket-obs', temp=True, version=Vrsn_2_0) as observer):
        controller = issuer.makeHab(name='controller')
        observerHab = observer.makeHab(name='observer')
        rip, update = issue(controller)
        reg = Registrar(registrar, observers=[observerHab.pre])
        obs = Observer(observer, readers=[controller.pre])
        requests = []

        class Requests:
            def process_request(self, req, rep):
                """Record actual HTTP request paths without changing Falcon dispatch.

                Args:
                    req (falcon.Request): Incoming real socket request.
                    rep (falcon.Response): Response left to the service endpoint.

                Returns:
                    None. Appends the path so tests can distinguish acquisition from cache reads."""
                requests.append(req.path)

        reg.app.add_middleware(Requests())
        server = http.Server(host='127.0.0.1', port=0, app=reg.app)
        try:
            assert not reg.ingest(controller.replay(gvrsn=Vrsn_2_0) + native(rip, update))['rejected']
            assert not reg.ingest(observerHab.replay(gvrsn=Vrsn_2_0))['rejected']
            assert server.reopen()
            url = f'http://127.0.0.1:{server.servant.ha[1]}/'
            obs.urls = frozenset([url])
            puller = RegistrarPuller(observerHab, obs, [url], interval=10, timeout=1)
            ticks = []
            queries = []
            cache = testing.TestClient(obs.app)

            def sentinel(tymth=None, tock=0.01, **kwa):
                """Observe scheduler progress while real registrar polling runs concurrently.

                Args:
                    tymth (Callable): HIO injected simulated clock.
                    tock (float): Cooperative scheduling delay.
                    **kwa: HIO lifecycle metadata unused by this observation doer.

                Yields:
                    float: Requested delay after recording a tick and, after startup, exercising
                    the observer cache. Cancellation closes the generator through ordinary HIO."""
                while True:
                    ticks.append(tymth())
                    if tymth() > 0.2:
                        queries.append(post(cache, controller, 'tels', {'i': 'unknown'}).status_code)
                    yield tock

            doing.Doist(real=True, limit=0.5, tock=0.01).do(doers=[
                http.ServerDoer(server=server), puller, doing.doify(sentinel)])
            assert len(ticks) > 10
            assert len(queries) > 10 and set(queries) == {404}
            assert requests == ['/']
            assert obs.store.head(rip.said).qb64 == update.said
            assert obs.observations.observations.get((url,)).heads[rip.said] == update.said
            assert puller.client is None
            # A second owner is cancelled while its request cannot complete.
            stalled = RegistrarPuller(observerHab, obs, ['http://127.0.0.1:1/'], timeout=10)
            doing.Doist(real=True, limit=0.1, tock=0.01).do(doers=[stalled])
            assert stalled.client is None
        finally:
            server.close()
            obs.close()
            reg.close()


def test_witness_dependency_retains_following_tel_and_recovers_after_store_reopen(tmp_path):
    """Keep a TEL following an unresolved witnessed KEL event and recover after actual store reopen and receipt arrival.

    Parameters:
        tmp_path: Pytest-owned persistent registry/observation directories for restart assertions.

    Returns:
        None. Assertions check the stated evidence boundary."""
    from keri.acdc.regbasing import RegBaser
    from keri.db.basing import Baser
    with (openHby(name='pending-witness-issuer', version=Vrsn_2_0) as issuer,
          openHby(name='pending-witnesses', version=Vrsn_2_0) as witnesses,
          openHby(name='pending-witness-service', version=Vrsn_2_0,
                  db=Baser(name='pending-witness-service', headDirPath=str(tmp_path), reopen=True)) as receiver):
        first = witnesses.makeHab(name='first', transferable=False)
        second = witnesses.makeHab(name='second', transferable=False)
        controller = issuer.makeHab(name='controller', wits=[first.pre, second.pre], toad=2)
        rip, update = issue(controller)
        kel = controller.replay(gvrsn=Vrsn_2_0)
        # These are real witness owners receiving their controller's signed KEL.
        witnesses.psr.parse(ims=bytearray(kel))
        events = [SerderKERI(raw=controller.msgOwnEvent(sn=sn, gvrsn=Vrsn_2_0))
                  for sn in range(controller.kever.sn + 1)]
        receipts = b''.join(witness.witness(event, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
                            for event in events for witness in (first, second))
        reger = RegBaser(name='pending-witness-service', headDirPath=str(tmp_path))
        ctx = Registrar(receiver, reger=reger)
        try:
            result = ctx.ingest(kel + native(rip, update))
            assert not result['rejected']
            assert result['pending'][f'kel:{controller.pre}'] == 3
            assert result['pending'][rip.said] == 2
            assert ctx.store.event(rip.said).said == rip.said
            assert ctx.store.event(update.said).said == update.said
            assert ctx.store.head(rip.said) is None
            # Reopen the actual KEL and TEL stores, then recreate service processors.
            ctx.close()
            receiver.db.close()
            receiver.db.reopen()
            reger.reopen()
            ctx = Registrar(receiver, reger=reger)
            assert ctx.store.event(rip.said) is not None
            result = ctx.ingest(receipts)
            assert not result['rejected']
            # Ordinary escrow workers may need the next cycle for successor KELs.
            for _ in range(3):
                ctx.kvy.processEscrows()
                ctx.rever.processEscrows()
            assert ctx.store.head(rip.said).qb64 == update.said
            assert receiver.db.fullyWitnessed(events[-1])
            assert list(reger.maes.getTopItemIter()) == []
            assert list(reger.ooes.getTopItemIter()) == []
        finally:
            ctx.close()


def test_conflicting_supplied_sibling_is_rejected_after_escrow_resolution():
    """Classify a supplied authenticated rival as rejected conflict after dependencies resolve, while preserving the accepted head.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with (openHby(name='service-sibling-issuer', version=Vrsn_2_0) as issuer,
          openHby(name='service-sibling-receiver', version=Vrsn_2_0) as receiver):
        controller = issuer.makeHab(name='controller')
        rip, first = issue(controller)
        other = blindate(regid=rip.said, prior=rip.said, blid=Diger(ser=b'other state').qb64)
        controller.interact(data=[dict(s=other.sad['n'], d=other.said)])
        ctx = Registrar(receiver)
        try:
            result = ctx.ingest(controller.replay(gvrsn=Vrsn_2_0) + native(first, other, rip))
            assert result['accepted'] == {rip.said: 2}
            assert result['rejected'] == {rip.said: 1}
            assert result['pending'] == {}
            assert result['heads'] == {rip.said: first.said}
            assert ctx.store.head(rip.said).qb64 == first.said
            assert list(ctx.reger.maes.getTopItemIter()) == []
            assert list(ctx.reger.ooes.getTopItemIter()) == []
        finally:
            ctx.close()


def test_occupied_slot_rival_is_pending_until_signed_anchor_arrives():
    """Report delayed authentication without serving the rival as accepted.

    Uses real independent issuer/service KEL processors and delayed signed
    evidence. Returns None; assertion failures identify premature rejection,
    a lost conflict proof, or conflicting TEL bytes in accepted-only cloning.
    """
    with (openHby(name='service-delayed-conflict-issuer', version=Vrsn_2_0) as issuer,
          openHby(name='service-delayed-conflict-receiver', version=Vrsn_2_0) as receiver):
        controller = issuer.makeHab(name='controller')
        rip, first = issue(controller)
        rival = blindate(regid=rip.said, prior=rip.said,
                         blid=Diger(ser=b'competing state').qb64)
        ctx = Registrar(receiver)
        try:
            assert not ctx.ingest(controller.replay(gvrsn=Vrsn_2_0)
                                  + native(rip, first))['rejected']
            result = ctx.ingest(native(rival))
            assert result == dict(accepted={}, pending={rip.said: 1}, rejected={}, heads={})
            assert ctx.reger.conflicts.get((rip.said, '1')) is None
            assert ctx.store.head(rip.said).qb64 == first.said

            controller.interact(data=[dict(s=rival.sad['n'], d=rival.said)])
            result = ctx.ingest(controller.msgOwnEvent(sn=controller.kever.sn,
                                                       gvrsn=Vrsn_2_0))
            assert not result['pending'] and not result['rejected']
            assert ctx.reger.conflicts.get((rip.said, '1')).raw == rival.raw
            assert ctx.store.head(rip.said).qb64 == first.said
            assert ctx.ingest(native(rival))['rejected']

            # A KEL seal may mention the rival; accepted TEL cloning must not
            # include the rival's body or manufacture an accepted ordinal.
            remaining, accepted = bytearray(ctx.clone([rip.said])), []
            parser = Parser(version=Vrsn_2_0)
            while remaining:
                dom = parser.parseOne(ims=remaining, processive=False)
                assert dom is not None
                if isinstance(dom.serder, SerderACDC):
                    accepted.append(dom.serder.said)
            assert accepted == [rip.said, first.said]
        finally:
            ctx.close()


def test_old_unanchored_rival_does_not_monopolize_observer_freshness():
    """Allow clean pulls past raw rivals while retaining missing-prefix gates.

    Uses an independent observer and real signed issuer KEL. Returns None;
    assertions expose ignored current-batch dependencies, junk monopolization,
    or false freshness while a genuinely unaccepted ordinal remains pending.
    """
    url = 'http://registrar.test/'
    with (openHby(name='observer-rival-issuer', version=Vrsn_2_0) as issuer,
          openHby(name='observer-rival-receiver', version=Vrsn_2_0) as receiver):
        controller = issuer.makeHab(name='controller')
        rip, first = issue(controller)
        public = controller.replay(gvrsn=Vrsn_2_0) + native(rip, first)
        obs = Observer(receiver, urls=[url])
        try:
            assert not obs.observe(url, public)['rejected']
            stale = Observation('2000-01-01T00:00:00.000000+00:00', {rip.said: first.said})
            obs.observations.observations.pin((url,), stale)
            rival = blindate(regid=rip.said, prior=rip.said,
                             blid=Diger(ser=b'unanchored rival').qb64)
            supplied = obs.observe(url, native(rival))
            assert supplied['pending'] == {rip.said: 1}
            assert obs.observations.observations.get((url,)) == stale

            clean = obs.observe(url, public)
            assert not clean['pending'] and not clean['rejected']
            fresh = obs.observations.observations.get((url,))
            assert fresh.completed != stale.completed and fresh.heads == stale.heads
            assert obs.reger.maes.get(keys=rip.said, on=1) == [(rival.said,)]
            assert obs.reger.conflicts.get((rip.said, '1')) is None

            # A later event with an unaccepted predecessor remains a real
            # dependency even if the current pull contains an accepted prefix.
            future = blindate(regid=rip.said, prior=Diger(ser=b'missing predecessor').qb64,
                              blid=Diger(ser=b'future state').qb64, sn=3)
            controller.interact(data=[dict(s=future.sad['n'], d=future.said)])
            waiting = obs.ingest(controller.msgOwnEvent(sn=controller.kever.sn,
                                                       gvrsn=Vrsn_2_0) + native(future))
            assert waiting['pending'] == {rip.said: 1}
            assert obs.reger.ooes.get(keys=rip.said, on=3) == [(future.said,)]
            obs.observations.observations.pin((url,), stale)
            assert not obs.observe(url, public)['rejected']
            assert obs.observations.observations.get((url,)) == stale
            assert obs.store.head(rip.said).qb64 == first.said
        finally:
            obs.close()


@pytest.mark.parametrize('value', [float('nan'), float('inf'), -float('inf'), 0, -1])
def test_observer_durations_must_be_finite_and_positive(value):
    """Refuse zero, negative, NaN, or infinite observer freshness/poll durations before runtime scheduling.

    Parameters:
        value: Invalid duration selected for freshness or polling configuration.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with pytest.raises(ValueError, match='finite and positive'):
        Observer(None, maximumAge=value)
    with pytest.raises(ValueError, match='finite and positive'):
        RegistrarPuller(None, None, [], interval=value)
    with pytest.raises(ValueError, match='finite and positive'):
        RegistrarPuller(None, None, [], timeout=value)
