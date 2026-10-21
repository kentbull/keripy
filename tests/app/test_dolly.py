"""Dolly acceptance requires actual protocol proofs and actual webhook HTTP."""
import json
from dataclasses import asdict

import falcon
import pytest
from hio.base import doing
from hio.core import http, tcp

from keri import Vrsn_1_0, Vrsn_2_0, Kinds
from keri.acdc import acdcmap, blindate, regcept, grant
from keri.app.habbing import openHby
from keri.app.dolly.serving import Context as Dolly
from keri.app.registrar.serving import Context as Registrar
from keri.app.observer.serving import Context as Observer, RegistrarPuller
from keri.app.httping import CESR_CONTENT_TYPE, CESR_ATTACHMENT_HEADER
from keri.core import (Blinder, Noncer, Compactor, messagize, Counter, Codens, Number, Diger,
                       SealSource, SealEvent, SerderKERI, Schemer, Parser)
from keri.peer import exchanging
from keri.vdr import eventing as legacy
from keri.vc import proving, protocoling
from keri.acdc import Regery, Registrar as NativeRegistrar, apply, offer, agree, admit, update
from keri.acdc.sectioning import SectionBaser
from keri.app.credentialing import Wallet
from keri.cli.common.native_exchange import Peer, Intake
from keri.help import helping


def native(*events):
    empty = Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b
    return b''.join(event.raw + empty for event in events)


def test_reopened_dolly_requires_active_observer_observation(tmp_path):
    from falcon import testing
    from keri.acdc.regbasing import RegBaser
    from keri.app.dolly.serving import DollyBaser
    from keri.app.registrar.serving import signedQuery

    oldURL, newURL = 'http://observer.old.test/', 'http://observer.new.test/'
    with (openHby(name='dolly-source-issuer', version=Vrsn_2_0) as issuer,
          openHby(name='dolly-source-observer', version=Vrsn_2_0) as observer,
          openHby(name='dolly-source-reader', version=Vrsn_2_0) as verifier):
        ihab, dhab = issuer.makeHab(name='issuer'), verifier.makeHab(name='dolly')
        rip = regcept(israid=ihab.pre)
        ihab.interact(data=[dict(s=rip.sad['n'], d=rip.said)])
        credential = acdcmap(israid=ihab.pre, regid=rip.said, attribute=dict(d='', value='public'))
        blinder = Blinder.blind(acdc=credential.said, state='issued')
        issued = blindate(regid=rip.said, prior=rip.said, blid=blinder.said)
        ihab.interact(data=[dict(s=issued.sad['n'], d=issued.said)])
        public = ihab.replay(gvrsn=Vrsn_2_0) + native(rip, issued)
        obs = Observer(observer, readers=[dhab.pre], urls=['http://registrar.test/'])
        obs.ingest(dhab.replay(gvrsn=Vrsn_2_0))
        assert not obs.observe('http://registrar.test/', public)['rejected']
        cache = testing.TestClient(obs.app)
        response = cache.simulate_post('/', body=signedQuery(dhab, 'tels', {'i': rip.said}),
                                      headers={'Content-Type': CESR_CONTENT_TYPE})
        assert response.status_code == 200
        report = dict(status=response.status_code, body=response.content,
                      headers={key.lower(): value for key, value in response.headers.items()})

        def context(url):
            evidence = Registrar(verifier, reger=RegBaser(name='dolly-source',
                headDirPath=str(tmp_path), temp=False))
            return Dolly(verifier, dhab, issuers=[ihab.pre], schemas=[credential.schema['$id']],
                fields={'value': 'a/value'}, observer=url, webhook='http://hook.test/',
                evidence=evidence, db=DollyBaser(name='dolly-source', headDirPath=str(tmp_path), temp=False))

        dolly = context(oldURL)
        try:
            assert dolly.observe(rip.said, report)
            assert dolly.fresh(rip.said)
            previous = dolly.db.observed.get((rip.said,))
        finally:
            dolly.close()
        dolly = context(newURL)
        try:
            assert dolly.rgy.store.head(rip.said).qb64 == issued.said
            assert dolly.db.observed.get((rip.said,)) == previous
            assert not dolly.fresh(rip.said)
            # The same authenticated evidence may be observed afresh through
            # the newly configured endpoint, without discarding public history.
            assert dolly.observe(rip.said, report)
            assert dolly.db.observed.get((rip.said,)).observer == newURL
            assert dolly.fresh(rip.said)
        finally:
            dolly.close()
            obs.close()


@pytest.mark.parametrize('binding', ['top', 'inner', 'oneway'])
def test_native_partial_full_grants_observer_acquisition_and_real_webhooks(binding):
    with (openHby(name='dolly-issuer', version=Vrsn_2_0) as issuer,
          openHby(name='dolly-registrar', version=Vrsn_2_0) as registrar,
          openHby(name='dolly-observer', version=Vrsn_2_0) as observer,
          openHby(name='dolly-verifier', version=Vrsn_2_0) as verifier):
        ihab = issuer.makeHab(name='issuer')
        ohab = observer.makeHab(name='observer')
        dhab = verifier.makeHab(name='dolly')
        rip = regcept(israid=ihab.pre)
        ihab.interact(data=[{'s': rip.sad['n'], 'd': rip.said}])
        attribute = {'d': '', 'u': Noncer().qb64,
                'status': {'d': '', 'u': Noncer().qb64, 'value': 'authorized'},
                'private': {'d': '', 'u': Noncer().qb64, 'value': 'secret-full-only'},
                'note': {'d': '', 'u': Noncer().qb64, 'value': None}}
        if binding == 'inner':
            attribute['rd'] = rip.said
        full = acdcmap(israid=ihab.pre, regid=rip.said if binding == 'top' else None,
                       uuid=Noncer().qb64, attribute=attribute)
        opening = Blinder.blind(acdc=full.said, state='issued')
        update = blindate(regid=rip.said, prior=rip.said, blid=opening.said)
        bonds = [opening.data]
        if binding == 'oneway':
            bonds.append(SealEvent(rip.said, '1', update.said))
        ihab.interact(data=[{'s': update.sad['n'], 'd': update.said}])
        compact = Compactor(mad=dict(full.sad['a']), makify=True, kind=Kinds.json)
        compact.compact(paths=['a/status/'], root='a')
        partial = acdcmap(israid=full.israid, regid=full.sad.get('rd'), uuid=full.sad['u'], schema=full.sad['s'],
                         attribute=dict(compact.partials[('a/status/',)].mad))
        assert partial.said == full.said
        reg = Registrar(registrar, observers=[ohab.pre])
        obs = Observer(observer, readers=[dhab.pre])
        received, observerRequests = [], []

        class Requests:
            def process_request(self, req, rep):
                observerRequests.append(req.path)

        obs.app.add_middleware(Requests())

        class Hook:
            def on_post(self, req, rep):
                received.append(req.media)
                rep.media = {'received': True}

        hookApp = falcon.App()
        hookApp.add_route('/hook', Hook())
        servers = [http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=app)
                   for app in (reg.app, obs.app, hookApp)]
        dolly = client = None
        try:
            assert not reg.ingest(ihab.replay(gvrsn=Vrsn_2_0) + native(rip, update))['rejected']
            assert not reg.ingest(ohab.replay(gvrsn=Vrsn_2_0))['rejected']
            assert not obs.ingest(dhab.replay(gvrsn=Vrsn_2_0))['rejected']
            for server in servers:
                assert server.reopen()
                server.servant.eha = server.servant.ha
            urls = [f'http://127.0.0.1:{server.servant.ha[1]}/' for server in servers]
            obs.urls = frozenset([urls[0]])
            dolly = Dolly(verifier, dhab, issuers=[ihab.pre], schemas=[full.schema['$id']],
                fields={'status': 'a/status/value', 'private': 'a/private/value', 'note': 'a/note/value'},
                required=['status'], observer=urls[1], webhook=urls[2] + 'hook')
            ingress = http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=dolly.app)
            assert ingress.reopen()
            ingress.servant.eha = ingress.servant.ha
            servers.append(ingress)
            grants, stream = [], bytearray(ihab.replay(gvrsn=Vrsn_2_0))
            for stage, credential in enumerate((partial, full), 1):
                proof = messagize(credential, bonds=bonds, framed=False, gvrsn=Vrsn_2_0)
                exn, atc = grant(ihab, dhab.pre, f'disclosure {stage}', origin=proof)
                grants.append(exn)
                stream.extend(exn.raw + atc)
            client = http.clienting.Client(hostname='127.0.0.1', port=ingress.servant.ha[1])
            client.request(method='POST', path='/ingest', body=bytes(stream),
                           headers={'Content-Type': CESR_CONTENT_TYPE})
            puller = RegistrarPuller(ohab, obs, [urls[0]], interval=10, timeout=1)
            doers = [http.ServerDoer(server=server) for server in servers]
            doers.extend([http.clienting.ClientDoer(client), puller, dolly])
            doing.Doist(real=True, tock=0.01, limit=2.5).do(doers=doers)
            assert client.responses.popleft()['status'] == 202
            assert len(received) == 2
            payloads = {item['grant']: item for item in received}
            first, second = (payloads[exn.said] for exn in grants)
            assert first['credential'] == second['credential'] == full.said
            assert first['business'] == {'status': 'authorized', 'private': None, 'note': None}
            assert first['disclosure']['private'] == first['disclosure']['note'] == 'undisclosed'
            assert 'secret-full-only' not in json.dumps(first)
            assert second['business'] == {'status': 'authorized', 'private': 'secret-full-only', 'note': None}
            assert second['disclosure']['private'] == 'disclosed'
            assert second['disclosure']['note'] == 'disclosed_null'
            assert all(dolly.db.submissions.get((exn.said,)).delivered for exn in grants)
            # A sender can re-sign the same EXN body with a fuller attachment.
            # It must not enrich the already accepted first disclosure view.
            replay = messagize(grants[0], tsgs=[(ihab.kever.prefixer,
                Number(sn=ihab.kever.lastEst.s), Diger(qb64=ihab.kever.lastEst.d),
                ihab.sign(grants[0].raw))], nests=[messagize(full,
                bonds=bonds, nested=True, framed=False, gvrsn=Vrsn_2_0)],
                framed=False, gvrsn=Vrsn_2_0)
            client.request(method='POST', path='/ingest', body=replay,
                           headers={'Content-Type': CESR_CONTENT_TYPE})
            doing.Doist(real=True, tock=0.01, limit=0.4).do(doers=doers)
            assert client.responses.popleft()['status'] == 202
            old = exchanging.loadParsedNestedSubstreams(verifier, grants[0].said)[0].serder
            later = exchanging.loadParsedNestedSubstreams(verifier, grants[1].said)[0].serder
            assert isinstance(old.sad['a']['private'], str)
            assert later.sad['a']['private']['value'] == 'secret-full-only'
            assert len(received) == 2
            assert dolly.db.submissions.get((grants[0].said,)).payload == first
            count = len(observerRequests)
            unknown = acdcmap(israid=ihab.pre, regid=Diger(ser=b'unknown registry').qb64,
                attribute={'d': '', 'value': 'unauthenticated fetch hint'})
            unknownProof = messagize(unknown, bonds=[Blinder.blind(acdc=unknown.said,
                state='issued').data], framed=False, gvrsn=Vrsn_2_0)
            forged, _ = grant(ihab, dhab.pre, 'bad authentication', origin=unknownProof)
            wrong = messagize(forged, tsgs=[(ihab.kever.prefixer,
                Number(sn=ihab.kever.lastEst.s), Diger(qb64=ihab.kever.lastEst.d),
                dhab.sign(forged.raw))], nests=[messagize(unknown,
                bonds=[Blinder.blind(acdc=unknown.said, state='issued').data],
                nested=True, framed=False, gvrsn=Vrsn_2_0)],
                framed=False, gvrsn=Vrsn_2_0)
            client.request(method='POST', path='/ingest', body=wrong,
                           headers={'Content-Type': CESR_CONTENT_TYPE})
            doing.Doist(real=True, tock=0.01, limit=1.2).do(doers=doers)
            assert client.responses.popleft()['status'] == 202
            assert not dolly.exc.complete(forged.said)
            assert len(observerRequests) == count
            assert len(received) == 2
        finally:
            if client:
                client.close()
            for server in servers:
                server.close()
            if dolly:
                dolly.close()
            obs.close()
            reg.close()


def test_legacy_current_source_tsn_and_same_real_webhook_contract():
    """Old issuance embeds authenticate history; a new signed TSN gates delivery."""
    with (openHby(name='dolly-old-issuer', version=Vrsn_1_0) as issuer,
          openHby(name='dolly-old-verifier', version=Vrsn_1_0) as verifier):
        ihab = issuer.makeHab(name='issuer', version=Vrsn_1_0)
        dhab = verifier.makeHab(name='dolly', version=Vrsn_1_0)
        vcp = legacy.incept(ihab.pre, cnfg=['NB'], version=Vrsn_1_0)
        ihab.interact(data=[SealEvent(vcp.pre, '0', vcp.said)._asdict()], version=Vrsn_1_0)
        vcpmsg = messagize(vcp, bonds=[SealSource(Number(num=ihab.kever.sn),
            Diger(qb64=ihab.kever.serder.said))], gvrsn=Vrsn_1_0, framed=False)
        schema = Schemer(sed={'$id': '', '$schema': 'http://json-schema.org/draft-07/schema#',
            'type': 'object', 'properties': {'a': {'type': 'object',
            'properties': {'status': {'type': 'string'}}}}, 'required': ['a']})
        credential = proving.credential(schema= schema.said, issuer=ihab.pre,
            status=vcp.pre, data={'status': 'authorized'}, version=Vrsn_1_0)
        iss = legacy.issue(credential.said, vcp.pre, version=Vrsn_1_0)
        ihab.interact(data=[SealEvent(credential.said, '0', iss.said)._asdict()], version=Vrsn_1_0)
        issmsg = messagize(iss, bonds=[SealSource(Number(num=ihab.kever.sn),
            Diger(qb64=ihab.kever.serder.said))], gvrsn=Vrsn_1_0, framed=False)
        proof = messagize(credential, bonds=[SealEvent(vcp.pre, '0', iss.said)],
            gvrsn=Vrsn_1_0, framed=True)
        grantExn, atc = protocoling.ipexGrantExn(ihab, dhab.pre, 'legacy disclosure',
            acdc=proof, iss=issmsg, anc=ihab.msgOwnEvent(sn=ihab.kever.sn,
            gvrsn=Vrsn_1_0), version=Vrsn_1_0, gvrsn=Vrsn_1_0)
        source = legacy.Reger(name='dolly-old-source', temp=True)
        tvy = legacy.Tevery(db=issuer.db, reger=source)
        Parser(tvy=tvy, version=Vrsn_1_0).parse(ims=bytearray(vcpmsg + issmsg))
        assert source.tevers[vcp.pre].vcState(credential.said).d == iss.said
        received, queries, outbox, allowReplies = [], [], [], [False]
        inflight, responses = [False], []
        dolly = None

        class Hook:
            def on_post(self, req, rep):
                received.append(req.media)
                rep.media = {'received': True}

        class Source:
            def on_post(self, req, rep):
                event = SerderKERI(sad=json.loads(req.bounded_stream.read()))
                stream = event.raw + req.get_header(CESR_ATTACHMENT_HEADER).encode()
                psr = Parser(kvy=issuer.kvy, tvy=tvy, version=Vrsn_1_0)
                dom = psr.parseOne(ims=bytearray(stream), processive=False)
                psr.msgProcess(asdict(dom), kvy=issuer.kvy, tvy=tvy, exc=None, rvy=None, vry=None)
                if event.ilk == 'qry':
                    queries.append(event.route)
                rep.status = falcon.HTTP_202

        sourceApp, hookApp = falcon.App(), falcon.App()
        sourceApp.add_route('/', Source())
        hookApp.add_route('/hook', Hook())
        servers = [http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=app)
                   for app in (sourceApp, hookApp)]
        client = replyClient = None
        try:
            for server in servers:
                assert server.reopen()
                server.servant.eha = server.servant.ha
            sourceURL = f'http://127.0.0.1:{servers[0].servant.ha[1]}/'
            hookURL = f'http://127.0.0.1:{servers[1].servant.ha[1]}/hook'
            dolly = Dolly(verifier, dhab, issuers=[ihab.pre], schemas=[schema.said],
                fields={'status': 'a/status'}, required=['status'], observer=sourceURL,
                legacySources=[ihab.pre], webhook=hookURL)
            verifier.db.schema.pin((schema.said,), schema)
            # Public KEL, registry inception and signed endpoint metadata are
            # ordinary bootstrap inputs. Credential issuance still comes via grant.
            dolly.ingest(ihab.replay(gvrsn=Vrsn_1_0) + vcpmsg + ihab.makeLocScheme(
                url=sourceURL, version=Vrsn_1_0, gvrsn=Vrsn_1_0), version=Vrsn_1_0)
            ingress = http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=dolly.app)
            assert ingress.reopen()
            ingress.servant.eha = ingress.servant.ha
            servers.append(ingress)
            client = http.clienting.Client(hostname='127.0.0.1', port=ingress.servant.ha[1])
            client.request(method='POST', path='/ingest', body=grantExn.raw + atc,
                headers={'Content-Type': CESR_CONTENT_TYPE, 'CESR-Genus': '1'})
            replyClient = http.clienting.Client(hostname='127.0.0.1', port=ingress.servant.ha[1])

            def replies(tymth=None, tock=0.01, **kwa):
                yield tock
                while True:
                    if allowReplies[0]:
                        while replyClient.responses:
                            responses.append(replyClient.responses.popleft())
                            inflight[0] = False
                        while tvy.cues:
                            cue = tvy.cues.popleft()
                            if cue['kin'] == 'replay':
                                # Preserve the old peer's requested attachment
                                # genus instead of the library's current default.
                                outbox.append(b''.join(source.clonePreIter(vcp.pre, gvrsn=Vrsn_1_0))
                                    + b''.join(source.clonePreIter(credential.said, gvrsn=Vrsn_1_0)))
                            elif cue['kin'] == 'reply':
                                # Source composition turns the conventional cue
                                # into a real source-endorsed core reply message.
                                outbox.append(ihab.reply(route=cue['route'] + '/' + ihab.pre,
                                    data=cue['data'], version=Vrsn_1_0, gvrsn=Vrsn_1_0))
                        if outbox and not inflight[0]:
                            replyClient.request(method='POST', path='/ingest', body=outbox.pop(0),
                                headers={'Content-Type': CESR_CONTENT_TYPE, 'CESR-Genus': '1'})
                            inflight[0] = True
                    yield tock

            doers = [http.ServerDoer(server=server) for server in servers]
            doers += [http.clienting.ClientDoer(client), http.clienting.ClientDoer(replyClient),
                      doing.doify(replies), dolly]
            doing.Doist(real=True, tock=0.01, limit=1.3).do(doers=doers)
            assert client.responses.popleft()['status'] == 202
            assert dolly.legacy.reger.saved.get((credential.said,)) is not None
            assert dolly.db.submissions.get((grantExn.said,)).state == 'pending'
            assert received == []
            allowReplies[0] = True
            doing.Doist(real=True, tock=0.01, limit=3).do(doers=doers)
            assert 'tsn' in queries and 'tels' in queries
            assert len(responses) == 3 and all(r['status'] == 202 for r in responses)
            assert len(received) == 1, dict(
                reason=dolly.db.submissions.get((grantExn.said,)).reason,
                responses=[(r['status'], bytes(r['body'])) for r in responses],
                query=vars(dolly.db.legacyQueries.get((credential.said,))),
                observation=dolly.db.observed.get(('legacy', credential.said)),
                current=str(dolly.legacy.reger.txnsb.current((credential.said, ihab.pre))),
                replies=[s.sad for _, s in dolly.legacy.reger.txnsb.serderdb.getTopItemIter()])
            payload = received[0]
            assert payload['schema'] == 'dolly.accepted-credential/v1'
            assert payload['protocol'] == 1 and payload['standing'] == 'issued'
            assert payload['business'] == {'status': 'authorized'}
            assert payload['disclosure'] == {'status': 'disclosed'}
            assert dolly.db.submissions.get((grantExn.said,)).delivered
            assert dolly.db.observed.get(('legacy', credential.said)).head == iss.said
        finally:
            for connection in (client, replyClient):
                if connection:
                    connection.close()
            for server in servers:
                server.close()
            if dolly:
                dolly.close()
            source.close()


def test_two_node_chain_declared_presentation_registry_and_full_ipex_over_http():
    """The actual app evaluates a rotated issuer/holder graph and exact grant binding."""
    with (openHby(name='graph-issuer', version=Vrsn_2_0) as issuer,
          openHby(name='graph-holder', bran='0123456789abcdefghijk', version=Vrsn_2_0) as holder,
          openHby(name='graph-registrar', version=Vrsn_2_0) as registrar,
          openHby(name='graph-observer', version=Vrsn_2_0) as observer,
          openHby(name='graph-dolly', bran='0123456789abcdefghijk', version=Vrsn_2_0) as verifier):
        authority, ihab = issuer.makeHab(name='authority'), issuer.makeHab(name='issuer')
        hhab, ohab, dhab = holder.makeHab(name='holder'), observer.makeHab(name='observer'), verifier.makeHab(name='dolly')
        irgy, hrgy = Regery(hby=issuer, temp=True), Regery(hby=holder, temp=True)
        irar, hrar = NativeRegistrar(irgy), NativeRegistrar(hrgy)
        farReg = irar.makeRegistry(name='authority', prefix=authority.pre)
        nearReg = irar.makeRegistry(name='entitlement', prefix=ihab.pre)
        presentationReg = hrar.makeRegistry(name='presentation', prefix=hhab.pre)

        def anchor(hab, registry, event):
            hab.interact(data=[dict(i=registry.regk, s=event.sad['n'], d=event.said)])
            assert registry.anchorMsg(event.said)
            return hab.kever.serder

        rips = (irgy.store.event(farReg.regk), irgy.store.event(nearReg.regk),
                hrgy.store.event(presentationReg.regk))
        for hab, registry, rip in zip((authority, ihab, hhab), (farReg, nearReg, presentationReg), rips):
            anchor(hab, registry, rip)
        far = acdcmap(israid=authority.pre, regid=farReg.regk, iseaid=ihab.pre,
                      attribute=dict(d='', authority='may-issue-entitlement'))
        full = acdcmap(israid=ihab.pre, regid=nearReg.regk, iseaid=hhab.pre, uuid=Noncer().qb64,
            attribute={'d': '', 'rd': presentationReg.regk, 'u': Noncer().qb64,
                'entitlement': {'d': '', 'u': Noncer().qb64, 'value': 'use-service'},
                'private': {'d': '', 'u': Noncer().qb64, 'value': 'not-negotiated'}},
            edge={'d': '', 'authority': {'d': '', 'n': far.said, 's': far.schema['$id'], 'o': 'I2I'}})
        farProof, farIss = irar.issue(farReg, acdc=far)
        nearProof, nearIss = irar.issue(nearReg, acdc=full)
        anchor(authority, farReg, farIss)
        anchor(ihab, nearReg, nearIss)
        ihab.rotate(version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        compact = Compactor(mad=dict(full.sad['a']), makify=True, kind=Kinds.json)
        compact.compact(paths=['a/entitlement/'], root='a')
        partial = acdcmap(israid=ihab.pre, regid=nearReg.regk, iseaid=hhab.pre,
            uuid=full.sad['u'], schema=full.sad['s'], edge=full.sad['e'],
            attribute=dict(compact.partials[('a/entitlement/',)].mad))
        assert partial.said == full.said and isinstance(partial.sad['a']['private'], str)
        reg, obs = Registrar(registrar, observers=[ohab.pre]), Observer(observer, readers=[dhab.pre])
        sections = SectionBaser(name=holder.name, temp=True)
        hwallet, dwallet = Wallet(holder, hrgy), None
        peer = Peer(holder, hrgy, hwallet, sections)
        public = bytes(authority.replay(gvrsn=Vrsn_2_0) + ihab.replay(gvrsn=Vrsn_2_0)
                       + hhab.replay(gvrsn=Vrsn_2_0) + native(*rips, farIss, nearIss))
        received = []

        class Hook:
            def on_post(self, req, rep):
                received.append(req.media)
                rep.media = {'received': True}

        holderApp, hookApp = falcon.App(), falcon.App()
        holderApp.add_route('/ingest', Intake(peer))
        hookApp.add_route('/hook', Hook())
        servers = [http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=app)
                   for app in (reg.app, obs.app, holderApp, hookApp)]
        dolly, clients = None, []
        try:
            assert not reg.ingest(public)['rejected']
            assert not reg.ingest(ohab.replay(gvrsn=Vrsn_2_0))['rejected']
            assert not obs.ingest(dhab.replay(gvrsn=Vrsn_2_0))['rejected']
            assert not peer.evidence.ingest(public)['rejected']
            for server in servers:
                assert server.reopen()
                server.servant.eha = server.servant.ha
            urls = [f'http://127.0.0.1:{server.servant.ha[1]}/' for server in servers]
            obs.urls = frozenset([urls[0]])
            dolly = Dolly(verifier, dhab, issuers=[ihab.pre, authority.pre],
                schemas=[full.schema['$id']], fields={'entitlement': 'a/entitlement/value',
                    'private': 'a/private/value'}, required=['entitlement'],
                observer=urls[1], webhook=urls[3] + 'hook')
            dwallet = Wallet(verifier, dolly.rgy, exc=dolly.exc)
            ingress = http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=dolly.app)
            assert ingress.reopen()
            ingress.servant.eha = ingress.servant.ha
            servers.append(ingress)
            dollyURL = f'http://127.0.0.1:{ingress.servant.ha[1]}/ingest'
            puller = RegistrarPuller(ohab, obs, [urls[0]], interval=0.1, timeout=1)
            doers = [http.ServerDoer(server=server) for server in servers] + [puller, dolly]

            def send(url, raw, duration=0.25):
                from urllib.parse import urlsplit
                target = urlsplit(url)
                client = http.clienting.Client(hostname=target.hostname, port=target.port)
                clients.append(client)
                client.request(method='POST', path=target.path, body=raw,
                               headers={'Content-Type': CESR_CONTENT_TYPE})
                owner = http.clienting.ClientDoer(client)
                doing.Doist(real=True, tock=0.01, limit=duration).do(doers=[*doers, owner])
                assert client.responses and client.responses.popleft()['status'] == 202

            plan = [[[full.schema['$id'], '/', []], [far.schema['$id'], '/e/authority/_/', []]]]
            application, aatc = apply(dhab, hhab.pre, 'request entitlement chain', modifiers={'dp': plan})
            dolly.ingest(application.raw + aatc)
            send(urls[2] + 'ingest', dhab.replay(gvrsn=Vrsn_2_0) + application.raw + aatc)
            assert peer.exc.complete(application.said)
            offered, oatc = offer(hhab, 'disclose selected entitlement', origin=partial,
                                  artifacts=[far], apply=application)
            peer.ingest(offered.raw + oatc)
            send(dollyURL, hhab.replay(gvrsn=Vrsn_2_0) + offered.raw + oatc)
            assert dolly.exc.complete(offered.said)
            agreed, gatc = agree(dhab, 'agree to this chain disclosure', offered)
            dolly.ingest(agreed.raw + gatc)
            send(urls[2] + 'ingest', agreed.raw + gatc)
            assert peer.exc.complete(agreed.said)
            hhab.rotate(version=Vrsn_2_0, gvrsn=Vrsn_2_0)
            stamp = helping.nowIso8601()
            draft, _ = grant(hhab, dhab.pre, 'present selected entitlement chain',
                origin=partial, artifacts=[far], agree=agreed, dt=stamp)
            # Commit the already final grant body into the holder's public TEL.
            presented = update(presentationReg.regk, rips[2].said, draft.said, 'presented')
            presentationReg.processEvent(presented)
            source = anchor(hhab, presentationReg, presented)
            proofedNear = messagize(partial, bonds=[nearProof.data,
                SealEvent(hhab.pre, source.snh, source.said)], gvrsn=Vrsn_2_0)
            proofedFar = messagize(far, bonds=[farProof.data], gvrsn=Vrsn_2_0)
            final, fatc = grant(hhab, dhab.pre, 'present selected entitlement chain',
                origin=proofedNear, artifacts=[proofedFar], agree=agreed, dt=stamp)
            assert final.raw == draft.raw and final.said == draft.said
            peer.ingest(final.raw + fatc)
            assert peer.exc.complete(final.said)
            assert not reg.ingest(hhab.replay(gvrsn=Vrsn_2_0) + native(presented))['rejected']
            send(dollyURL, hhab.replay(gvrsn=Vrsn_2_0) + final.raw + fatc, duration=2.5)
            assert dolly.exc.complete(final.said)
            assert len(received) == 1, dolly.db.submissions.get((final.said,))
            assert received[0]['credential'] == full.said
            assert received[0]['business'] == {'entitlement': 'use-service', 'private': None}
            assert received[0]['disclosure']['private'] == 'undisclosed'
            assert 'not-negotiated' not in json.dumps(received[0])
            assert all(dolly.fresh(regid) for regid in (farReg.regk, nearReg.regk, presentationReg.regk))
            assert verifier.kevers[ihab.pre].lastEst.d == ihab.kever.lastEst.d
            assert verifier.kevers[hhab.pre].lastEst.d == hhab.kever.lastEst.d
            admitted, iatc = admit(dhab, 'admit the verified entitlement chain', final)
            dolly.ingest(admitted.raw + iatc)
            assert dolly.exc.complete(admitted.said)
            assert dwallet.recordAdmission(final.said, admitted.said, consent=True).credential == full.said
            send(urls[2] + 'ingest', admitted.raw + iatc)
            assert peer.exc.complete(admitted.said)
        finally:
            for client in clients:
                client.close()
            for server in servers:
                server.close()
            if dwallet:
                dwallet.close()
            if dolly:
                dolly.close()
            hwallet.close()
            sections.close()
            reg.close()
            obs.close()
            irgy.close()
            hrgy.close()
