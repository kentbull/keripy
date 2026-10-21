"""Legacy evidence service authenticates actual socket requests and core replies."""
import json
import time

import falcon
import pytest
from hio.base import doing
from hio.core import http, tcp

from keri import Vrsn_1_0, Vrsn_2_0, Kinds
from keri.app import openHby
from keri.cli.common.legacy_evidence import Source
from keri.core import Parser, SealEvent, Seqner, Diger, Prefixer, SerderKERI, Counter, Codens
from keri.vdr import Regery


def anchor(hab, rgy, reg, event):
    """Accept event through a real Hab KEL seal and ordinary legacy processors.

    hab/rgy/reg are test-owned core objects; event is their staged TEL event.
    Return None. Core acceptance errors propagate, and assertions require the
    accepted TEL marker rather than installing a synthesized accepted row.
    """
    hab.interact(data=[SealEvent(event.pre, event.snh, event.said)._asdict()],
                 version=Vrsn_1_0, kind=Kinds.json)
    reg.anchorMsg(pre=event.pre, regd=event.said, seqner=Seqner(sn=hab.kever.sn),
                  saider=Diger(qb64=hab.kever.serder.said))
    rgy.processEscrows()
    assert rgy.reger.tels.get(keys=event.pre, on=event.sn) == event.said


def advance(doist, predicate):
    """Drive real cooperative sockets until predicate or a finite wall deadline.

    doist owns entered test doers; predicate observes actual transport results.
    Return None when true. AssertionError exposes stalls instead of allowing a
    hung request to pass as rejection.
    """
    deadline = time.monotonic() + 5
    while not predicate():
        assert time.monotonic() < deadline
        doist.recur()
        time.sleep(0.002)


def test_signed_legacy_source_queries_and_core_state_replies(monkeypatch):
    """Require real source-authenticated TSNs/replay and reject hostile requests.

    monkeypatch injects one operationally oversized signed reply; return None.
    Socket responses prove signed last-establishment
    query handling, fresh conventional TSN generation, exact accepted replay and
    no unauthorized callback. Wrong signer, signature, registry, version/header,
    oversized and truncated frames must fail without hanging or queuing proof.
    """
    with (openHby(name='source-issuer', version=Vrsn_1_0) as issuer,
          openHby(name='source-reader', version=Vrsn_1_0) as reader,
          openHby(name='source-stranger', version=Vrsn_1_0) as stranger):
        ihab = issuer.makeHab(name='issuer', version=Vrsn_1_0)
        rhab = reader.makeHab(name='reader', version=Vrsn_1_0)
        shab = stranger.makeHab(name='stranger', version=Vrsn_1_0)
        for hab in (rhab, shab):
            Parser(version=Vrsn_1_0).parse(ims=bytearray(hab.replay(gvrsn=Vrsn_1_0)), kvy=issuer.kvy)
        rgy = Regery(hby=issuer, name=issuer.name, temp=True)
        servers, client, doist = [], None, None
        try:
            reg = rgy.makeRegistry(prefix=ihab.pre, name='r', noBackers=True,
                                   version=Vrsn_1_0, kind=Kinds.json)
            from keri.vdr import eventing
            anchor(ihab, rgy, reg, reg.vcp)
            target = Diger(ser=b'real credential commitment').qb64
            issued = reg.issue(said=target)
            anchor(ihab, rgy, reg, issued)
            replies = []

            class Capture:
                """Capture bytes actually delivered over the independent socket."""
                def on_post(self, req, rep):
                    """Append req bytes, acknowledge via rep; return None, I/O errors fail."""
                    replies.append(req.bounded_stream.read())
                    rep.status = falcon.HTTP_202

            app = falcon.App()
            app.add_route('/proof', Capture())
            callback = http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=app)
            assert callback.reopen()
            callback.servant.eha = callback.servant.ha
            servers.append(callback)
            source = Source(issuer, rgy, ihab, reg, [rhab.pre],
                f'http://127.0.0.1:{callback.servant.ha[1]}/proof', timeout=1)
            listener = http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=source.app)
            assert listener.reopen()
            listener.servant.eha = listener.servant.ha
            servers.append(listener)
            client = http.clienting.Client(hostname='127.0.0.1', port=listener.servant.ha[1])
            doist = doing.Doist(tock=0.01, real=False, doers=[
                *(http.ServerDoer(server=item) for item in servers),
                http.clienting.ClientDoer(client), source])
            doist.enter()

            def request(raw, expected, headers=None):
                """Send raw query bytes and require expected actual HTTP status.

                headers optionally supplies framing overrides. Return None; a
                transport stall or mismatched status raises AssertionError.
                """
                client.request(method='POST', path='/', body=bytes(raw),
                    headers={'Content-Type': 'application/cesr', **(headers or {})})
                advance(doist, lambda: bool(client.responses))
                response = client.responses.popleft()
                assert response['status'] == expected, response

            def query(hab=rhab, route='tsn', registry=None, version=Vrsn_1_0):
                """Return a normal Hab-signed query selecting this accepted credential.

                hab/route/registry/version select real query fields and keys.
                Core signing errors propagate. No query or reply row is written.
                """
                return hab.query(target, src=ihab.pre, route=route,
                    query={'ri': registry or reg.regk}, version=version, gvrsn=version, kind=Kinds.json)

            request(query(), 202)
            advance(doist, lambda: len(replies) == 2)
            routes = []
            for raw in replies:
                ims = bytearray(raw)
                while ims:
                    dom = Parser(version=Vrsn_1_0).parseOne(ims=ims, processive=False)
                    if dom.serder.ilk == 'rpy':
                        routes.append(dom.serder.route)
                        assert dom.serder.sad['a']['d'] in (reg.regd, issued.said)
                        assert dom.serder.pvrsn == Vrsn_1_0
            assert routes == ['/tsn/registry/' + ihab.pre, '/tsn/credential/' + ihab.pre]
            request(query(route='tels'), 202)
            advance(doist, lambda: len(replies) == 3)
            assert issued.raw in replies[-1] and reg.vcp.raw in replies[-1]
            replay = bytearray(replies[-1])
            seals = {}
            while replay:
                dom = Parser(version=Vrsn_1_0).parseOne(ims=replay, processive=False)
                assert dom is not None and dom.serder.pvrsn == Vrsn_1_0
                if dom.serder.ilk in ('vcp', 'iss'):
                    assert len(dom.sscs) == 1
                    number, diger = dom.sscs[0]
                    seals[dom.serder.said] = (number.num, diger.qb64)
            assert seals == {
                reg.vcp.said: (1, issuer.db.kels.getLast(keys=ihab.pre, on=1)),
                issued.said: (2, issuer.db.kels.getLast(keys=ihab.pre, on=2))}

            request(query(hab=shab), 401)
            altered = bytearray(query())
            altered[-12] = ord('A') if altered[-12] != ord('A') else ord('B')
            request(altered, 401)
            request(query(registry=Diger(ser=b'other registry').qb64), 400)
            from keri.core.eventing import query as makeQuery
            for fields in ([], {'ri': reg.regk, 'src': ihab.pre, 'i': []},
                           {'ri': {}, 'src': ihab.pre, 'i': target}):
                malformed = makeQuery(route='tsn', query=fields,
                    version=Vrsn_1_0, kind=Kinds.json)
                request(rhab.endorse(malformed, last=True, gvrsn=Vrsn_1_0), 400)
            request(query(version=Vrsn_2_0), 400)
            request(query(), 400, {'CESR-Genus': '2'})
            request(query()[:-12], 400)
            # Unsupported factors cannot be ignored even beside a valid signer.
            event = makeQuery(route='tsn', query={'ri': reg.regk, 'src': ihab.pre, 'i': target},
                              version=Vrsn_1_0, kind=Kinds.json)
            extra = bytearray(rhab.endorse(event, last=True, framed=True, gvrsn=Vrsn_1_0))
            extra.extend(Counter(Codens.WitnessIdxSigs, count=1, version=Vrsn_1_0).qb64b)
            extra.extend(rhab.sign(b'invalid query witness signature')[0].qb64b)
            request(extra, 401)
            # A bad later frame cannot queue an earlier otherwise valid reply.
            request(query() + query()[:-12], 400)
            assert not source.outbox
            with pytest.raises(ValueError):
                Source(issuer, rgy, ihab, reg, [rhab.pre], 'http://127.0.0.1:not-a-port/proof')
            request(b'x' * 65537, 413)
            originalReply = ihab.reply

            def oversizedReply(**options):
                """Sign one deliberately oversized fixture reply through the real Hab.

                options are normal source reply arguments. Return genuine signed
                bytes with extra fixture data; core errors propagate. This tests
                operational queue cleanup, not acceptance of the enlarged payload.
                """
                options['data'] = dict(options['data'], fixturePadding='x' * (4 * 1024 * 1024))
                return originalReply(**options)

            with monkeypatch.context() as patch:
                patch.setattr(ihab, 'reply', oversizedReply)
                request(query(), 503)
            assert not source.outbox and not source.tvy.cues
            request(query(), 202)
            advance(doist, lambda: len(replies) == 5)
            for _ in range(10):
                doist.recur()
            assert len(replies) == 5 and not source.outbox
        finally:
            if doist is not None:
                doist.exit()
            if client is not None:
                client.close()
            for server in servers:
                server.close()
            rgy.close()


def test_source_reopens_persisted_reader_without_kel_reintroduction():
    """Authenticate a stored foreign reader after actual source-store reopening.

    No arguments/return. Public query bytes are retained across both contexts;
    ordinary KEL/TEL processors establish state before close. Reopening must use
    persisted reader key state without receiving its KEL again. Assertions expose
    a cold-cache authorization failure or accidental reliance on live objects.
    """
    import uuid
    name = 'legacy-source-reopen-' + uuid.uuid4().hex
    base = 'legacy-source-reopen'
    with (openHby(name=name, base=base, temp=False, version=Vrsn_1_0) as issuer,
          openHby(name='reader-reopen', version=Vrsn_1_0) as reader):
        hab = issuer.makeHab(name='issuer', version=Vrsn_1_0)
        rhab = reader.makeHab(name='reader', version=Vrsn_1_0)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(rhab.replay(gvrsn=Vrsn_1_0)), kvy=issuer.kvy)
        rgy = Regery(hby=issuer, name=name, base=base, temp=False)
        try:
            reg = rgy.makeRegistry(prefix=hab.pre, name='r', noBackers=True,
                                   version=Vrsn_1_0, kind=Kinds.json)
            anchor(hab, rgy, reg, reg.vcp)
            credential = Diger(ser=b'reopen credential').qb64
            issued = reg.issue(said=credential)
            anchor(hab, rgy, reg, issued)
            query = bytes(rhab.query(credential, src=hab.pre, route='tsn',
                query={'ri': reg.regk}, version=Vrsn_1_0, gvrsn=Vrsn_1_0, kind=Kinds.json))
            readerAid = rhab.pre
        finally:
            rgy.close()
    with openHby(name=name, base=base, temp=False, version=Vrsn_1_0) as issuer:
        assert readerAid not in list(issuer.kevers)
        rgy = Regery(hby=issuer, name=name, base=base, temp=False)
        try:
            source = Source(issuer, rgy, issuer.habByName('issuer'),
                rgy.registryByName('r'), [readerAid], 'http://127.0.0.1:19999/ingest')
            assert source.ingest(query) == 2
            assert len(source.outbox) == 2
        finally:
            rgy.close()
