"""Poster selects HTTP transport that preserves its configured stream framing."""

import itertools

import falcon
import pytest
from hio.base import doing
from hio.core import http, tcp

from keri import Kinds, Roles, Schemes, Vrsn_1_0, Vrsn_2_0
from keri.app import Poster, openHab, httping
from keri.app.agenting import HTTPMessenger, HTTPStreamMessenger
from keri.core import Parser, SerderKERI
from tests.app.test_tcp_stream_delivery import advance


@pytest.mark.parametrize('version, cancel', [(Vrsn_1_0, False), (Vrsn_2_0, False), (Vrsn_2_0, True)])
def test_poster_direct_http_authenticates_exact_child(version, cancel):
    """Actual clients preserve the signed child and its verifiable authenticators."""
    with openHab(name='direct-http-sender', temp=True, version=version,
                 kind=Kinds.json if version == Vrsn_1_0 else Kinds.cesr) as (hby, sender), \
            openHab(name='direct-http-recipient', temp=True, version=version) as (rby, recipient):
        captured = []

        class Intake:
            def on_post(self, req, rep):
                """Pass HTTP-native bytes or legacy split headers to the existing parser."""
                if httping.CESR_ATTACHMENT_HEADER not in req.headers:
                    stream = req.bounded_stream.read()
                else:
                    request = httping.parseCesrHttpRequest(req)
                    stream = SerderKERI(sad=request.payload, kind=Kinds.json).raw + request.attachments.encode()
                captured.append(stream)
                if cancel:
                    rep.stream = itertools.repeat(b'')  # accepted request, stalled response
                else:
                    rep.status = falcon.HTTP_204

            on_put = on_post

        app = falcon.App()
        app.add_route('/', Intake())
        server = http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=app)
        assert server.reopen()
        server.servant.eha = server.servant.ha
        evidence = recipient.replay(gvrsn=version)
        evidence.extend(recipient.makeEndRole(eid=recipient.pre, role=Roles.controller,
            version=version, gvrsn=version))
        evidence.extend(recipient.makeLocScheme(url=f'http://127.0.0.1:{server.servant.ha[1]}',
            scheme=Schemes.http, version=version, gvrsn=version))
        hby.psr.parse(ims=evidence)
        child = sender.kever.serder
        raw = sender.msgOwnInception(gvrsn=version)
        poster = Poster(hby, version=version)
        poster.send(dest=recipient.pre, topic='replay', hab=sender,
            serder=child, attachment=raw[child.size:], gvrsn=version)
        doist = doing.Doist(tock=0.01)
        transports = []

        def complete():
            for transport in poster.doers:
                if isinstance(transport, (HTTPMessenger, HTTPStreamMessenger)) and transport not in transports:
                    transports.append(transport)
            return bool(captured and transports) if cancel else poster.sent(child.said)

        try:
            doist.deeds.extend(doist.enter(doers=[http.ServerDoer(server), poster]))
            advance(doist, complete)
            assert len(captured) == 1
            parsed = Parser(version=version).parse(ims=bytearray(captured[0]), processive=False)
            assert len(parsed) == 1 and parsed[0].serder.raw == child.raw
            assert len(parsed[0].sigers) == 1
            signature = parsed[0].sigers[0]
            assert sender.kever.verfers[signature.index].verify(signature.raw, child.raw)
            if version == Vrsn_1_0:
                assert captured == [bytes(raw)]
            elif not cancel:
                assert all(isinstance(transport, HTTPStreamMessenger) and transport.done for transport in transports)
                assert all(transport not in poster.doers for transport in transports)
            else:
                assert not poster.sent(child.said) and all(not transport.done for transport in transports)
        finally:
            doist.exit()
            server.close()
        assert transports and all(transport.client.connector.cs is None and not transport.deeds for transport in transports)
        assert all(transport not in poster.doers for transport in transports)
