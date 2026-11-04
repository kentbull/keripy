"""Both CESR HTTP media types carry the same body and detached attachments."""

import time

import falcon
import pytest
from hio.core import http

from keri import kering
from keri.app import httping, indirecting
from keri.core import counting, eventing, parsing, signing
from keri.db import basing


@pytest.mark.parametrize("version", [kering.Vrsn_1_0, kering.Vrsn_2_0], ids=["v1", "v2"])
@pytest.mark.parametrize("content_type", ["application/cesr", "application/cesr+json"])
@pytest.mark.parametrize("valid", [True, False], ids=["valid-signature", "invalid-signature"])
def test_cesr_http_loopback_preserves_detached_attachments(version, content_type, valid, unused_tcp_port):
    signer = signing.Signer(raw=b's' * 32)
    serder = eventing.incept(keys=[signer.verfer.qb64],
                            version=version, kind=kering.Kinds.json)
    signing_key = signer if valid else signing.Signer(raw=b'x' * 32)
    signature = signing_key.sign(ser=serder.raw, index=0)
    message = eventing.messagize(serder, sigers=[signature], gvrsn=version)
    expected = bytes(message)
    attachments = expected[serder.size:]

    endpoint = indirecting.HttpEnd()
    app = falcon.App()
    app.add_route("/", endpoint)
    with http.openServer(host="127.0.0.1", port=unused_tcp_port, app=app) as server:
        assert server.servant.opened
        with http.openClient(hostname="127.0.0.1", port=server.servant.ha[1]) as client:
            httping.createCESRRequest(bytearray(message), client, dest=serder.pre)
            request = client.requests[-1]
            assert request["body"] == serder.raw
            assert bytes(request["headers"][httping.CESR_ATTACHMENT_HEADER]) == attachments
            request["headers"]["Content-Type"] = content_type
            deadline = time.monotonic() + 2.0
            while not client.responses and time.monotonic() < deadline:
                client.service()
                server.service()
                time.sleep(0.001)
            assert client.responses, "loopback HTTP response timed out"
            response = client.responses.popleft()
            assert response["status"] == 204

    assert bytes(endpoint.rxbs) == expected
    with basing.openDB(name="cesr-http-receiver") as db:
        kvy = eventing.Kevery(db=db)
        assert serder.pre not in kvy.kevers  # HTTP submission has not authenticated it
        parsing.Parser(version=version).parse(ims=endpoint.rxbs, kvy=kvy)
        assert not endpoint.rxbs
        assert (serder.pre in kvy.kevers) is valid
        if valid:
            assert kvy.kevers[serder.pre].serder.raw == serder.raw
            assert [sig.qb64 for sig in db.sigs.get(keys=(serder.pre, serder.said))] == [signature.qb64]


def test_cesr_http_loopback_restores_advertised_genus(unused_tcp_port):
    """One shared V2 parser authenticates declared contexts independently of body version."""
    endpoint = indirecting.HttpEnd()
    app = falcon.App()
    app.add_route("/", endpoint)
    events = []
    expected = bytearray()
    with http.openServer(host="127.0.0.1", port=unused_tcp_port, app=app) as server:
        def deliver(event, message, genus):
            # HttpEnd closes each response connection; each delivery owns a fresh real client.
            with http.openClient(hostname="127.0.0.1", port=server.servant.ha[1]) as client:
                httping.createCESRRequest(bytearray(message), client, dest=event.pre)
                request = client.requests[-1]
                assert request["body"] == event.raw
                assert bytes(request["headers"][httping.CESR_ATTACHMENT_HEADER]) == message[event.size:]
                request["headers"]["CESR-Genus"] = genus
                deadline = time.monotonic() + 2.0
                while not client.responses and time.monotonic() < deadline:
                    client.service()
                    server.service()
                    time.sleep(0.001)
                assert client.responses, "loopback HTTP response timed out"
                return client.responses.popleft()["status"]

        for secret, genus in ((b'a' * 32, kering.Vrsn_1_0), (b'b' * 32, kering.Vrsn_2_0)):
            signer = signing.Signer(raw=secret)
            # Both bodies are V1: the second proof still requires the advertised V2 context.
            event = eventing.incept(keys=[signer.verfer.qb64], version=kering.Vrsn_1_0,
                                   kind=kering.Kinds.json)
            signature = signer.sign(ser=event.raw, index=0)
            message = eventing.messagize(event, sigers=[signature], gvrsn=genus)
            assert deliver(event, message, str(genus.major)) == 204
            expected.extend(counting.Counter.makeGVC(genus) + message)
            events.append((event, signature))
        assert bytes(endpoint.rxbs) == expected

        # Unsupported and malformed explicit contexts refuse before adding parser input.
        for genus in ("3", "2.0"):
            assert deliver(event, message, genus) == 400
            assert bytes(endpoint.rxbs) == expected

    with basing.openDB(name="mixed-genus-http-receiver") as db:
        kvy = eventing.Kevery(db=db)
        assert all(event.pre not in kvy.kevers for event, _ in events)
        parsing.Parser(version=kering.Vrsn_2_0).parse(ims=endpoint.rxbs, kvy=kvy)
        assert not endpoint.rxbs
        for event, signature in events:
            assert kvy.kevers[event.pre].serder.raw == event.raw
            assert [sig.qb64 for sig in db.sigs.get(keys=(event.pre, event.said))] == [signature.qb64]
