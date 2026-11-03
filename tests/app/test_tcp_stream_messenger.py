"""Exercise finite stream-messenger payload and scheduler ownership over TCP."""
import socket
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from hio.base import doing
from hio.core import tcp

from keri.app import agenting, openHby
from keri.kering import Schemes


@pytest.mark.parametrize("payload", [b"CESR stream", bytes(range(256)) * 1024],
                         ids=["small", "multi-buffer"])
def test_tcp_stream_delivers_exact_payload_and_finishes(payload):
    """Factory delivery drains exact multi-buffer bytes and closes owned I/O."""
    with openHby(name="tcp-stream") as hby:
        hab = hby.makeHab(name="sender")
        server = tcp.Server(host="127.0.0.1", port=0)
        server.reopen()
        server.eha = server.ha
        try:
            sender = agenting.streamMessengerFrom(
                hab, hab.pre, {Schemes.tcp: f"tcp://127.0.0.1:{server.ha[1]}"},
                msg=bytearray(payload))
            doing.Doist(real=True, tock=0.001, limit=0.5).do(
                doers=[tcp.ServerDoer(server=server), sender])
            received = b"".join(bytes(remote.rxbs) for remote in server.ixes.values())
            assert received == payload
            assert sender.done is True  # transport completion, no receiver authentication
            assert sender.client.cs is None
            assert not sender.deeds
        finally:
            server.close()


def test_tcp_stream_cancellation_closes_unavailable_peer():
    """An outer timeout closes owned I/O without claiming stream completion."""
    with openHby(name="tcp-unavailable") as hby, socket.socket() as reserved:
        hab = hby.makeHab(name="sender")
        reserved.bind(("127.0.0.1", 0))  # occupied endpoint deliberately never listens
        sender = agenting.streamMessengerFrom(
            hab, hab.pre, {Schemes.tcp: f"tcp://127.0.0.1:{reserved.getsockname()[1]}"},
            msg=b"CESR stream")
        doing.Doist(real=True, tock=0.001, limit=0.05).do(doers=[sender])
        assert sender.done is False
        assert sender.client.cs is None
        assert not sender.deeds


def test_tcp_stream_peer_close_after_drain_is_complete():
    """A real received EOF cannot undo an already drained local send buffer."""
    payload = b"finite CESR stream" * 4096
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(2)

        def receive_and_close():
            received = bytearray()
            peer, _ = listener.accept()
            with peer:
                peer.settimeout(2)
                while len(received) < len(payload):
                    part = peer.recv(65536)
                    if not part:
                        break
                    received.extend(part)
            return bytes(received)

        sender = agenting.TCPStreamMessenger(
            hab=None, wit="peer", url=f"tcp://127.0.0.1:{listener.getsockname()[1]}",
            msg=payload)
        with ThreadPoolExecutor(max_workers=1) as executor:
            received = executor.submit(receive_and_close)
            try:
                sender.client.reopen()
                deadline = time.monotonic() + 2
                # Delay the parent's completion check until actual peer EOF.
                while not sender.client.cutoff and time.monotonic() < deadline:
                    sender.client.service()
                    time.sleep(0.0001)
                assert received.result(timeout=2) == payload
                assert sender.client.connected
                assert not sender.client.txbs
                assert sender.client.cutoff
                assert sender.recur(tyme=0.0) is True
            finally:
                sender.client.close()


@pytest.mark.parametrize("url", ["http://127.0.0.1:1234", "tcp://127.0.0.1",
                                 "tcp://user@127.0.0.1:1234", "tcp://127.0.0.1:1234/path"],
                         ids=["wrong-scheme", "missing-port", "credentials", "path"])
def test_tcp_stream_refuses_invalid_destination(url):
    with pytest.raises(ValueError):
        agenting.TCPStreamMessenger(hab=None, wit="peer", url=url, msg=b"CESR stream")
