# -*- encoding: utf-8 -*-
"""
tests.app.test_pr1614_http module

Exercises the HTTP messengers against a real peer that answers the request and
then closes the connection, so the cutoff bookkeeping runs in the order HIO
produces it: cutoff becomes visible on the connector during
``serviceReceives``, while the response it terminates is only finalized by a
later ``Patron.service`` pass that calls ``respondent.close()``.

Two peer framings are covered because they exercise different HIO paths:

* a close framed body (``Connection: close`` with no ``Content-Length``), where
  the peer's FIN is the body terminator, and
* a ``Content-Length`` framed body written in full before the peer closes.
"""
import socket
import threading
import time

import pytest

from hio.base import doing

from keri.app import agenting, habbing


# Peer response terminated by the connection close itself - HTTP/1.0 style
# framing that proxies and load balancers still emit.
RESPONSE_CLOSE_FRAMED = (b"HTTP/1.1 200 OK\r\n"
                         b"Content-Type: application/json\r\n"
                         b"Connection: close\r\n"
                         b"\r\n"
                         b"{}")

# Peer response framed by Content-Length and written in full, after which the
# peer closes immediately - the shape a witness behind a load balancer that
# reaps idle connections produces.
RESPONSE_LENGTH_FRAMED = (b"HTTP/1.1 200 OK\r\n"
                          b"Content-Type: application/json\r\n"
                          b"Content-Length: 2\r\n"
                          b"Connection: close\r\n"
                          b"\r\n"
                          b"{}")

PEER_RESPONSES = (
    pytest.param(RESPONSE_CLOSE_FRAMED, id="close-framed-body"),
    pytest.param(RESPONSE_LENGTH_FRAMED, id="content-length-then-close"),
)


def takeRequest(buf):
    """Pop one complete HTTP request off buf, or return None if incomplete.

    Parameters:
        buf (bytearray): accumulated bytes received from the messenger.

    Returns:
        tuple | None: (head, body) bytes of one request, consumed from buf.
    """
    if b"\r\n\r\n" not in buf:
        return None

    head, _, rest = bytes(buf).partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())

    if len(rest) < length:
        return None

    del buf[:len(head) + 4 + length]
    return head, rest[:length]


class CannedResponsePeer:
    """One shot HTTP peer that answers a single request and then closes.

    A canned peer rather than a real witness, because these tests need exact
    control over the response framing and over when the peer's FIN reaches the
    messenger's connector.
    """

    def __init__(self, response, timeout=5.0):
        """Bind an ephemeral localhost listener for a single connection.

        Parameters:
            response (bytes): raw bytes written back to the one accepted peer.
            timeout (float): socket timeout so a stalled peer fails the test
                with an assertion rather than hanging it.
        """
        self.response = response
        self.timeout = timeout
        self.conn = None
        self.request = None
        self.failure = None

        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(timeout)
        self.port = self.listener.getsockname()[1]

        self.thread = threading.Thread(target=self.serve,
                                       name="pr1614-http-peer",
                                       daemon=True)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        self.thread.start()

    def serve(self):
        """Accept one connection, read one whole request, answer, then close."""
        try:
            conn, _ = self.listener.accept()
            self.conn = conn
            conn.settimeout(self.timeout)
            self.request = self.readRequest(conn)
            conn.sendall(self.response)
            # Half close so the peer's FIN follows the response bytes.  The
            # whole request was read first, so the kernel sends FIN rather than
            # RST and the messenger sees a clean end of stream.
            conn.shutdown(socket.SHUT_WR)
        except BaseException as ex:  # surfaced by the waiter's failure message
            self.failure = ex

    @staticmethod
    def readRequest(conn):
        """Block until one whole request has been read from conn."""
        buf = bytearray()
        while True:
            request = takeRequest(buf)
            if request is not None:
                return request

            chunk = conn.recv(4096)
            if not chunk:
                raise AssertionError("peer saw EOF before a whole request")
            buf.extend(chunk)

    def stop(self):
        """Join the peer thread and release both sockets."""
        self.thread.join(timeout=self.timeout)
        if self.conn is not None:
            self.conn.close()
        self.listener.close()


def recurUntilPeer(doist, peer, condition, message, timeout=5.0):
    """Recur a Doist in real time until condition holds or timeout expires.

    The real time analogue of tests.app.recurUntil, which advances Doist tyme
    rather than wall clock time.  Progress here depends on a peer running on
    another thread, so the loop has to sleep between recurrences and bound
    itself by a wall clock deadline; that keeps a stalled peer an assertion
    rather than a hang.

    message may be a callable so a state dump is rendered when the wait fails
    rather than when the wait starts.
    """
    deadline = time.time() + timeout
    while not condition():
        if time.time() > deadline:
            report = message() if callable(message) else message
            raise AssertionError(f"{report} (peer failure={peer.failure!r})")
        doist.recur()
        time.sleep(doist.tock)


@pytest.mark.parametrize("response", PEER_RESPONSES)
def test_http_messenger_keeps_response_when_peer_closes(response):
    """A 200 that the peer terminates by closing is a response, not a failure."""
    with habbing.openHab(name="pr1614-http-messenger",
                         salt=b"0123456789abcdef") as (_, hab):
        peer = CannedResponsePeer(response=response)
        peer.start()

        messenger = agenting.HTTPMessenger(hab=hab, wit=hab.pre, url=peer.url)
        doist = doing.Doist(tock=0.03125, limit=1.0, doers=[messenger])
        doist.enter()

        try:
            messenger.msgs.append(bytearray(hab.makeOwnInception()))

            recurUntilPeer(
                doist, peer,
                condition=lambda: bool(messenger.sent),
                message="the peer's 200 response never reached sent",
            )
            assert peer.failure is None

            # settle so cutoff bookkeeping from the closing connection lands
            for _ in range(8):
                doist.recur()
                time.sleep(doist.tock)

            # the response is preserved intact
            rep = messenger.sent[0]
            assert rep.status == 200

            # and an arrived response is not a connection failure
            assert messenger.error is None, (
                f"status {rep.status} reached sent, yet "
                f"error={messenger.error!r} and idle={messenger.idle}")
            assert messenger.idle
        finally:
            doist.exit()
            peer.stop()


@pytest.mark.parametrize("response", PEER_RESPONSES)
def test_http_stream_messenger_keeps_response_when_peer_closes(response):
    """The one shot messenger reports the 200 it received, not a cutoff."""
    with habbing.openHab(name="pr1614-http-stream-messenger",
                         salt=b"0123456789abcdef") as (_, hab):
        peer = CannedResponsePeer(response=response)
        peer.start()

        messenger = agenting.HTTPStreamMessenger(hab=hab,
                                                 wit=hab.pre,
                                                 url=peer.url,
                                                 msg=hab.makeOwnInception())
        doist = doing.Doist(tock=0.03125, limit=1.0, doers=[messenger])
        doist.enter()

        try:
            recurUntilPeer(
                doist, peer,
                condition=lambda: (messenger.done or
                                   messenger.rep is not None or
                                   messenger.error is not None),
                message="the one shot messenger never terminated",
            )
            assert peer.failure is None

            # the response is preserved rather than discarded as a cutoff
            assert messenger.rep is not None, (
                f"the peer answered 200 but rep is None with "
                f"error={messenger.error!r}")
            assert messenger.rep.status == 200
            assert messenger.error is None
        finally:
            doist.exit()
            peer.stop()
