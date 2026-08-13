# -*- encoding: utf-8 -*-
"""
tests.app.test_pr1614_error_escape module

What a Poster does when a witness endpoint resets the TCP connection while a
delivery is still in flight.

The endpoint here is a real localhost socket that accepts, waits for the first
bytes to arrive, then resets, so the transport failure and the messenger's
reaction to it come from the production code path rather than from a hand-set
attribute.

Why the failure reaches the scheduler, for whoever reads a failure here: the
transport failure surfaces at ``raise witer.error`` in ``Poster.sendDirect``
(``src/keri/app/forwarding.py:174``), and nothing above it contains the
exception.  hio contains only ``StopIteration``
(``hio/base/doing.py:300`` and ``:1083``); every other exception is re-raised
by ``DoDoer.do`` (``:975``) and again by ``Doist.do`` (``:195``).
``ClosedError`` is a sibling of ``ConfigurationError`` rather than a subclass
(``src/keri/kering.py:382`` and ``:391``), so ``deliverDo``'s handler
(``src/keri/app/forwarding.py:94``) does not catch it either.  One witness
resetting one connection therefore ends the Doist and every other doer sharing
it.
"""
import socket
import struct
import threading
from contextlib import contextmanager

from hio.base import doing

from keri import kering
from keri.app import forwarding, habbing
from keri.db import basing
from keri.peer import exchanging

# One delivery larger than any pair of localhost socket buffers can absorb, so
# that bytes are still queued in the messenger when the peer disappears. A
# cutoff after a complete drain is not a failed delivery and is not of interest
# here.
PADSIZE = 8 * 1024 * 1024

TOCK = 0.03125
LIMIT = 2.0


class FakeEndpoint:
    """Localhost TCP peer standing in for a witness or controller endpoint.

    Parameters:
        drain (bool): True reads and discards everything sent, so a messenger
            completes normally. False reads one byte to prove the transfer
            started, then resets the connection with bytes still unsent.
    """

    def __init__(self, drain=False):
        self.drain = drain
        self.lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lsock.bind(("127.0.0.1", 0))  # port 0 so the kernel picks a free one
        self.lsock.listen(1)
        self.lsock.settimeout(0.25)
        self.port = self.lsock.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)

    @property
    def url(self):
        return f"tcp://127.0.0.1:{self.port}"

    def serve(self):
        conn = None
        try:
            while not self.stop.is_set():
                try:
                    conn, _ = self.lsock.accept()
                    break
                except TimeoutError:  # socket.timeout, keep polling .stop
                    continue

            if conn is None:
                return

            conn.settimeout(0.25)
            if self.drain:
                while not self.stop.is_set():
                    try:
                        if not conn.recv(65536):
                            break
                    except TimeoutError:
                        continue
                    except OSError:
                        break
            else:
                try:
                    conn.recv(1)  # the sender has started writing
                except OSError:
                    pass
                # SO_LINGER with a zero timeout makes close() send a RST, which
                # is what a reaped or restarted witness looks like to the sender
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                struct.pack("ii", 1, 0))
        finally:
            if conn is not None:
                conn.close()
            self.lsock.close()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join(timeout=2.0)
        return False


def seedControllerEnd(hab, recp, url):
    """Authorize recp's own AID as its controller endpoint at url."""
    hab.db.ends.pin(keys=(recp, kering.Roles.controller, recp),
                    val=basing.EndpointRecord(allowed=True))
    hab.db.locs.pin(keys=(recp, kering.Schemes.tcp),
                    val=basing.LocationRecord(url=url))


@contextmanager
def deadEndpointDelivery(name):
    """Queue one Poster delivery whose endpoint resets the connection."""
    with habbing.openHab(name=name, transferable=True, temp=True) as (hby, hab), \
            FakeEndpoint() as endpoint:
        recp = hby.makeHab(name="recp", transferable=True)
        seedControllerEnd(hab, recp.pre, endpoint.url)

        exn, _ = exchanging.exchange(route="/echo",
                                     payload=dict(msg="test"),
                                     sender=hab.pre)
        atc = hab.endorse(exn, last=False)
        del atc[:exn.size]
        atc.extend(bytes(PADSIZE))  # keep bytes queued across the reset

        poster = forwarding.Poster(hby=hby)
        poster.send(src=hab.pre, dest=recp.pre, topic="echo",
                    serder=exn, attachment=atc)

        yield poster, exn


def test_poster_transport_cutoff_does_not_escape_the_doist():
    # a witness that resets the connection must fail one delivery, not the process
    with deadEndpointDelivery(name="pr1614-escape") as (poster, _):
        doist = doing.Doist(tock=TOCK, limit=LIMIT, real=True)

        doist.do(doers=[poster])  # must return at its limit rather than raise


def test_poster_transport_cutoff_does_not_stop_unrelated_doers():
    # every other doer in the same Doist keeps running through the failure
    beats = []

    @doing.doize(tock=TOCK)
    def heartbeat(tymth=None, tock=0.0, **kwa):
        while True:
            beats.append(len(beats))
            yield tock

    with deadEndpointDelivery(name="pr1614-collateral") as (poster, _):
        doist = doing.Doist(tock=TOCK, limit=LIMIT, real=True)

        escaped = None
        try:
            doist.do(doers=[poster, heartbeat])
        except kering.ClosedError as ex:
            escaped = ex

        assert escaped is None, (
            f"a witness transport reset stopped the scheduler after "
            f"{len(beats)} heartbeats: {escaped!r}")
        assert len(beats) > LIMIT / TOCK / 2  # ran for most of the limit


def test_poster_transport_cutoff_is_neither_fatal_nor_reported_as_sent():
    # the delivery neither takes the process down nor claims to have succeeded
    #
    # This one fails on the merge base as well, so it describes an existing gap
    # in the delivery outcome rather than a change in behavior on this branch.
    with deadEndpointDelivery(name="pr1614-outcome") as (poster, exn):
        doist = doing.Doist(tock=TOCK, limit=LIMIT, real=True)

        escaped = None
        try:
            doist.do(doers=[poster])
        except kering.ClosedError as ex:
            escaped = ex

        assert escaped is None, (
            f"the delivery failure terminated the scheduler: {escaped!r}")
        assert not poster.sent(exn.said), (
            "the delivery was cued as sent even though the connection reset "
            "with bytes still unsent")
