# -*- encoding: utf-8 -*-
"""
tests.app.test_pr1614_directing module

Outbound delivery behavior of Directant when an inactivity timeout ends a
connection.  Every assertion is made at the peer end of a real socket, so the
subject is the bytes the far side receives rather than transport state.
"""

import socket

from hio.base import doing
from hio.core.tcp import serving

from keri.app import directing

from tests.app import recurUntil
from tests.app.test_directing import direct_habs, make_remoter  # noqa: F401


def drain(sock):
    """Return whatever bytes the peer socket holds without blocking on it."""
    sock.setblocking(False)
    received = bytearray()
    while True:
        try:
            data = sock.recv(4096)
        except (BlockingIOError, OSError):
            break
        if not data:
            break
        received.extend(data)
    return bytes(received)


def test_directant_timeout_flushes_queued_outbound_bytes(direct_habs):
    """Bytes queued on an idle connection reach the peer when the timeout ends it."""
    _, bob = direct_habs

    # peerSocket keeps the far end open so the close comes from timeout instead of EOF
    remoterSocket, peerSocket = socket.socketpair()
    remoter = make_remoter(cs=remoterSocket, tymeout=0.03125)
    ca = remoter.ca

    server = serving.Server()
    server.ixes[ca] = remoter
    directant = directing.Directant(hab=bob, server=server)
    doist = doing.Doist(tock=0.03125, limit=1.0, doers=[directant])
    doist.enter()

    # a response is queued on the connection before it goes idle
    response = b"queued outbound bytes"
    remoter.tx(response)

    received = bytearray()

    def closed():
        received.extend(drain(peerSocket))
        return ca not in server.ixes

    try:
        recurUntil(doist, condition=closed,
                   message="the idle connection was never torn down")
        received.extend(drain(peerSocket))

        assert bytes(received) == response, (
            f"peer received {bytes(received)!r}; {len(remoter.txbs)} bytes were "
            f"discarded with the connection, remoter.cutoff={remoter.cutoff}")
    finally:
        doist.exit()
        server.close()
        peerSocket.close()


def test_directant_timeout_delivers_receipt_for_buffered_event(direct_habs):
    """A receipt cued from buffered input on an idle connection reaches the peer."""
    alice, bob = direct_habs

    # peerSocket keeps the far end open so the close comes from timeout instead of EOF
    remoterSocket, peerSocket = socket.socketpair()
    # one complete event is already received when the connection goes idle
    remoter = make_remoter(alice.makeOwnEvent(sn=0),
                           cs=remoterSocket, tymeout=0.03125)
    ca = remoter.ca

    server = serving.Server()
    server.ixes[ca] = remoter
    directant = directing.Directant(hab=bob, server=server)
    doist = doing.Doist(tock=0.03125, limit=1.0, doers=[directant])
    doist.enter()

    received = bytearray()

    def closed():
        received.extend(drain(peerSocket))
        return ca not in server.ixes

    try:
        recurUntil(doist, condition=closed,
                   message="the idle connection was never torn down")
        received.extend(drain(peerSocket))

        assert bytes(received), (
            f"peer received no bytes; {len(remoter.txbs)} bytes were discarded "
            f"with the connection, remoter.cutoff={remoter.cutoff}")
        assert b'"t":"rct"' in bytes(received)
    finally:
        doist.exit()
        server.close()
        peerSocket.close()


def test_serviced_server_delivers_receipt_after_peer_half_close(direct_habs,
                                                                unused_tcp_port):
    """A ServerDoer servicing sends every recurrence still answers a half closed peer.

    This one fails on the merge base as well, so it describes an existing gap in
    the half close path rather than a change in behavior on this branch.
    """
    alice, bob = direct_habs

    # keripy always runs a serving.ServerDoer on the same Server as the Directant:
    # src/keri/app/indirecting.py:111-117 and src/keri/demo/demoing.py:61-69
    #
    # A concrete port is needed because Server cannot bind port 0: serviceAxes
    # compares self.eha[1] to the accepted socket's port (hio/core/tcp/serving.py:559).
    server = serving.Server(host="127.0.0.1", port=unused_tcp_port)
    serverDoer = serving.ServerDoer(server=server)
    directant = directing.Directant(hab=bob, server=server)
    doist = doing.Doist(tock=0.03125, limit=2.0, doers=[directant, serverDoer])
    doist.enter()

    # the peer sends one event and half closes, so it can no longer send but can
    # still read the receipt it is waiting for
    peer = socket.create_connection(("127.0.0.1", unused_tcp_port))
    peer.sendall(alice.makeOwnEvent(sn=0))
    peer.shutdown(socket.SHUT_WR)

    received = bytearray()
    remoters = []

    def closed():
        received.extend(drain(peer))
        remoters.extend(ix for ix in server.ixes.values() if ix not in remoters)
        return bool(remoters) and not server.ixes

    try:
        recurUntil(doist, condition=closed,
                   message="the half closed connection was never torn down")
        received.extend(drain(peer))

        queued = len(remoters[0].txbs) if remoters else 0
        assert bytes(received), (
            f"peer received no bytes although a ServerDoer serviced sends on every "
            f"recurrence; {queued} bytes remain queued on the connection, "
            f"event accepted into the local KEL={alice.pre in bob.kevers}")
        assert b'"t":"rct"' in bytes(received)
    finally:
        doist.exit()
        peer.close()
