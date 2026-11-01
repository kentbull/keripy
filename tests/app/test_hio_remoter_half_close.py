# -*- encoding: utf-8 -*-
"""Validate Directant teardown against HIO's directional Remoter cutoff."""

import socket

from hio.base import doing
from hio.core.tcp import serving

from keri.app import directing

from tests.app import recurUntil
from tests.app.test_directing import direct_habs, make_remoter  # noqa: F401


def drain(sock):
    """Return all currently readable bytes without blocking."""
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


def test_directant_timeout_delivers_receipt_for_buffered_event(direct_habs):
    """A local idle close waits for the final receipt to reach the peer."""
    alice, bob = direct_habs
    remoterSocket, peerSocket = socket.socketpair()
    remoter = make_remoter(alice.makeOwnEvent(sn=0),
                           cs=remoterSocket,
                           tymeout=0.03125)
    ca = remoter.ca

    server = serving.Server()
    server.ixes[ca] = remoter
    directant = directing.Directant(hab=bob, server=server)
    doist = doing.Doist(tock=0.03125, limit=1.0, doers=[directant])
    doist.enter()
    received = bytearray()

    def closed():
        received.extend(drain(peerSocket))
        return ca not in server.ixes and ca not in directant.rants

    try:
        recurUntil(doist, condition=closed,
                   message="timed-out connection did not finish draining")
        received.extend(drain(peerSocket))

        assert alice.pre in bob.kevers
        assert b'"t":"rct"' in received
    finally:
        doist.exit()
        server.close()
        peerSocket.close()


def test_directant_delivers_receipt_after_peer_half_close(
        direct_habs, unused_tcp_port):
    """A peer FIN stops input without suppressing the final receipt output."""
    alice, bob = direct_habs
    server = serving.Server(host="127.0.0.1", port=unused_tcp_port)
    directant = directing.Directant(hab=bob, server=server)
    serverDoer = serving.ServerDoer(server=server)
    doist = doing.Doist(tock=0.03125, limit=2.0,
                        doers=[directant, serverDoer])
    doist.enter()

    peer = socket.create_connection(("127.0.0.1", unused_tcp_port))
    peer.sendall(alice.makeOwnEvent(sn=0))
    peer.shutdown(socket.SHUT_WR)
    received = bytearray()
    remoters = []

    def closed():
        received.extend(drain(peer))
        remoters.extend(ix for ix in server.ixes.values()
                        if ix not in remoters)
        return bool(remoters) and not server.ixes and not directant.rants

    try:
        recurUntil(doist, condition=closed,
                   message="half-closed connection did not finish draining")
        received.extend(drain(peer))

        assert alice.pre in bob.kevers
        assert b'"t":"rct"' in received
    finally:
        doist.exit()
        peer.close()
