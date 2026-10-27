"""Finite TCP delivery owns real sockets; completion is only a transport claim.

The sender/server scheduling pattern follows test_agenting's existing hio tests.
No transport or verifier is patched, and no accepted receiver state is injected.
"""
import time

import pytest
from hio.base import doing
from hio.core import tcp

from keri.app import agenting, openHab, StreamPoster
from keri.core import Parser
from keri.kering import Kinds, Roles, Schemes, Vrsn_1_0, Vrsn_2_0


def advance(doist, predicate, timeout=2.0):
    """Advance actual socket owners until a bounded observable condition holds."""
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        doist.recur()
        time.sleep(0.001)
    assert predicate()


def received(server):
    """Return only bytes received in the real server's connection-local buffers."""
    return b''.join(bytes(remoter.rxbs) for remoter in server.ixes.values())


@pytest.mark.parametrize('version', [Vrsn_1_0, Vrsn_2_0])
@pytest.mark.parametrize('empty', [False, True])
def test_factory_tcp_stream_sends_exact_bytes_and_finishes(version, empty):
    """Factory forwards even an empty stream; nonempty v1/v2 bytes arrive exactly.

    A finite parent matching StreamPoster's delivery owner must complete rather
    than retain the perpetual queued messenger. Its client socket closes before
    the independently owned server stops. No peer acceptance is asserted.
    """
    with openHab(name='stream-sender', temp=True, version=version) as (_, hab):
        server = tcp.Server(ha=('127.0.0.1', 0))
        assert server.reopen()
        server.eha = server.ha
        payload = b'' if empty else bytes(hab.replay(gvrsn=version))
        messenger = agenting.streamMessengerFrom(hab, hab.pre,
            {Schemes.tcp: f'tcp://127.0.0.1:{server.ha[1]}'}, msg=payload)
        parent = doing.DoDoer(doers=[messenger])
        doist = doing.Doist(tock=0.01)
        try:
            doist.deeds.extend(doist.enter(doers=[tcp.ServerDoer(server=server), parent]))
            advance(doist, lambda: parent.done and received(server) == payload)
            assert messenger.done and messenger.client.cs is None
            assert not messenger.deeds and not parent.deeds
            assert server.opened
        finally:
            doist.exit()
            server.close()


@pytest.mark.parametrize('version', [Vrsn_1_0, Vrsn_2_0])
@pytest.mark.parametrize('role', [Roles.controller, Roles.mailbox])
def test_stream_poster_default_tcp_endpoint_completes(version, role):
    """Real signed controller/mailbox records select finite TCP delivery.

    This covers the default delivery branch used by the v1 negotiation CLI,
    using normal reply verification rather than a patched endsFor lookup.
    Mailbox forwarding must deliver its complete signed envelope, not only the
    child message; controller delivery must preserve the original stream.
    The v2 case preserves the same transport boundary without disabling KRAM.
    """
    with (openHab(name='poster-sender', temp=True, version=version) as (hby, hab),
          openHab(name='poster-recipient', temp=True, version=version) as (_, recp)):
        server = tcp.Server(ha=('127.0.0.1', 0))
        assert server.reopen()
        server.eha = server.ha
        endpoint = f'tcp://127.0.0.1:{server.ha[1]}'
        evidence = recp.replay(gvrsn=version)
        evidence.extend(recp.makeEndRole(eid=recp.pre, role=role,
            version=version, gvrsn=version, kind=Kinds.json))
        evidence.extend(recp.makeLocScheme(url=endpoint, scheme=Schemes.tcp,
            version=version, gvrsn=version, kind=Kinds.json))
        hby.psr.parse(ims=evidence)
        assert hab.endsFor(recp.pre)[role][recp.pre][Schemes.tcp] == endpoint
        message = hab.kever.serder
        stream = hab.endorse(message, framed=True, gvrsn=version)
        poster = StreamPoster(hby=hby, hab=hab, recp=recp.pre, topic='credential')
        poster.send(message, attachment=stream[message.size:], gvrsn=version)
        queued = poster.evts[0]
        expected = bytes(queued["serder"].raw + queued["attachment"])
        if role == Roles.controller:
            assert expected == stream
        else:
            assert queued["serder"].route == "/fwd" and expected != stream
        messengers = poster.deliver()
        assert len(messengers) == 1
        parent = doing.DoDoer(doers=messengers)
        doist = doing.Doist(tock=0.01)
        try:
            doist.deeds.extend(doist.enter(doers=[tcp.ServerDoer(server=server), parent]))
            # Mailbox transport also introduces the sender's public KEL/replies.
            # Require the exact complete signed envelope after that bootstrap.
            advance(doist, lambda: parent.done and received(server).endswith(expected))
            wire = received(server)
            if role == Roles.controller:
                assert wire == expected
            else:
                frames = Parser(version=version).parse(ims=bytearray(wire), processive=False)
                assert frames[0].serder.raw == message.raw
                assert frames[-1].serder.raw == queued['serder'].raw
            assert messengers[0].done and messengers[0].client.cs is None
            assert not parent.deeds
        finally:
            doist.exit()
            server.close()


def test_tcp_stream_cancellation_closes_owned_client():
    """Cancel an entered stream before scheduling transfer and close its socket."""
    with openHab(name='cancel-stream', temp=True) as (_, hab):
        server = tcp.Server(ha=('127.0.0.1', 0))
        assert server.reopen()
        messenger = agenting.TCPStreamMessenger(hab, hab.pre,
            f'tcp://127.0.0.1:{server.ha[1]}', msg=b'pending transport bytes')
        parent = doing.DoDoer(doers=[messenger])
        doist = doing.Doist(tock=0.01)
        try:
            doist.deeds.extend(doist.enter(doers=[parent]))
            assert messenger.client.cs is not None and messenger.client.txbs
            assert not parent.done and not messenger.done
        finally:
            doist.exit()
            server.close()
        assert messenger.client.cs is None
        assert not messenger.deeds and not parent.deeds


def test_queued_tcp_messenger_remains_perpetual_after_send():
    """Protect the separate existing queue service from one-shot semantics."""
    with openHab(name='queued-sender', temp=True) as (_, hab):
        server = tcp.Server(ha=('127.0.0.1', 0))
        assert server.reopen()
        server.eha = server.ha
        messenger = agenting.TCPMessenger(hab, hab.pre,
            f'tcp://127.0.0.1:{server.ha[1]}')
        payload = bytes(hab.replay())
        messenger.msgs.append(payload)
        doist = doing.Doist(tock=0.01)
        try:
            doist.deeds.extend(doist.enter(doers=[tcp.ServerDoer(server=server), messenger]))
            advance(doist, lambda: list(messenger.sent) == [payload]
                    and received(server) == payload)
            assert not messenger.done
        finally:
            doist.exit()
            server.close()
