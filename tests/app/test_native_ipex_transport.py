"""Exercise the native CLI sender against actual sockets without wallet setup."""
from types import SimpleNamespace

import pytest
from hio.base import doing
from hio.core import tcp

from keri.cli.common.native_exchange import ExchangeDoer
from keri.kering import ConfigurationError


class Sender(ExchangeDoer):
    """Drive only the command's transport boundary under the real HIO scheduler."""

    def __init__(self, url, body, timeout=0.5):
        """Retain destination and exact bytes; timeout bounds simulated HIO time."""
        self.url, self.body, self.result = url, body, None
        super().__init__(SimpleNamespace(timeout=timeout), 'grant')

    def run(self, tymth, tock=0.001, **kwa):
        """Schedule transport and retain its result without asserting acceptance."""
        self.wind(tymth)
        self.tock = tock
        yield tock
        self.result = yield from self.request(self.url, self.body)


def test_tcp_send_preserves_bytes_and_only_reports_transport():
    """A real TCP listener receives a multi-buffer stream unchanged, with no ACK."""
    server = tcp.Server(host='127.0.0.1', port=0)
    server.reopen()
    # HIO keeps the advertised address separate from its ephemeral bind.
    server.eha = server.ha
    payload = bytes(range(256)) * 1024
    sender = Sender(f'tcp://127.0.0.1:{server.ha[1]}', payload)
    try:
        doing.Doist(real=True, tock=0.001, limit=0.8).do(
            doers=[tcp.ServerDoer(server=server), sender])
        received = b''.join(bytes(remote.rxbs) for remote in server.ixes.values())
        assert received == payload
        assert sender.result == {'transport': 'tcp', 'sent': len(payload)}
        assert 'accepted' not in sender.result
        assert not any(isinstance(child, tcp.ClientDoer) for child in sender.doers)
    finally:
        server.close()


@pytest.mark.parametrize('url', ['tcp://localhost', 'tcp://localhost:1234/path',
                                  'tcp://user@localhost:1234', 'file:///tmp/message'])
def test_invalid_transport_destination_is_refused(url):
    """Invalid destinations fail before a message can be reported as sent."""
    sender = Sender(url, b'signed-message')
    with pytest.raises(ConfigurationError):
        doing.Doist(real=False, tock=0.001, limit=1).do(doers=[sender])
    assert sender.result is None


def test_unavailable_tcp_peer_times_out_without_claiming_delivery():
    """A reserved but non-listening port cannot leave a command waiting forever."""
    import socket

    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        sender = Sender(f'tcp://127.0.0.1:{reserved.getsockname()[1]}', b'message', timeout=0.05)
        with pytest.raises(TimeoutError):
            doing.Doist(real=True, tock=0.001, limit=0.5).do(doers=[sender])
        assert sender.result is None
        assert not any(isinstance(child, tcp.ClientDoer) for child in sender.doers)
