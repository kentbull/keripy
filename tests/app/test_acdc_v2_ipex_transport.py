"""Exercise the ACDC v2 IPEX CLI sender against actual sockets without wallet setup."""
from types import SimpleNamespace

import pytest
from hio.base import doing
from hio.core import tcp

from keri.cli.common.acdc_v2_ipex import ExchangeDoer
from keri.kering import ConfigurationError


class Sender(ExchangeDoer):
    """Drive only the command's transport boundary under the real HIO scheduler."""

    def __init__(self, url, body, timeout=0.5):
        """Compose only the installed CLI sender's transport boundary for a test.

        Args:
            url (str): Explicit HTTP or TCP destination passed to ExchangeDoer.request.
            body (bytes): Exact stream to transmit without protocol reinterpretation.
            timeout (float): Finite request deadline measured by HIO's injected clock.

        Returns:
            None. Initializes an empty result and the production command doer; this
            fixture supplies no wallet, route acceptance, or application receipt."""
        self.url, self.body, self.result = url, body, None
        super().__init__(SimpleNamespace(timeout=timeout), 'grant')

    def run(self, tymth, tock=0.001, **kwa):
        """Schedule actual transport and retain only its reported delivery result.

        Args:
            tymth (Callable): HIO injected clock used by request deadlines.
            tock (float): Cooperative initial scheduling delay.
            **kwa: Additional HIO lifecycle metadata, unused by this fixture.

        Yields:
            float | None: Initial delay and delegated request progress until completion.

        Returns:
            None. Saves the request result for assertions. ConfigurationError and
            TimeoutError propagate; neither transport completion nor an HTTP status
            establishes credential acceptance."""
        self.wind(tymth)
        self.tock = tock
        yield tock
        self.result = yield from self.request(self.url, self.body)


def test_tcp_send_preserves_bytes_and_only_reports_transport():
    """Deliver a multi-buffer stream over real TCP byte-for-byte, require child-client cleanup, and report sent bytes without claiming acceptance.

    Returns:
        None. Assertions check the stated evidence boundary."""
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
    """Reject malformed/unsupported destinations before any send result is recorded.

    Parameters:
        url: Malformed or unsupported destination vector.

    Returns:
        None. Assertions check the stated evidence boundary."""
    sender = Sender(url, b'signed-message')
    with pytest.raises(ConfigurationError):
        doing.Doist(real=False, tock=0.001, limit=1).do(doers=[sender])
    assert sender.result is None


def test_unavailable_tcp_peer_times_out_without_claiming_delivery():
    """Bound a real non-listening loopback connection by timeout and remove its client child without claiming delivery.

    Returns:
        None. Assertions check the stated evidence boundary."""
    import socket

    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        sender = Sender(f'tcp://127.0.0.1:{reserved.getsockname()[1]}', b'message', timeout=0.05)
        with pytest.raises(TimeoutError):
            doing.Doist(real=True, tock=0.001, limit=0.5).do(doers=[sender])
        assert sender.result is None
        assert not any(isinstance(child, tcp.ClientDoer) for child in sender.doers)


@pytest.mark.parametrize('status', [202, 400])
def test_http_preserves_query_and_does_not_hide_refusal(status):
    """Preserve the exact HTTP path/query/body and propagate an actual refusal while terminating the fixture listener and thread.

    Parameters:
        status: Fixture HTTP 202 success or 400 refusal status.

    Returns:
        None. Assertions check the stated evidence boundary."""
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread

    requests = []

    class Endpoint(BaseHTTPRequestHandler):
        """Record the HTTP request at the real socket boundary."""

        def do_POST(self):
            """Read one bounded real HTTP request and emit the selected fixture status.

            Returns:
                None. Records the exact path/query/body, writes a two-byte JSON response,
                and leaves status interpretation to the production sender. The enclosing
                test owns server/thread shutdown, including when a refusal raises."""
            requests.append((self.path, self.rfile.read(int(self.headers['Content-Length']))))
            self.send_response(status)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'{}')

        def log_message(self, *args):
            """Suppress BaseHTTPRequestHandler fixture logging without changing dispatch.

            Args:
                *args: HTTP server format string and interpolation arguments, unused.

            Returns:
                None. Request bytes/status remain observable through the explicit recorder."""

    server = HTTPServer(('127.0.0.1', 0), Endpoint)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    sender = Sender(f'http://127.0.0.1:{server.server_port}/ingest?profile=v1', b'exact-stream')
    try:
        scheduler = doing.Doist(real=True, tock=0.001, limit=0.8)
        if status == 400:
            with pytest.raises(ConfigurationError, match='400'):
                scheduler.do(doers=[sender])
            assert sender.result is None
        else:
            scheduler.do(doers=[sender])
            assert sender.result['status'] == status
        assert requests == [('/ingest?profile=v1', b'exact-stream')]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def test_http_intake_accepts_streamposter_put_without_changing_verification():
    """POST and StreamPoster PUT pass exact bytes to the same ACDC v2 IPEX peer."""
    import falcon
    from falcon import testing
    from keri.cli.common.acdc_v2_ipex import Intake

    class Peer:
        """Record only the transport boundary; protocol tests cover the peer."""
        def __init__(self):
            """Create the empty intake trace."""
            self.messages = []

        def ingest(self, raw):
            """Retain exact bytes, returning the peer's transport outcome."""
            self.messages.append(raw)
            return {'accepted': []}

    peer = Peer()
    api = falcon.App()
    api.add_route('/', Intake(peer))
    client = testing.TestClient(api)
    for method in ('POST', 'PUT'):
        response = client.simulate_request(method=method, path='/', body=b'cesr-frame',
                                           headers={'Content-Type': 'application/cesr'})
        assert response.status_code == 202 and response.json == {'accepted': []}
    assert peer.messages == [b'cesr-frame', b'cesr-frame']
