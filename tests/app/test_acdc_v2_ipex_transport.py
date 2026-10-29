"""Exercise ACDC v2 IPEX CLI transport and exact registry synchronization."""
from contextlib import contextmanager, nullcontext
from datetime import timedelta
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ipaddress
from pathlib import Path
from threading import Thread
from types import SimpleNamespace

import pytest
from hio.base import doing
from hio.core import http, tcp

from keri.cli.common.acdc_v2_ipex import ExchangeDoer
from keri.cli.common import acdc_v2, acdc_v2_ipex, public_evidence
from keri.kering import ConfigurationError
from keri import Vrsn_2_0
from keri.acdc import Registrar, acdcmap
from keri.acdc.sectioning import SectionBaser
from keri.app.evidencing import EvidenceContext
from keri.core import Counter, Codens, Diger
from keri.help import helping
from tests.acdc.test_registraring import _anchor, _persistent_registry_owners


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


@contextmanager
def registry_response(tmp_path, case, monkeypatch, *, tls=False):
    """Serve real signed registry evidence to the commands' ordinary processors."""
    source, srgy = _persistent_registry_owners(tmp_path, 'sync-source')
    target, rgy = _persistent_registry_owners(tmp_path, 'sync-target')
    sections = SectionBaser(name=target.name, base=target.base,
        headDirPath=str(tmp_path), temp=False)
    server = thread = None
    try:
        assert Path(sections.path).is_relative_to(tmp_path)
        issuer = source.makeHab(name='issuer')
        target.makeHab(name='actor')
        registries = []
        for name in ('requested', 'other'):
            reg = srgy.makeRegistry(name, issuer.pre)
            rip = _anchor(issuer, reg, srgy.store.event(reg.regk))
            credential = acdcmap(israid=issuer.pre, regid=reg.regk,
                                 attribute={'d': '', 'value': name})
            _, first = Registrar(srgy).issue(reg, acdc=credential)
            _anchor(issuer, reg, first)
            _, newer = Registrar(srgy).issue(reg, acdc=credential, state='revoked')
            _anchor(issuer, reg, newer)
            registries.append((rip, first, newer))
        requested, other = registries
        foot = Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b

        def stream(events):
            return bytes(issuer.replay(gvrsn=Vrsn_2_0)) + b''.join(event.raw + foot for event in events)

        if case == 'stale-prefix':
            result = EvidenceContext(target, reger=rgy.baser).ingest(stream(requested))
            assert result['heads'][requested[0].said] == requested[2].said
        selected = other if case == 'unrelated' else requested
        body = stream(selected if case == 'matching' else selected[:2])

        requests = []

        class Endpoint(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                requests.append(self.path)
                self.send_response(202 if case == 'wrong-status' else 200)
                self.send_header('Content-Type', 'text/plain' if case == 'wrong-media' else 'application/cesr')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Endpoint)
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(tls))
            server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        thread.start()
        ingested = []
        ordinary_ingest = EvidenceContext.ingest

        def ingest(evidence, raw):
            ingested.append(bytes(raw))
            return ordinary_ingest(evidence, raw)

        monkeypatch.setattr(EvidenceContext, 'ingest', ingest)
        # Substitute only owner acquisition; transport and all acceptance processors are real.
        monkeypatch.setattr(acdc_v2, 'openedRegistry', lambda *args, **kwa: nullcontext((target, rgy)))
        monkeypatch.setattr(acdc_v2_ipex, 'openLMDB', lambda **kwa: nullcontext(sections))
        yield SimpleNamespace(target=target, rgy=rgy, requested=requested,
            body=body, ingested=ingested, issuer=issuer, other=other, requests=requests, url=f'{"https" if tls else "http"}://127.0.0.1:{server.server_port}/')
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=2)
            assert not thread.is_alive()
        sections.close()
        rgy.close()
        target.close()
        srgy.close()
        source.close()


@pytest.mark.parametrize('case', ['unrelated', 'stale-prefix',
                                  'wrong-media', 'wrong-status', 'matching'])
def test_ipex_synchronization_requires_exact_requested_result(tmp_path, monkeypatch, capsys, case):
    """A response must prove the requested operation before the real Apply is authored."""
    with registry_response(tmp_path, case, monkeypatch) as fixture:
        args = SimpleNamespace(name=fixture.target.name, base=fixture.target.base, bran=None,
            alias='actor', timeout=2, input=None, registry=[fixture.requested[0].said],
            observer=fixture.url, proposal=None, proposal_output=None, recipient=fixture.issuer.pre,
            message='', time=None, plan=json.dumps([[Diger(ser=b'schema').qb64, '/', ['a/value']]]),
            output=None, endpoint=None)
        doer = ExchangeDoer(args, 'apply')
        if case == 'matching':
            doing.Doist(real=True, tock=0.01, limit=2).do(doers=[doer])
            assert json.loads(capsys.readouterr().out)['accepted']
            assert fixture.rgy.store.headEvent(args.registry[0]).said == fixture.requested[2].said
        else:
            with pytest.raises(ConfigurationError):
                doing.Doist(real=True, tock=0.01, limit=2).do(doers=[doer])
            assert list(fixture.target.db.exns.getTopItemIter()) == []
        assert fixture.ingested == ([] if case in ('wrong-media', 'wrong-status') else [fixture.body])


def test_public_query_old_exact_prefix_is_synchronized_without_freshness(tmp_path, monkeypatch, capsys):
    """A fresh receiver can verify an old exact HTTP prefix without knowing a later head."""
    with registry_response(tmp_path, 'old-exact-prefix', monkeypatch) as fixture:
        output = tmp_path / 'verified.cesr'
        args = SimpleNamespace(name=fixture.target.name, base=fixture.target.base, bran=None,
            alias='actor', endpoint=fixture.url, timeout=2,
            registry=fixture.requested[0].said, output=str(output))
        assert fixture.rgy.store.headEvent(args.registry) is None
        doing.Doist(real=True, tock=0.01, limit=2).do(doers=[public_evidence.Request(args, 'query')])
        result = json.loads(capsys.readouterr().out)
        assert result['accepted'] and result['head'] == fixture.requested[1].said
        assert output.read_bytes() == fixture.body
        assert fixture.ingested == [fixture.body]
        regid, head = args.registry, result['head']
    reopened, rgy = _persistent_registry_owners(tmp_path, 'sync-target')
    try:
        assert rgy.store.headEvent(regid).said == head
    finally:
        rgy.close()
        reopened.close()


@pytest.fixture
def observer_certificates(tmp_path):
    """Create test-owned independent trust roots and a localhost TLS identity."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    paths = []
    for name in ('trusted', 'unrelated'):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        now = helping.nowUTC()
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
            .sign(key, hashes.SHA256()))
        path = tmp_path / f'{name}.pem'
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        paths.append(path)
    return paths


@pytest.mark.parametrize('host, cert_name', [('localhost', None), ('127.0.0.1', None), ('127.0.0.1', 'localhost')])
def test_observer_tls_accepts_configured_authority(tmp_path, monkeypatch, capsys, observer_certificates, host, cert_name):
    """TLS trust protects the source connection; CESR processors still verify its evidence."""
    with registry_response(tmp_path, 'matching', monkeypatch, tls=observer_certificates[0]) as fixture:
        args = SimpleNamespace(name=fixture.target.name, base=fixture.target.base, bran=None,
            alias='actor', endpoint=fixture.url.replace('127.0.0.1', host), timeout=2,
            registry=fixture.requested[0].said, output=str(tmp_path / 'observed.cesr'),
            observer_ca_file=str(observer_certificates[0]), observer_cert_name=cert_name)
        doing.Doist(real=True, tock=0.01, limit=3).do(doers=[public_evidence.Request(args, 'query')])
        assert json.loads(capsys.readouterr().out)['accepted']
        assert Path(args.output).read_bytes() == fixture.body
        assert fixture.ingested == [fixture.body]


@pytest.mark.parametrize('failure', ['ca', 'name'])
def test_observer_tls_connection_refuses_other_authority(tmp_path, monkeypatch, observer_certificates, failure):
    """A wrong TLS authority cannot authorize output or reach evidence processing."""
    with registry_response(tmp_path, 'matching', monkeypatch, tls=observer_certificates[0]) as fixture:
        args = SimpleNamespace(name=fixture.target.name, base=fixture.target.base, bran=None,
            alias='actor', endpoint=fixture.url, timeout=2, registry=fixture.requested[0].said,
            output=str(tmp_path / 'refused.cesr'),
            observer_ca_file=str(observer_certificates[failure == 'ca']),
            observer_cert_name='wrong.example' if failure == 'name' else 'localhost')
        doer = public_evidence.Request(args, 'query')
        with pytest.raises((ConfigurationError, ssl.SSLCertVerificationError)):
            doing.Doist(real=True, tock=0.01, limit=3).do(doers=[doer])
        assert fixture.ingested == [] and not Path(args.output).exists()
        assert not any(isinstance(child, (http.clienting.ClientDoer, EvidenceContext))
                       for child in doer.doers)


@pytest.mark.parametrize('url, options', [
    (None, {'observer_ca_file': '/unused'}),
    ('http://observer.example/', {'observer_cert_name': 'observer.example'}),
    ('https://user:pass@observer.example/', {}), ('https://observer.example/#part', {}),
    ('https://observer.example/', {'observer_cert_name': 'other.example'}),
    ('https://127.0.0.1/', {'observer_cert_name': '127.0.0.1'}),
    ('https://observer.example/', {'observer_ca_file': 'relative.pem'}),
])
def test_observer_policy_refuses_misapplied_options(url, options):
    """Reject orphaned, insecure and ambiguous source settings before I/O."""
    with pytest.raises(ConfigurationError):
        public_evidence.ObserverConnection.fromArgs(SimpleNamespace(**options), url)


@pytest.mark.parametrize('verb', ['apply', 'offer', 'agree', 'grant', 'admit', 'spurn', 'receive', 'query'])
def test_observer_options_are_explicit_in_every_cli(verb):
    """Shared flags parse everywhere and cannot silently configure legacy IPEX."""
    from importlib import import_module
    module = import_module('keri.cli.commands.' + ('vc.registry.query' if verb == 'query' else f'ipex.{verb}'))
    values = {'name': 'unused', 'alias': 'actor', 'recipient': 'recipient', 'said': 'said',
              'endpoint': 'https://observer.example/', 'registry': 'registry', 'output': 'unused.cesr'}
    argv = [item for action in module.parser._actions if action.required
            for item in (f'--{action.dest}', values[action.dest])]
    args = module.parser.parse_args(argv + ['--observer-cert-name', 'localhost'])
    assert args.observer_cert_name == "localhost"
    if verb != 'query':
        with pytest.raises(ConfigurationError):
            doers = module.handler(args)
            doing.Doist(real=False, tock=0.01, limit=1).do(doers=doers)


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


def test_http_intake_accepts_streamposter_put_without_changing_verification(tmp_path):
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

    from keri import Vrsn_1_0
    from keri.acdc import ipexing
    from keri.core import Schemer

    source, srgy = _persistent_registry_owners(tmp_path, 'http-source')
    target, rgy = _persistent_registry_owners(tmp_path, 'http-target')
    sections = SectionBaser(name=target.name, base=target.base,
        headDirPath=str(tmp_path), temp=False)
    try:
        assert Path(sections.path).is_relative_to(tmp_path)
        sender = source.makeHab(name='sender', version=Vrsn_1_0)
        recipient = target.makeHab(name='recipient')
        actual = acdc_v2_ipex.Peer(target, rgy, sections)
        app = falcon.App()
        app.add_route('/', Intake(actual))
        transport = testing.TestClient(app)
        body = sender.kever.serder.raw
        replay = bytes(sender.replay(gvrsn=Vrsn_2_0))
        assert replay.startswith(body)
        response = transport.simulate_post('/', body=body, headers={
            'Content-Type': 'application/cesr', 'CESR-Genus': '2',
            'CESR-ATTACHMENT': replay[len(body):].decode('ascii')})
        assert response.status_code == 202, response.text
        assert target.kevers[sender.pre].serder.raw == body

        schema = Schemer(sed={'$id': '', 'version': '1.0.0', 'type': 'object'})
        apply, attachment = ipexing.apply(sender, recipient.pre, 'detached proof',
            modifiers={'dp': [[schema.said, '/', []]]}, gvrsn=Vrsn_2_0)
        response = transport.simulate_put('/', body=apply.raw, headers={
            'Content-Type': 'application/cesr',
            'CESR-ATTACHMENT': bytes(attachment).decode('ascii')})
        assert response.status_code == 202, response.text
        assert actual.exc.complete(apply.said)
        assert target.db.exns.get((apply.said,)).raw == apply.raw
        genus_one = bytes(sender.replay(gvrsn=Vrsn_1_0))
        response = transport.simulate_post('/', body=body, headers={
            'Content-Type': 'application/cesr', 'CESR-Genus': '1',
            'CESR-ATTACHMENT': genus_one[len(body):].decode('ascii')})
        assert response.status_code == 202, response.text
        streamed, foot = ipexing.apply(sender, recipient.pre, 'raw stream after genus one',
            modifiers={'dp': [[schema.said, '/', []]]}, gvrsn=Vrsn_2_0)
        response = transport.simulate_put('/', body=streamed.raw + bytes(foot),
            headers={'Content-Type': 'application/cesr'})
        assert response.status_code == 202, response.text
        assert actual.exc.complete(streamed.said)
        assert target.db.exns.get((streamed.said,)).raw == streamed.raw
        assert actual.verification.admissions() == []

        for headers, raw in (({'CESR-Genus': '3'}, apply.raw),
                             ({'CESR-ATTACHMENT': ''}, apply.raw + apply.raw)):
            response = transport.simulate_post('/', body=raw,
                headers={'Content-Type': 'application/cesr', **headers})
            assert response.status_code == 400
    finally:
        sections.close()
        rgy.close()
        target.close()
        srgy.close()
        source.close()
