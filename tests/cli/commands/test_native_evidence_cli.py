"""Installed selected Admit waits for authenticated native evidence over actual TLS."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ssl
import subprocess
from threading import Thread
import time

import pytest

from keri import Vrsn_2_0 as V2
from keri.acdc import blindate
from keri.acdc.regbasing import RegBaser
from keri.app import openHby
from keri.core import Blinder, Parser, SealSource, SerderACDC, SerderKERI, messagize
from keri.db import Baser
from keri.peer.exchanging import serializeParsedSubstream, verifyQueryAttachments

from tests.cli.commands.test_native_issuance_cli import issue, live_parties
from tests.cli.commands.test_native_negotiation_cli import enable_kram, exchange_deadline
from tests.cli.commands.test_native_presentation_cli import intake, present, state, update

pytestmark = pytest.mark.real_store_roots


def public(raw, registry, *, prefix=False, replacement=None):
    """Select actual signed KEL/TEL from the existing mixed issuance publication."""
    messages = Parser(version=V2).parse(ims=bytearray(raw), processive=False)
    kel, tel = {}, {}
    for parsed in messages:
        event = parsed.serder
        if isinstance(event, SerderKERI) and event.ilk in ('icp', 'dip', 'rot', 'drt', 'ixn', 'rct'):
            kel[(event.pre, event.sn, event.said)] = parsed
        elif isinstance(event, SerderACDC) and event.ilk in ('rip', 'bup'):
            if (event.said if event.ilk == 'rip' else event.regid) == registry:
                tel[event.sn] = parsed
    if replacement is not None:
        tel[1] = replacement
    selected = list(kel.values()) + [tel[sn] for sn in sorted(tel) if not prefix or sn == 0]
    return b''.join(serializeParsedSubstream(parsed) for parsed in selected)


def retained(holder, grant):
    db = Baser(name=holder['name'], base=holder['base'], reopen=True, readonly=True)
    try:
        deadline = exchange_deadline(db, grant)
        return dict(accepted=db.exns.get((grant,)) is not None,
                    terminal=db.erpy.get((grant,)) is not None,
                    deadline=deadline)
    finally:
        db.close()


@contextmanager
def observer(tmp_path, parties, mode, *, selected_file='grant.cesr', extra=None, issuer_process=None):
    issuer, holder = parties
    cert, key, config = (tmp_path / name for name in ('cert.pem', 'key.pem', 'tls.cnf'))
    config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=server\nprompt=no\n'
        '[dn]\nCN=localhost\n[server]\nsubjectAltName=DNS:localhost\n'
        'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n'
        'extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', str(key), '-out', str(cert), '-days', '1', '-config', str(config)],
        check=True, capture_output=True, timeout=15)
    calls, observations, failures = [], [], []
    with openHby(name='query-verifier', version=V2) as verifier:
        verifier.psr.parse(ims=bytearray(holder['public'].read_bytes()), local=False)
        class Intake(BaseHTTPRequestHandler):
            def do_POST(self):
                try:
                    raw = self.rfile.read(int(self.headers['Content-Length']))
                    stream = bytearray(raw)
                    query = Parser(version=V2).parseOneBare(ims=stream, processive=False)
                    body = SerderACDC(raw=(tmp_path / 'body.cesr').read_bytes())
                    assert not stream and query.serder.route == 'tels'
                    assert query.serder.pre == holder['pre'] and query.serder.sad['q'] == {'i': body.regid}
                    assert verifyQueryAttachments(verifier, query.serder, lsgs=query.lsgs,
                        tsgs=query.tsgs, sigers=query.sigers, cigars=query.cigars)
                    calls.append(query.serder.said)
                    grant = next(parsed.serder for parsed in Parser(version=V2).parse(
                        ims=bytearray((tmp_path / selected_file).read_bytes()), processive=False)
                        if getattr(parsed.serder, 'route', None) == '/ipex/grant')
                    snapshot = retained(holder, grant.said)
                    assert not snapshot['accepted'] and not snapshot['terminal']
                    regdb = RegBaser(name=holder['name'], base=holder['base'], reopen=True, readonly=True)
                    try:
                        assert regdb.evts.get(regdb.heads.get(body.regid).qb64).ilk == 'bup'
                    finally:
                        regdb.close()
                    observations.append(snapshot)
                    wire = (tmp_path / 'grant.cesr').read_bytes()
                    if extra is not None:
                        wire += extra.read_bytes()
                    if mode in ('revoked', 'conflict'):
                        issuer_process[0].terminate()
                        issuer_process[0].wait(timeout=5)  # Release the issuer before authoring another real event.
                    if mode == 'retry' and len(calls) <= 2:
                        self.send_response(404 if len(calls) == 1 else 503)
                        self.end_headers()
                        return
                    if mode in ('retry', 'stale') and (mode == 'stale' or len(calls) == 3):
                        payload = public(wire, body.regid, prefix=True)
                    elif mode == 'revoked':
                        later = tmp_path / 'revoked.cesr'
                        update(issuer, body, later, value='revoked')
                        payload = public(wire + later.read_bytes(), body.regid)
                    elif mode == 'conflict':
                        # A genuinely signed/witnessed conflicting BUP, never a fabricated accepted row.
                        hby = state(issuer)
                        try:
                            hab = hby.habByName('issuer')
                            event = blindate(body.regid, body.regid,
                                Blinder.blind(acdc=body.said, state='issued').said)
                            from hio.base import doing
                            from keri.app import Receiptor
                            anchor = SerderKERI(raw=hab.interact(
                                data=[dict(i=body.regid, s='1', d=event.said)], gvrsn=V2))
                            receipts = Receiptor(hby=hby)
                            def receipt(tymth, tock=.03125, **kwa):
                                yield tock
                                yield from receipts.receipt(hab.pre, sn=anchor.sn)
                                owner.remove([receipts])
                            owner = doing.DoDoer(doers=[receipts, doing.doify(receipt)])
                            doing.Doist(real=True, tock=.03125, limit=5).do(doers=[owner])
                            assert owner.done
                            conflicting = Parser(version=V2).parseOneBare(ims=bytearray(messagize(event,
                                bonds=[SealSource(s=anchor.snh, d=anchor.said)], gvrsn=V2)), processive=False)
                            payload = public(wire + bytes(hab.replay(gvrsn=V2)), body.regid,
                                             replacement=conflicting)
                        finally:
                            hby.close()
                    else:
                        payload = public(wire, body.regid)
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/cesr')
                    self.send_header('Content-Length', str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except Exception as error:
                    failures.append(error)
                    self.send_response(500)
                    self.end_headers()
            def log_message(self, *_):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Intake)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield (['--evidence-url', f'https://127.0.0.1:{server.server_port}',
                    '--evidence-ca', str(cert), '--evidence-hostname',
                    'wrong.localhost' if mode == 'tls' else 'localhost'], calls, observations)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
            assert not failures, failures


def test_installed_admit_waits_through_http_failures_and_authentic_prefix(tmp_path, live_parties):
    with observer(tmp_path, live_parties, 'retry') as (flags, calls, snapshots):
        selected, _ = issue(tmp_path, live_parties, admit_options=flags)
    assert len(calls) >= 4
    assert len({snapshot['deadline'] for snapshot in snapshots}) == 1
    assert retained(live_parties[1], selected['grant'])['terminal']


def test_native_expiry_stops_stale_source_despite_longer_cli_timeout(tmp_path, live_parties):
    started = time.monotonic()
    # The holder's accepted KRAM exchange window (xl) is the native clock that must expire first.
    hby = state(live_parties[1])
    try:
        enable_kram(hby, caches={'~': [1000, 20000, 20000, 20000, 60000, 60000, 300000]})
    finally:
        hby.close()
    with observer(tmp_path, live_parties, 'stale') as (flags, calls, snapshots):
        selected, _, output = issue(tmp_path, live_parties, admit_options=[*flags, '--timeout', '60'],
                                    succeeds=False)
    assert 'original exchange deadline' in output and 'before --timeout' not in output
    # Setup plus the 20 s window that starts at the Apply, well before the admit's 60 s CLI timeout.
    assert time.monotonic() - started < 35
    assert len(calls) > 3 and len({snapshot['deadline'] for snapshot in snapshots}) == 1
    assert not retained(live_parties[1], selected['grant'])['terminal']


def test_source_ahead_revocation_refuses_selected_issuance_admit(tmp_path, live_parties):
    issuer_process = []
    with observer(tmp_path, live_parties, 'revoked', issuer_process=issuer_process) as (flags, calls, _):
        selected, _, output = issue(tmp_path, live_parties, admit_options=flags, succeeds=False,
                                   issuer_process=issuer_process)
    assert len(calls) == 1 and 'current registry head does not open this credential as issued' in output
    assert not retained(live_parties[1], selected['grant'])['terminal']


def test_authenticated_conflicting_prefix_is_terminal(tmp_path, live_parties):
    issuer_process = []
    with observer(tmp_path, live_parties, 'conflict', issuer_process=issuer_process) as (flags, calls, _):
        selected, _, output = issue(tmp_path, live_parties, admit_options=flags, succeeds=False,
                                   issuer_process=issuer_process)
    assert len(calls) == 1 and 'conflicts with accepted registry' in output
    assert not retained(live_parties[1], selected['grant'])['terminal']


def test_tls_hostname_failure_is_terminal_before_any_query(tmp_path, live_parties):
    with observer(tmp_path, live_parties, 'tls') as (flags, calls, _):
        selected, _, output = issue(tmp_path, live_parties, admit_options=flags, succeeds=False)
    assert not calls and 'CERTIFICATE_VERIFY_FAILED' in output
    assert not retained(live_parties[1], selected['grant'])['terminal']


def test_presentation_acquires_before_unblind_selects_its_current_head(tmp_path, live_parties):
    issuer, holder = live_parties
    selected, body = issue(tmp_path, live_parties)
    later = tmp_path / 'later.cesr'
    update(issuer, body, later)
    messages = Parser(version=V2).parse(ims=bytearray(later.read_bytes()), processive=False)
    intake(holder, b''.join(serializeParsedSubstream(message) for message in messages[:-1]))
    with observer(tmp_path, (holder, issuer), 'retry', selected_file='presentation.cesr', extra=later) as (flags, calls, snapshots):
        _, before, received = present(tmp_path, holder, issuer, selected['grant'], 'presentation',
            admit_options=flags)
    assert len(calls) >= 4 and len({snapshot['deadline'] for snapshot in snapshots}) == 1
    assert not before['accepted'] and received['accepted'] and received['terminal']
    assert before['deadline'] == received['deadline']
