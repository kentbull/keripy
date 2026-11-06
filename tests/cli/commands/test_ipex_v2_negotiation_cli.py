"""v2 IPEX negotiation through installed console scripts and independent stores."""
import json
import shutil
import subprocess
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Thread
from types import SimpleNamespace
from uuid import uuid4

import pytest
from hio.base import doing

from keri import Kinds, Vrsn_2_0
from keri.acdc import offer
from keri.acdc.ipexing import loadHandlers
from keri.app import Notifier
from keri.cli.common import setupHby
from keri.cli.commands.ipex.apply import handler as apply_command, parser as apply_parser
from keri.core import Diger, Parser, Salter, Siger
from keri.peer import Exchanger
from keri.peer.exchanging import serializeParsedSubstream, verify


pytestmark = pytest.mark.real_store_roots


def kli(tmp_path, *args, succeeds=True):
    result = subprocess.run([shutil.which('kli'), *args], cwd=tmp_path,
                            capture_output=True, text=True, timeout=30)
    output = result.stdout + result.stderr
    assert (result.returncode == 0 and 'ERR:' not in output) == succeeds, output
    return output


# Live DH and Unblind require an accepted KRAM transaction; installed kli reads
# KRAM settings from each Habery's own config file and keeps them off by default.
KRAM_CACHES = {'~': [1000, 60000, 60000, 300000, 60000, 60000, 300000]}


def exchange_deadline(db, said):
    """Return a stored v2 Grant's accepted KRAM exchange deadline, or None."""
    serder = db.exns.get((said,)) or db.epse.get((said,))
    if serder is None:
        return None
    return Exchanger(hby=SimpleNamespace(db=db), handlers=[]).exchangeDeadline(serder)


def enable_kram(hby, caches=None):
    """Enable KRAM in this Habery's config file, as an operator would."""
    config = hby.cf.get()
    config['kram'] = dict(enabled=True, denials=[], caches=caches or KRAM_CACHES)
    hby.cf.put(config)


@pytest.fixture
def actors(tmp_path):
    sides = []
    config = tmp_path / 'identity.json'
    config.write_text(json.dumps(dict(transferable=True, wits=[], toad=0,
                                     icount=2, isith='2', ncount=2, nsith='2')))
    for alias in ('alice', 'bob'):
        name, base = f'negotiation-{uuid4().hex}', 'r10b'
        common = ['--name', name, '--base', base]
        kli(tmp_path, 'init', *common, '--nopasscode', '--version', '2.0')
        kli(tmp_path, 'incept', *common, '--alias', alias, '--file', str(config), '--version', '2.0')
        hby = setupHby(name=name, base=base, noPrompt=True, version=Vrsn_2_0)
        try:
            prefix = hby.habByName(alias).pre
        finally:
            hby.close()
        sides.append((common + ['--alias', alias, '--version', '2.0'], prefix))
    return sides


def send(tmp_path, verb, side, filename, *args, succeeds=True):
    output = kli(tmp_path, 'ipex', verb, *side[0], '--output', str(tmp_path / filename),
                 *args, succeeds=succeeds)
    return json.loads(output.splitlines()[-1]) if succeeds else output


def stored(side, said):
    args = side[0]
    hby = setupHby(name=args[1], base=args[3], noPrompt=True, version=Vrsn_2_0)
    try:
        body = hby.db.exns.get((said,))
        assert body is not None
        signatures, cigars = verify(hby, body)
        assert len(signatures) == 1 and len(signatures[0][3]) == 2 and not cigars
        return body
    finally:
        hby.close()


def test_installed_ipex_v2_negotiation_preserves_exact_parties_plan_and_thread(tmp_path, actors):
    alice, bob = actors
    plan = [[[Diger(ser=b'public requested schema').qb64, '/', []]]]
    (tmp_path / 'plan.json').write_text(json.dumps(plan))
    application = send(tmp_path, 'apply', alice, 'apply.cesr', '--recipient', bob[1], '--plan', '@' + str(tmp_path / 'plan.json'))
    # A counter-offer is allowed; Agree must inherit this exact new approved plan.
    counter = [[[Diger(ser=b'counter-offered schema').qb64, '/', ['a/name']]]]
    offer = send(tmp_path, 'offer', bob, 'offer.cesr', '--input', str(tmp_path / 'apply.cesr'),
                 '--prior', application['exchange'], '--plan', json.dumps(counter))
    accepted = stored(bob, application['exchange'])
    assert accepted.pre == alice[1] and accepted.sad['ri'] == bob[1] and accepted.sad['q']['dp'] == plan
    agreement = send(tmp_path, 'agree', alice, 'agree.cesr', '--input', str(tmp_path / 'offer.cesr'),
                     '--said', offer['exchange'])
    offered = stored(alice, offer['exchange'])
    agreed = stored(alice, agreement['exchange'])
    assert offered.pre == bob[1] and offered.sad['ri'] == alice[1] and offered.sad['q']['dp'] == counter
    assert agreed.pre == alice[1] and agreed.sad['ri'] == bob[1]
    assert offered.sad['p'] == application['exchange'] and agreed.sad['p'] == offer['exchange']
    assert offered.sad['x'] == agreed.sad['x'] == application['exchange']
    assert agreed.sad['q']['dp'] == [[]]  # Exact inherited plan, not a rebuilt proposal.
    send(tmp_path, 'apply', bob, 'independent.cesr', '--input', str(tmp_path / 'agree.cesr'),
         '--recipient', alice[1], '--plan', json.dumps(plan))
    assert stored(bob, agreement['exchange']).raw == agreed.raw
    for result in (application, offer, agreement):
        assert result['locally_accepted'] is True and result['transmitted'] is False


def test_installed_ipex_v2_negotiation_refuses_wrong_parties_prior_plan_and_input(tmp_path, actors):
    alice, bob = actors
    plan = json.dumps([[[Diger(ser=b'public schema').qb64, '/', []]]])
    application = send(tmp_path, 'apply', alice, 'apply.cesr', '--recipient', bob[1], '--plan', plan)
    for filename, side, extra in (
        ('wrong-recipient', bob, ['--input', str(tmp_path / 'apply.cesr'), '--prior', application['exchange'], '--recipient', bob[1]]),
        ('unknown-prior', bob, ['--prior', Diger(ser=b'absent prior').qb64]),
        ('wrong-sender', alice, ['--prior', application['exchange']]),
        ('malformed-plan', bob, ['--recipient', alice[1], '--plan', '[[], []]']),
        ('invalid-wait', bob, ['--recipient', alice[1], '--plan', plan, '--timeout', 'nan']),
    ):
        send(tmp_path, 'offer', side, filename, *extra, succeeds=False)
        assert not (tmp_path / filename).exists()
    send(tmp_path, 'agree', alice, 'wrong-route', '--said', application['exchange'], succeeds=False)
    untouched = (tmp_path / 'apply.cesr').read_bytes()
    send(tmp_path, 'apply', alice, 'apply.cesr', '--recipient', bob[1], '--plan', plan, succeeds=False)
    assert (tmp_path / 'apply.cesr').read_bytes() == untouched
    forged = send(tmp_path, 'apply', alice, 'unsigned.cesr', '--recipient', bob[1], '--plan', plan, '--message', 'other request')
    children = Parser(version=Vrsn_2_0).parse(ims=bytearray((tmp_path / 'unsigned.cesr').read_bytes()), processive=False)
    signatures = children[-1].tsgs[0][3]
    good = signatures[0]
    signatures[0] = Siger(raw=bytes([good.raw[0] ^ 1]) + good.raw[1:], index=good.index)
    (tmp_path / 'forged.cesr').write_bytes(b''.join(serializeParsedSubstream(child) for child in children))
    send(tmp_path, 'offer', bob, 'forged-output', '--input', str(tmp_path / 'forged.cesr'),
         '--prior', forged['exchange'], succeeds=False)
    assert not (tmp_path / 'forged-output').exists()


@pytest.mark.parametrize('verb', ['apply', 'offer', 'agree'])
def test_existing_default_invocation_still_prints_nonce(tmp_path, verb):
    for version in ([], ['--version', '1.0']):
        output = kli(tmp_path, 'ipex', verb, *version).strip()
        assert Salter(qb64=output).qb64 == output


def test_anchored_agree_refuses_before_kel_mutation_without_silencing_requirement(tmp_path, actors):
    alice, bob = actors
    hby = setupHby(name=bob[0][1], base=bob[0][3], noPrompt=True, version=Vrsn_2_0)
    try:
        hab = hby.habByName('bob')
        body, atc = offer(hab, message='requires anchor', origin=None, recp=alice[1],
                          modifiers=dict(dp=[[]]), ax=[True], kind=Kinds.json, gvrsn=Vrsn_2_0)
        (tmp_path / 'anchored.cesr').write_bytes(bytes(hab.replay(gvrsn=Vrsn_2_0)) + body.raw + atc)
    finally:
        hby.close()
    output = send(tmp_path, 'agree', alice, 'refused-agree', '--input', str(tmp_path / 'anchored.cesr'),
                  '--said', body.said, succeeds=False)
    assert 'anchored Agree completion' in output and not (tmp_path / 'refused-agree').exists()
    assert stored(alice, body.said).sad['a']['ax'] == [True]
    hby = setupHby(name=alice[0][1], base=alice[0][3], noPrompt=True, version=Vrsn_2_0)
    try:
        assert hby.habByName('alice').kever.sn == 0
        assert hby.db.erpy.get((body.said,)) is None, 'public receive is not consent'
    finally:
        hby.close()


@pytest.mark.parametrize('outcome', [204, 403, 500, 'timeout', 'cancel'],
                         ids=['success', 'forbidden', 'server-error', 'timeout', 'cancel'])
def test_installed_finite_delivery_sends_signed_bytes_to_real_http_endpoint(tmp_path, actors, outcome):
    alice, bob = actors
    received, closed = [], Event()
    class Intake(BaseHTTPRequestHandler):
        def do_PUT(self):
            received.append((self.headers['Content-Type'], self.rfile.read(int(self.headers['Content-Length']))))
            if outcome in ('timeout', 'cancel'):
                assert self.rfile.read(1) == b''  # Finite owner cancellation closes its live connection.
                closed.set()
                return
            self.send_response(outcome)
            self.end_headers()
        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Intake)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    hby = setupHby(name=bob[0][1], base=bob[0][3], noPrompt=True, version=Vrsn_2_0)
    try:
        hab = hby.habByName('bob')
        endpoints = bytes(hab.replay(gvrsn=Vrsn_2_0)) + hab.makeEndRole(hab.pre, pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0)
        endpoints += hab.makeLocScheme(f'http://127.0.0.1:{server.server_port}', pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0)
        (tmp_path / 'endpoint.cesr').write_bytes(endpoints)
    finally:
        hby.close()
    try:
        arguments = ['--input', str(tmp_path / 'endpoint.cesr'), '--recipient', bob[1], '--plan', '[[]]', '--deliver']
        if outcome == 'cancel':
            args = apply_parser.parse_args([*alice[0], '--output', str(tmp_path / 'delivered.cesr'), *arguments])
            doing.Doist(real=True, tock=0.03125, limit=0.25).do(doers=apply_command(args))
        else:
            if outcome == 'timeout':
                arguments += ['--timeout', '0.2']
            result = send(tmp_path, 'apply', alice, 'delivered.cesr', *arguments, succeeds=outcome == 204)
        assert len(received) == 1
        if outcome != 204:
            if outcome in ('timeout', 'cancel'):
                assert closed.wait(1), 'timeout/cancellation must close the actual client connection'
            if outcome != 'cancel':
                assert ('before --timeout' if outcome == 'timeout' else f'HTTP submission failed with status {outcome}') in result
                assert 'locally_accepted' not in result
            # Reopening both real owners in-process also detects leaked LMDB handles after cancellation.
            hby = setupHby(name=alice[0][1], base=alice[0][3], noPrompt=True, version=Vrsn_2_0)
            notifier = Notifier(hby)
            notifier.noter.close()
            hby.close()
            return
        assert result['transmitted'] is True
        assert received[0][0] == 'application/cesr'
        hby = setupHby(name=bob[0][1], base=bob[0][3], noPrompt=True, version=Vrsn_2_0)
        notifier = Notifier(hby)
        try:
            exc = Exchanger(hby=hby, handlers=[])
            loadHandlers(hby, exc, notifier)
            psr = Parser(kvy=hby.kvy, exc=exc, rvy=hby.rvy, version=Vrsn_2_0)
            public = bytearray((tmp_path / 'delivered.cesr').read_bytes())
            inception = psr.parseOneBare(ims=public, processive=False)
            psr.msgProcess(asdict(inception), kvy=hby.kvy, tvy=None, exc=exc, rvy=hby.rvy, vry=None)
            psr.parseOneBare(ims=bytearray(received[0][1]))
            assert exc.complete(result['exchange'])
        finally:
            notifier.noter.close()
            hby.close()
        assert stored(bob, result['exchange']).pre == alice[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
