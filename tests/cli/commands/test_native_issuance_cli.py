"""Installed live Grant and Admit with independent stores and a real witness."""
import json
import shutil
import subprocess
import sys
import time
from uuid import uuid4

import pytest
from hio.base import doing

from keri import Vrsn_2_0 as V2
from keri.acdc import Regery
from keri.app import Habery, Receiptor
from keri.cli.common import setupHby
from keri.core import Parser, SerderACDC
from keri.peer.exchanging import verify

from tests.cli.commands.test_native_negotiation_cli import kli


pytestmark = pytest.mark.real_store_roots
PASSCODE = '0123456789abcdefghijk'


@pytest.fixture
def live_parties(tmp_path, unused_tcp_port_factory):
    port = unused_tcp_port_factory()
    base = f'live-{uuid4().hex}'
    ready = tmp_path / 'witness.cesr'
    witness = subprocess.Popen([sys.executable, '-c', '''
import sys
from pathlib import Path
from hio.base import doing
from keri import Vrsn_2_0 as V2
from keri.app import Habery, setupWitness
hby = Habery(name='witness', base=sys.argv[1], version=V2)
doers = setupWitness(hby, alias='witness', tcpPort=None, httpPort=int(sys.argv[3]), version=V2)
hab = hby.habByName('witness')
raw = bytes(hab.replay(gvrsn=V2)) + hab.makeLocScheme('http://127.0.0.1:' + sys.argv[3], pvrsn=V2, gvrsn=V2)
Path(sys.argv[2]).write_bytes(raw)
doing.Doist(real=True, tock=0.03125).do(doers=doers)
''', base, str(ready), str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while not ready.exists():
            assert witness.poll() is None
            assert time.monotonic() < deadline
            time.sleep(0.03)
        sides = []
        witness_raw = ready.read_bytes()
        witness_pre = Parser(version=V2).parseOneBare(ims=bytearray(witness_raw), processive=False).serder.pre
        for alias in ('issuer', 'holder'):
            name = f'{alias}-{uuid4().hex}'
            hby = Habery(name=name, base=base, bran=PASSCODE, version=V2)
            try:
                Parser(kvy=hby.kvy, rvy=hby.rvy, version=V2).parse(ims=bytearray(witness_raw))
                hab = hby.makeHab(name=alias, wits=[witness_pre], toad=1)
                receipts = Receiptor(hby=hby)
                def receipt(tymth, tock=0.03125, **kwa):
                    yield tock
                    yield from receipts.receipt(hab.pre, sn=0)
                    owner.remove([receipts])
                owner = doing.DoDoer(doers=[receipts, doing.doify(receipt)])
                doing.Doist(real=True, tock=0.03125, limit=10).do(doers=[owner])
                assert owner.done
                public = tmp_path / f'{alias}.cesr'
                public.write_bytes(bytes(hab.replay(gvrsn=V2)))
                sides.append(dict(name=name, base=base, alias=alias, pre=hab.pre, public=public,
                    args=['--name', name, '--base', base, '--alias', alias, '--passcode', PASSCODE, '--version', '2.0']))
            finally:
                hby.close()
        yield sides
    finally:
        witness.terminate()
        witness.communicate(timeout=10)


def issue(tmp_path, live_parties, data='{"role":"reader"}'):
    issuer, holder = live_parties
    kli(tmp_path, 'vc', 'registry', 'incept', *issuer['args'], '--registry-name', 'fresh')
    bodyfile = tmp_path / 'body.cesr'
    kli(tmp_path, 'vc', 'create', *issuer['args'], '--registry-name', 'fresh',
        '--recipient', holder['pre'], '--data', data, '--output', str(bodyfile))
    application = tmp_path / 'apply.cesr'
    # Preserve the Apply opener XID through the entire live issuance.
    body = SerderACDC(raw=bodyfile.read_bytes())
    applied = json.loads(kli(tmp_path, 'ipex', 'apply', *holder['args'],
        '--recipient', issuer['pre'], '--plan', json.dumps([[[body.schema['$id'], '/', []]]]),
        '--output', str(application)).splitlines()[-1])
    grantfile, issuerlog = tmp_path / 'grant.cesr', tmp_path / 'issuer.log'
    with issuerlog.open('w+') as output:
        process = subprocess.Popen([shutil.which('kli'), 'ipex', 'grant', *issuer['args'],
            '--credential', str(bodyfile), '--recipient', holder['pre'], '--prior', applied['exchange'],
            '--input', str(holder['public']), '--input', str(application),
            '--issue', '--deliver', '--output', str(grantfile), '--timeout', '20'],
            cwd=tmp_path, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while not grantfile.exists():
                output.flush()
                assert process.poll() is None, issuerlog.read_text()
                assert time.monotonic() < deadline, issuerlog.read_text()
                time.sleep(0.03)
            selected = next(json.loads(line) for line in issuerlog.read_text().splitlines() if line.startswith('{'))
            assert selected['xid'] == applied['exchange'] != selected['grant']
            refused = kli(tmp_path, 'ipex', 'admit', *holder['args'], '--said', applied['exchange'],
                '--input', str(issuer['public']), '--input', str(grantfile), '--deliver', succeeds=False)
            assert 'exact pending native Grant' in refused
            holderfile = tmp_path / 'holder-evidence.cesr'
            admitted = kli(tmp_path, 'ipex', 'admit', *holder['args'], '--said', selected['grant'],
                '--output', str(holderfile), '--deliver', '--timeout', '20')
            process.wait(timeout=25)
            assert process.returncode == 0 and 'ERR:' not in issuerlog.read_text(), issuerlog.read_text()
            result = json.loads(admitted.splitlines()[-1])
            assert result['admitted'] and result['registry_issued']
            assert result == json.loads(issuerlog.read_text().splitlines()[-1])
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
    roots = []
    for side in live_parties:
        hby = setupHby(name=side['name'], base=side['base'], bran=PASSCODE, noPrompt=True, version=V2)
        rgy = Regery(hby=hby, name=side['name'], base=side['base'])
        try:
            for said in (selected['grant'], result['admit']):
                message = hby.db.exns.get((said,))
                assert message is not None
                verify(hby, message)
            assert hby.db.exrs.get((selected['grant'], body.said)).state == 'issued'
            assert rgy.store.headEvent(body.regid).ilk == 'bup'
            roots.append(hby.habByName(side['alias']).mgr.getRegistryRoot(side['pre'], body.regid).qb64)
        finally:
            rgy.close()
            hby.close()
    assert roots[0] == roots[1]
    assert roots[0].encode() not in grantfile.read_bytes()
    assert roots[0].encode() not in holderfile.read_bytes()
    evidence = Parser(version=V2).parse(ims=bytearray(holderfile.read_bytes()), processive=False)
    assert [parsed.serder.said for parsed in evidence] == [selected['grant'], result['admit']]
    return selected, body


def test_installed_witnessed_apply_grant_dh_bup_and_selected_admit(tmp_path, live_parties):
    issue(tmp_path, live_parties)


def test_finite_grant_timeout_keeps_registry_unissued_and_has_no_restart_keys(tmp_path, live_parties):
    issuer, holder = live_parties
    kli(tmp_path, 'vc', 'registry', 'incept', *issuer['args'], '--registry-name', 'fresh')
    bodyfile, grantfile = tmp_path / 'body.cesr', tmp_path / 'pending.cesr'
    kli(tmp_path, 'vc', 'create', *issuer['args'], '--registry-name', 'fresh',
        '--recipient', holder['pre'], '--data', '{"role":"reader"}', '--output', str(bodyfile))
    arguments = ['ipex', 'grant', *issuer['args'], '--credential', str(bodyfile),
        '--recipient', holder['pre'], '--input', str(holder['public']), '--deliver', '--output', str(grantfile)]
    assert 'requires --credential and --issue' in kli(tmp_path, *arguments, succeeds=False)
    assert not grantfile.exists()
    output = kli(tmp_path, *arguments, '--issue', '--timeout', '0.4', succeeds=False)
    assert 'before --timeout' in output
    selected = next(json.loads(line) for line in output.splitlines() if line.startswith('{'))
    hby = setupHby(name=issuer['name'], base=issuer['base'], bran=PASSCODE, noPrompt=True, version=V2)
    rgy = Regery(hby=hby, name=issuer['name'], base=issuer['base'])
    try:
        body = SerderACDC(raw=bodyfile.read_bytes())
        assert rgy.store.headEvent(body.regid).ilk == 'rip'
        assert hby.db.epse.get((selected['grant'],)) is not None
        assert hby.db.exns.get((selected['grant'],)) is None
        assert hby.habByName('issuer').mgr.getRegistryRoot(issuer['pre'], body.regid) is None
        assert list(hby.ks.rroots.getTopItemIter()) == []
    finally:
        rgy.close()
        hby.close()
    before = grantfile.read_bytes()
    assert 'output already exists' in kli(tmp_path, *arguments, '--issue', succeeds=False)
    assert grantfile.read_bytes() == before
