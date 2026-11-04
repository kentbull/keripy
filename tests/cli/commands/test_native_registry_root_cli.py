"""Installed existing-root copies use one live approval and real witness mailboxes."""
import json
import shutil
import subprocess
import time

import pytest
from hio.base import doing

from keri import Vrsn_2_0 as V2
from keri.acdc import Regery, Registrar, acdcmap, regeventing
from keri.acdc.salting import RegistrySalt
from keri.app import Receiptor
from keri.cli.common import setupHby
from keri.core import Blinder, Encrypter, Parser, Salter, SealSource, messagize, reply
from tests.cli.commands.test_native_issuance_cli import PASSCODE
from tests.cli.commands.test_native_issuance_cli import live_parties as live_parties
from tests.cli.commands.test_native_negotiation_cli import kli


pytestmark = pytest.mark.real_store_roots


def last_result(output):
    return json.loads([line for line in output.splitlines() if line.startswith('{')][-1])


def existing_registry(tmp_path, sides):
    """Author and witness the existing registry before either provisioning command."""
    issuer, receiver = sides
    hby = setupHby(name=issuer['name'], base=issuer['base'], bran=PASSCODE, noPrompt=True, version=V2)
    rgy = Regery(hby, name=issuer['name'], base=issuer['base'])
    try:
        hab = hby.habByName('issuer')
        hby.psr.parse(ims=bytearray(receiver['public'].read_bytes()), framed=False)
        registry = Registrar(rgy).makeRegistry('existing', hab.pre)

        def seal(event):
            hab.interact(data=[dict(i=registry.regk, s=event.sad['n'], d=event.said)], gvrsn=V2)
            receipts = Receiptor(hby=hby)
            def collect(tymth, tock=0.03125, **kwa):
                yield tock
                yield from receipts.receipt(hab.pre, sn=hab.kever.sn)
                owner.remove([receipts])
            owner = doing.DoDoer(doers=[receipts, doing.doify(collect)])
            doing.Doist(real=True, tock=0.03125, limit=10).do(doers=[owner])
            assert owner.done and registry.anchorMsg(event.said)

        seal(rgy.store.event(registry.regk))
        root = Salter()
        hab.mgr.putRegistryRoot(hab.pre, registry.regk, root)
        body = acdcmap(israid=hab.pre, iseaid=receiver['pre'], regid=registry.regk,
                       attribute=dict(d='', role='reader'))
        opening, event = Registrar(rgy).issue(registry, body, salt=root.qb64)
        seal(event)
        evidence = bytearray(hab.replay(gvrsn=V2))
        for raw in rgy.store.cloneTelIter(registry.regk):
            node = type(event)(raw=raw)
            sn, said = regeventing.vetAnchor(node, db=hby.db, issuer=hab.pre)
            evidence.extend(messagize(node, bonds=[SealSource(s=f'{sn:x}', d=said)], gvrsn=V2))
        public = tmp_path / 'public.cesr'
        public.write_bytes(evidence)
        held = tmp_path / 'held-opening.cesr'
        held.write_bytes(opening.qb64b)
        return body, event, opening, root.qb64, public, held
    finally:
        rgy.close()
        hby.close()


def retained(side, body):
    hby = setupHby(name=side['name'], base=side['base'], bran=PASSCODE, noPrompt=True, version=V2)
    rgy = Regery(hby, name=side['name'], base=side['base'])
    try:
        hab = hby.habByName(side['alias'])
        root = hab.mgr.getRegistryRoot(hab.pre, body.regid)
        return (root.qb64 if root else None,
                hby.ks.rroots.get((hab.pre, body.regid)).qb64 if root else None,
                tuple(rgy.store.cloneTelIter(body.regid)))
    finally:
        rgy.close()
        hby.close()


def receive_args(side, body, event, public, held):
    return ['vc', 'registry', 'receive', *side['args'], '--registry', body.regid,
            '--sender', body.israid, '--event', event.said, '--opening', str(held),
            '--evidence', str(public)]


def test_installed_copy_reopens_and_rejects_false_receipt_with_existing_root(tmp_path, live_parties):
    issuer, receiver = live_parties
    body, event, opening, root, public, held = existing_registry(tmp_path, live_parties)
    before = retained(issuer, body)
    assert retained(receiver, body)[0] is None
    args = receive_args(receiver, body, event, public, held)
    for name in ('first', 'identical'):
        destination = tmp_path / (name + '.cesr')
        prepared = last_result(kli(tmp_path, 'vc', 'registry', 'provision', *issuer['args'],
            '--registry', body.regid, '--recipient', receiver['pre'], '--output', str(destination)))
        result = last_result(kli(tmp_path, *args, '--message', str(destination)))
        assert result['received'] and result['reply'] == prepared['reply'] and not prepared['transmitted']
        assert root.encode() not in destination.read_bytes() and root.encode() not in public.read_bytes()
    saved = retained(receiver, body)
    assert saved[0] == root and saved[1] != root and retained(issuer, body) == before
    derived = Blinder.unblind(event.sad['b'], salt=saved[0], sn=1, acdc=body.said, states=('issued',))
    assert derived.qb64 == opening.qb64
    malformed = tmp_path / 'trailing-garbage.cesr'
    malformed.write_bytes(public.read_bytes() + b'garbage')
    output = kli(tmp_path, *args, '--evidence', str(malformed), '--message', str(destination), succeeds=False)
    assert 'complete public KEL/TEL frames' in output and '"phase": "approved"' not in output
    assert retained(receiver, body) == saved
    truncated = tmp_path / 'truncated.cesr'
    truncated.write_bytes(public.read_bytes()[:-1])
    output = kli(tmp_path, *args, '--evidence', str(truncated), '--message', str(destination), succeeds=False)
    assert 'complete public KEL/TEL frames' in output and '"phase": "approved"' not in output
    assert retained(receiver, body) == saved
    output = kli(tmp_path, *args, '--message', str(destination), '--timeout', '0.000001', succeeds=False)
    assert 'before --timeout' in output and '"received": true' not in output
    assert retained(receiver, body) == saved

    # BADA can retain this authenticated reply before native decryption/root checks fail.
    hby = setupHby(name=issuer['name'], base=issuer['base'], bran=PASSCODE, noPrompt=True, version=V2)
    try:
        hab = hby.habByName('issuer')
        wrong = Encrypter(verkey=hby.kevers[receiver['pre']].verfers[0].qb64).encrypt(prim=Salter())
        bad = reply(pre=hab.pre, route=RegistrySalt.Route, pvrsn=V2,
            data=dict(registry=body.regid, recipient=receiver['pre'], target=receiver['pre'], cipher=wrong.qb64))
        rejected = tmp_path / 'rejected.cesr'
        rejected.write_bytes(hab.endorse(bad, gvrsn=V2))
    finally:
        hby.close()
    output = kli(tmp_path, *args, '--message', str(rejected), succeeds=False)
    assert 'root does not reproduce' in output and '"received": true' not in output
    assert retained(receiver, body) == saved and retained(issuer, body) == before


def test_live_receive_timeout_needs_fresh_approval_then_real_mailbox_delivery(tmp_path, live_parties):
    issuer, receiver = live_parties
    body, event, _, root, public, held = existing_registry(tmp_path, live_parties)
    args = receive_args(receiver, body, event, public, held)
    output = kli(tmp_path, *args, '--listen', '--timeout', '0.4', succeeds=False)
    assert 'before --timeout' in output and '"received": true' not in output
    assert retained(receiver, body)[0] is None
    log = tmp_path / 'receive.log'
    with log.open('w+') as output:
        process = subprocess.Popen([shutil.which('kli'), *args, '--listen', '--timeout', '15'],
            cwd=tmp_path, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while '"phase": "approved"' not in log.read_text():
                assert process.poll() is None, log.read_text()
                assert time.monotonic() < deadline, log.read_text()
                time.sleep(.03)
            destination = tmp_path / 'delivered.cesr'
            prepared = last_result(kli(tmp_path, 'vc', 'registry', 'provision', *issuer['args'],
                '--registry', body.regid, '--recipient', receiver['pre'], '--output', str(destination),
                '--deliver', '--timeout', '15'))
            process.wait(timeout=20)
            assert process.returncode == 0 and 'ERR:' not in log.read_text(), log.read_text()
            received = last_result(log.read_text())
            assert received['received'] and received['reply'] == prepared['reply'] and prepared['transmitted']
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)
    assert retained(receiver, body)[0] == root
