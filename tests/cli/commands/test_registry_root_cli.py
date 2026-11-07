"""Installed kli root replication over real witness mailboxes, with the file fallback."""
import json
import shutil
import subprocess
import time

import pytest
from hio.base import doing

from keri import Vrsn_2_0 as V2
from keri.acdc import Regery, Registrar, acdcmap, regeventing
from keri.app import Receiptor
from keri.cli.common import setupHby
from keri.core import Kevery, Parser, Salter, SealSource, messagize
from tests.cli.commands.test_ipex_v2_issuance_cli import PASSCODE, group_issue, holder_group
from tests.cli.commands.test_ipex_v2_issuance_cli import live_parties as live_parties
from tests.cli.commands.test_ipex_v2_negotiation_cli import kli


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


def group_copy(tmp_path, live_parties, data='{"role":"group reader"}'):
    """Continue the real 2of2 issuance; the lead copies its root to the rootless member."""
    issuer, holders, body, selected = group_issue(tmp_path, live_parties, data=data)
    lead, target = holders
    before = retained(lead, body)
    assert before[0] is not None and retained(target, body)[0] is None
    wire = tmp_path / 'group-root.cesr'
    sent = results(kli(tmp_path, 'vc', 'registry', 'root', 'send', *lead['args'],
        '--registry', body.regid, '--acdc', body.said, '--out', str(wire)))
    assert [(item['recipient'], item['gid']) for item in sent] == [(target['member'], target['pre'])]
    received = results(kli(tmp_path, 'vc', 'registry', 'root', 'receive', *target['args'],
        '--registry', body.regid, '--message', str(wire)))
    assert received == [dict(gid=target['pre'], registry=body.regid, retained=True)]
    saved = retained(target, body)
    assert saved[0] == before[0] and saved[1] != before[0] and saved[2] == before[2]
    assert retained(lead, body) == before and before[0].encode() not in wire.read_bytes()
    return issuer, holders, body, selected


def results(output):
    return [json.loads(line) for line in output.splitlines() if line.startswith('{')]


def root(side, gid, registry):
    hby = setupHby(name=side['name'], base=side['base'], bran=PASSCODE, noPrompt=True, version=V2)
    try:
        held = hby.mgr.getRegistryRoot(gid, registry)
        return held.qb64 if held else None
    finally:
        hby.close()


def accept_public(side, raw):
    """Give the receiver the issuer's public KEL/TEL, as an IPEX holder already has."""
    hby = setupHby(name=side['name'], base=side['base'], bran=PASSCODE, noPrompt=True, version=V2)
    rgy = Regery(hby, name=side['name'], base=side['base'])
    try:
        kvy = Kevery(db=hby.db, rvy=hby.rvy, lax=True, local=False)
        Parser(version=V2, kvy=kvy, rvy=hby.rvy, rgy=rgy).parse(ims=bytearray(raw), framed=False)
        kvy.processEscrows()
        rgy.processEscrows()
    finally:
        rgy.close()
        hby.close()


def test_cross_party_file_fallback_retains_by_commitment_on_arrival(tmp_path, live_parties):
    issuer, receiver = live_parties
    body, event, _, expected, public, _ = existing_registry(tmp_path, live_parties)
    accept_public(receiver, public.read_bytes())
    wire = tmp_path / 'root.cesr'
    sent = results(kli(tmp_path, 'vc', 'registry', 'root', 'send', *issuer['args'],
        '--registry', body.regid, '--recipient', receiver['pre'], '--acdc', body.said, '--out', str(wire)))
    assert len(sent) == 1 and not sent[0]['transmitted'] and sent[0]['gid'] == receiver['pre']
    assert expected.encode() not in wire.read_bytes()
    refused = kli(tmp_path, 'vc', 'registry', 'root', 'send', *issuer['args'],
        '--registry', body.regid, '--recipient', receiver['pre'], '--out', str(wire), succeeds=False)
    assert 'output already exists' in refused
    receive = ['vc', 'registry', 'root', 'receive', *receiver['args']]
    received = results(kli(tmp_path, *receive, '--registry', body.regid, '--message', str(wire)))
    assert received == [dict(gid=receiver['pre'], registry=body.regid, retained=True)]
    assert root(receiver, receiver['pre'], body.regid) == expected
    # Nothing is left pending, and a duplicate file delivery is idempotent.
    assert results(kli(tmp_path, *receive)) == []
    assert results(kli(tmp_path, *receive, '--registry', body.regid, '--message', str(wire))) == received


def group_root(tmp_path, live_parties):
    """A witnessed 2-of-2 holder group whose lead holds an existing registry root."""
    issuer, holders, public, _ = holder_group(tmp_path, live_parties)
    lead, peer = holders
    group = dict(public=public, pre=lead['pre'])
    body, _, _, expected, evidence, _ = existing_registry(tmp_path, (issuer, group))
    for side in holders:
        accept_public(side, evidence.read_bytes())
    # The lead holds the group root, as the custodian does after group DH.
    hby = setupHby(name=lead['name'], base=lead['base'], bran=PASSCODE, noPrompt=True, version=V2)
    try:
        hby.mgr.putRegistryRoot(lead['pre'], body.regid, Salter(qb64=expected))
    finally:
        hby.close()
    assert root(peer, peer['pre'], body.regid) is None
    return lead, peer, body, expected


def test_mailbox_copy_fetched_after_the_kram_window_is_received(tmp_path, live_parties):
    lead, peer, body, expected = group_root(tmp_path, live_parties)
    sent = results(kli(tmp_path, 'vc', 'registry', 'root', 'send', *lead['args'],
        '--registry', body.regid, '--acdc', body.said, '--timeout', '25'))
    assert [(item['recipient'], item['transmitted']) for item in sent] == [(peer['member'], True)]
    # The peer is offline past its whole KRAM short-lag window (1 s + 5 s).
    time.sleep(8)
    received = results(kli(tmp_path, 'vc', 'registry', 'root', 'receive', *peer['args'],
        '--registry', body.regid, '--listen', '--timeout', '20'))[-1]
    assert received == dict(gid=peer['pre'], registry=body.regid, retained=True)
    assert root(peer, peer['pre'], body.regid) == expected


def test_group_member_send_defaults_to_members_through_mailbox(tmp_path, live_parties):
    lead, peer, body, expected = group_root(tmp_path, live_parties)
    log = tmp_path / 'root-receive.log'
    with log.open('w+') as output:
        process = subprocess.Popen([shutil.which('kli'), 'vc', 'registry', 'root', 'receive', *peer['args'],
            '--registry', body.regid, '--listen', '--timeout', '60'],
            cwd=tmp_path, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 30
            while '"phase": "listening"' not in log.read_text():
                assert process.poll() is None, log.read_text()
                assert time.monotonic() < deadline, log.read_text()
                time.sleep(.03)
            sent = results(kli(tmp_path, 'vc', 'registry', 'root', 'send', *lead['args'],
                '--registry', body.regid, '--acdc', body.said, '--timeout', '25'))
            assert [(item['recipient'], item['gid'], item['transmitted']) for item in sent] == [
                (peer['member'], peer['pre'], True)]
            assert expected.encode() not in log.read_bytes()
            process.wait(timeout=65)
            assert process.returncode == 0 and 'ERR:' not in log.read_text(), log.read_text()
            received = results(log.read_text())[-1]
            assert received == dict(gid=peer['pre'], registry=body.regid, retained=True)
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)
    assert root(peer, peer['pre'], body.regid) == expected
    # The newcomers command refuses anything but an accepted group rotation.
    refused = kli(tmp_path, 'vc', 'registry', 'root', 'newcomers', *lead['args'],
        '--rotation', body.said, succeeds=False)
    assert 'accepted group rotation' in refused


def test_copy_drained_by_vc_list_is_retained_without_receive(tmp_path, live_parties):
    lead, peer, body, expected = group_root(tmp_path, live_parties)
    sent = results(kli(tmp_path, 'vc', 'registry', 'root', 'send', *lead['args'],
        '--registry', body.regid, '--acdc', body.said, '--timeout', '25'))
    assert [(item['recipient'], item['transmitted']) for item in sent] == [(peer['member'], True)]
    # The recipient runs only an ordinary credential-mailbox command, never receive.
    kli(tmp_path, 'vc', 'list', '--name', peer['name'], '--base', peer['base'],
        '--alias', peer['alias'], '--passcode', PASSCODE, '--poll')
    assert root(peer, peer['pre'], body.regid) == expected
    # A later receive (no --listen) only reports the retained root.
    received = results(kli(tmp_path, 'vc', 'registry', 'root', 'receive', *peer['args'],
        '--registry', body.regid))
    assert received == [dict(gid=peer['pre'], registry=body.regid, retained=True)]
