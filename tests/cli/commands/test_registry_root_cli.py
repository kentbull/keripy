"""Installed kli root replication over real witness mailboxes, with the file fallback."""
import json
import shutil
import subprocess
import time

import pytest

from keri import Vrsn_2_0 as V2
from keri.acdc import Regery
from keri.cli.common import setupHby
from keri.core import Kevery, Parser, Salter
from tests.cli.commands.test_acdc_v2_registry_root_cli import existing_registry
from tests.cli.commands.test_ipex_v2_issuance_cli import PASSCODE, holder_group
from tests.cli.commands.test_ipex_v2_issuance_cli import live_parties as live_parties
from tests.cli.commands.test_ipex_v2_negotiation_cli import kli


pytestmark = pytest.mark.real_store_roots


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


def test_cross_party_file_fallback_lists_then_retains_by_commitment(tmp_path, live_parties):
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
    output = kli(tmp_path, *receive, '--registry', body.regid, '--sender', receiver['pre'],
                 '--message', str(wire), succeeds=False)
    assert 'no matching pending' in output and root(receiver, receiver['pre'], body.regid) is None
    assert [item['said'] for item in results(kli(tmp_path, *receive))] == [sent[0]['exchange']]
    received = results(kli(tmp_path, *receive, '--registry', body.regid, '--sender', issuer['pre']))[-1]
    assert received['received'] and received['said'] == sent[0]['exchange']
    assert root(receiver, receiver['pre'], body.regid) == expected
    assert results(kli(tmp_path, *receive)) == []


def test_group_member_send_defaults_to_members_through_mailbox(tmp_path, live_parties):
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
    log = tmp_path / 'root-receive.log'
    with log.open('w+') as output:
        process = subprocess.Popen([shutil.which('kli'), 'vc', 'registry', 'root', 'receive', *peer['args'],
            '--registry', body.regid, '--sender', lead['member'], '--listen', '--timeout', '60'],
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
            assert received['received'] and received['said'] == sent[0]['exchange']
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)
    assert root(peer, peer['pre'], body.regid) == expected
    # The newcomers command refuses anything but an accepted group rotation.
    refused = kli(tmp_path, 'vc', 'registry', 'root', 'newcomers', *lead['args'],
        '--rotation', body.said, succeeds=False)
    assert 'accepted group rotation' in refused
