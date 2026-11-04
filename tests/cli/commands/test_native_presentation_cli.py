"""Installed presentation selects admitted views; Unblind never grants use by itself."""
import json
import shutil
import subprocess
import time

from hio.base import doing

from keri import Vrsn_2_0 as V2
from keri.acdc import Regery, Registrar
from keri.app import Receiptor
from keri.cli.common import setupHby
from keri.core import Parser, SealSource, SerderKERI, messagize
from keri.peer import Exchanger
from keri.peer.exchanging import serializeParsedSubstream
from keri.acdc.ipexing import loadHandlers
from types import SimpleNamespace

from tests.cli.commands.test_native_issuance_cli import PASSCODE, issue, live_parties
from tests.cli.commands.test_native_negotiation_cli import kli

import pytest
pytestmark = pytest.mark.real_store_roots


def state(side):
    return setupHby(name=side['name'], base=side['base'], bran=PASSCODE, noPrompt=True, version=V2)


def update(side, credential, output, *, value='', bound=False):
    """Use the existing real witness receipt path for each exact native BUP anchor."""
    hby = state(side)
    rgy = Regery(hby, name=side['name'], base=side['base'])
    try:
        hab = hby.habByName(side['alias'])
        reg = rgy.regs[credential.regid]
        root = hab.mgr.getRegistryRoot(hab.pre, reg.regk)
        kwargs = dict(salt=root.qb64)
        if bound:
            issuee = hby.db.kevers[credential.iseaid]
            kwargs.update(bound=True, bsn=issuee.sn, bd=issuee.serder.said)
        registrar = Registrar(rgy)
        proof, event = (registrar.issue(reg, credential, state=value, **kwargs) if value else
            registrar.vacate(reg, **(dict(kwargs, bsn=0, bd='') if bound else kwargs)))
        anchor = SerderKERI(raw=hab.interact(
            data=[dict(i=reg.regk, s=event.sad['n'], d=event.said)], gvrsn=V2))
        receipts = Receiptor(hby=hby)
        def receipt(tymth, tock=0.03125, **kwa):
            yield tock
            yield from receipts.receipt(hab.pre, sn=anchor.sn)
            owner.remove([receipts])
        owner = doing.DoDoer(doers=[receipts, doing.doify(receipt)])
        doing.Doist(real=True, tock=0.03125, limit=10).do(doers=[owner])
        assert owner.done and reg.anchorMsg(event.said)
        output.write_bytes(bytes(hab.replay(gvrsn=V2)) + messagize(event,
            bonds=[SealSource(s=anchor.snh, d=anchor.said)], gvrsn=V2))
        return event, proof
    finally:
        rgy.close()
        hby.close()


def intake(side, raw, *, proof=None, event=None):
    hby = state(side)
    rgy = Regery(hby, name=side['name'], base=side['base'])
    try:
        exc = Exchanger(hby, handlers=[])
        loadHandlers(hby, exc, SimpleNamespace(add=lambda **_: None), rgy=rgy)
        Parser(kvy=hby.kvy, rvy=hby.rvy, rgy=rgy, exc=exc, version=V2).parse(ims=bytearray(raw))
        if proof:
            assert rgy.store.putOpening(event.said, proof)
    finally:
        rgy.close()
        hby.close()


def present(tmp_path, sender, receiver, source, filename, *extra, succeeds=True, admit_options=()):
    evidence, log = tmp_path / (filename + '.cesr'), tmp_path / (filename + '.log')
    with log.open('w') as output:
        process = subprocess.Popen([shutil.which('kli'), 'ipex', 'present', *sender['args'],
            '--from-grant', source, '--recipient', receiver['pre'], '--input', str(receiver['public']),
            '--respond-unblind', '--deliver', '--output', str(evidence), '--timeout', '12', *extra],
            cwd=tmp_path, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while not evidence.exists():
                assert process.poll() is None, log.read_text()
                assert time.monotonic() < deadline, log.read_text()
                time.sleep(0.03)
            selected = next(json.loads(line) for line in log.read_text().splitlines() if line.startswith('{'))
            intake(receiver, evidence.read_bytes())
            before = inspect(tmp_path, receiver, selected['grant'])
            admitted = kli(tmp_path, 'ipex', 'admit', *receiver['args'], '--unblind', '--said', selected['grant'],
                '--deliver', '--timeout', '10', *admit_options, succeeds=succeeds)
            if succeeds:
                process.wait(timeout=15)
                assert process.returncode == 0 and 'ERR:' not in log.read_text(), log.read_text()
                result = json.loads(admitted.splitlines()[-1])
                assert result == json.loads(log.read_text().splitlines()[-1])
                return selected['grant'], before, inspect(tmp_path, receiver, selected['grant'])
            assert 'current verified issued state' in admitted, admitted
            return selected['grant'], before, inspect(tmp_path, receiver, selected['grant'])
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


def inspect(tmp_path, side, said, *, current=False):
    args = ['--name', side['name'], '--base', side['base'], '--version', '2.0', '--said', said]
    return json.loads(kli(tmp_path, 'ipex', 'inspect', *args, *(['--current'] if current else [])).splitlines()[-1])


def snapshot(side):
    hby = state(side)
    rgy = Regery(hby, name=side['name'], base=side['base'])
    try:
        return [(label, bytes(key), bytes(value)) for owner in (hby.db, rgy.baser)
                for label, suber in vars(owner).items() if hasattr(suber, 'sdb')
                for key, value in owner.env.begin().cursor(suber.sdb)]
    finally:
        rgy.close()
        hby.close()


def test_selected_admitted_view_unblind_refresh_and_read_only_inspection(tmp_path, live_parties):
    issuer, holder = live_parties
    selected, body = issue(tmp_path, live_parties,
        data='{"d":"","shown":{"d":"","name":"Ada"},"secret":{"d":"","name":"hidden"}}')
    old = inspect(tmp_path, holder, selected['grant'])
    refused = kli(tmp_path, 'ipex', 'present', *issuer['args'], '--from-grant', selected['grant'],
        '--recipient', holder['pre'], '--deliver', succeeds=False)
    assert 'local recipient' in refused
    assert inspect(tmp_path, holder, selected['grant'], current=True)['current']['observations'][body.said]['state'] == 'issued'
    later = tmp_path / 'vacate.cesr'
    update(issuer, body, later)
    public = Parser(version=V2).parse(ims=bytearray(later.read_bytes()), processive=False)
    intake(holder, b''.join(serializeParsedSubstream(child) for child in public[:-1]))
    # Recipient knows a newer vacuous head; sender still carries the issued proof.
    presented, before, received = present(tmp_path, holder, issuer, selected['grant'], 'partial',
        '--disclose', 'a/shown/')
    assert received['deadline'] == before['deadline'] and received['terminal']
    assert not before['accepted'] and received['accepted']
    assert received['grant'] == before['grant']
    assert received['disclosure'][0]['raw_b64'] == before['disclosure'][0]['raw_b64']
    assert received['disclosure'][0]['evidence_b64'] != before['disclosure'][0]['evidence_b64']
    assert received['disclosure'][0]['body']['a']['shown']['name'] == 'Ada'
    assert isinstance(received['disclosure'][0]['body']['a']['secret'], str)
    assert inspect(tmp_path, holder, selected['grant']) == old
    # The issuer also holds the full same-SAID body, but must use its admitted partial.
    update(issuer, body, later, value='issued')
    intake(holder, later.read_bytes())
    rejected = kli(tmp_path, 'ipex', 'present', *issuer['args'], '--from-grant', presented,
        '--recipient', holder['pre'], '--deliver', succeeds=False)
    assert 'current verified issued state' in rejected
    original = inspect(tmp_path, issuer, presented)
    second, _, received2 = present(tmp_path, issuer, holder, presented, 'refreshed', '--refresh', '--derive')
    assert second != presented
    assert [node['raw_b64'] for node in received2['disclosure']] == [node['raw_b64'] for node in original['disclosure']]
    assert inspect(tmp_path, issuer, presented) == original
    cannot_widen = kli(tmp_path, 'ipex', 'present', *issuer['args'], '--from-grant', presented,
        '--recipient', holder['pre'], '--refresh', '--derive', '--disclose', 'a/secret/', '--deliver', succeeds=False)
    assert 'Invalid disclosure' in cannot_widen
    state_before = snapshot(issuer)
    assert inspect(tmp_path, issuer, presented)['observations'] == original['observations']
    assert inspect(tmp_path, issuer, presented, current=True)['current']['verdict']['verdict'] == 'unknown'
    assert snapshot(issuer) == state_before
    assert inspect(tmp_path, holder, selected['grant']) == old


def test_held_bound_refresh_and_invalid_revoked_refusal(tmp_path, live_parties):
    issuer, holder = live_parties
    selected, body = issue(tmp_path, live_parties)
    original = inspect(tmp_path, holder, selected['grant'])
    later, proof_file = tmp_path / 'bound-history.cesr', tmp_path / 'opening.cesr'
    event, proof = update(issuer, body, later, value='issued', bound=True)
    proof_file.write_bytes(proof.qb64b)
    intake(holder, later.read_bytes())
    # Explicit bound opening refreshes only the new outgoing presentation.
    _, _, accepted = present(tmp_path, holder, issuer, selected['grant'], 'bound',
        '--refresh', '--opening', str(proof_file))
    assert accepted['observations'][body.said]['state'] == 'issued'
    assert inspect(tmp_path, holder, selected['grant']) == original
    # Native Unblind preserves the carried bound proof and discovers revoked state.
    update(issuer, body, later, value='revoked')
    public = Parser(version=V2).parse(ims=bytearray(later.read_bytes()), processive=False)
    intake(holder, b''.join(serializeParsedSubstream(child) for child in public[:-1]))
    _, before, refused = present(tmp_path, holder, issuer, selected['grant'], 'revoked',
        '--refresh', '--opening', str(proof_file), succeeds=False)
    assert refused['accepted'] and refused['observations'][body.said]['state'] == 'revoked'
    assert refused['terminal'] is None and refused['deadline'] == before['deadline']
    proof_file.write_bytes(b'invalid')
    refused = kli(tmp_path, 'ipex', 'present', *holder['args'], '--from-grant', selected['grant'],
        '--recipient', issuer['pre'], '--refresh', '--opening', str(proof_file), '--deliver', succeeds=False)
    assert 'complete CESR state opening' in refused
    assert inspect(tmp_path, holder, selected['grant']) == original
