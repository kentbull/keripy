"""Operator commands expose public evidence without lifecycle fixture writes."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid
from types import SimpleNamespace

import pytest

from keri.acdc import messaging
from keri.app.credentialing import DerivedUpdate
from keri.cli.common import acdc_v2
from keri.core import Blinder, BlindState, BoundState


def invoke(name, *arguments, okay=True):
    """Execute one isolated installed KLI command and inspect its actual result.

    Args:
        name (str): Unique persistent identity under the public-evidence-cli base.
        *arguments: Public CLI tokens, including the explicit operation/version.
        okay (bool): True requires success; False requires a real refusal.

    Returns:
        list[dict] | str: Parsed JSON output lines on success, otherwise combined
        stdout/stderr from the expected failing command.

    Raises:
        AssertionError: Exit status/textual ERR does not match the expected outcome.
        TimeoutExpired: The command exceeds twenty seconds.

    The fixture environment supplies a public test passcode. Commands must preserve
    an existing unencrypted Keeper despite that variable; the dedicated test checks
    this instead of assuming the environment grants migration permission."""
    env = dict(os.environ, KLI_KEYSTORE_PASSCODE='0123456789abcdefghijk')
    command = [sys.executable, '-m', 'keri.cli.kli', *arguments,
               '--name', name, '--base', 'public-evidence-cli']
    result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=20)
    failed = result.returncode != 0 or 'ERR:' in result.stdout
    if not okay:
        assert failed, result.stdout + result.stderr
        return result.stdout + result.stderr
    assert not failed, result.stdout + result.stderr
    return [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]


@contextmanager
def _owned_wallet(name):
    """Reopen all five real owners under the parent/child test store root."""
    args = SimpleNamespace(name=name, base='public-evidence-cli',
                           bran='0123456789abcdefghijk')
    with acdc_v2.opened(args, custody=True) as owners:
        hby, rgy, wallet = owners
        root = Path(os.environ['KERIPY_TEST_STORE_ROOT'])
        assert all(Path(owner.path).is_relative_to(root) for owner in
                   (hby.ks, hby.db, hby.cf, rgy.baser, wallet.db))
        yield owners


def _public_blind_cli_case(tmp_path, *, bound=False):
    """Create actual signed public evidence and an admitted two-actor Grant."""
    alice, bob = 'alice-' + uuid.uuid4().hex, 'bob-' + uuid.uuid4().hex
    options = tmp_path / 'incept.json'
    options.write_text(json.dumps(dict(transferable=True, wits=[], toad=0,
        icount=1, isith='1', ncount=1, nsith='1')))
    for name in (alice, bob):
        invoke(name, 'init', '--version', '2.0')
        invoke(name, 'incept', '--alias', 'self', '--version', '2.0', '--file', str(options))
    # Endpoint creation and export are real signed protocol operations too.
    invoke(alice, 'location', 'add', '-a', 'self', '--url', 'http://127.0.0.1:19999/', '--version', '2.0')
    aid_output = subprocess.run([sys.executable, '-m', 'keri.cli.kli', 'aid',
        '--name', alice, '--base', 'public-evidence-cli', '-a', 'self'],
        env=dict(os.environ, KLI_KEYSTORE_PASSCODE='0123456789abcdefghijk'),
        capture_output=True, text=True, timeout=20)
    assert aid_output.returncode == 0, aid_output.stdout + aid_output.stderr
    aid = aid_output.stdout.strip().splitlines()[-1]
    invoke(alice, 'ends', 'add', '-a', 'self', '--role', 'controller', '--eid', aid, '--version', '2.0')
    kel = tmp_path / 'alice.cesr'
    exported = invoke(alice, 'kel', 'export', '-a', 'self', '--ends', '--output', str(kel))[0]
    assert exported['aid'] == aid
    assert b'/loc/scheme' in kel.read_bytes() and b'/end/role/add' in kel.read_bytes()
    assert invoke(bob, 'kel', 'import', '--file', str(kel))[0]['accepted']
    assert invoke(bob, 'kel', 'import', '--file', str(kel))[0]['accepted']
    assert 'File exists' in invoke(alice, 'kel', 'export', '-a', 'self', '--output', str(kel), okay=False)
    bob_kel = tmp_path / 'bob.cesr'
    bob_aid = invoke(bob, 'kel', 'export', '-a', 'self', '--output', str(bob_kel))[0]['aid']
    invoke(alice, 'kel', 'import', '--file', str(bob_kel))
    registry = invoke(alice, 'vc', 'registry', 'incept', '--acdc-v2', '-a', 'self', '-r', 'r',
        '--with-custody', '--discloser', bob_aid)[0]['registry']
    with _owned_wallet(alice) as (hby, _, _):
        bound_args = ['--bound-event', hby.kevers[bob_aid].serder.said] if bound else []
    recipient = ['--recipient', bob_aid] if bound else []
    issued = invoke(alice, 'vc', 'create', '--acdc-v2', '-a', 'self', '-r', 'r',
        *recipient, *bound_args, '--data', '{"status":"authorized"}')[0]
    first = tmp_path / 'first.opening'
    initial = invoke(alice, 'vc', 'registry', 'opening', '-r', 'r', '-s', issued['credential'],
        '--ordinal', '1', *bound_args, '--output', str(first))[0]
    assert initial['event'] == issued['update']
    next_event = invoke(alice, 'vc', 'registry', 'advance', '-a', 'self', '-r', 'r',
        '-s', issued['credential'], *bound_args)[0]
    assert next_event['accepted'] and next_event['sn'] == 2
    current = tmp_path / 'current.opening'
    latest = invoke(alice, 'vc', 'registry', 'opening', '-r', 'r', '-s', issued['credential'],
        '--ordinal', '2', *bound_args, '--output', str(current))[0]
    assert latest['event'] == next_event['update'] and latest['opening'] != initial['opening']
    proof = Blinder(clan=BoundState if bound else BlindState, qb64b=current.read_bytes())
    assert proof.acdc == issued['credential'] and proof.state == 'issued'
    assert b'salt' not in current.read_bytes()
    bad = tmp_path / 'wrong-state.opening'
    invoke(alice, 'vc', 'registry', 'opening', '-r', 'r', '-s', issued['credential'],
        '--ordinal', '2', '--state', 'revoked', '--output', str(bad), okay=False)
    assert not bad.exists()
    full, grant = tmp_path / 'full.cesr', tmp_path / 'grant.cesr'
    disclosure = ['--opening', str(current)] if bound else ['--derive']
    invoke(alice, 'vc', 'export', '--acdc-v2', '-a', 'self', '-r', 'r',
        '-s', issued['credential'], '--full', '--derive', '--output', str(full))
    granted = invoke(alice, 'ipex', 'grant', '--acdc-v2', *disclosure, '-a', 'self', '-r', bob_aid,
        '-s', issued['credential'], '--output', str(grant))[0]
    incoming = tmp_path / 'incoming.cesr'
    incoming.write_bytes(full.read_bytes() + grant.read_bytes())
    invoke(bob, 'ipex', 'admit', '--acdc-v2', '-a', 'self', '-s', granted['exchange'], '--input', str(incoming))
    retained = invoke(bob, 'ipex', 'inspect', '-s', granted['exchange'])[0]
    assert retained['accepted'] and retained['sender'] == aid and retained['recipient'] == bob_aid
    assert retained['nodes'][0]['credential'] == issued['credential']
    held_opening = tmp_path / 'held.opening'
    opening_args = ('vc', 'registry', 'opening', '--registry', registry,
        '--from-grant', granted['exchange'], '-s', issued['credential'], '--ordinal', '2',
        '--output', str(held_opening))
    return SimpleNamespace(alice=alice, bob=bob, aid=aid, bob_aid=bob_aid, registry=registry,
                           granted=granted, issued=issued, next_event=next_event, bound_args=bound_args,
                           proof=proof,
                           initial=initial, latest=latest, current=current,
                           held_opening=held_opening, opening_args=opening_args)


@pytest.mark.parametrize('bound', [False, True])
def test_public_kel_and_explicit_blind_commands(tmp_path, bound):
    """Retain exact new/staged derivations across reopen and a public successor."""
    case = _public_blind_cli_case(tmp_path, bound=bound)
    bob, registry, initial, granted = case.bob, case.registry, case.initial, case.granted
    opening_args, held_opening = case.opening_args, case.held_opening
    invoke(bob, *opening_args, okay=False)
    assert not held_opening.exists()
    wrong_credential = tmp_path / 'wrong-credential.opening'
    refusal = invoke(bob, 'vc', 'registry', 'opening', '--registry', registry,
        '--from-grant', granted['exchange'], '-s', initial['opening'], '--ordinal', '2',
        '--output', str(wrong_credential), okay=False)
    assert 'admitted grant does not bind the requested credential' in refusal
    assert not wrong_credential.exists()

    # Each CLI invocation and each context closes Keeper/Baser/Configer/registry/wallet.
    with _owned_wallet(case.alice) as (hby, rgy, wallet):
        reg = rgy.registryByName('r')
        acdc = wallet.issuedCredential(case.issued['credential'])
        parameters = wallet.boundEvent(acdc, case.bound_args[1]) if bound else {}
        head = reg.store.headEvent(case.registry)
        coordinates = dict(bn=case.proof.bsn, bd=case.proof.bd) if bound else {}
        assert wallet.db.derivations.get((head.said,)) == DerivedUpdate(acdc.said, 'issued', coordinates)
        assert wallet.publicOpening(head) is None
        # Ordinary unanchored staging models interruption before coordinates were retained.
        proof = wallet.custody.derive(case.registry, 3, acdc.said, 'issued', **parameters)
        staged = messaging.blindate(case.registry, head.said, proof.said, sn=3)
        reg.processEvent(staged)
        assert wallet.db.derivations.get((staged.said,)) is None
    resumed = invoke(case.alice, 'vc', 'registry', 'advance', '-a', 'self', '-r', 'r',
                     '-s', acdc.said, *case.bound_args)[0]
    assert resumed['accepted'] and resumed['update'] == staged.said and resumed['sn'] == 3
    with _owned_wallet(case.alice) as (_, rgy, wallet):
        reg = rgy.registryByName('r')
        assert reg.store.headEvent(case.registry).raw == staged.raw
        assert wallet.db.derivations.get((staged.said,)) == DerivedUpdate(acdc.said, 'issued', coordinates)
        assert wallet.publicOpening(staged) is None
    public = invoke(case.alice, 'vc', 'create', '--acdc-v2', '--public', '-a', 'self',
                    '-r', 'r', '--data', '{"status":"public successor"}')[0]
    with _owned_wallet(case.alice) as (_, rgy, wallet):
        reg = rgy.registryByName('r')
        head = reg.store.headEvent(case.registry)
        assert head.sn == 4 and head.said == public['update']
        assert reg.store.seqEvent(case.registry, 2).said == case.next_event['update']
        assert reg.store.seqEvent(case.registry, 3).raw == staged.raw
        assert wallet.publicOpening(head).acdc == public['credential']

    if not bound:
        # A rival pending state remains intact; Advance must not retain its coordinates.
        conflict_reg = invoke(case.alice, 'vc', 'registry', 'incept', '--acdc-v2',
            '--with-custody', '-a', 'self', '-r', 'conflict')[0]['registry']
        issued = invoke(case.alice, 'vc', 'create', '--acdc-v2', '-a', 'self', '-r', 'conflict',
                        '--data', '{"status":"conflicting retry"}')[0]
        with _owned_wallet(case.alice) as (hby, rgy, wallet):
            reg = rgy.registryByName('conflict')
            head = reg.store.headEvent(conflict_reg)
            rival = wallet.custody.derive(conflict_reg, 2, issued['credential'], 'revoked')
            pending = messaging.blindate(conflict_reg, head.said, rival.said, sn=2)
            reg.processEvent(pending)
            kel_head = hby.habByName('self').kever.serder.said
        refusal = invoke(case.alice, 'vc', 'registry', 'advance', '-a', 'self', '-r', 'conflict',
                         '-s', issued['credential'], okay=False)
        assert 'registry has different pending authoring work' in refusal
        with _owned_wallet(case.alice) as (hby, rgy, wallet):
            assert rgy.store.headEvent(conflict_reg).said == head.said
            assert rgy.store.event(pending.said).raw == pending.raw
            assert wallet.db.derivations.get((pending.said,)) is None
            assert hby.habByName('self').kever.serder.said == kel_head


@pytest.mark.skipif(os.name != 'posix', reason='protected plaintext custody handoff requires POSIX')
def test_holder_opening_after_protected_custody_handoff(tmp_path):
    """Only the designated recipient can import protected custody and derive the same opening."""
    case = _public_blind_cli_case(tmp_path)
    alice, bob, aid, bob_aid = case.alice, case.bob, case.aid, case.bob_aid
    registry, latest, current = case.registry, case.latest, case.current
    opening_args, held_opening = case.opening_args, case.held_opening
    private = tmp_path / 'custody.json'
    invoke(alice, 'vc', 'export', '--acdc-v2', '-a', 'self', '-r', 'r', '--custody', '--output', str(private))
    invoke(bob, 'vc', 'import', '--acdc-v2', '--custody', '--registry', registry,
        '--controller', aid, '--discloser', aid, '--file', str(private),
        '--passcode', '0123456789abcdefghijk', okay=False)
    invoke(bob, 'vc', 'import', '--acdc-v2', '--custody', '--registry', registry,
        '--controller', aid, '--discloser', bob_aid, '--file', str(private))
    derived = invoke(bob, *opening_args)[0]
    assert derived['opening'] == latest['opening'] and held_opening.read_bytes() == current.read_bytes()


def test_unencrypted_kel_operations_ignore_environment_passcode(tmp_path):
    """Preserve an unencrypted Keeper across public KEL export/import CLI invocations.

    Args:
        tmp_path (Path): Exclusive public KEL export file owned by pytest.

    Returns:
        None. Reopens the actual Keeper and checks its AEID remains empty despite
        the invoking process having the fixture environment passcode."""
    from keri import Vrsn_2_0
    from keri.app import openHby, Keeper
    name = 'plain-' + uuid.uuid4().hex
    with openHby(name=name, base='public-evidence-cli', temp=False, version=Vrsn_2_0) as hby:
        hby.makeHab(name='self', version=Vrsn_2_0)
    output = tmp_path / 'public.cesr'
    invoke(name, 'kel', 'export', '-a', 'self', '--output', str(output))
    invoke(name, 'kel', 'import', '--file', str(output))
    keeper = Keeper(name=name, base='public-evidence-cli', reopen=True)
    try:
        assert keeper.gbls.get('aeid') == ''
    finally:
        keeper.close()
