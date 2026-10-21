"""Operator commands expose public evidence without lifecycle fixture writes."""
import json
import os
import subprocess
import sys
import socket
import time
import uuid
from urllib.request import urlopen

from keri.core import Blinder, BlindState


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


def test_public_kel_and_explicit_blind_commands(tmp_path):
    """Exercise public evidence and explicit opening/custody capabilities through installed KLI.

    Args:
        tmp_path (Path): Exclusive bootstrap, KEL, proof, and private fixture-transfer
        files owned by pytest; existing files must not be silently overwritten.

    Returns:
        None. Assertions cover signed endpoint/KEL import, accepted native issuance,
        distinct later openings, real holder admission/inspection, absent derivation
        capability, wrong-recipient import, and wrong-credential/state refusals.
        Successful per-event opening output contains no registry salt."""
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
    registry = invoke(alice, 'vc', 'registry', 'incept', '--v2', '-a', 'self', '-r', 'r',
        '--with-custody', '--discloser', bob_aid)[0]['registry']
    issued = invoke(alice, 'vc', 'create', '--v2', '-a', 'self', '-r', 'r', '--data', '{"status":"authorized"}')[0]
    first = tmp_path / 'first.opening'
    initial = invoke(alice, 'vc', 'registry', 'opening', '-r', 'r', '-s', issued['credential'],
        '--ordinal', '1', '--output', str(first))[0]
    assert initial['event'] == issued['update']
    next_event = invoke(alice, 'vc', 'registry', 'advance', '-a', 'self', '-r', 'r',
        '-s', issued['credential'])[0]
    assert next_event['accepted'] and next_event['sn'] == 2
    current = tmp_path / 'current.opening'
    latest = invoke(alice, 'vc', 'registry', 'opening', '-r', 'r', '-s', issued['credential'],
        '--ordinal', '2', '--output', str(current))[0]
    assert latest['event'] == next_event['update'] and latest['opening'] != initial['opening']
    proof = Blinder(clan=BlindState, qb64b=current.read_bytes())
    assert proof.acdc == issued['credential'] and proof.state == 'issued'
    assert b'salt' not in current.read_bytes()
    bad = tmp_path / 'wrong-state.opening'
    invoke(alice, 'vc', 'registry', 'opening', '-r', 'r', '-s', issued['credential'],
        '--ordinal', '2', '--state', 'revoked', '--output', str(bad), okay=False)
    assert not bad.exists()
    full, grant = tmp_path / 'full.cesr', tmp_path / 'grant.cesr'
    invoke(alice, 'vc', 'export', '--v2', '-a', 'self', '-r', 'r',
        '-s', issued['credential'], '--full', '--output', str(full))
    granted = invoke(alice, 'ipex', 'grant', '--v2', '-a', 'self', '-r', bob_aid,
        '-s', issued['credential'], '--output', str(grant))[0]
    incoming = tmp_path / 'incoming.cesr'
    incoming.write_bytes(full.read_bytes() + grant.read_bytes())
    invoke(bob, 'ipex', 'admit', '--v2', '-a', 'self', '-s', granted['exchange'], '--input', str(incoming))
    retained = invoke(bob, 'ipex', 'inspect', '-s', granted['exchange'])[0]
    assert retained['accepted'] and retained['sender'] == aid and retained['recipient'] == bob_aid
    assert retained['nodes'][0]['credential'] == issued['credential']
    held_opening = tmp_path / 'held.opening'
    opening_args = ('vc', 'registry', 'opening', '--registry', registry,
        '--from-grant', granted['exchange'], '-s', issued['credential'], '--ordinal', '2',
        '--output', str(held_opening))
    invoke(bob, *opening_args, okay=False)
    assert not held_opening.exists()
    private = tmp_path / 'custody.json'
    invoke(alice, 'vc', 'export', '--v2', '-a', 'self', '-r', 'r', '--custody', '--output', str(private))
    invoke(bob, 'vc', 'import', '--v2', '--custody', '--registry', registry,
        '--controller', aid, '--discloser', aid, '--file', str(private),
        '--passcode', '0123456789abcdefghijk', okay=False)
    invoke(bob, 'vc', 'import', '--v2', '--custody', '--registry', registry,
        '--controller', aid, '--discloser', bob_aid, '--file', str(private))
    derived = invoke(bob, *opening_args)[0]
    assert derived['opening'] == latest['opening'] and held_opening.read_bytes() == current.read_bytes()
    wrong_credential = tmp_path / 'wrong-credential.opening'
    invoke(bob, 'vc', 'registry', 'opening', '--registry', registry,
        '--from-grant', granted['exchange'], '-s', initial['opening'], '--ordinal', '2',
        '--output', str(wrong_credential), okay=False)
    assert not wrong_credential.exists()


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


def test_signed_publication_and_independent_observer_query(tmp_path):
    """Publish signed evidence and acquire a fresh independently verified observer result.

    Args:
        tmp_path (Path): Exclusive bootstrap, exported proof, inception options, and
        service diagnostic files owned by pytest.

    Returns:
        None. Actual installed registrar/observer processes and signed KLI commands
        must converge on the expected accepted head and fresh query proof. Readiness
        and query polling are bounded; failures print diagnostics, and finally
        terminates both processes before closing their logs."""
    suffix = uuid.uuid4().hex
    names = {role: role + suffix for role in ('issuer', 'registrar', 'observer')}
    options = tmp_path / 'incept.json'
    options.write_text(json.dumps(dict(transferable=True, wits=[], toad=0,
        icount=1, isith='1', ncount=1, nsith='1')))
    aids, bootstrap = {}, bytearray()
    for role, name in names.items():
        invoke(name, 'init', '--version', '2.0')
        invoke(name, 'incept', '-a', 'self', '--version', '2.0', '--file', str(options))
        path = tmp_path / (role + '.cesr')
        aids[role] = invoke(name, 'kel', 'export', '-a', 'self', '--output', str(path))[0]['aid']
        bootstrap.extend(path.read_bytes())
    boot = tmp_path / 'bootstrap.cesr'
    boot.write_bytes(bootstrap)
    registry = invoke(names['issuer'], 'vc', 'registry', 'incept', '--v2', '-a', 'self',
                      '-r', 'r', '--with-custody')[0]['registry']
    issued = invoke(names['issuer'], 'vc', 'create', '--v2', '-a', 'self', '-r', 'r',
                    '--data', '{"status":"authorized"}')[0]
    public = tmp_path / 'public.cesr'
    invoke(names['issuer'], 'vc', 'export', '--v2', '-a', 'self', '-r', 'r',
        '-s', issued['credential'], '--kels', '--tels', '--output', str(public))
    ports = []
    for _ in range(2):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            ports.append(sock.getsockname()[1])
    urls = [f'http://127.0.0.1:{port}/' for port in ports]
    processes, logs = [], []
    try:
        commands = [
            ('registrar', ['registrar', 'start', '--publisher', aids['issuer'],
                '--observer', aids['observer'], '--kel', str(boot), '--port', str(ports[0]), '--no-prompt']),
            ('observer', ['observer', 'start', '-a', 'self', '--registrar', urls[0],
                '--reader', aids['issuer'], '--kel', str(boot), '--interval', '0.1',
                '--maximum-age', '2', '--timeout', '1', '--port', str(ports[1]), '--no-prompt'])]
        for index, (role, command) in enumerate(commands):
            log = (tmp_path / (role + '.log')).open('w+')
            logs.append(log)
            process = subprocess.Popen([sys.executable, '-m', 'keri.cli.kli', *command,
                '--name', names[role], '--base', 'public-evidence-cli'], stdout=log, stderr=log,
                env=dict(os.environ, KLI_KEYSTORE_PASSCODE='0123456789abcdefghijk'))
            processes.append(process)
            deadline = time.monotonic() + 10
            while True:
                try:
                    if urlopen(urls[index] + 'health', timeout=0.2).status == 200:
                        break
                except OSError:
                    pass
                assert process.poll() is None and time.monotonic() < deadline
                time.sleep(0.05)
        result = invoke(names['issuer'], 'vc', 'registry', 'publish', '-a', 'self',
            '--endpoint', urls[0] + 'ingest', '--file', str(public))[0]
        assert result['accepted'] and result['result']['heads'][registry] == issued['update']
        output = tmp_path / 'observed.cesr'
        deadline = time.monotonic() + 10
        while True:
            try:
                observed = invoke(names['issuer'], 'vc', 'registry', 'query', '-a', 'self',
                    '--endpoint', urls[1], '--registry', registry, '--output', str(output))[0]
                break
            except AssertionError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
        assert observed['accepted'] and observed['fresh'] and observed['head'] == issued['update']
        assert output.read_bytes()
    except BaseException:
        for log in logs:
            log.flush()
            log.seek(0)
            print(log.read())
        raise
    finally:
        for process in reversed(processes):
            process.terminate()
            process.wait(timeout=5)
        for log in logs:
            log.close()
