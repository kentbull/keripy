"""ACDC v2 authoring through real KLI subprocesses and reopened encrypted stores."""
import json
import os
import subprocess
import sys
import uuid

import multicommand
import pytest

from keri import Vrsn_2_0
from keri.acdc import Regery
from keri.app import openHby
from keri.app.credentialing import Wallet
from keri.cli import commands
from keri.core import Kevery, Parser, SerderACDC


PASSCODE = '0123456789abcdefghijk'


def command(name, *args):
    """Execute one bounded installed CLI process against a persistent fixture store.

    Args:
        name (str): Isolated test identity under native-cli-test.
        *args: Public KLI command tokens, including explicit ACDC v2 selection.

    Returns:
        CompletedProcess: Captured status/stdout/stderr for success or refusal checks.

    Raises:
        TimeoutExpired: The process exceeds twenty seconds. The public fixture
        passcode is supplied through the environment rather than command logging."""
    env = dict(os.environ, KLI_KEYSTORE_PASSCODE=PASSCODE)
    result = subprocess.run([sys.executable, '-m', 'keri.cli.kli', *args,
                             '--name', name, '--base', 'native-cli-test'],
                            capture_output=True, text=True, env=env, timeout=20)
    return result


def invoke(name, *args):
    """Require success from one installed command and decode its JSON transcript.

    Args:
        name (str): Existing isolated test identity.
        *args: Public KLI tokens forwarded unchanged to command.

    Returns:
        list[dict]: Every JSON-object output line, preserving emission order.

    Raises:
        AssertionError: Nonzero exit or KLI's textual ERR fallback reports refusal.
        TimeoutExpired, JSONDecodeError: Execution/output is not a valid success."""
    result = command(name, *args)
    assert result.returncode == 0, result.stderr
    assert 'ERR:' not in result.stdout, result.stdout
    return [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]


def test_acdc_v2_cli_authoring_reopen_and_private_export(tmp_path):
    """Reopen installed ACDC v2 authoring, verify actual public/private exports, and retain exact old issuance after revocation or custody-row loss.

    Parameters:
        tmp_path: Pytest-owned exclusive credential, public proof, private custody, and bound-evidence files.

    Returns:
        None. Assertions check the stated evidence boundary."""
    name = 'native-' + uuid.uuid4().hex
    with openHby(name=name, base='native-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name='issuer', version=Vrsn_2_0)
        prefix = issuer.pre

    created = invoke(name, 'vc', 'registry', 'incept', '--acdc-v2', '--with-custody', '-a', 'issuer', '-r', 'authority')[0]
    assert created['accepted'] is True
    assert created['controller'] == prefix
    regid = created['registry']
    status = invoke(name, 'vc', 'registry', 'status', '--acdc-v2', '-r', 'authority')[0]
    assert status['sn'] == 0
    assert status['head'] == regid
    assert invoke(name, 'vc', 'registry', 'list', '--acdc-v2')[0]['registry'] == regid

    issued = invoke(name, 'vc', 'create', '--acdc-v2', '-a', 'issuer', '-r', 'authority',
                    '--data', '{"name":"Alice"}')[0]
    assert issued['accepted'] is True
    assert issued['state'] == 'issued'
    credential = issued['credential']
    assert invoke(name, 'vc', 'list', '--acdc-v2', '--issued', '-a', 'issuer')[0]['credential'] == credential

    public = tmp_path / 'credential.json'
    invoke(name, 'vc', 'export', '--acdc-v2', '-a', 'issuer', '-r', 'authority',
           '--said', credential, '--output', str(public))
    assert SerderACDC(raw=public.read_bytes()).said == credential
    full = tmp_path / 'full.cesr'
    invoke(name, 'vc', 'export', '--acdc-v2', '-a', 'issuer', '-r', 'authority',
           '--said', credential, '--full', '--derive', '--output', str(full))
    parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(full.read_bytes()), processive=False)
    tels = [item for item in parsed if isinstance(item.serder, SerderACDC)
            and item.serder.ilk in ('rip', 'bup')]
    assert len(tels) == 2
    assert all(item.sscs for item in tels)
    assert [item.sscs[0][0].num for item in tels] == [1, 2]
    assert parsed[-1].serder.said == credential
    assert parsed[-1].bsqs[0][2].qb64 == credential
    private = tmp_path / 'custody.json'
    output = invoke(name, 'vc', 'export', '--acdc-v2', '-a', 'issuer', '-r', 'authority',
                    '--custody', '--output', str(private))[0]
    assert 'salt' not in output
    assert private.stat().st_mode & 0o777 == 0o600
    custody = private.read_bytes()
    invoke(name, 'vc', 'import', '--acdc-v2', '--custody', '--registry', regid,
           '--controller', prefix, '--discloser', prefix, '--file', str(private), '--passcode', PASSCODE)

    revoked = invoke(name, 'vc', 'revoke', '--acdc-v2', '-a', 'issuer', '-r', 'authority', '--said', credential)[0]
    assert revoked['accepted'] is True
    assert revoked['state'] == 'revoked'
    assert invoke(name, 'vc', 'registry', 'status', '--acdc-v2', '-r', 'authority')[0]['sn'] == 2
    # Retrying each command does not reissue, rotate a secret, or append a new event.
    repeated = invoke(name, 'vc', 'create', '--acdc-v2', '-a', 'issuer', '-r', 'authority',
                      '--credential', '@' + str(public))[0]
    assert repeated['credential'] == credential
    assert repeated['state'] == 'unknown'  # retained issuance is not current blinded standing
    assert invoke(name, 'vc', 'revoke', '--acdc-v2', '-a', 'issuer', '-r', 'authority',
                  '--said', credential)[0]['update'] == revoked['update']
    assert invoke(name, 'vc', 'registry', 'status', '--acdc-v2', '-r', 'authority')[0]['sn'] == 2
    assert private.read_bytes() == custody
    # Simulate loss of this test registry's custody row. Historical issuance
    # retry must neither regenerate a salt nor try to derive current standing.
    with openHby(name=name, base='native-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        rgy = Regery(hby=hby, name=name, base=hby.base)
        wallet = Wallet(hby, rgy)
        try:
            assert wallet.db.custody.rem((regid,))
        finally:
            wallet.close()
            rgy.close()
    retained = invoke(name, 'vc', 'create', '--acdc-v2', '-a', 'issuer', '-r', 'authority',
                      '--credential', '@' + str(public))[0]
    assert retained['update'] == issued['update']
    assert retained['state'] == 'unknown'
    assert invoke(name, 'vc', 'registry', 'status', '--acdc-v2', '-r', 'authority')[0]['sn'] == 2


def test_acdc_v2_option_is_explicit_and_v1_remains_default():
    """Select ACDC v2 explicitly and reject the removed experimental aliases.

    Returns:
        None. Assertions check the stated evidence boundary."""
    parser = multicommand.create_parser(commands)
    for command in (['vc', 'registry', 'incept', '-a', 'issuer'],
                    ['vc', 'registry', 'list'],
                    ['vc', 'registry', 'status', '-r', 'registry'],
                    ['vc', 'create', '-a', 'issuer', '--data', '{}'],
                    ['vc', 'revoke', '-a', 'issuer', '--said', 'example'],
                    ['vc', 'export', '-a', 'issuer'],
                    ['vc', 'import', '--file', 'example.cesr'],
                    ['vc', 'list'],
                    ['ipex', 'apply', '-a', 'issuer', '-r', 'recipient'],
                    ['ipex', 'offer', '-a', 'issuer', '-r', 'recipient', '-s', 'example'],
                    ['ipex', 'agree', '-a', 'issuer', '-s', 'example'],
                    ['ipex', 'grant', '-a', 'issuer', '-r', 'recipient', '-s', 'example'],
                    ['ipex', 'admit', '-a', 'issuer', '-s', 'example'],
                    ['ipex', 'spurn', '-a', 'issuer', '-s', 'example'],
                    ['ipex', 'receive', '-a', 'issuer']):
        assert parser.parse_args(command + ['--name', 'example']).acdc_v2 is False
        assert parser.parse_args(command + ['--name', 'example', '--acdc-v2']).acdc_v2 is True
        for old_option in ('--native', '--v2'):
            with pytest.raises(SystemExit):
                parser.parse_args(command + ['--name', 'example', old_option])


def test_acdc_v2_cli_refuses_unencrypted_custody_before_registry_creation():
    """Refuse requested private custody on an unencrypted Keeper before creating any named registry.

    Returns:
        None. Assertions check the stated evidence boundary."""
    name = 'unencrypted-' + uuid.uuid4().hex
    with openHby(name=name, base='native-cli-test', temp=False, version=Vrsn_2_0) as hby:
        hby.makeHab(name='issuer', version=Vrsn_2_0)
    result = command(name, 'vc', 'registry', 'incept', '--acdc-v2', '--with-custody', '-a', 'issuer', '-r', 'blocked')
    assert 'authenticated encrypted Keeper' in result.stdout
    assert '"accepted": true' not in result.stdout
    with openHby(name=name, base='native-cli-test', temp=False, version=Vrsn_2_0) as hby:
        rgy = Regery(hby=hby, name=name, base='native-cli-test')
        try:
            assert rgy.registryByName('blocked') is None
        finally:
            rgy.close()


def test_public_cli_lifecycle_never_provisions_or_encrypts_custody():
    """Run public inception/issue/revoke/list without salt records or implicit Keeper AEID migration despite an environment passcode.

    Returns:
        None. Assertions check the stated evidence boundary."""
    name = 'public-' + uuid.uuid4().hex
    with openHby(name=name, base='native-cli-test', temp=False, version=Vrsn_2_0) as hby:
        hby.makeHab(name='issuer', version=Vrsn_2_0)
        assert not hby.mgr.aeid
    reg = invoke(name, 'vc', 'registry', 'incept', '--acdc-v2', '-a', 'issuer', '-r', 'public')[0]
    assert reg['custody'] == 'not requested'
    issued = invoke(name, 'vc', 'create', '--acdc-v2', '--unblinded', '-a', 'issuer',
                    '-r', 'public', '--data', '{"name":"Public"}')[0]
    assert issued['state'] == 'issued'
    revoked = invoke(name, 'vc', 'revoke', '--acdc-v2', '--unblinded', '-a', 'issuer',
                     '-r', 'public', '--said', issued['credential'])[0]
    assert revoked['state'] == 'revoked'
    assert invoke(name, 'vc', 'list', '--acdc-v2', '--issued', '-a', 'issuer')[0]['state'] == 'revoked'
    with openHby(name=name, base='native-cli-test', temp=False, version=Vrsn_2_0) as hby:
        rgy = Regery(hby=hby, name=name, base=hby.base)
        wallet = Wallet(hby, rgy)
        try:
            assert not hby.mgr.aeid
            assert wallet.custody is None
            assert list(wallet.db.custody.getTopItemIter()) == []
            assert rgy.registryByName('public').sn == 2
        finally:
            wallet.close()
            rgy.close()


def test_acdc_v2_cli_pending_witness_anchor_resumes_without_resealing():
    """Keep missing real witness receipts pending, then resume the same staged registry/anchor without creating another sealing event.

    Returns:
        None. Assertions check the stated evidence boundary."""
    name = 'pending-' + uuid.uuid4().hex
    with openHby(name='witness-' + uuid.uuid4().hex, version=Vrsn_2_0) as whby:
        witness = whby.makeHab(name='witness', transferable=False, version=Vrsn_2_0)
        with openHby(name=name, base='native-cli-test', temp=False, bran=PASSCODE,
                     version=Vrsn_2_0) as hby:
            hby.makeHab(name='issuer', wits=[witness.pre], toad=1, version=Vrsn_2_0)
        # No witness endpoint has been configured; the normal receipt owner
        # cannot complete. The CLI must leave honest pending state, not success.
        result = command(name, 'vc', 'registry', 'incept', '--acdc-v2', '--with-custody', '-a', 'issuer',
                         '-r', 'pending', '--timeout', '0.2')
        assert 'ERR:' in result.stdout
        assert '"accepted": true' not in result.stdout
        status = invoke(name, 'vc', 'registry', 'status', '--acdc-v2', '-r', 'pending')[0]
        assert status['accepted'] is False
        assert status['pending']

        with openHby(name=name, base='native-cli-test', temp=False, bran=PASSCODE,
                     version=Vrsn_2_0) as hby:
            hab = hby.habByName('issuer')
            sealing_sn = hab.kever.sn
            parser = Parser(kvy=Kevery(db=whby.db, lax=False, local=True),
                            version=Vrsn_2_0, local=True)
            for raw in hby.db.clonePreIter(pre=hab.pre, version=Vrsn_2_0):
                parser.parse(ims=bytearray(raw))
            for sn in range(hab.kever.sn + 1):
                event, _, _ = hab.getOwnEvent(sn=sn)
                receipt = witness.witness(event, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
                hby.psr.parse(ims=bytearray(receipt))
        accepted = invoke(name, 'vc', 'registry', 'incept', '--acdc-v2', '--with-custody', '-a', 'issuer', '-r', 'pending')[0]
        assert accepted['registry'] == status['registry']
        assert accepted['accepted'] is True
        with openHby(name=name, base='native-cli-test', temp=False, bran=PASSCODE,
                     version=Vrsn_2_0) as hby:
            assert hby.habByName('issuer').kever.sn == sealing_sn


def test_acdc_v2_cli_unblinded_issuance_then_blind_revocation(tmp_path):
    """Preserve one mixed public/blinded history and bind explicit ACDC v2 revocation without fabricating an issuance opening.

    Parameters:
        tmp_path: Pytest-owned exclusive credential, public proof, private custody, and bound-evidence files.

    Returns:
        None. Assertions check the stated evidence boundary."""
    name = 'mixed-' + uuid.uuid4().hex
    with openHby(name=name, base='native-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        hby.makeHab(name='issuer', version=Vrsn_2_0)
    invoke(name, 'vc', 'registry', 'incept', '--acdc-v2', '--with-custody', '-a', 'issuer', '-r', 'mixed')
    issued = invoke(name, 'vc', 'create', '--acdc-v2', '--unblinded', '-a', 'issuer', '-r', 'mixed',
                    '--data', '{"name":"Bob"}')[0]
    assert issued['state'] == 'issued'
    artifact = tmp_path / 'unblinded.cesr'
    invoke(name, 'vc', 'export', '--acdc-v2', '-a', 'issuer', '-r', 'mixed', '--said', issued['credential'],
           '--full', '--output', str(artifact))
    parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(artifact.read_bytes()), processive=False)
    update = [item.serder for item in parsed if item.serder.ilk == 'upd'][0]
    assert update.sad['td'] == issued['credential']
    assert update.sad['ts'] == 'issued'
    assert parsed[-1].bsqs == []
    revoked = invoke(name, 'vc', 'revoke', '--acdc-v2', '-a', 'issuer', '-r', 'mixed',
                     '--said', issued['credential'])[0]
    assert revoked['state'] == 'revoked'
    assert invoke(name, 'vc', 'list', '--acdc-v2', '--issued', '-a', 'issuer')[0]['state'] == 'unknown'


def test_acdc_v2_cli_bound_issue_revoke_and_historical_retry(tmp_path):
    """Use real Issuee KEL coordinates for bound issuance/revocation and preserve the exact historical issuance on retry.

    Parameters:
        tmp_path: Pytest-owned exclusive credential, public proof, private custody, and bound-evidence files.

    Returns:
        None. Assertions check the stated evidence boundary."""
    name = 'bound-' + uuid.uuid4().hex
    with openHby(name=name, base='native-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        hby.makeHab(name='issuer', version=Vrsn_2_0)
        holder = hby.makeHab(name='holder', version=Vrsn_2_0)
        issuee, first = holder.pre, holder.kever.serder.said
    invoke(name, 'vc', 'registry', 'incept', '--acdc-v2', '--with-custody', '-a', 'issuer', '-r', 'bound')
    issued = invoke(name, 'vc', 'create', '--acdc-v2', '-a', 'issuer', '-r', 'bound',
                    '--recipient', issuee, '--bound-event', first, '--data', '{"role":"bound"}')[0]
    assert issued['state'] == 'issued'
    artifact = tmp_path / 'bound.cesr'
    invoke(name, 'vc', 'export', '--acdc-v2', '-a', 'issuer', '-r', 'bound',
           '--said', issued['credential'], '--full', '--derive', '--output', str(artifact))
    parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(artifact.read_bytes()), processive=False)
    assert parsed[-1].bsss
    acdc = parsed[-1].serder
    credential = tmp_path / 'credential.json'
    credential.write_bytes(acdc.raw)
    with openHby(name=name, base='native-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        holder = hby.habByName('holder')
        holder.interact(version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        current = holder.kever.serder.said
    granted = invoke(name, 'ipex', 'grant', '--acdc-v2', '-a', 'issuer',
                     '--recipient', issuee, '--said', acdc.said, '--derive')[0]
    assert granted['accepted'] is True
    refused = command(name, 'vc', 'revoke', '--acdc-v2', '-a', 'issuer', '-r', 'bound',
                      '--said', acdc.said, '--bound-event', first)
    assert 'known current issuee event' in refused.stdout
    revoked = invoke(name, 'vc', 'revoke', '--acdc-v2', '-a', 'issuer', '-r', 'bound',
                     '--said', acdc.said, '--bound-event', current)[0]
    assert revoked['state'] == 'revoked'
    repeated = invoke(name, 'vc', 'create', '--acdc-v2', '-a', 'issuer', '-r', 'bound',
                      '--credential', '@' + str(credential))[0]
    assert repeated['update'] == issued['update']
    assert invoke(name, 'vc', 'revoke', '--acdc-v2', '-a', 'issuer', '-r', 'bound',
                  '--said', acdc.said, '--bound-event', current)[0]['update'] == revoked['update']
    assert invoke(name, 'vc', 'registry', 'status', '--acdc-v2', '-r', 'bound')[0]['sn'] == 2
    historical = tmp_path / 'historical.cesr'
    invoke(name, 'vc', 'export', '--acdc-v2', '-a', 'issuer', '-r', 'bound',
           '--said', acdc.said, '--full', '--derive', '--output', str(historical))
    old = Parser(version=Vrsn_2_0).parse(ims=bytearray(historical.read_bytes()), processive=False)[-1]
    # Compare wire primitives, not identities of independently parsed objects.
    assert [[field.qb64 for field in proof] for proof in old.bsss] == [
        [field.qb64 for field in proof] for proof in parsed[-1].bsss]


def test_full_export_requires_explicit_verified_opening(tmp_path):
    """Reject wrong supplied/derived proofs before output; valid held proof ignores custody.

    tmp_path owns the exclusive artifacts. A deliberately replaced test salt is
    structurally valid and correctly encrypted, but cannot open the old issuance.
    This exercises real installed commands and core vet, not mocked verification.
    """
    from keri.core import Blinder, Salter

    name = 'export-proof-' + uuid.uuid4().hex
    with openHby(name=name, base='native-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        prefix = hby.makeHab(name='issuer', version=Vrsn_2_0).pre
    regid = invoke(name, 'vc', 'registry', 'incept', '--acdc-v2', '--with-custody',
                   '-a', 'issuer', '-r', 'r')[0]['registry']
    said = invoke(name, 'vc', 'create', '--acdc-v2', '-a', 'issuer', '-r', 'r',
                  '--data', '{"status":"valid"}')[0]['credential']
    full = ['vc', 'export', '--acdc-v2', '-a', 'issuer', '-r', 'r', '-s', said, '--full']
    missing = tmp_path / 'missing.cesr'
    refusal = command(name, *full, '--output', str(missing))
    assert refusal.returncode != 0 and 'issuance opening unavailable' in refusal.stdout + refusal.stderr
    assert not missing.exists()

    valid = tmp_path / 'opening.cesr'
    invoke(name, 'vc', 'registry', 'opening', '-r', 'r', '-s', said,
           '--ordinal', '1', '--output', str(valid))
    bad = tmp_path / 'wrong-opening.cesr'
    bad.write_bytes(Blinder.blind(salt=Salter().qb64, sn=1, acdc=said, state='issued').qb64b)
    wrong = tmp_path / 'wrong.cesr'
    refusal = command(name, *full, '--opening', str(bad), '--output', str(wrong))
    assert refusal.returncode != 0
    assert not wrong.exists()

    # Import a well-formed wrong salt after explicitly losing only this test's
    # row. Possession, encryption and bindings cannot replace event verification.
    private = tmp_path / 'salt.json'
    invoke(name, 'vc', 'export', '--acdc-v2', '-a', 'issuer', '-r', 'r',
           '--custody', '--output', str(private))
    payload = json.loads(private.read_text())
    payload['salt'] = Salter().qb64
    private.write_text(json.dumps(payload))
    with openHby(name=name, base='native-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        rgy = Regery(hby=hby, name=name, base=hby.base)
        wallet = Wallet(hby, rgy)
        try:
            assert wallet.db.custody.rem((regid,))
        finally:
            wallet.close()
            rgy.close()
    invoke(name, 'vc', 'import', '--acdc-v2', '--custody', '--file', str(private),
           '--registry', regid, '--controller', prefix, '--discloser', prefix)
    wrongSalt = tmp_path / 'wrong-salt.cesr'
    refusal = command(name, *full, '--derive', '--output', str(wrongSalt))
    assert refusal.returncode != 0
    assert not wrongSalt.exists()
    with openHby(name=name, base='native-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        rgy = Regery(hby=hby, name=name, base=hby.base)
        wallet = Wallet(hby, rgy)
        try:
            row = wallet.db.custody.get((regid,))
            row.cipher = 'invalid-ciphertext'
            wallet.db.custody.pin((regid,), row)
        finally:
            wallet.close()
            rgy.close()
    # Even unusable custody cannot disable export of a possessed valid proof.
    supplied = tmp_path / 'supplied.cesr'
    invoke(name, *full, '--opening', str(valid), '--output', str(supplied))
    parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(supplied.read_bytes()), processive=False)
    assert parsed[-1].serder.said == said and parsed[-1].bsqs
    public = tmp_path / 'public.cesr'
    invoke(name, 'vc', 'export', '--acdc-v2', '-a', 'issuer', '-r', 'r', '-s', said,
           '--kels', '--tels', '--output', str(public))
    assert public.stat().st_size > 0
    # Exclusive creation still protects an existing artifact, even on retries.
    original = supplied.read_bytes()
    assert command(name, *full, '--opening', str(valid), '--output', str(supplied)).returncode != 0
    assert supplied.read_bytes() == original


@pytest.mark.parametrize('tokens, message', [
    (['vc', 'export', '-a', 'issuer', '--custody'], 'require --acdc-v2'),
    (['vc', 'export', '-a', 'issuer', '--derive'], 'require --acdc-v2'),
    (['vc', 'export', '-a', 'issuer', '--opening', 'absent'], 'require --acdc-v2'),
    *[(['vc', 'export', '--acdc-v2', '-a', 'issuer', '--custody', *flag], 'cannot be combined')
      for flag in (['--full'], ['--kels'], ['--tels'], ['--chains'], ['--files'],
                   ['--said', 'credential'], ['--derive'], ['--opening', 'absent'])],
    (['vc', 'export', '--acdc-v2', '-a', 'issuer', '--derive'], 'require --acdc-v2 --full'),
    (['vc', 'export', '--acdc-v2', '-a', 'issuer', '--opening', 'absent'], 'require --acdc-v2 --full'),
    (['vc', 'export', '--acdc-v2', '-a', 'issuer', '--files'], 'uses --output'),
    *[(['vc', 'import', '--file', 'absent', *flag], 'require --acdc-v2 --custody')
      for flag in (['--custody'], ['--rewrap'], ['--registry', 'r'],
                   ['--controller', 'i'], ['--discloser', 'h'])],
    (['vc', 'import', '--acdc-v2', '--file', 'absent', '--said', 'credential'], 'not credentials'),
])
def test_provisioning_options_fail_before_store_or_file_access(tokens, message):
    """Reject incompatible modes before touching nonexistent identity/file inputs.

    tokens selects a real parser/handler path; message identifies its boundary.
    No database or output is provisioned by this parameterized refusal test.
    """
    from keri.kering import ConfigurationError

    args = multicommand.create_parser(commands).parse_args([*tokens, '--name', 'does-not-exist'])
    with pytest.raises(ConfigurationError, match=message):
        args.handler(args)
