"""Native authoring through real KLI subprocesses and reopened encrypted stores."""
import json
import os
import subprocess
import sys
import uuid

import multicommand

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
        *args: Public KLI command tokens, including explicit native version selection.

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


def test_native_cli_authoring_reopen_and_private_export(tmp_path):
    """Reopen installed native authoring, verify actual public/private exports, and retain exact old issuance after revocation or custody-row loss.

    Parameters:
        tmp_path: Pytest-owned exclusive credential, public proof, private custody, and bound-evidence files.

    Returns:
        None. Assertions check the stated evidence boundary."""
    name = 'native-' + uuid.uuid4().hex
    with openHby(name=name, base='native-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name='issuer', version=Vrsn_2_0)
        prefix = issuer.pre

    created = invoke(name, 'vc', 'registry', 'incept', '--native', '--with-custody', '-a', 'issuer', '-r', 'authority')[0]
    assert created['accepted'] is True
    assert created['controller'] == prefix
    regid = created['registry']
    status = invoke(name, 'vc', 'registry', 'status', '--native', '-r', 'authority')[0]
    assert status['sn'] == 0
    assert status['head'] == regid
    assert invoke(name, 'vc', 'registry', 'list', '--native')[0]['registry'] == regid

    issued = invoke(name, 'vc', 'create', '--native', '-a', 'issuer', '-r', 'authority',
                    '--data', '{"name":"Alice"}')[0]
    assert issued['accepted'] is True
    assert issued['state'] == 'issued'
    credential = issued['credential']
    assert invoke(name, 'vc', 'list', '--native', '--issued', '-a', 'issuer')[0]['credential'] == credential

    public = tmp_path / 'credential.json'
    invoke(name, 'vc', 'export', '--native', '-a', 'issuer', '-r', 'authority',
           '--said', credential, '--output', str(public))
    assert SerderACDC(raw=public.read_bytes()).said == credential
    full = tmp_path / 'full.cesr'
    invoke(name, 'vc', 'export', '--native', '-a', 'issuer', '-r', 'authority',
           '--said', credential, '--full', '--output', str(full))
    parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(full.read_bytes()), processive=False)
    tels = [item for item in parsed if isinstance(item.serder, SerderACDC)
            and item.serder.ilk in ('rip', 'bup')]
    assert len(tels) == 2
    assert all(item.sscs for item in tels)
    assert [item.sscs[0][0].num for item in tels] == [1, 2]
    assert parsed[-1].serder.said == credential
    assert parsed[-1].bsqs[0][2].qb64 == credential
    private = tmp_path / 'custody.json'
    output = invoke(name, 'vc', 'export', '--native', '-a', 'issuer', '-r', 'authority',
                    '--custody', '--output', str(private))[0]
    assert 'salt' not in output
    assert private.stat().st_mode & 0o777 == 0o600
    custody = private.read_bytes()
    invoke(name, 'vc', 'import', '--native', '--custody', '--registry', regid,
           '--controller', prefix, '--discloser', prefix, '--file', str(private), '--passcode', PASSCODE)

    revoked = invoke(name, 'vc', 'revoke', '--native', '-a', 'issuer', '-r', 'authority', '--said', credential)[0]
    assert revoked['accepted'] is True
    assert revoked['state'] == 'revoked'
    assert invoke(name, 'vc', 'registry', 'status', '--native', '-r', 'authority')[0]['sn'] == 2
    # Retrying each command does not reissue, rotate a secret, or append a new event.
    repeated = invoke(name, 'vc', 'create', '--native', '-a', 'issuer', '-r', 'authority',
                      '--credential', '@' + str(public))[0]
    assert repeated['credential'] == credential
    assert repeated['state'] == 'unknown'  # retained issuance is not current blinded standing
    assert invoke(name, 'vc', 'revoke', '--native', '-a', 'issuer', '-r', 'authority',
                  '--said', credential)[0]['update'] == revoked['update']
    assert invoke(name, 'vc', 'registry', 'status', '--native', '-r', 'authority')[0]['sn'] == 2
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
    retained = invoke(name, 'vc', 'create', '--native', '-a', 'issuer', '-r', 'authority',
                      '--credential', '@' + str(public))[0]
    assert retained['update'] == issued['update']
    assert retained['state'] == 'unknown'
    assert invoke(name, 'vc', 'registry', 'status', '--native', '-r', 'authority')[0]['sn'] == 2


def test_native_option_is_explicit_and_legacy_remains_default():
    """Keep v1 command defaults while recognizing --v2 and --native as the same explicit native selection.

    Returns:
        None. Assertions check the stated evidence boundary."""
    parser = multicommand.create_parser(commands)
    for command in (['vc', 'registry', 'incept', '-a', 'issuer'],
                    ['vc', 'create', '-a', 'issuer', '--data', '{}'],
                    ['vc', 'revoke', '-a', 'issuer', '--said', 'example']):
        assert parser.parse_args(command + ['--name', 'example']).native is False
        assert parser.parse_args(command + ['--name', 'example', '--native']).native is True
        assert parser.parse_args(command + ['--name', 'example', '--v2']).native is True


def test_native_cli_refuses_unencrypted_custody_before_registry_creation():
    """Refuse requested private custody on an unencrypted Keeper before creating any named registry.

    Returns:
        None. Assertions check the stated evidence boundary."""
    name = 'unencrypted-' + uuid.uuid4().hex
    with openHby(name=name, base='native-cli-test', temp=False, version=Vrsn_2_0) as hby:
        hby.makeHab(name='issuer', version=Vrsn_2_0)
    result = command(name, 'vc', 'registry', 'incept', '--native', '--with-custody', '-a', 'issuer', '-r', 'blocked')
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
    reg = invoke(name, 'vc', 'registry', 'incept', '--native', '-a', 'issuer', '-r', 'public')[0]
    assert reg['custody'] == 'not requested'
    issued = invoke(name, 'vc', 'create', '--native', '--unblinded', '-a', 'issuer',
                    '-r', 'public', '--data', '{"name":"Public"}')[0]
    assert issued['state'] == 'issued'
    revoked = invoke(name, 'vc', 'revoke', '--native', '--unblinded', '-a', 'issuer',
                     '-r', 'public', '--said', issued['credential'])[0]
    assert revoked['state'] == 'revoked'
    assert invoke(name, 'vc', 'list', '--native', '--issued', '-a', 'issuer')[0]['state'] == 'revoked'
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


def test_native_cli_pending_witness_anchor_resumes_without_resealing():
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
        result = command(name, 'vc', 'registry', 'incept', '--native', '--with-custody', '-a', 'issuer',
                         '-r', 'pending', '--timeout', '0.2')
        assert 'ERR:' in result.stdout
        assert '"accepted": true' not in result.stdout
        status = invoke(name, 'vc', 'registry', 'status', '--native', '-r', 'pending')[0]
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
        accepted = invoke(name, 'vc', 'registry', 'incept', '--native', '--with-custody', '-a', 'issuer', '-r', 'pending')[0]
        assert accepted['registry'] == status['registry']
        assert accepted['accepted'] is True
        with openHby(name=name, base='native-cli-test', temp=False, bran=PASSCODE,
                     version=Vrsn_2_0) as hby:
            assert hby.habByName('issuer').kever.sn == sealing_sn


def test_native_cli_unblinded_issuance_then_blind_revocation(tmp_path):
    """Preserve one mixed public/blinded history and bind explicit native revocation without fabricating an issuance opening.

    Parameters:
        tmp_path: Pytest-owned exclusive credential, public proof, private custody, and bound-evidence files.

    Returns:
        None. Assertions check the stated evidence boundary."""
    name = 'mixed-' + uuid.uuid4().hex
    with openHby(name=name, base='native-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        hby.makeHab(name='issuer', version=Vrsn_2_0)
    invoke(name, 'vc', 'registry', 'incept', '--native', '--with-custody', '-a', 'issuer', '-r', 'mixed')
    issued = invoke(name, 'vc', 'create', '--native', '--unblinded', '-a', 'issuer', '-r', 'mixed',
                    '--data', '{"name":"Bob"}')[0]
    assert issued['state'] == 'issued'
    artifact = tmp_path / 'unblinded.cesr'
    invoke(name, 'vc', 'export', '--native', '-a', 'issuer', '-r', 'mixed', '--said', issued['credential'],
           '--full', '--output', str(artifact))
    parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(artifact.read_bytes()), processive=False)
    update = [item.serder for item in parsed if item.serder.ilk == 'upd'][0]
    assert update.sad['td'] == issued['credential']
    assert update.sad['ts'] == 'issued'
    assert parsed[-1].bsqs == []
    revoked = invoke(name, 'vc', 'revoke', '--native', '-a', 'issuer', '-r', 'mixed',
                     '--said', issued['credential'])[0]
    assert revoked['state'] == 'revoked'
    assert invoke(name, 'vc', 'list', '--native', '--issued', '-a', 'issuer')[0]['state'] == 'unknown'


def test_native_cli_bound_issue_revoke_and_historical_retry(tmp_path):
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
    invoke(name, 'vc', 'registry', 'incept', '--native', '--with-custody', '-a', 'issuer', '-r', 'bound')
    issued = invoke(name, 'vc', 'create', '--native', '-a', 'issuer', '-r', 'bound',
                    '--recipient', issuee, '--bound-event', first, '--data', '{"role":"bound"}')[0]
    assert issued['state'] == 'issued'
    artifact = tmp_path / 'bound.cesr'
    invoke(name, 'vc', 'export', '--native', '-a', 'issuer', '-r', 'bound',
           '--said', issued['credential'], '--full', '--output', str(artifact))
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
    granted = invoke(name, 'ipex', 'grant', '--native', '-a', 'issuer',
                     '--recipient', issuee, '--said', acdc.said)[0]
    assert granted['accepted'] is True
    refused = command(name, 'vc', 'revoke', '--native', '-a', 'issuer', '-r', 'bound',
                      '--said', acdc.said, '--bound-event', first)
    assert 'known current issuee event' in refused.stdout
    revoked = invoke(name, 'vc', 'revoke', '--native', '-a', 'issuer', '-r', 'bound',
                     '--said', acdc.said, '--bound-event', current)[0]
    assert revoked['state'] == 'revoked'
    repeated = invoke(name, 'vc', 'create', '--native', '-a', 'issuer', '-r', 'bound',
                      '--credential', '@' + str(credential))[0]
    assert repeated['update'] == issued['update']
    assert invoke(name, 'vc', 'revoke', '--native', '-a', 'issuer', '-r', 'bound',
                  '--said', acdc.said, '--bound-event', current)[0]['update'] == revoked['update']
    assert invoke(name, 'vc', 'registry', 'status', '--native', '-r', 'bound')[0]['sn'] == 2
