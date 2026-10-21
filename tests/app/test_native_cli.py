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
    env = dict(os.environ, KLI_KEYSTORE_PASSCODE=PASSCODE)
    result = subprocess.run([sys.executable, '-m', 'keri.cli.kli', *args,
                             '--name', name, '--base', 'native-cli-test'],
                            capture_output=True, text=True, env=env, timeout=20)
    return result


def invoke(name, *args):
    result = command(name, *args)
    assert result.returncode == 0, result.stderr
    assert 'ERR:' not in result.stdout, result.stdout
    return [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]


def test_native_cli_authoring_reopen_and_private_export(tmp_path):
    name = 'native-' + uuid.uuid4().hex
    with openHby(name=name, base='native-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name='issuer', version=Vrsn_2_0)
        prefix = issuer.pre

    created = invoke(name, 'vc', 'registry', 'incept', '--native', '-a', 'issuer', '-r', 'authority')[0]
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
    assert repeated['state'] == 'revoked'
    assert invoke(name, 'vc', 'revoke', '--native', '-a', 'issuer', '-r', 'authority',
                  '--said', credential)[0]['update'] == revoked['update']
    assert invoke(name, 'vc', 'registry', 'status', '--native', '-r', 'authority')[0]['sn'] == 2
    assert private.read_bytes() == custody


def test_native_option_is_explicit_and_legacy_remains_default():
    parser = multicommand.create_parser(commands)
    for command in (['vc', 'registry', 'incept', '-a', 'issuer'],
                    ['vc', 'create', '-a', 'issuer', '--data', '{}'],
                    ['vc', 'revoke', '-a', 'issuer', '--said', 'example']):
        assert parser.parse_args(command + ['--name', 'example']).native is False
        assert parser.parse_args(command + ['--name', 'example', '--native']).native is True


def test_native_cli_refuses_unencrypted_custody_before_registry_creation():
    name = 'unencrypted-' + uuid.uuid4().hex
    with openHby(name=name, base='native-cli-test', temp=False, version=Vrsn_2_0) as hby:
        hby.makeHab(name='issuer', version=Vrsn_2_0)
    result = command(name, 'vc', 'registry', 'incept', '--native', '-a', 'issuer', '-r', 'blocked')
    assert 'authenticated encrypted Keeper' in result.stdout
    assert '"accepted": true' not in result.stdout
    with openHby(name=name, base='native-cli-test', temp=False, version=Vrsn_2_0) as hby:
        rgy = Regery(hby=hby, name=name, base='native-cli-test')
        try:
            assert rgy.registryByName('blocked') is None
        finally:
            rgy.close()


def test_native_cli_pending_witness_anchor_resumes_without_resealing():
    name = 'pending-' + uuid.uuid4().hex
    with openHby(name='witness-' + uuid.uuid4().hex, version=Vrsn_2_0) as whby:
        witness = whby.makeHab(name='witness', transferable=False, version=Vrsn_2_0)
        with openHby(name=name, base='native-cli-test', temp=False, bran=PASSCODE,
                     version=Vrsn_2_0) as hby:
            hby.makeHab(name='issuer', wits=[witness.pre], toad=1, version=Vrsn_2_0)
        # No witness endpoint has been configured; the normal receipt owner
        # cannot complete. The CLI must leave honest pending state, not success.
        result = command(name, 'vc', 'registry', 'incept', '--native', '-a', 'issuer',
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
        accepted = invoke(name, 'vc', 'registry', 'incept', '--native', '-a', 'issuer', '-r', 'pending')[0]
        assert accepted['registry'] == status['registry']
        assert accepted['accepted'] is True
        with openHby(name=name, base='native-cli-test', temp=False, bran=PASSCODE,
                     version=Vrsn_2_0) as hby:
            assert hby.habByName('issuer').kever.sn == sealing_sn


def test_native_cli_unblinded_issuance_then_blind_revocation(tmp_path):
    name = 'mixed-' + uuid.uuid4().hex
    with openHby(name=name, base='native-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        hby.makeHab(name='issuer', version=Vrsn_2_0)
    invoke(name, 'vc', 'registry', 'incept', '--native', '-a', 'issuer', '-r', 'mixed')
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
    assert invoke(name, 'vc', 'list', '--native', '--issued', '-a', 'issuer')[0]['state'] == 'revoked'


def test_native_cli_bound_issue_revoke_and_historical_retry(tmp_path):
    name = 'bound-' + uuid.uuid4().hex
    with openHby(name=name, base='native-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        hby.makeHab(name='issuer', version=Vrsn_2_0)
        holder = hby.makeHab(name='holder', version=Vrsn_2_0)
        issuee, first = holder.pre, holder.kever.serder.said
    invoke(name, 'vc', 'registry', 'incept', '--native', '-a', 'issuer', '-r', 'bound')
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
