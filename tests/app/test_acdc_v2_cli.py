"""ACDC v2 authoring through real KLI subprocesses and reopened encrypted stores."""
import json
import os
import subprocess
import sys
from types import SimpleNamespace
import uuid

import multicommand
import pytest

from keri import Vrsn_2_0
from keri.acdc import Regery, Registrar, acdcmap
from keri.acdc.regeventing import vet, vetBlind
from keri.app import openHby
from keri.app.credentialing import DerivedUpdate, Wallet
from keri.app.evidencing import EvidenceContext
from keri.cli import commands
from keri.cli.common.acdc_v2 import AcdcV2Author
from keri.core import Kevery, Parser, SerderACDC
from keri.kering import ConfigurationError
from tests.app.test_acdc_v2_wallet import anchored


PASSCODE = '0123456789abcdefghijk'


def command(name, *args):
    """Execute one bounded installed CLI process against a persistent fixture store.

    Args:
        name (str): Isolated test identity under acdc-v2-cli-test.
        *args: Public KLI command tokens, including explicit ACDC v2 selection.

    Returns:
        CompletedProcess: Captured status/stdout/stderr for success or refusal checks.

    Raises:
        TimeoutExpired: The process exceeds twenty seconds. The public fixture
        passcode is supplied through the environment rather than command logging."""
    env = dict(os.environ, KLI_KEYSTORE_PASSCODE=PASSCODE)
    result = subprocess.run([sys.executable, '-m', 'keri.cli.kli', *args,
                             '--name', name, '--base', 'acdc-v2-cli-test'],
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


def _issued_cli_case(registry_name, data):
    """Create one real encrypted issuer, registry and accepted CLI issuance."""
    name = 'acdc-v2-' + uuid.uuid4().hex
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name='issuer', version=Vrsn_2_0)
        prefix = issuer.pre

    created = invoke(name, 'vc', 'registry', 'incept', '--acdc-v2', '--with-custody', '-a', 'issuer', '-r', registry_name)[0]
    assert created['accepted'] is True
    assert created['controller'] == prefix
    regid = created['registry']
    status = invoke(name, 'vc', 'registry', 'status', '--acdc-v2', '-r', registry_name)[0]
    assert status['sn'] == 0
    assert status['head'] == regid
    assert invoke(name, 'vc', 'registry', 'list', '--acdc-v2')[0]['registry'] == regid

    issued = invoke(name, 'vc', 'create', '--acdc-v2', '-a', 'issuer', '-r', registry_name,
                    '--data', data)[0]
    assert issued['accepted'] is True
    assert issued['state'] == 'issued'
    credential = issued['credential']
    assert invoke(name, 'vc', 'list', '--acdc-v2', '--issued', '-a', 'issuer')[0]['credential'] == credential

    return SimpleNamespace(name=name, prefix=prefix, regid=regid, issued=issued,
                           credential=credential)


def _revoke_and_retry_cli(case, public):
    """Revoke and retry the exact issuance through independently reopened CLI calls."""
    name, credential = case.name, case.credential
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


def test_acdc_v2_cli_authoring_reopen_and_public_export(tmp_path):
    """Retain public/full evidence and historical retries without plaintext handoff."""
    case = _issued_cli_case('authority', '{"name":"Alice"}')
    name, regid, credential, issued = case.name, case.regid, case.credential, case.issued
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
    _revoke_and_retry_cli(case, public)
    # Simulate loss of this test registry's custody row. Historical issuance
    # retry must neither regenerate a salt nor try to derive current standing.
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
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
    for command in (['vc', 'create', '-a', 'issuer', '--data', '{}'],
                    ['vc', 'revoke', '-a', 'issuer', '--said', 'example']):
        with pytest.raises(SystemExit):
            parser.parse_args(command + ['--name', 'example', '--unblinded'])


def test_acdc_v2_cli_refuses_unencrypted_custody_before_registry_creation():
    """Refuse requested private custody on an unencrypted Keeper before creating any named registry.

    Returns:
        None. Assertions check the stated evidence boundary."""
    name = 'unencrypted-' + uuid.uuid4().hex
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, version=Vrsn_2_0) as hby:
        hby.makeHab(name='issuer', version=Vrsn_2_0)
    result = command(name, 'vc', 'registry', 'incept', '--acdc-v2', '--with-custody', '-a', 'issuer', '-r', 'blocked')
    assert 'authenticated encrypted Keeper' in result.stdout
    assert '"accepted": true' not in result.stdout
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, version=Vrsn_2_0) as hby:
        rgy = Regery(hby=hby, name=name, base='acdc-v2-cli-test')
        try:
            assert rgy.registryByName('blocked') is None
        finally:
            rgy.close()


def test_public_cli_lifecycle_never_provisions_or_encrypts_custody():
    """Run public inception/issue/revoke/list without salt records or implicit Keeper AEID migration despite an environment passcode.

    Returns:
        None. Assertions check the stated evidence boundary."""
    name = 'public-' + uuid.uuid4().hex
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, version=Vrsn_2_0) as hby:
        hby.makeHab(name='issuer', version=Vrsn_2_0)
        assert not hby.mgr.aeid
    reg = invoke(name, 'vc', 'registry', 'incept', '--acdc-v2', '-a', 'issuer', '-r', 'public')[0]
    assert reg['custody'] == 'not requested'
    issued = invoke(name, 'vc', 'create', '--acdc-v2', '--public', '-a', 'issuer',
                    '-r', 'public', '--data', '{"name":"Public"}')[0]
    assert issued['state'] == 'issued'
    revoked = invoke(name, 'vc', 'revoke', '--acdc-v2', '--public', '-a', 'issuer',
                     '-r', 'public', '--said', issued['credential'])[0]
    assert revoked['state'] == 'revoked'
    assert invoke(name, 'vc', 'list', '--acdc-v2', '--issued', '-a', 'issuer')[0]['state'] == 'revoked'
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, version=Vrsn_2_0) as hby:
        rgy = Regery(hby=hby, name=name, base=hby.base)
        wallet = Wallet(hby, rgy)
        try:
            assert not hby.mgr.aeid
            assert wallet.custody is None
            assert list(wallet.db.custody.getTopItemIter()) == []
            assert rgy.registryByName('public').sn == 2
            head = rgy.registryByName('public').store.headEvent(reg['registry'])
            assert head.ilk == 'bup'
            assert wallet.publicOpening(head).state == 'revoked'
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
        with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
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

        with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
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
        with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
                     version=Vrsn_2_0) as hby:
            assert hby.habByName('issuer').kever.sn == sealing_sn


def test_acdc_v2_cli_public_bup_issuance_then_derived_revocation(tmp_path):
    """Preserve public-opening issuance and derived revocation as one bup-only history.

    Parameters:
        tmp_path: Pytest-owned exclusive credential, public proof, private custody, and bound-evidence files.

    Returns:
        None. Assertions check the stated evidence boundary."""
    name = 'mixed-' + uuid.uuid4().hex
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        hby.makeHab(name='issuer', version=Vrsn_2_0)
    invoke(name, 'vc', 'registry', 'incept', '--acdc-v2', '--with-custody', '-a', 'issuer', '-r', 'mixed')
    issued = invoke(name, 'vc', 'create', '--acdc-v2', '--public', '-a', 'issuer', '-r', 'mixed',
                    '--data', '{"name":"Bob"}')[0]
    assert issued['state'] == 'issued'
    artifact = tmp_path / 'public-bup.cesr'
    invoke(name, 'vc', 'export', '--acdc-v2', '-a', 'issuer', '-r', 'mixed', '--said', issued['credential'],
           '--full', '--output', str(artifact))
    parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(artifact.read_bytes()), processive=False)
    update = [item.serder for item in parsed if item.serder.ilk == 'bup'][0]
    assert update.sad['b'] == parsed[-1].bsqs[0][0].qb64
    assert parsed[-1].bsqs[0][2].qb64 == issued['credential']
    assert parsed[-1].bsqs[0][3].text == 'issued'
    public = tmp_path / 'public-registry.cesr'
    invoke(name, 'vc', 'export', '--acdc-v2', '-a', 'issuer', '-r', 'mixed',
           '--said', issued['credential'], '--kels', '--tels', '--output', str(public))
    published = Parser(version=Vrsn_2_0).parse(
        ims=bytearray(public.read_bytes()), processive=False)
    update = next(item for item in published if item.serder.ilk == 'bup')
    assert len(update.bsqs) == 1
    opening = update.bsqs[0]
    target, state = vetBlind(''.join(field.qb64 for field in opening),
                             blid=update.serder.sad['b'])
    assert target == issued['credential']
    assert state == 'issued'
    with openHby(name='public-observer-' + uuid.uuid4().hex, temp=True,
                 version=Vrsn_2_0) as observer:
        evidence = EvidenceContext(observer)
        try:
            result = evidence.ingest(public.read_bytes())
            assert not result['pending'] and not result['rejected']
            assert result['heads'][issued['registry']] == update.serder.said
            assert evidence.store.headEvent(issued['registry']).said == update.serder.said
            rip = next(item.serder for item in published if item.serder.ilk == 'rip')
            standing = vet(rip, [update.serder], db=observer.db,
                           blinder=''.join(field.qb64 for field in opening))
            assert standing.acdc == issued['credential']
            assert standing.state == 'issued'
        finally:
            evidence.close()
    revoked = invoke(name, 'vc', 'revoke', '--acdc-v2', '-a', 'issuer', '-r', 'mixed',
                     '--said', issued['credential'])[0]
    assert revoked['state'] == 'revoked'
    assert invoke(name, 'vc', 'list', '--acdc-v2', '--issued', '-a', 'issuer')[0]['state'] == 'unknown'


def test_acdc_v2_cli_derived_issuance_then_public_revocation():
    """Classify the accepted derived predecessor before authoring a public revocation."""
    name = 'derived-public-' + uuid.uuid4().hex
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        hby.makeHab(name='issuer', version=Vrsn_2_0)
    regid = invoke(name, 'vc', 'registry', 'incept', '--acdc-v2', '--with-custody',
                   '-a', 'issuer', '-r', 'mixed')[0]['registry']
    issued = invoke(name, 'vc', 'create', '--acdc-v2', '-a', 'issuer', '-r', 'mixed',
                    '--data', '{"name":"Derived"}')[0]
    revoked = invoke(name, 'vc', 'revoke', '--acdc-v2', '--public', '-a', 'issuer',
                     '-r', 'mixed', '--said', issued['credential'])[0]
    assert revoked['state'] == 'revoked'
    assert revoked['update'] != issued['update']
    assert invoke(name, 'vc', 'revoke', '--acdc-v2', '--public', '-a', 'issuer',
                  '-r', 'mixed', '--said', issued['credential'])[0]['update'] == revoked['update']
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        rgy = Regery(hby=hby, name=name, base=hby.base)
        wallet = Wallet(hby, rgy)
        try:
            reg = rgy.registryByName('mixed')
            issuance = reg.store.seqEvent(regid, 1)
            revocation = reg.store.seqEvent(regid, 2)
            assert issuance.said == issued['update']
            assert wallet.publicOpening(issuance) is None
            assert wallet.publicOpening(revocation).state == 'revoked'
            assert reg.store.headEvent(regid).said == revocation.said
        finally:
            wallet.close()
            rgy.close()


def test_acdc_v2_cli_public_request_after_same_state_derived_head_appends_opening():
    """Honor explicit public mode even when the accepted derived state already matches."""
    name = 'same-state-derived-public-' + uuid.uuid4().hex
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        hby.makeHab(name='issuer', version=Vrsn_2_0)
    regid = invoke(name, 'vc', 'registry', 'incept', '--acdc-v2', '--with-custody',
                   '-a', 'issuer', '-r', 'mixed')[0]['registry']
    issued = invoke(name, 'vc', 'create', '--acdc-v2', '-a', 'issuer', '-r', 'mixed',
                    '--data', '{"name":"Derived"}')[0]
    private = invoke(name, 'vc', 'revoke', '--acdc-v2', '-a', 'issuer', '-r', 'mixed',
                     '--said', issued['credential'])[0]
    public = invoke(name, 'vc', 'revoke', '--acdc-v2', '--public', '-a', 'issuer',
                    '-r', 'mixed', '--said', issued['credential'])[0]
    assert public['update'] != private['update']
    assert invoke(name, 'vc', 'revoke', '--acdc-v2', '--public', '-a', 'issuer',
                  '-r', 'mixed', '--said', issued['credential'])[0]['update'] == public['update']
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        rgy = Regery(hby=hby, name=name, base=hby.base)
        wallet = Wallet(hby, rgy)
        try:
            reg = rgy.registryByName('mixed')
            assert reg.store.seqEvent(regid, 2).said == private['update']
            head = reg.store.headEvent(regid)
            assert head.sad['n'] == '3' and head.said == public['update']
            assert wallet.publicOpening(head).state == 'revoked'
        finally:
            wallet.close()
            rgy.close()


def test_acdc_v2_cli_public_update_after_different_derived_credential():
    """Classify a derived head by its retained owner across credential interleaving."""
    name = 'interleaved-derived-public-' + uuid.uuid4().hex
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        hby.makeHab(name='issuer', version=Vrsn_2_0)
    regid = invoke(name, 'vc', 'registry', 'incept', '--acdc-v2', '--with-custody',
                   '-a', 'issuer', '-r', 'mixed')[0]['registry']
    first = invoke(name, 'vc', 'create', '--acdc-v2', '-a', 'issuer', '-r', 'mixed',
                   '--data', '{"name":"First"}')[0]
    second = invoke(name, 'vc', 'create', '--acdc-v2', '--public', '-a', 'issuer',
                    '-r', 'mixed', '--data', '{"name":"Second"}')[0]
    assert second['credential'] != first['credential']
    assert second['update'] != first['update']
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        rgy = Regery(hby=hby, name=name, base=hby.base)
        wallet = Wallet(hby, rgy)
        try:
            reg = rgy.registryByName('mixed')
            assert reg.store.seqEvent(regid, 1).said == first['update']
            assert wallet.publicOpening(reg.store.seqEvent(regid, 1)) is None
            head = reg.store.headEvent(regid)
            assert head.said == second['update']
            assert wallet.publicOpening(head).acdc == second['credential']
        finally:
            wallet.close()
            rgy.close()


def test_acdc_v2_cli_public_update_after_bound_derived_predecessor():
    """Open a later bound derived head before authoring the next public update."""
    name = 'bound-derived-public-' + uuid.uuid4().hex
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        hby.makeHab(name='issuer', version=Vrsn_2_0)
        holder = hby.makeHab(name='holder', version=Vrsn_2_0)
        issuee, first = holder.pre, holder.kever.serder.said
    regid = invoke(name, 'vc', 'registry', 'incept', '--acdc-v2', '--with-custody',
                   '-a', 'issuer', '-r', 'bound')[0]['registry']
    issued = invoke(name, 'vc', 'create', '--acdc-v2', '-a', 'issuer', '-r', 'bound',
                    '--recipient', issuee, '--bound-event', first,
                    '--data', '{"role":"Bound"}')[0]
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        holder = hby.habByName('holder')
        holder.interact(version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        current = holder.kever.serder.said
    revoked = invoke(name, 'vc', 'revoke', '--acdc-v2', '-a', 'issuer', '-r', 'bound',
                     '--said', issued['credential'], '--bound-event', current)[0]
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        rgy = Regery(hby=hby, name=name, base=hby.base)
        wallet = Wallet(hby, rgy)
        try:
            marker = wallet.db.derivations.get((revoked['update'],))
            assert marker == DerivedUpdate(issued['credential'], 'revoked',
                                           dict(bn=1, bd=current))
            assert not hasattr(marker, 'salt')
            assert wallet.publicOpening(rgy.registryByName('bound').store.headEvent(regid)) is None
        finally:
            wallet.close()
            rgy.close()
    public = invoke(name, 'vc', 'create', '--acdc-v2', '--public', '-a', 'issuer',
                    '-r', 'bound', '--data', '{"role":"Public successor"}')[0]
    assert public['update'] not in (issued['update'], revoked['update'])
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        rgy = Regery(hby=hby, name=name, base=hby.base)
        wallet = Wallet(hby, rgy)
        try:
            reg = rgy.registryByName('bound')
            assert reg.store.seqEvent(regid, 2).said == revoked['update']
            head = reg.store.headEvent(regid)
            assert head.sad['n'] == '3' and head.said == public['update']
            assert wallet.publicOpening(head).acdc == public['credential']
        finally:
            wallet.close()
            rgy.close()


def test_public_transition_refuses_wrong_or_missing_derived_update_coordinates():
    """Fail closed when a later accepted derived head lacks exact durable coordinates."""
    name = 'derived-coordinate-refusal-' + uuid.uuid4().hex
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        hby.makeHab(name='issuer', version=Vrsn_2_0)
    regid = invoke(name, 'vc', 'registry', 'incept', '--acdc-v2', '--with-custody',
                   '-a', 'issuer', '-r', 'private')[0]['registry']
    issued = invoke(name, 'vc', 'create', '--acdc-v2', '-a', 'issuer', '-r', 'private',
                    '--data', '{"role":"Private"}')[0]
    revoked = invoke(name, 'vc', 'revoke', '--acdc-v2', '-a', 'issuer', '-r', 'private',
                     '--said', issued['credential'])[0]

    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        rgy = Regery(hby=hby, name=name, base=hby.base)
        wallet = Wallet(hby, rgy)
        try:
            marker = wallet.db.derivations.get((revoked['update'],))
            assert marker == DerivedUpdate(issued['credential'], 'revoked', {})
            wallet.db.derivations.pin(
                (revoked['update'],), DerivedUpdate(issued['credential'], 'issued', {}))
        finally:
            wallet.close()
            rgy.close()
    successor = ['vc', 'create', '--acdc-v2', '--public', '-a', 'issuer', '-r', 'private',
                 '--data', '{"role":"Blocked successor"}']
    refused = command(name, *successor)
    assert refused.returncode != 0
    assert 'neither a retained public opening nor matching derived custody' in refused.stdout

    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        rgy = Regery(hby=hby, name=name, base=hby.base)
        wallet = Wallet(hby, rgy)
        try:
            assert wallet.db.derivations.rem((revoked['update'],))
        finally:
            wallet.close()
            rgy.close()
    refused = command(name, *successor)
    assert refused.returncode != 0
    assert 'neither a retained public opening nor matching derived custody' in refused.stdout
    status = invoke(name, 'vc', 'registry', 'status', '--acdc-v2', '-r', 'private')[0]
    assert status['head'] == revoked['update'] and status['sn'] == 2
    assert status['registry'] == regid


def test_public_pending_bup_without_retained_opening_refuses_replacement():
    """Refuse a public retry whose staged bytes lost their event-specific opening."""
    with openHby(name='missing-public-opening-' + uuid.uuid4().hex,
                 version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name='issuer', version=Vrsn_2_0)
        rgy = Regery(hby=hby, name=hby.name)
        wallet = Wallet(hby, rgy)
        try:
            reg = Registrar(rgy=rgy).makeRegistry(name='public', prefix=hab.pre)
            rip = rgy.store.event(reg.regk)
            anchored(hab, reg, rip)
            acdc = acdcmap(israid=hab.pre, regid=reg.regk,
                           attribute={'d': '', 'name': 'Pending'})
            args = SimpleNamespace(public=True, bound_event=None, time=None)
            event = AcdcV2Author(args, 'create').update(wallet, reg, acdc, 'issued')
            raw = event.raw
            assert wallet.publicOpening(event).state == 'issued'
            assert wallet.db.openings.rem((event.said,))

            with pytest.raises(ConfigurationError,
                               match='pending public bup is missing its retained opening'):
                AcdcV2Author(args, 'create').update(wallet, reg, acdc, 'issued')
            pending = [item for _, item in reg.store.baser.evts.getTopItemIter()
                       if item.sad.get('rd') == reg.regk and item.sad.get('n') == '1']
            assert len(pending) == 1
            assert pending[0].said == event.said
            assert pending[0].raw == raw
            assert reg.store.headEvent(reg.regk).said == rip.said
        finally:
            wallet.close()
            rgy.close()


def test_acdc_v2_cli_bound_issue_revoke_and_historical_retry(tmp_path):
    """Use real Issuee KEL coordinates for bound issuance/revocation and preserve the exact historical issuance on retry.

    Parameters:
        tmp_path: Pytest-owned exclusive credential, public proof, private custody, and bound-evidence files.

    Returns:
        None. Assertions check the stated evidence boundary."""
    name = 'bound-' + uuid.uuid4().hex
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
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
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
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


def _full_export_cli_case(tmp_path):
    """Obtain a real issuance opening and exercise missing/wrong proof refusal."""
    from keri.core import Blinder, Salter

    case = _issued_cli_case('r', '{"status":"valid"}')
    name, said = case.name, case.credential
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

    case.full, case.valid = full, valid
    return case


def test_full_export_requires_explicit_verified_opening(tmp_path):
    """A held verified opening works despite corrupt custody; exports stay exclusive."""
    case = _full_export_cli_case(tmp_path)
    name, regid, said, full, valid = case.name, case.regid, case.credential, case.full, case.valid
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
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


def test_full_export_rejects_wrong_salt_after_encrypted_reply(tmp_path):
    """An authenticated encrypted salt still has to reproduce the exact TEL commitment."""
    from keri.core import Encrypter, Salter, reply
    from keri.app.registry_salt_service import ROUTE

    case = _full_export_cli_case(tmp_path)
    name, regid, prefix, full = case.name, case.regid, case.prefix, case.full
    # Deliberately lose this test-owned row, then supply an issuer-signed wrong
    # root. This checks event verification independently of immutable storage.
    transfer = tmp_path / 'encrypted-salt.cesr'
    with openHby(name=name, base='acdc-v2-cli-test', temp=False, bran=PASSCODE,
                 version=Vrsn_2_0) as hby:
        rgy = Regery(hby=hby, name=name, base=hby.base)
        wallet = Wallet(hby, rgy)
        try:
            assert wallet.db.custody.rem((regid,))
            hab = hby.habByName('issuer')
            cipher = Encrypter(verkey=hab.kever.verfers[0].qb64).encrypt(prim=Salter())
            body = reply(pre=prefix, route=ROUTE, version=Vrsn_2_0,
                data=dict(registry=regid, recipient=prefix, target=prefix, cipher=cipher.qb64))
            transfer.write_bytes(hab.endorse(body, gvrsn=Vrsn_2_0))
        finally:
            wallet.close()
            rgy.close()
    invoke(name, 'vc', 'registry', 'salt', 'receive', '-a', 'issuer', '--input', str(transfer))
    wrongSalt = tmp_path / 'wrong-salt.cesr'
    refusal = command(name, *full, '--derive', '--output', str(wrongSalt))
    assert refusal.returncode != 0
    assert not wrongSalt.exists()


@pytest.mark.parametrize('tokens, message', [
    (['vc', 'export', '-a', 'issuer', '--derive'], 'require --acdc-v2'),
    (['vc', 'export', '-a', 'issuer', '--opening', 'absent'], 'require --acdc-v2'),
    (['vc', 'export', '--acdc-v2', '-a', 'issuer', '--derive'], 'require --acdc-v2 --full'),
    (['vc', 'export', '--acdc-v2', '-a', 'issuer', '--opening', 'absent'], 'require --acdc-v2 --full'),
    (['vc', 'export', '--acdc-v2', '-a', 'issuer', '--files'], 'uses --output'),
    (['vc', 'import', '--acdc-v2', '--file', 'absent', '--said', 'credential'], 'Use IPEX intake'),
])
def test_evidence_options_fail_before_store_or_file_access(tokens, message):
    """Reject incompatible modes before touching nonexistent identity/file inputs.

    tokens selects a real parser/handler path; message identifies its boundary.
    No database or output is provisioned by this parameterized refusal test.
    """
    from keri.kering import ConfigurationError

    args = multicommand.create_parser(commands).parse_args([*tokens, '--name', 'does-not-exist'])
    with pytest.raises(ConfigurationError, match=message):
        args.handler(args)
