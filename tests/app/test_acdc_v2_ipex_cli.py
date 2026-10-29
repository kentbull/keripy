"""Separate KLI invocations negotiate, admit and present retained ACDC v2 IPEX proofs."""
import json
import os
import subprocess
import sys
import uuid
from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0
from keri.app import openHby
from keri.core import Parser, SerderACDC


PASSCODE = '0123456789abcdefghijk'


def invoke(name, *args):
    """Run an installed ACDC v2 IPEX command over one independently reopened fixture store.

    Args:
        name (str): Isolated identity under acdc-v2-ipex-cli.
        *args: Public command/version/input/output/capability tokens.

    Returns:
        list[dict]: Ordered JSON-object transcript lines after a successful command.

    Raises:
        AssertionError: Nonzero process exit or textual KLI ERR indicates refusal.
        TimeoutExpired, JSONDecodeError: Bounded process/output handling fails.

    Each call is a separate process; retaining a Python object cannot conceal a
    missing persisted prior, admission, or optional derivation capability."""
    result = subprocess.run([sys.executable, '-m', 'keri.cli.kli', *args,
        '--name', name, '--base', 'acdc-v2-ipex-cli'], capture_output=True, text=True,
        env=dict(os.environ, KLI_KEYSTORE_PASSCODE=PASSCODE), timeout=20)
    assert result.returncode == 0, result.stderr + result.stdout
    assert 'ERR:' not in result.stdout, result.stdout + result.stderr
    return [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]


def _negotiated_cli_case(tmp_path):
    """Negotiate/admit with three real CLI actors and retain a genuinely newer TEL head."""
    names, prefixes = {}, {}
    for role in ('issuer', 'holder', 'verifier'):
        name = names[role] = role + '-' + uuid.uuid4().hex
        with openHby(name=name, base='acdc-v2-ipex-cli', temp=False, bran=PASSCODE,
                     version=Vrsn_2_0) as hby:
            hab = hby.makeHab(name=role, version=Vrsn_2_0)
            prefixes[role] = hab.pre
            (tmp_path / (role + '.kel')).write_bytes(hab.replay(gvrsn=Vrsn_2_0))
    from keri.core import Kevery, Parser
    with openHby(name=names['issuer'], base='acdc-v2-ipex-cli', temp=False,
                 bran=PASSCODE, version=Vrsn_2_0) as hby:
        Parser(kvy=Kevery(db=hby.db, lax=False, local=False), version=Vrsn_2_0).parse(
            ims=bytearray((tmp_path / 'holder.kel').read_bytes()))
    invoke(names['issuer'], 'vc', 'registry', 'incept', '--acdc-v2', '--with-custody', '-a', 'issuer', '-r', 'r',
        '--discloser', prefixes['holder'])
    issued = invoke(names['issuer'], 'vc', 'create', '--acdc-v2', '-a', 'issuer', '-r', 'r',
                    '--data', '{"status":"authorized"}')[0]
    said = issued['credential']
    credentialFile, evidence = tmp_path / 'credential.json', tmp_path / 'evidence.cesr'
    invoke(names['issuer'], 'vc', 'export', '--acdc-v2', '-a', 'issuer', '-r', 'r',
        '--said', said, '--output', str(credentialFile))
    invoke(names['issuer'], 'vc', 'export', '--acdc-v2', '-a', 'issuer', '-r', 'r',
        '--said', said, '--full', '--derive', '--output', str(evidence))
    credential = SerderACDC(raw=credentialFile.read_bytes())
    plan = json.dumps([[credential.schema['$id'], '/', ['a/status']]])
    # Prepare capabilities before the freshness-sensitive signed negotiation.
    granted = tmp_path / 'grant.cesr'
    implicit = subprocess.run([sys.executable, '-m', 'keri.cli.kli', 'ipex', 'grant',
        '--acdc-v2', '-a', 'issuer', '-r', prefixes['holder'], '-s', said,
        '--output', str(granted), '--name', names['issuer'], '--base', 'acdc-v2-ipex-cli'],
        env=dict(os.environ, KLI_KEYSTORE_PASSCODE=PASSCODE), capture_output=True, text=True, timeout=20)
    assert implicit.returncode != 0
    assert 'opening unavailable' in implicit.stdout + implicit.stderr
    assert not granted.exists()
    # A previously obtained event opening suffices for the issuer too. No salt
    # capability is selected by the evidence-producing Grant operation.
    originalOpening = tmp_path / 'original-opening.cesr'
    invoke(names['issuer'], 'vc', 'registry', 'opening', '-r', 'r', '-s', said,
           '--ordinal', '1', '--output', str(originalOpening))
    application = tmp_path / 'apply.cesr'
    app = invoke(names['holder'], 'ipex', 'apply', '--acdc-v2', '-a', 'holder',
        '-r', prefixes['issuer'], '--plan', plan, '--output', str(application))[0]
    offered = tmp_path / 'offer.cesr'
    offer = invoke(names['issuer'], 'ipex', 'offer', '--acdc-v2', '-a', 'issuer',
        '-r', prefixes['holder'], '-s', said, '--prior', app['exchange'],
        '--input', str(application), '--output', str(offered))[0]
    agreement = tmp_path / 'agree.cesr'
    agree = invoke(names['holder'], 'ipex', 'agree', '--acdc-v2', '-a', 'holder',
        '-s', offer['exchange'], '--input', str(offered), '--output', str(agreement))[0]
    grant = invoke(names['issuer'], 'ipex', 'grant', '--acdc-v2', '-a', 'issuer',
        '-r', prefixes['holder'], '-s', said, '--opening', str(originalOpening), '--prior', agree['exchange'],
        '--input', str(agreement), '--output', str(granted))[0]
    incoming = tmp_path / 'incoming.cesr'
    incoming.write_bytes(evidence.read_bytes() + granted.read_bytes())
    admitted = invoke(names['holder'], 'ipex', 'admit', '--acdc-v2', '-a', 'holder',
        '-s', grant['exchange'], '--input', str(incoming))[0]
    assert admitted['admitted'] is True
    # New process reopens encrypted wallet and uses the received opening. The
    # holder has never received or imported the issuer's long-lived salt.
    presentation = tmp_path / 'presentation.cesr'
    presented = invoke(names['holder'], 'ipex', 'grant', '--acdc-v2', '-a', 'holder',
        '-r', prefixes['verifier'], '-s', said, '--from-grant', grant['exchange'],
        '--output', str(presentation))[0]
    assert presented['exchange'] != grant['exchange']
    incoming.write_bytes(evidence.read_bytes() + presentation.read_bytes())
    assert invoke(names['verifier'], 'ipex', 'admit', '--acdc-v2', '-a', 'verifier',
        '-s', presented['exchange'], '--input', str(incoming))[0]['admitted'] is True
    # Author a genuine state-preserving update without changing the admitted
    # credential view or original grant. Each test supplies its own opening capability.
    from keri.acdc import Regery
    from keri.acdc.messaging import blindate
    from keri.app.credentialing import Wallet
    from keri.app.registry_custody import RegistryCustody
    with openHby(name=names['issuer'], base='acdc-v2-ipex-cli', temp=False,
                 bran=PASSCODE, version=Vrsn_2_0) as hby:
        rgy = Regery(hby=hby, name=hby.name, base=hby.base)
        wallet = Wallet(hby, rgy)
        try:
            reg = rgy.registryByName('r')
            opening = RegistryCustody(hby, rgy).derive(reg.regk, 2, said, 'issued')
            event = blindate(reg.regk, reg.store.headEvent(reg.regk).said, opening.said, sn=2)
            reg.processEvent(event)
            hby.habByName('issuer').interact(data=[dict(s=event.sad['n'], d=event.said)])
            assert reg.anchorMsg(event.said)
        finally:
            wallet.close()
            rgy.close()
    refreshed = tmp_path / 'refreshed.cesr'
    invoke(names['issuer'], 'vc', 'export', '--acdc-v2', '-a', 'issuer', '-r', 'r',
        '--said', said, '--kels', '--tels', '--output', str(refreshed))
    return SimpleNamespace(names=names, prefixes=prefixes, said=said, grant=grant,
                           presented=presented, regid=reg.regk, opening=opening,
                           refreshed=refreshed, incoming=incoming)


def _present_with_supplied_opening(case, tmp_path):
    """Refresh and independently admit one presentation using a supplied event opening."""
    names, prefixes, said, grant = case.names, case.prefixes, case.said, case.grant
    opening, refreshed, incoming = case.opening, case.refreshed, case.incoming
    # A supplied event opening is a narrower capability than a derivation salt.
    # The holder can refresh and present it before any reusable salt is received.
    specific = tmp_path / 'event-opening.cesr'
    specific.write_bytes(opening.qb64b)
    suppliedPresentation = tmp_path / 'supplied-presentation.cesr'
    supplied = invoke(names['holder'], 'ipex', 'grant', '--acdc-v2', '-a', 'holder',
        '-r', prefixes['verifier'], '-s', said, '--from-grant', grant['exchange'],
        '--refresh', '--opening', str(specific), '--input', str(refreshed),
        '--output', str(suppliedPresentation))[0]
    incoming.write_bytes(refreshed.read_bytes() + suppliedPresentation.read_bytes())
    assert invoke(names['verifier'], 'ipex', 'admit', '--acdc-v2', '-a', 'verifier',
        '-s', supplied['exchange'], '--input', str(incoming))[0]['admitted'] is True


def test_acdc_v2_cli_full_negotiation_and_holder_presentation(tmp_path):
    """Retained and refreshed supplied-opening presentations need no salt transfer."""
    case = _negotiated_cli_case(tmp_path)
    _present_with_supplied_opening(case, tmp_path)


def test_cli_holder_refresh_derives_after_encrypted_salt_reply(tmp_path):
    """A designated holder receives an encrypted salt before fresh derived presentation."""
    case = _negotiated_cli_case(tmp_path)
    _present_with_supplied_opening(case, tmp_path)
    names, prefixes, said, grant = case.names, case.prefixes, case.said, case.grant
    presented, refreshed, incoming = case.presented, case.refreshed, case.incoming
    encrypted = tmp_path / 'salt-reply.cesr'
    invoke(names['issuer'], 'vc', 'registry', 'salt', 'send', '-a', 'issuer',
        '--registry', case.regid, '--party', prefixes['holder'], '--output', str(encrypted))
    invoke(names['holder'], 'vc', 'registry', 'salt', 'receive', '-a', 'holder',
        '--input', str(encrypted))
    fresh = tmp_path / 'fresh-presentation.cesr'
    current = invoke(names['holder'], 'ipex', 'grant', '--acdc-v2', '-a', 'holder',
        '-r', prefixes['verifier'], '-s', said, '--from-grant', grant['exchange'],
        '--refresh', '--derive', '--input', str(refreshed), '--output', str(fresh))[0]
    assert current['exchange'] != presented['exchange']
    incoming.write_bytes(refreshed.read_bytes() + fresh.read_bytes())
    assert invoke(names['verifier'], 'ipex', 'admit', '--acdc-v2', '-a', 'verifier',
        '-s', current['exchange'], '--input', str(incoming))[0]['admitted'] is True


def test_public_bup_cli_grant_and_real_holder_admission(tmp_path):
    """Admit a public bup Grant with its verified opening and no custody provisioning.

    Parameters:
        tmp_path: Pytest-owned exclusive KEL/proposal/credential/opening files transferred between installed processes.

    Returns:
        None. Assertions check the stated evidence boundary."""
    names, prefixes = {}, {}
    for role in ('issuer', 'holder'):
        name = names[role] = 'public-' + role + '-' + uuid.uuid4().hex
        with openHby(name=name, base='acdc-v2-ipex-cli', temp=False,
                     bran=PASSCODE, version=Vrsn_2_0) as hby:
            prefixes[role] = hby.makeHab(name=role, version=Vrsn_2_0).pre
    invoke(names['issuer'], 'vc', 'registry', 'incept', '--acdc-v2', '-a', 'issuer', '-r', 'r')
    issued = invoke(names['issuer'], 'vc', 'create', '--acdc-v2', '--public',
                    '-a', 'issuer', '-r', 'r',
                    '--data', '{"status":"authorized"}')[0]
    public, opening, granted, incoming = (
        tmp_path / name for name in
        ('public.cesr', 'opening.cesr', 'grant.cesr', 'incoming.cesr'))
    invoke(names['issuer'], 'vc', 'export', '--acdc-v2', '-a', 'issuer', '-r', 'r',
        '--said', issued['credential'], '--kels', '--tels', '--output', str(public))
    frames = Parser(version=Vrsn_2_0).parse(
        ims=bytearray(public.read_bytes()), processive=False)
    update = next(frame for frame in frames if frame.serder.ilk == 'bup')
    assert len(update.bsqs) == 1
    opening.write_bytes(b''.join(field.qb64b for field in update.bsqs[0]))
    grant = invoke(names['issuer'], 'ipex', 'grant', '--acdc-v2', '-a', 'issuer',
        '-r', prefixes['holder'], '-s', issued['credential'], '--opening', str(opening),
        '--output', str(granted))[0]
    incoming.write_bytes(public.read_bytes() + granted.read_bytes())
    assert invoke(names['holder'], 'ipex', 'admit', '--acdc-v2', '-a', 'holder',
        '-s', grant['exchange'], '--input', str(incoming))[0]['admitted'] is True


def test_acdc_v2_group_cli_approves_exact_exchange_after_reopen(tmp_path):
    """Reopen pending real group exchange proposals and require explicit member approval of their exact child bytes.

    Parameters:
        tmp_path: Pytest-owned exclusive KEL/proposal/credential/opening files transferred between installed processes.

    Returns:
        None. Assertions check the stated evidence boundary."""
    from contextlib import ExitStack
    from keri.acdc import acdcmap
    from keri.core import Parser

    names = ['ipex-member-' + uuid.uuid4().hex for _ in range(2)]
    with ExitStack() as stack:
        hbys = [stack.enter_context(openHby(name=name, base='acdc-v2-ipex-cli',
            temp=False, bran=PASSCODE, version=Vrsn_2_0)) for name in names]
        members = [hby.makeHab(name='member', version=Vrsn_2_0) for hby in hbys]
        for hby in hbys:
            for member in members:
                Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(
                    ims=bytearray(member.replay(gvrsn=Vrsn_2_0)), local=True)
        groups = [hby.makeGroupHab(group='group', mhab=member,
            smids=[item.pre for item in members], isith='2', nsith='2', version=Vrsn_2_0)
            for hby, member in zip(hbys, members)]
        inceptions = [group.msgOwnInception(allowPartiallySigned=True, gvrsn=Vrsn_2_0)
                      for group in groups]
        for hby in hbys:
            for raw in inceptions:
                Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(raw), local=True)
            hby.kvy.processEscrows()
        assert all(group.accepted for group in groups)
        recipient = members[0].pre
        credential = acdcmap(israid=groups[0].pre, attribute=dict(d='', role='test'))
        plan = json.dumps([[credential.schema['$id'], '/', ['a/role']]])
    first, second = tmp_path / 'first.cesr', tmp_path / 'second.cesr'
    common = ['ipex', 'apply', '--acdc-v2', '-a', 'group', '-r', recipient, '--plan', plan]
    pending = subprocess.run([sys.executable, '-m', 'keri.cli.kli', *common,
        '--name', names[0], '--base', 'acdc-v2-ipex-cli', '--timeout', '0.2',
        '--proposal-output', str(first)], env=dict(os.environ, KLI_KEYSTORE_PASSCODE=PASSCODE),
        capture_output=True, text=True, timeout=20)
    assert pending.returncode != 0
    assert 'pending member approval' in pending.stdout + pending.stderr
    assert first.is_file()
    approved = invoke(names[1], *common, '--proposal', str(first),
        '--proposal-output', str(second), '--output', str(tmp_path / 'accepted.cesr'))[0]
    assert approved['accepted'] is True
    repeated = invoke(names[0], *common, '--proposal', str(second),
        '--proposal-output', str(tmp_path / 'repeat.cesr'))[0]
    assert repeated['exchange'] == approved['exchange']
    # An authenticated member proposal cannot silently replace the recipient
    # chosen explicitly by this operator.
    wrong = subprocess.run([sys.executable, '-m', 'keri.cli.kli', *common,
        '--recipient', groups[0].pre, '--name', names[0], '--base', 'acdc-v2-ipex-cli',
        '--proposal', str(second)], env=dict(os.environ, KLI_KEYSTORE_PASSCODE=PASSCODE),
        capture_output=True, text=True, timeout=20)
    assert wrong.returncode != 0
    assert 'different recipient' in wrong.stdout + wrong.stderr
