"""Separate KLI invocations negotiate, admit and present retained native proofs."""
import json
import os
import subprocess
import sys
import uuid

from keri import Vrsn_2_0
from keri.app import openHby
from keri.core import SerderACDC


PASSCODE = '0123456789abcdefghijk'


def invoke(name, *args):
    result = subprocess.run([sys.executable, '-m', 'keri.cli.kli', *args,
        '--name', name, '--base', 'native-ipex-cli'], capture_output=True, text=True,
        env=dict(os.environ, KLI_KEYSTORE_PASSCODE=PASSCODE), timeout=20)
    assert result.returncode == 0, result.stderr + result.stdout
    assert 'ERR:' not in result.stdout, result.stdout + result.stderr
    return [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]


def test_native_cli_full_negotiation_and_holder_presentation(tmp_path):
    names, prefixes = {}, {}
    for role in ('issuer', 'holder', 'verifier'):
        name = names[role] = role + '-' + uuid.uuid4().hex
        with openHby(name=name, base='native-ipex-cli', temp=False, bran=PASSCODE,
                     version=Vrsn_2_0) as hby:
            hab = hby.makeHab(name=role, version=Vrsn_2_0)
            prefixes[role] = hab.pre
            (tmp_path / (role + '.kel')).write_bytes(hab.replay(gvrsn=Vrsn_2_0))
    from keri.core import Kevery, Parser
    with openHby(name=names['issuer'], base='native-ipex-cli', temp=False,
                 bran=PASSCODE, version=Vrsn_2_0) as hby:
        Parser(kvy=Kevery(db=hby.db, lax=False, local=False), version=Vrsn_2_0).parse(
            ims=bytearray((tmp_path / 'holder.kel').read_bytes()))
    invoke(names['issuer'], 'vc', 'registry', 'incept', '--native', '-a', 'issuer', '-r', 'r',
        '--discloser', prefixes['holder'])
    issued = invoke(names['issuer'], 'vc', 'create', '--native', '-a', 'issuer', '-r', 'r',
                    '--data', '{"status":"authorized"}')[0]
    said = issued['credential']
    credentialFile, evidence = tmp_path / 'credential.json', tmp_path / 'evidence.cesr'
    invoke(names['issuer'], 'vc', 'export', '--native', '-a', 'issuer', '-r', 'r',
        '--said', said, '--output', str(credentialFile))
    invoke(names['issuer'], 'vc', 'export', '--native', '-a', 'issuer', '-r', 'r',
        '--said', said, '--full', '--output', str(evidence))
    credential = SerderACDC(raw=credentialFile.read_bytes())
    plan = json.dumps([[[credential.schema['$id'], '/', ['']]]])
    application = tmp_path / 'apply.cesr'
    app = invoke(names['holder'], 'ipex', 'apply', '--native', '-a', 'holder',
        '-r', prefixes['issuer'], '--plan', plan, '--output', str(application))[0]
    offered = tmp_path / 'offer.cesr'
    offer = invoke(names['issuer'], 'ipex', 'offer', '--native', '-a', 'issuer',
        '-r', prefixes['holder'], '-s', said, '--prior', app['exchange'],
        '--input', str(application), '--output', str(offered))[0]
    agreement = tmp_path / 'agree.cesr'
    agree = invoke(names['holder'], 'ipex', 'agree', '--native', '-a', 'holder',
        '-s', offer['exchange'], '--input', str(offered), '--output', str(agreement))[0]
    granted = tmp_path / 'grant.cesr'
    grant = invoke(names['issuer'], 'ipex', 'grant', '--native', '-a', 'issuer',
        '-r', prefixes['holder'], '-s', said, '--prior', agree['exchange'],
        '--input', str(agreement), '--output', str(granted))[0]
    incoming = tmp_path / 'incoming.cesr'
    incoming.write_bytes(evidence.read_bytes() + granted.read_bytes())
    admitted = invoke(names['holder'], 'ipex', 'admit', '--native', '-a', 'holder',
        '-s', grant['exchange'], '--input', str(incoming))[0]
    assert admitted['admitted'] is True
    # New process reopens encrypted wallet and uses the received opening. The
    # holder has never received or imported the issuer's long-lived salt.
    presentation = tmp_path / 'presentation.cesr'
    presented = invoke(names['holder'], 'ipex', 'grant', '--native', '-a', 'holder',
        '-r', prefixes['verifier'], '-s', said, '--from-grant', grant['exchange'],
        '--output', str(presentation))[0]
    assert presented['exchange'] != grant['exchange']
    incoming.write_bytes(evidence.read_bytes() + presentation.read_bytes())
    assert invoke(names['verifier'], 'ipex', 'admit', '--native', '-a', 'verifier',
        '-s', presented['exchange'], '--input', str(incoming))[0]['admitted'] is True
    # Author a genuine state-preserving update, then provision the designated
    # holder and let a new CLI process derive the fresh opening. The admitted
    # credential view and original grant are unchanged.
    from keri.acdc import Regery
    from keri.acdc.messaging import blindate
    from keri.app.credentialing import Wallet
    with openHby(name=names['issuer'], base='native-ipex-cli', temp=False,
                 bran=PASSCODE, version=Vrsn_2_0) as hby:
        rgy = Regery(hby=hby, name=hby.name, base=hby.base)
        wallet = Wallet(hby, rgy)
        try:
            reg = rgy.registryByName('r')
            opening = wallet.derive(reg.regk, 2, said, 'issued')
            event = blindate(reg.regk, reg.store.headEvent(reg.regk).said, opening.said, sn=2)
            reg.processEvent(event)
            hby.habByName('issuer').interact(data=[dict(s=event.sad['n'], d=event.said)])
            assert reg.anchorMsg(event.said)
        finally:
            wallet.close()
            rgy.close()
    refreshed = tmp_path / 'refreshed.cesr'
    private = tmp_path / 'custody.json'
    invoke(names['issuer'], 'vc', 'export', '--native', '-a', 'issuer', '-r', 'r',
        '--said', said, '--kels', '--tels', '--output', str(refreshed))
    invoke(names['issuer'], 'vc', 'export', '--native', '-a', 'issuer', '-r', 'r',
        '--custody', '--output', str(private))
    invoke(names['holder'], 'vc', 'import', '--native', '--custody', '--registry', reg.regk,
        '--controller', prefixes['issuer'], '--discloser', prefixes['holder'],
        '--file', str(private), '--passcode', PASSCODE)
    fresh = tmp_path / 'fresh-presentation.cesr'
    current = invoke(names['holder'], 'ipex', 'grant', '--native', '-a', 'holder',
        '-r', prefixes['verifier'], '-s', said, '--from-grant', grant['exchange'],
        '--refresh', '--input', str(refreshed), '--output', str(fresh))[0]
    assert current['exchange'] != presented['exchange']
    incoming.write_bytes(refreshed.read_bytes() + fresh.read_bytes())
    assert invoke(names['verifier'], 'ipex', 'admit', '--native', '-a', 'verifier',
        '-s', current['exchange'], '--input', str(incoming))[0]['admitted'] is True


def test_public_upd_cli_grant_and_real_holder_admission(tmp_path):
    """An accepted public update needs no fabricated blinded opening."""
    names, prefixes = {}, {}
    for role in ('issuer', 'holder'):
        name = names[role] = 'public-' + role + '-' + uuid.uuid4().hex
        with openHby(name=name, base='native-ipex-cli', temp=False,
                     bran=PASSCODE, version=Vrsn_2_0) as hby:
            prefixes[role] = hby.makeHab(name=role, version=Vrsn_2_0).pre
    invoke(names['issuer'], 'vc', 'registry', 'incept', '--native', '-a', 'issuer', '-r', 'r')
    issued = invoke(names['issuer'], 'vc', 'create', '--native', '-a', 'issuer', '-r', 'r',
                    '--unblinded', '--data', '{"status":"authorized"}')[0]
    public, granted, incoming = (tmp_path / name for name in ('public.cesr', 'grant.cesr', 'incoming.cesr'))
    invoke(names['issuer'], 'vc', 'export', '--native', '-a', 'issuer', '-r', 'r',
        '--said', issued['credential'], '--kels', '--tels', '--output', str(public))
    grant = invoke(names['issuer'], 'ipex', 'grant', '--native', '-a', 'issuer',
        '-r', prefixes['holder'], '-s', issued['credential'], '--output', str(granted))[0]
    incoming.write_bytes(public.read_bytes() + granted.read_bytes())
    assert invoke(names['holder'], 'ipex', 'admit', '--native', '-a', 'holder',
        '-s', grant['exchange'], '--input', str(incoming))[0]['admitted'] is True


def test_native_group_cli_approves_exact_exchange_after_reopen(tmp_path):
    from contextlib import ExitStack
    from keri.acdc import acdcmap
    from keri.core import Parser

    names = ['ipex-member-' + uuid.uuid4().hex for _ in range(2)]
    with ExitStack() as stack:
        hbys = [stack.enter_context(openHby(name=name, base='native-ipex-cli',
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
        plan = json.dumps([[[credential.schema['$id'], '/', ['']]]])
    first, second = tmp_path / 'first.cesr', tmp_path / 'second.cesr'
    common = ['ipex', 'apply', '--native', '-a', 'group', '-r', recipient, '--plan', plan]
    pending = subprocess.run([sys.executable, '-m', 'keri.cli.kli', *common,
        '--name', names[0], '--base', 'native-ipex-cli', '--timeout', '0.2',
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
        '--recipient', groups[0].pre, '--name', names[0], '--base', 'native-ipex-cli',
        '--proposal', str(second)], env=dict(os.environ, KLI_KEYSTORE_PASSCODE=PASSCODE),
        capture_output=True, text=True, timeout=20)
    assert wrong.returncode != 0
    assert 'different recipient' in wrong.stdout + wrong.stderr
