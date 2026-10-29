"""Installed KLI recovery of an exact DH agreement without plaintext salt files."""
from contextlib import ExitStack
import json
import uuid

import pytest

from keri import Vrsn_2_0
from keri.acdc import Regery
from keri.app import openHby
from keri.app.credentialing import Wallet
from keri.app.registry_custody import RegistryCustody
from keri.core import Diger, SealSource, SerderACDC, messagize
from tests.app.test_acdc_v2_cli import PASSCODE, command, invoke


@pytest.mark.parametrize('initiator', ['issuer', 'holder'])
def test_installed_kli_two_party_agreement_survives_every_command_exit(tmp_path, initiator):
    """Both initiating directions retain one identical root through separate processes.

    Only public signed replies and accepted KEL/TEL evidence cross files. Each
    command reopens its encrypted Keeper and wallet; no in-memory private key is
    carried between commands. The test compares derived openings, not just sends.
    """
    names = {role: 'salt-cli-' + uuid.uuid4().hex for role in ('issuer', 'holder')}
    aids, public = {}, {}
    for role, name in names.items():
        with openHby(name=name, base='acdc-v2-cli-test', temp=False,
                     bran=PASSCODE, version=Vrsn_2_0) as hby:
            hab = hby.makeHab(name=role, version=Vrsn_2_0)
            aids[role] = hab.pre
            public[role] = bytes(hab.replay(gvrsn=Vrsn_2_0))
    registry = invoke(names['issuer'], 'vc', 'registry', 'incept', '--acdc-v2',
                      '-a', 'issuer', '-r', 'agreed-root')[0]['registry']
    with openHby(name=names['issuer'], base='acdc-v2-cli-test', temp=False,
                 bran=PASSCODE, version=Vrsn_2_0) as hby:
        rgy = Regery(hby=hby, name=hby.name, base=hby.base)
        try:
            public['issuer'] = bytes(hby.habByName('issuer').replay(gvrsn=Vrsn_2_0))
            rip = rgy.store.seqEvent(registry, 0)
            number, diger = rgy.store.anchor(rip.said)
            tel = messagize(rip, bonds=[SealSource(s=number.numh, d=diger.qb64)], gvrsn=Vrsn_2_0)
        finally:
            rgy.close()
    evidence = tmp_path / 'public-evidence.cesr'
    evidence.write_bytes(public['issuer'] + public['holder'] + tel)
    rosters = tmp_path / 'trusted-rosters.json'
    rosters.write_text(json.dumps({aid: [aid] for aid in aids.values()}))

    def run(role, action, *tokens):
        """Run an explicit installed action with accepted local roster configuration."""
        return invoke(names[role], 'vc', 'registry', 'salt', action, '-a', role,
                      '--rosters', str(rosters), *tokens)

    # Import public evidence first, without any private/root capability.
    for role in names:
        run(role, 'status', '--registry', registry, '--evidence', str(evidence))
    initFile, bindFile, confirmFile = [tmp_path / f'{name}.cesr' for name in ('init', 'bind', 'confirm')]
    init = run(initiator, 'init', '--issuer', aids['issuer'], '--discloser', aids['holder'],
               '--output', str(initFile))[0]['said']
    resumed = run(initiator, 'resume', '--init', init)[0]
    assert resumed['said'] == init  # no new ephemeral key or timestamp on reopen
    responder = 'holder' if initiator == 'issuer' else 'issuer'
    bind = run(responder, 'bind', '--init', init, '--registry', registry,
               '--input', str(initFile), '--output', str(bindFile))[0]['said']
    run(initiator, 'import', '--input', str(bindFile))
    confirm = run('issuer', 'confirm', '--init', init, '--bind', bind,
                  '--output', str(confirmFile))[0]['said']
    run('holder', 'import', '--input', str(confirmFile))
    for role in names:
        result = run(role, 'status', '--registry', registry)[0]
        assert result['custody_present'] is True
        assert result['origin']['init'] == init and result['origin']['bind'] == bind
        assert result['origin']['confirm'] == confirm

    openings, roots = [], []
    for role, name in names.items():
        with openHby(name=name, base='acdc-v2-cli-test', temp=False,
                     bran=PASSCODE, version=Vrsn_2_0) as hby, ExitStack() as stack:
            rgy = Regery(hby=hby, name=hby.name, base=hby.base)
            stack.callback(rgy.close)
            wallet = Wallet(hby, rgy)
            stack.callback(wallet.close)
            custody = RegistryCustody(hby, rgy, db=wallet.db)
            openings.append(custody.derive(registry, 1, Diger(ser=b'credential').qb64, 'issued').qb64)
            roots.append(custody._load(registry).salt)
    assert openings[0] == openings[1] and roots[0] == roots[1]
    for path in (evidence, rosters, initFile, bindFile, confirmFile):
        assert roots[0].encode() not in path.read_bytes()
    refused = command(names['holder'], 'vc', 'registry', 'salt', 'export', '-a', 'holder',
                      '--said', confirm, '--output', str(confirmFile))
    assert refused.returncode != 0  # existing files are never overwritten
