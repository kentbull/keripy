"""Installed KLI encrypted salt sharing through ordinary signed replies."""
from contextlib import ExitStack
import uuid


from keri import Vrsn_2_0
from keri.acdc import Regery
from keri.app import openHby
from keri.app.credentialing import Wallet
from keri.app.registry_custody import RegistryCustody
from keri.core import Diger, SealSource, messagize
from tests.app.test_acdc_v2_cli import PASSCODE, command, invoke


def test_installed_kli_encrypted_salt_survives_every_command_exit(tmp_path):
    """Separate commands share one issuer-created salt and derive after reopening.

    Public KEL/TEL evidence and a recipient-encrypted signed reply cross files.
    Commands reopen their encrypted Keeper; no private state crosses in memory.
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
                      '-a', 'issuer', '-r', 'shared-root', '--with-custody')[0]['registry']
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
    def run(role, action, *tokens):
        """Run one installed salt action with no separate roster configuration."""
        return invoke(names[role], 'vc', 'registry', 'salt', action, '-a', role, *tokens)

    for role in names:
        run(role, 'status', '--registry', registry, '--evidence', str(evidence))
    reply_file = tmp_path / 'encrypted-salt.cesr'
    sent = run('issuer', 'send', '--registry', registry, '--party', aids['holder'],
               '--output', str(reply_file))[0]
    assert sent['submitted'] is False  # File output is not a transport acknowledgement.
    run('holder', 'receive', '--input', str(reply_file))
    # Re-delivery of the same signed reply does not change the retained salt.
    run('holder', 'receive', '--input', str(reply_file))
    for role in names:
        assert run(role, 'status', '--registry', registry)[0]['custody_present'] is True

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
    for path in (evidence, reply_file):
        assert roots[0].encode() not in path.read_bytes()
    refused = command(names['issuer'], 'vc', 'registry', 'salt', 'send', '-a', 'issuer',
                      '--registry', registry, '--party', aids['holder'], '--output', str(reply_file))
    assert refused.returncode != 0  # Existing output files are never overwritten.


def test_installed_group_inception_reuses_encrypted_proposal_after_exit(tmp_path):
    """A real 2-of-3 group preserves its initiator's salt across partial-command exits."""
    from keri.core import Parser

    names = ['salt-group-cli-' + uuid.uuid4().hex for _ in range(3)]
    with ExitStack() as stack:
        hbys = [stack.enter_context(openHby(name=name, base='acdc-v2-cli-test',
                    temp=False, bran=PASSCODE, version=Vrsn_2_0)) for name in names]
        people = [hby.makeHab(name='member', version=Vrsn_2_0) for hby in hbys]
        for hby in hbys:
            for member in people:
                Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(
                    ims=bytearray(member.replay(gvrsn=Vrsn_2_0)), local=True)
        groups = [hby.makeGroupHab(group='issuer', mhab=member,
                    smids=[person.pre for person in people], isith='2', nsith='2', version=Vrsn_2_0)
                  for hby, member in zip(hbys, people)]
        for hby in hbys:
            for group in groups[:2]:
                Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(
                    group.msgOwnInception(allowPartiallySigned=True, gvrsn=Vrsn_2_0)), local=True)
            hby.kvy.processEscrows()
        assert all(group.accepted for group in groups)

    tokens = ('vc', 'registry', 'incept', '--acdc-v2', '--with-custody',
              '-a', 'issuer', '-r', 'shared', '--timeout', '0.1')
    first, repeated, second = [tmp_path / name for name in ('first.cesr', 'repeated.cesr', 'second.cesr')]
    pending = command(names[0], *tokens, '--proposal-output', str(first))
    assert pending.returncode != 0 and first.exists()
    again = command(names[0], *tokens, '--proposal-output', str(repeated))
    assert again.returncode != 0 and repeated.exists()

    def proposal(path):
        """Extract the signed registry proposal from its public evidence stream."""
        return next(item.serder for item in Parser(version=Vrsn_2_0).parse(
            ims=bytearray(path.read_bytes()), processive=False)
            if item.serder.ilk == 'exn' and item.serder.route == '/multisig/rip')

    original, retry = proposal(first), proposal(repeated)
    assert original.sad['a']['tel'] == retry.sad['a']['tel']
    assert original.sad['a']['salts'] == retry.sad['a']['salts']
    accepted = invoke(names[1], *tokens, '--proposal', str(first), '--proposal-output', str(second))[0]
    assert accepted['accepted'] is True
    assert proposal(second).sad['a']['salts'] == original.sad['a']['salts']
    resumed = invoke(names[0], *tokens, '--proposal', str(second))[0]
    assert resumed['registry'] == accepted['registry']
    roots = []
    for name in names[:2]:
        with openHby(name=name, base='acdc-v2-cli-test', temp=False,
                     bran=PASSCODE, version=Vrsn_2_0) as hby, ExitStack() as stack:
            rgy = Regery(hby=hby, name=hby.name, base=hby.base)
            stack.callback(rgy.close)
            wallet = Wallet(hby, rgy)
            stack.callback(wallet.close)
            custody = RegistryCustody(hby, rgy, db=wallet.db)
            roots.append(custody._load(accepted['registry']).salt)
    assert roots[0] == roots[1]
    assert roots[0].encode() not in first.read_bytes() + second.read_bytes()
