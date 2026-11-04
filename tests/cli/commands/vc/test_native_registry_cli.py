"""Registry version selection through the real kli console entry point."""

import json
import shutil
import subprocess
from uuid import uuid4

import pytest

from keri import Vrsn_2_0
from keri.acdc import Regery
from keri.cli.common import setupHby


pytestmark = pytest.mark.real_store_roots


def kli(tmp_path, *args, succeeds=True):
    result = subprocess.run([shutil.which('kli'), *args], cwd=tmp_path,
                            capture_output=True, text=True, timeout=30)
    output = result.stdout + result.stderr
    if succeeds:
        assert result.returncode == 0 and 'ERR:' not in output, output
    else:
        assert result.returncode != 0, output
    return output


def create_issuer(tmp_path, *, version='2.0', est_only=False):
    name, base = f'registry-cli-{uuid4().hex}', 'r10a'
    common = ['--name', name, '--base', base]
    kli(tmp_path, 'init', *common, '--nopasscode', '--version', version)
    config = tmp_path / 'issuer.json'
    config.write_text(json.dumps(dict(transferable=True, wits=[], toad=0,
                                     icount=1, isith='1', ncount=1, nsith='1',
                                     estOnly=est_only)))
    kli(tmp_path, 'incept', *common, '--alias', 'issuer', '--file', str(config),
        '--version', version)
    return name, base, common


@pytest.mark.parametrize('est_only', [False, True], ids=['interaction', 'accepted-establishment-only'])
def test_native_registry_installed_lifecycle_and_refusal(tmp_path, est_only):
    name, base, common = create_issuer(tmp_path, est_only=est_only)
    output = kli(tmp_path, 'vc', 'registry', 'incept', *common, '--alias', 'issuer',
                 '--registry-name', 'native', '--version', '2.0')
    hby = setupHby(name=name, base=base, noPrompt=True, version=Vrsn_2_0)
    rgy = Regery(hby=hby, name=name, base=base)
    try:
        reg = rgy.registryByName('native')
        assert reg is not None and reg.sn == 0
        rip = rgy.store.seqEvent(reg.regk, 0)
        assert rip.ilk == 'rip' and rip.said in output
        hab = hby.habByName('issuer')
        assert hab.kever.sn == 1
        assert hab.kever.serder.ilk == ('rot' if est_only else 'ixn')
        assert dict(i=rip.said, s='0', d=rip.said) in hab.kever.serder.seals
        registry, head, issuer = reg.regk, reg.head.qb64, hab.pre
        assert list(hby.ks.rroots.getTopItemIter()) == []
    finally:
        rgy.close()
        hby.close()
    listing = kli(tmp_path, 'vc', 'registry', 'list', *common, '--version', '2.0')
    assert all(value in listing for value in ('native', registry, issuer, head))
    status = kli(tmp_path, 'vc', 'registry', 'status', *common, '--version', '2.0',
                 '--registry-name', 'native', '--verbose')
    assert all(value in status for value in (registry, issuer, head, 'Seq No.  0', '"rip"'))
    missing = kli(tmp_path, 'vc', 'registry', 'status', *common, '--version', '2.0',
                  '--registry-name', 'missing', succeeds=False)
    assert 'unknown registry' in missing
    for index, options in enumerate((['--backers', issuer], ['--no-backers', 'False'],
                                     ['--establishment-only', 'True'])):
        refused = kli(tmp_path, 'vc', 'registry', 'incept', *common, '--version', '2.0',
                      '--alias', 'issuer', '--registry-name', f'refused-{index}',
                      *options, succeeds=False)
        assert 'not supported' in refused
    hby = setupHby(name=name, base=base, noPrompt=True, version=Vrsn_2_0)
    rgy = Regery(hby=hby, name=name, base=base)
    try:
        assert list(rgy.names) == ['native']
        assert hby.habByName('issuer').kever.sn == 1
        assert rgy.registryByName('native').head.qb64 == head
    finally:
        rgy.close()
        hby.close()


def test_default_registry_commands_preserve_legacy_store(tmp_path):
    _, _, common = create_issuer(tmp_path, version='1.0')
    created = kli(tmp_path, 'vc', 'registry', 'incept', *common, '--alias', 'issuer',
                  '--registry-name', 'legacy')
    assert 'legacy' in created
    assert 'legacy' in kli(tmp_path, 'vc', 'registry', 'list', *common)
    status = kli(tmp_path, 'vc', 'registry', 'status', *common, '--registry-name', 'legacy')
    assert 'Seq No.  0' in status
    assert 'legacy' not in kli(tmp_path, 'vc', 'registry', 'list', *common, '--version', '2.0')


def test_native_group_installed_cli_accepts_exact_registry_anchor(tmp_path):
    name, base, common = create_issuer(tmp_path)
    hby = setupHby(name=name, base=base, noPrompt=True, version=Vrsn_2_0)
    member = hby.habByName('issuer')
    group = hby.makeGroupHab(group='group', mhab=member, smids=[member.pre],
                            isith='1', nsith='1', data=[dict(d=member.kever.serder.said)],
                            version=Vrsn_2_0)
    assert group.accepted and group.pre != member.pre
    prefix = group.pre
    hby.close()
    created = kli(tmp_path, 'vc', 'registry', 'incept', *common, '--version', '2.0',
                  '--alias', 'group', '--registry-name', 'group-registry', '--usage', 'membership')
    hby = setupHby(name=name, base=base, noPrompt=True, version=Vrsn_2_0)
    rgy = Regery(hby=hby, name=name, base=base)
    try:
        registry = rgy.registryByName('group-registry')
        rip = rgy.store.seqEvent(registry.regk, 0)
        anchor = hby.habs[prefix].kever.serder
        assert rip.said in created and anchor.sn == 1
        assert dict(i=rip.said, s='0', d=rip.said) in anchor.seals
        assert rgy.store.anchor(rip.said)[1].qb64 == anchor.said
        wrappers = [event for _, event in hby.db.exns.getTopItemIter()
                    if event.route == '/multisig/rip']
        assert len(wrappers) == 1 and wrappers[0].sad['a']['usage'] == 'membership'
        assert list(hby.ks.rroots.getTopItemIter()) == []
    finally:
        rgy.close()
        hby.close()


def test_native_read_commands_report_staged_registry_as_pending(tmp_path):
    name, base, common = create_issuer(tmp_path)
    hby = setupHby(name=name, base=base, noPrompt=True, version=Vrsn_2_0)
    rgy = Regery(hby=hby, name=name, base=base)
    try:
        registry = rgy.makeRegistry('pending-registry', hby.habByName('issuer').pre)
        regid = registry.regk
        assert registry.head is None
    finally:
        rgy.close()
        hby.close()
    listing = kli(tmp_path, 'vc', 'registry', 'list', *common, '--version', '2.0')
    assert regid in listing and 'pending-registry' in listing and 'pending' in listing
    status = kli(tmp_path, 'vc', 'registry', 'status', *common, '--version', '2.0',
                 '--registry-name', 'pending-registry')
    assert 'Seq No.  -1' in status and 'Head:  pending' in status
