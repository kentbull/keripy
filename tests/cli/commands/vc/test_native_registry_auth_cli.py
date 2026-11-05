"""Witness-code option refusals must precede native registry and KEL mutation."""
import pytest

from keri import Vrsn_2_0
from keri.acdc import Regery
from keri.cli.common import setupHby

from tests.cli.commands.vc.test_native_registry_cli import create_issuer, kli


pytestmark = pytest.mark.real_store_roots


def test_native_witness_options_refuse_bad_scope_before_authoring(tmp_path):
    name, base, common = create_issuer(tmp_path)
    hby = setupHby(name=name, base=base, noPrompt=True, version=Vrsn_2_0)
    try:
        issuer = hby.habByName('issuer')
        aid, initial = issuer.pre, issuer.kever.serder.said
        group = hby.makeGroupHab(group='group', mhab=issuer, smids=[aid], isith='1', nsith='1',
                                 data=[dict(d=initial)], version=Vrsn_2_0)
        group_head = group.kever.serder.said
    finally:
        hby.close()
    for options, reason in (
        (['--code', f'{aid}:123456'], 'require --authenticate'),
        (['--code-time', '2026-11-03T00:00:00+00:00'], 'require --authenticate'),
        (['--authenticate', '--code-time', 'not-a-time'], 'timestamp with timezone'),
        (['--authenticate', '--code-time', '2026-11-03T00:00:00'], 'timestamp with timezone'),
        (['--authenticate', '--code', f'{aid}:123456'], 'selected witness'),
        (['--authenticate', '--code', 'malformed'], 'selected witness'),
        (['--alias', 'group', '--authenticate', '--code', f'{aid}:123456'], 'selected witness'),
        (['--version', '1.0', '--authenticate'], 'require native --version 2.0'),
    ):
        output = kli(tmp_path, 'vc', 'registry', 'incept', *common, '--version', '2.0',
            '--alias', 'issuer', '--registry-name', 'refused', *options, succeeds=False)
        assert reason in output
        hby = setupHby(name=name, base=base, noPrompt=True, version=Vrsn_2_0)
        rgy = Regery(hby=hby, name=name, base=base)
        try:
            assert hby.habByName('issuer').kever.serder.said == initial
            assert hby.habByName('group').kever.serder.said == group_head
            assert list(rgy.names) == []
            assert list(rgy.baser.evts.getTopItemIter()) == []
            assert list(hby.ks.rroots.getTopItemIter()) == []
        finally:
            rgy.close()
            hby.close()
