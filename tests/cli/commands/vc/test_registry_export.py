"""Public registry bootstrap is a real KLI operation with no issued inventory."""
import json
import uuid


from keri import Vrsn_2_0
from keri.core import Diger, Parser
from tests.app.test_acdc_v2_cli import command, invoke


def test_public_registry_export_needs_no_credential_and_creates_exclusively(tmp_path):
    """Export an accepted rip/controller KEL through installed, reopened KLI stores."""
    name = 'registry-proof-' + uuid.uuid4().hex
    config = tmp_path / 'identity.json'
    config.write_text(json.dumps(dict(transferable=True, wits=[], toad=0,
                                     icount=1, isith='1', ncount=1, nsith='1')))
    invoke(name, 'init', '--version', '2.0')
    invoke(name, 'incept', '-a', 'issuer', '--version', '2.0', '--file', str(config))
    registry = invoke(name, 'vc', 'registry', 'incept', '--acdc-v2',
                      '-a', 'issuer', '-r', 'registry')[0]['registry']
    assert invoke(name, 'vc', 'list', '--acdc-v2') == []
    output = tmp_path / 'public-registry.cesr'
    result = invoke(name, 'vc', 'registry', 'export', '--registry', registry, '--output', str(output))[0]
    assert result['accepted'] and result['registry'] == result['head'] == registry
    frames = Parser(version=Vrsn_2_0).parse(ims=bytearray(output.read_bytes()), processive=False)
    assert [frame.serder.ilk for frame in frames] == ['icp', 'ixn', 'rip']
    assert frames[-1].serder.said == registry
    assert all(not frame.bsqs and not frame.bsss for frame in frames)
    previous = output.read_bytes()
    refused = command(name, 'vc', 'registry', 'export', '--registry', registry, '--output', str(output))
    assert refused.returncode != 0
    assert output.read_bytes() == previous
    absent = tmp_path / 'unknown.cesr'
    refused = command(name, 'vc', 'registry', 'export', '--registry',
                      Diger(ser=b'unknown registry').qb64, '--output', str(absent))
    assert refused.returncode != 0 and not absent.exists()
