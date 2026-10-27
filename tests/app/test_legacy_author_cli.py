"""Real author commands preserve protocol versions and schema authentication."""
import json
import os
import subprocess
import sys
import uuid

import pytest
from keri import Vrsn_1_0, Vrsn_2_0
from keri.core import Parser, Schemer


@pytest.mark.parametrize('version', ['1.0', '2.0'])
def test_cli_registry_issue_revoke_keeps_selected_version(tmp_path, version):
    """Author through actual CLI and inspect exported proofs for both versions.

    tmp_path owns JSON/CESR files; version selects legacy v1 or explicit ACDC v2
    commands. Return None. CLI timeouts/errors and any mixed-version exported KEL
    body fail assertions. No fixture installs accepted events or credentials.
    """
    name = 'author-version-' + uuid.uuid4().hex
    base = 'author-protocol-cli'
    env = dict(os.environ, KLI_KEYSTORE_PASSCODE='0123456789abcdefghijk')

    def invoke(*args):
        """Return stdout from bounded real CLI args over this encrypted environment.

        Nonzero exits, KLI ERR output and timeouts raise test failures, never a
        synthetic accepted result. Only public command tokens are logged.
        """
        result = subprocess.run([sys.executable, '-m', 'keri.cli.kli', *args,
            '--name', name, '--base', base], env=env, capture_output=True, text=True, timeout=20)
        assert result.returncode == 0 and 'ERR:' not in result.stdout, result.stdout + result.stderr
        return result.stdout

    options = tmp_path / 'inception.json'
    options.write_text(json.dumps(dict(transferable=True, wits=[], toad=0,
        icount=1, isith='1', ncount=1, nsith='1')))
    invoke('init', '--version', version)
    invoke('incept', '-a', 'issuer', '--version', version, '--file', str(options))
    acdc_v2 = ['--acdc-v2'] if version == '2.0' else []
    create = []
    if version == '1.0':
        schema = Schemer(sed={'$id': '', '$schema': 'http://json-schema.org/draft-07/schema#',
            'type': 'object', 'properties': {'a': {'type': 'object'}}, 'required': ['a']})
        schemaFile = tmp_path / 'schema.json'
        schemaFile.write_bytes(schema.raw)
        invoke('vc', 'schema', 'import_', '--schema', str(schemaFile))
        create = ['--schema', schema.said]
    else:
        create = ['--public']
    invoke('vc', 'registry', 'incept', *acdc_v2, '-a', 'issuer', '-r', 'r')
    issued = invoke('vc', 'create', *acdc_v2, '-a', 'issuer', '-r', 'r', *create,
                    '--data', '{"status":"authorized"}')
    if acdc_v2:
        credential = next(json.loads(line)['credential'] for line in issued.splitlines() if line.startswith('{'))
    else:
        credential = invoke('vc', 'list', '-a', 'issuer', '--issued', '--said').strip()
    assert len(credential) == 44
    invoke('vc', 'revoke', *acdc_v2, '-a', 'issuer', '-r', 'r',
           *(['--public'] if acdc_v2 else []), '--said', credential)
    kel = tmp_path / 'issuer.cesr'
    invoke('kel', 'export', '-a', 'issuer', '--version', version, '--output', str(kel))
    expected = Vrsn_1_0 if version == '1.0' else Vrsn_2_0
    remaining, events = bytearray(kel.read_bytes()), []
    while remaining:
        dom = Parser(version=expected).parseOne(ims=remaining, processive=False)
        events.append(dom.serder)
    assert len(events) == 4  # inception plus actual registry/issuance/revocation anchors
    assert all(event.pvrsn == expected for event in events)
    assert all(event.ilk == 'ixn' and event.seals for event in events[1:])
