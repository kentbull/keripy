"""Real schema-import commands preserve the existing Keeper identity policy."""

import os
import subprocess
import sys
import uuid

import pytest

from keri.app import Keeper, openHby
from keri.core import Schemer


pytestmark = pytest.mark.real_store_roots


PASSCODE = '0123456789abcdefghijk'  # Public test-only passcode.


def keeper_aeid(name, base):
    keeper = Keeper(name=name, base=base, reopen=True)
    try:
        return keeper.gbls.get('aeid')
    finally:
        keeper.close()


@pytest.mark.parametrize('encrypted', [False, True], ids=['unencrypted', 'encrypted'])
@pytest.mark.parametrize('source', ['explicit', 'environment'])
def test_schema_import_preserves_existing_keeper_policy(tmp_path, encrypted, source):
    name, base = 'schema-import-' + uuid.uuid4().hex, 'schema-import-policy'
    bran = PASSCODE if encrypted else None
    schema = Schemer(sed={'$id': '', '$schema': 'http://json-schema.org/draft-07/schema#',
                          'type': 'object', 'properties': {'name': {'type': 'string'}}})
    schema_file = tmp_path / 'schema.json'
    schema_file.write_bytes(schema.raw)
    with openHby(name=name, base=base, temp=False, bran=bran) as hby:
        pre = hby.makeHab(name='self').pre
        assert hby.db.schema.get((schema.said,)) is None
    original = keeper_aeid(name, base)
    assert bool(original) is encrypted

    def invoke(passcode):
        command = [sys.executable, '-m', 'keri.cli.kli', 'vc', 'schema', 'import_',
                   '--name', name, '--base', base, '--schema', str(schema_file), '--no-prompt']
        env = dict(os.environ, KLI_KEYSTORE_PASSCODE=passcode)
        if source == 'explicit':
            command.extend(['--passcode', passcode])
            env['KLI_KEYSTORE_PASSCODE'] = 'abcdefghijklmnopqrstu'  # Flag takes precedence.
        return subprocess.run(command, env=env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=10)

    if encrypted:
        refused = invoke('abcdefghijklmnopqrstu')
        assert 'ERR:' in refused.stdout or refused.returncode != 0
        assert 'Schema successfully imported' not in refused.stdout
        assert 'Valid passcode required' not in refused.stdout
        assert keeper_aeid(name, base) == original
        with openHby(name=name, base=base, temp=False, bran=bran) as hby:
            assert hby.db.schema.get((schema.said,)) is None

    imported = invoke(PASSCODE)
    assert imported.returncode == 0 and 'ERR:' not in imported.stdout, imported.stdout + imported.stderr
    assert 'Schema successfully imported' in imported.stdout
    assert keeper_aeid(name, base) == original
    with openHby(name=name, base=base, temp=False, bran=bran) as hby:
        assert hby.db.schema.get((schema.said,)).raw == schema.raw
        hab = hby.habByName('self')
        assert hab.pre == pre
        siger = hby.mgr.sign(ser=b'after schema import', verfers=hab.kever.verfers)[0]
        assert hab.kever.verfers[siger.index].verify(siger.raw, b'after schema import')
