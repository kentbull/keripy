"""Installed schema import preserves existing Keeper authentication policy."""
import os
import subprocess
import sys
import uuid

import pytest

from keri.app import Keeper, openHby


PASSCODE = '0123456789abcdefghijk'  # public test fixture only


def keeper_aeid(name, base):
    """Read the exact persisted Keeper AEID without opening an identity manager.

    Args:
        name (str): Existing test environment name.
        base (str): Test-owned persistent environment namespace.

    Returns:
        str: Stored encryption AID, or the empty string for an unencrypted Keeper.
        Storage errors propagate; the independently opened Keeper always closes.
    """
    keeper = Keeper(name=name, base=base, reopen=True)
    try:
        return keeper.gbls.get('aeid')
    finally:
        keeper.close()


@pytest.mark.parametrize('encrypted', [False, True], ids=['unencrypted', 'encrypted'])
def test_schema_import_preserves_keeper_aeid(tmp_path, seeder, encrypted):
    """Import a real schema using an environment passcode without migrating AEID.

    Args:
        tmp_path (Path): Pytest-owned public schema transfer file.
        seeder: Normal schema fixture; supplies schema evidence only.
        encrypted (bool): Whether the existing identity initially requires a passcode.

    Returns:
        None. Actual installed CLI processes must import the exact schema while
        preserving each Keeper's original AEID. A wrong passcode for the encrypted
        identity must fail before importing or changing AEID. Stores are reopened
        with their original authentication mode and always closed by their contexts.

    Raises:
        AssertionError: Authentication, stored schema, or AEID differs from contract.
        TimeoutExpired: A CLI invocation exceeds the bounded subprocess deadline.
    """
    name = 'schema-import-' + uuid.uuid4().hex
    base = 'schema-import-cli'
    bran = PASSCODE if encrypted else None
    schema_said = 'EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC'
    with openHby(name='schema-import-fixture') as fixture:
        seeder.seedSchema(fixture.db)
        schema = fixture.db.schema.get((schema_said,))
        schema_file = tmp_path / 'schema.json'
        schema_file.write_bytes(schema.raw)
    with openHby(name=name, base=base, temp=False, bran=bran) as hby:
        hby.makeHab(name='self')
        assert hby.db.schema.get((schema_said,)) is None
    original = keeper_aeid(name, base)
    assert bool(original) is encrypted

    def invoke(passcode):
        """Run installed schema import with passcode in the subprocess environment.

        passcode is a public fixture value. Return CompletedProcess with actual
        exit/output; --no-prompt rejects an incorrect passcode without an
        interactive retry. Process I/O and the ten-second timeout propagate.
        """
        return subprocess.run([sys.executable, '-m', 'keri.cli.kli', 'vc', 'schema',
            'import_', '--name', name, '--base', base, '--schema', str(schema_file),
            '--no-prompt'],
            env=dict(os.environ, KLI_KEYSTORE_PASSCODE=passcode),
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)

    if encrypted:
        refused = invoke('abcdefghijklmnopqrstu')
        assert refused.returncode != 0 or 'ERR:' in refused.stdout, refused.stdout + refused.stderr
        assert 'Schema successfully imported' not in refused.stdout
        assert keeper_aeid(name, base) == original
        with openHby(name=name, base=base, temp=False, bran=bran) as hby:
            assert hby.db.schema.get((schema_said,)) is None

    imported = invoke(PASSCODE)
    assert imported.returncode == 0 and 'ERR:' not in imported.stdout, imported.stdout + imported.stderr
    assert f'Schema successfully imported with SAID: {schema_said}' in imported.stdout
    assert keeper_aeid(name, base) == original
    with openHby(name=name, base=base, temp=False, bran=bran) as hby:
        assert hby.db.schema.get((schema_said,)).raw == schema.raw
        assert hby.mgr.aeid == original
