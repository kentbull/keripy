"""Supplied registry roots share the wallet's existing atomic storage boundary."""
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path

import pytest

from keri.acdc import Registrar
from keri.app.credentialing import WalletBaser
from keri.app.registry_custody import CustodyInfo, RegistryCustody
from keri.core import Encrypter, MtrDex, Salter, Signer
from keri.kering import AuthError, ValidationError
from tests.app.test_acdc_v2_wallet import encrypted, anchored, regery


@pytest.fixture
def roots(tmp_path):
    """Yield accepted registries and authenticated Keeper custody in real stores."""
    with ExitStack() as stack:
        hby = stack.enter_context(encrypted('root-retention', tmp_path, Signer(transferable=False)))
        issuer = hby.makeHab(name='issuer')
        recipient = hby.makeHab(name='recipient')
        rgy = regery(hby, tmp_path)
        stack.callback(rgy.close)
        db = WalletBaser(name=hby.name, headDirPath=str(tmp_path))
        stack.callback(db.close)
        custody = RegistryCustody(hby, rgy, db=db)
        registry = Registrar(rgy=rgy).makeRegistry(name='root', prefix=issuer.pre)
        anchored(issuer, registry, rgy.store.event(registry.regk))
        info = CustodyInfo(registry.regk, issuer.pre, recipient.pre)
        root = Salter(raw=b'0123456789abcdef')
        yield custody, info, root, issuer, recipient


def retain(custody, prepared):
    """Use one caller-owned transaction, as the future domain owner will do."""
    with custody.db.env.begin(write=True) as txn:
        return custody.retainPrepared(prepared, txn)


def test_supplied_root_is_immutable_idempotent_and_never_plaintext(roots, capsys):
    """Preserve supplied bytes and metadata without random regeneration or logging."""
    custody, info, root, _, recipient = roots
    prepared = custody.prepareRoot(info, root)
    assert custody.db.custody.get((info.registry,)) is None
    assert root.qb64 not in repr(prepared)
    assert root.qb64b not in prepared.encrypted
    assert retain(custody, prepared)
    first = custody.db.custody.get((info.registry,))
    assert root.qb64 not in repr(first)
    assert not retain(custody, custody.prepareRoot(info, root))
    assert custody.db.custody.get((info.registry,)) == first
    sealed = custody.sealRoot(info.registry, Encrypter(verkey=recipient.kever.verfers[0].qb64))
    assert custody.openRoot(sealed, recipient.kever.verfers[0]).qb64 == root.qb64
    with pytest.raises(ValidationError, match='different registry custody'):
        custody.prepareRoot(info, Salter(raw=b'fedcba9876543210'))
    with pytest.raises(ValidationError, match='different registry custody'):
        custody.prepareRoot(replace(info, discloser=info.controller), root)
    assert custody.db.custody.get((info.registry,)) == first
    stored = Path(custody.db.path, 'data.mdb').read_bytes()
    assert root.qb64b not in stored and root.raw not in stored
    captured = capsys.readouterr()
    assert root.qb64 not in captured.out + captured.err


def test_caller_rollback_keeps_all_custody_unchanged(roots):
    """An application failure rolls back multiple prepared root writes together."""
    custody, info, root, issuer, _ = roots
    second = Registrar(rgy=custody.rgy).makeRegistry(name='second', prefix=issuer.pre)
    anchored(issuer, second, custody.rgy.store.event(second.regk))
    other = replace(info, registry=second.regk)
    prepared = custody.prepareRoot(info, root)
    another = custody.prepareRoot(other, Salter(raw=b'fedcba9876543210'))
    with pytest.raises(RuntimeError, match='application rollback'):
        with custody.db.env.begin(write=True) as txn:
            assert custody.retainPrepared(prepared, txn)
            assert custody.retainPrepared(another, txn)
            raise RuntimeError('application rollback')
    assert custody.db.custody.get((info.registry,)) is None
    assert custody.db.custody.get((other.registry,)) is None
    assert retain(custody, prepared)
    assert retain(custody, another)


def test_prepared_cas_cannot_replace_concurrently_retained_root(roots):
    """Preparation is not a lock; an intervening root makes the old CAS fail."""
    custody, info, root, _, _ = roots
    stale = custody.prepareRoot(info, root)
    replacement = custody.prepareRoot(info, Salter(raw=b'fedcba9876543210'))
    assert retain(custody, replacement)
    previous = custody.db.custody.get((info.registry,))
    with pytest.raises(ValidationError, match='changed during prepared retention'):
        retain(custody, stale)
    assert custody.db.custody.get((info.registry,)) == previous


def test_keeper_identity_change_invalidates_preparation_and_existing_custody(roots):
    """AEID rotation neither commits an old prepared cipher nor rewraps a root."""
    custody, info, root, _, _ = roots
    assert retain(custody, custody.prepareRoot(info, root))
    prepared = custody.prepareRoot(info, root)
    previous = custody.db.custody.get((info.registry,))
    replacement = Signer(transferable=False)
    custody.hby.mgr.updateAeid(replacement.verfer.qb64, replacement.qb64)
    with pytest.raises(AuthError, match='authenticated Keeper'):
        retain(custody, prepared)
    with pytest.raises(AuthError, match='AEID changed'):
        custody.prepareRoot(info, root)
    assert custody.db.custody.get((info.registry,)) == previous


def test_root_seal_uses_exact_recipient_key_and_retained_historical_seed(roots):
    """Wrong and rotated current keys fail while the exact retained old key works."""
    custody, info, root, issuer, recipient = roots
    assert retain(custody, custody.prepareRoot(info, root))
    original = recipient.kever.verfers[0]
    sealed = custody.sealRoot(info.registry, Encrypter(verkey=original.qb64))
    assert sealed.code == MtrDex.X25519_Cipher_Salt
    assert custody.openRoot(sealed.qb64, original).qb64 == root.qb64
    with pytest.raises(AuthError, match='unable to open encrypted registry root'):
        custody.openRoot(sealed, issuer.kever.verfers[0])
    recipient.rotate()
    with pytest.raises(AuthError, match='unable to open encrypted registry root'):
        custody.openRoot(sealed, recipient.kever.verfers[0])
    assert custody.openRoot(sealed, original).qb64 == root.qb64
    with pytest.raises(ValidationError, match='unsupported'):
        custody.openRoot(sealed.qb64 + 'AAAA', original)


def test_root_preparation_checks_profile_registry_and_keeper_without_role_inference(roots, monkeypatch):
    """Structural custody guards do not mistake original metadata for entitlement."""
    custody, info, root, _, recipient = roots
    with pytest.raises(ValidationError, match='fixed custody profile'):
        custody.prepareRoot(replace(info, version=2), root)
    with pytest.raises(ValidationError, match='accepted registry controller'):
        custody.prepareRoot(replace(info, controller=recipient.pre), root)
    with pytest.raises(ValidationError, match='Salt_128'):
        custody.prepareRoot(info, root.qb64)
    # The network domain, rather than this metadata, must authorize the actual
    # recipient. Preparing valid original metadata does not require its local Hab.
    remote = Signer().verfer.qb64
    assert custody.prepareRoot(replace(info, discloser=remote), root).expected is None
    monkeypatch.setattr(custody.hby.mgr, 'decrypter', None)
    with pytest.raises(AuthError, match='authenticated encrypted Keeper'):
        custody.prepareRoot(info, root)
