"""Random root preparation remains encrypted, recoverable and inactive until approval."""

from dataclasses import replace
from pathlib import Path

import pytest

from keri.acdc import Registrar
from keri.app.credentialing import WalletBaser
from keri.app.registry_custody import EncryptedCustody, RegistryCustody
from keri.core import Diger, Signer
from keri.kering import AuthError, ConfigurationError, ValidationError
from tests.app.test_registry_root_retention import roots
from tests.app.test_acdc_v2_wallet import encrypted, anchored, regery


def test_candidate_recovers_after_all_owners_close(tmp_path):
    """A fresh Keeper and registry/wallet owners recover the exact pending salt."""
    key = Signer(transferable=False)
    for reopened in (False, True):
        with encrypted('candidate-restart', tmp_path, key) as hby:
            rgy = regery(hby, tmp_path)
            db = WalletBaser(name=hby.name, headDirPath=str(tmp_path))
            try:
                custody = RegistryCustody(hby, rgy, db=db)
                if not reopened:
                    issuer = hby.makeHab(name='issuer')
                    registry = Registrar(rgy=rgy).makeRegistry(name='candidate', prefix=issuer.pre)
                    anchored(issuer, registry, rgy.store.event(registry.regk))
                    regid = registry.regk
                    original = custody.createCandidate(regid)
                else:
                    recovered = custody.createCandidate(regid)
                    assert recovered.expected == original.expected
                    assert recovered.root.qb64 == original.root.qb64
                    assert db.custody.get((regid,)) is None
            finally:
                db.close()
                rgy.close()


def test_candidate_reopen_preserves_cipher_and_does_not_enable_derivation(roots):
    """No active custody or root regeneration occurs before assignment acceptance."""
    custody, info, _, _, _ = roots
    candidate = custody.createCandidate(info.registry)
    assert candidate.info.controller == candidate.info.discloser == info.controller
    assert custody.createCandidate(info.registry).root.qb64 == candidate.root.qb64
    assert custody.candidate(info.registry).expected == candidate.expected
    assert custody.db.custody.get((info.registry,)) is None
    with pytest.raises(ConfigurationError, match='not provisioned'):
        custody.derive(info.registry, 1, Diger(ser=b'credential').qb64, 'issued')
    custody.db.close()
    custody.db.reopen()
    reopened = custody.createCandidate(info.registry)
    assert reopened.expected == candidate.expected
    assert reopened.root.qb64 == candidate.root.qb64
    assert candidate.root.qb64 not in repr(candidate)
    stored = Path(custody.db.path, 'data.mdb').read_bytes()
    assert candidate.root.raw not in stored and candidate.root.qb64b not in stored


def test_candidate_activation_and_retirement_share_the_caller_transaction(roots):
    """A failed authorization commit leaves the recoverable candidate inactive."""
    custody, info, _, _, _ = roots
    candidate = custody.createCandidate(info.registry)
    prepared = custody.prepareRoot(candidate.info, candidate.root)
    with pytest.raises(RuntimeError, match='authorization rollback'):
        with custody.db.env.begin(write=True) as txn:
            custody.retainPrepared(prepared, txn)
            custody.retireCandidate(candidate, txn)
            raise RuntimeError('authorization rollback')
    assert custody.candidate(info.registry).expected == candidate.expected
    assert custody.db.custody.get((info.registry,)) is None
    with custody.db.env.begin(write=True) as txn:
        custody.retainPrepared(prepared, txn)
        custody.retireCandidate(candidate, txn)
    assert custody._load(info.registry).salt == candidate.root.qb64
    with pytest.raises(ConfigurationError, match='not prepared'):
        custody.candidate(info.registry)
    with pytest.raises(ConfigurationError, match='explicitly adopt'):
        custody.createCandidate(info.registry)


def test_changed_candidate_prevents_activation_transaction(roots):
    """A stale draft cannot erase another candidate while committing its own salt."""
    custody, info, _, _, _ = roots
    candidate = custody.createCandidate(info.registry)
    prepared = custody.prepareRoot(candidate.info, candidate.root)
    # The public operation cannot overwrite a candidate. Inject a concurrent
    # row change directly to exercise its transactional compare-and-swap guard.
    changed = replace(custody.db.saltCandidates.get((info.registry,)), cipher='changed')
    custody.db.saltCandidates.pin((info.registry,), changed)
    with pytest.raises(ValidationError, match='candidate changed'):
        with custody.db.env.begin(write=True) as txn:
            custody.retainPrepared(prepared, txn)
            custody.retireCandidate(candidate, txn)
    assert custody.db.custody.get((info.registry,)) is None
    assert custody.db.saltCandidates.get((info.registry,)) == changed


@pytest.mark.parametrize('failure', ['cipher', 'row', 'keeper', 'locked'])
def test_candidate_failure_never_regenerates(roots, monkeypatch, failure):
    """Corrupt ciphertext, malformed storage and Keeper changes fail closed."""
    custody, info, _, _, _ = roots
    candidate = custody.createCandidate(info.registry)
    key = (info.registry,)
    if failure == 'cipher':
        custody.db.saltCandidates.pin(key, EncryptedCustody(custody.hby.mgr.aeid, 'invalid'))
    elif failure == 'row':
        with custody.db.env.begin(write=True) as txn:
            txn.put(custody.db.saltCandidates._tokey(key), b'bad-json', db=custody.db.saltCandidates.sdb)
    elif failure == 'keeper':
        signer = Signer(transferable=False)
        custody.hby.mgr.updateAeid(signer.verfer.qb64, signer.qb64)
    else:
        monkeypatch.setattr(custody.hby.mgr, 'decrypter', None)
    with custody.db.env.begin() as txn:
        before = txn.get(custody.db.saltCandidates._tokey(key), db=custody.db.saltCandidates.sdb)
    for operation in (custody.candidate, custody.createCandidate):
        with pytest.raises(AuthError) as error:
            operation(info.registry)
        assert candidate.root.qb64 not in str(error.value)
    with custody.db.env.begin() as txn:
        assert txn.get(custody.db.saltCandidates._tokey(key), db=custody.db.saltCandidates.sdb) == before
    assert custody.db.custody.get(key) is None


def test_unknown_registry_cannot_create_a_candidate(roots):
    """A local request cannot create salt custody for an unaccepted registry."""
    custody, _, _, _, _ = roots
    unknown = Diger(ser=b'not accepted').qb64
    with pytest.raises(ValidationError, match='accepted local issuer'):
        custody.createCandidate(unknown)
    assert custody.db.saltCandidates.get((unknown,)) is None
