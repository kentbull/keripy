"""Encrypted, immutable registry-root custody in the existing Keeper owner."""

import pytest

from keri.app import Manager, openKS
from keri.core import Diger, Encrypter, MtrDex, Salter, Signer
from keri.kering import AuthError, ValidationError


OLD = Signer(raw=b'A' * 32, transferable=False)
NEW = Signer(raw=b'B' * 32, transferable=False)
WRONG = Signer(raw=b'C' * 32, transferable=False)
AID = Diger(ser=b'local AID').qb64
REGISTRY = Diger(ser=b'registry').qb64
ROOT = Salter(raw=b'0123456789abcdef')
OTHER = Salter(raw=b'fedcba9876543210')


def encrypted_manager(keeper, signer=OLD):
    return Manager(ks=keeper, seed=signer.qb64, aeid=signer.verfer.qb64)


def test_registry_root_ciphertext_survives_reopen_and_wrong_unlock(tmp_path):
    options = dict(name='registry-roots', temp=False, headDirPath=str(tmp_path))
    with openKS(**options) as keeper:
        manager = encrypted_manager(keeper)
        assert manager.getRegistryRoot(AID, REGISTRY) is None
        assert manager.putRegistryRoot(AID, REGISTRY, ROOT) is True
        cipher = keeper.rroots.get((AID, REGISTRY))
        assert cipher.code == MtrDex.X25519_Cipher_Salt
        assert cipher.qb64 != ROOT.qb64
        assert ROOT.qb64b not in cipher.qb64b
        retained = cipher.qb64

    with openKS(**options) as keeper:
        with pytest.raises(AuthError):
            encrypted_manager(keeper, WRONG)
        manager = encrypted_manager(keeper)
        assert keeper.rroots.get((AID, REGISTRY)).qb64 == retained
        assert manager.getRegistryRoot(AID, REGISTRY).qb64 == ROOT.qb64
        assert manager.putRegistryRoot(AID, REGISTRY, ROOT) is False
        assert keeper.rroots.get((AID, REGISTRY)).qb64 == retained


def test_registry_root_is_immutable_and_scoped_to_aid_and_registry():
    with openKS() as keeper:
        manager = encrypted_manager(keeper)
        assert manager.putRegistryRoot(AID, REGISTRY, ROOT) is True
        retained = keeper.rroots.get((AID, REGISTRY)).qb64
        assert manager.putRegistryRoot(AID, REGISTRY, ROOT) is False
        with pytest.raises(ValidationError):
            manager.putRegistryRoot(AID, REGISTRY, OTHER)
        assert keeper.rroots.get((AID, REGISTRY)).qb64 == retained
        other_aid = Diger(ser=b'other local AID').qb64
        other_reg = Diger(ser=b'other registry').qb64
        assert manager.putRegistryRoot(other_aid, REGISTRY, OTHER) is True
        assert manager.putRegistryRoot(AID, other_reg, OTHER) is True
        assert manager.getRegistryRoot(AID, REGISTRY).qb64 == ROOT.qb64
        assert manager.getRegistryRoot(other_aid, REGISTRY).qb64 == OTHER.qb64
        assert manager.getRegistryRoot(AID, other_reg).qb64 == OTHER.qb64
        assert manager.getRegistryRoot(other_aid, other_reg) is None


@pytest.mark.parametrize('aid,regid', [(AID + '1AAP', REGISTRY),
                                     (AID, REGISTRY + '1AAP'),
                                     ('invalid', REGISTRY), (AID, ROOT.qb64)],
                         ids=['trailing-aid', 'trailing-registry', 'invalid-aid', 'non-digest'])
def test_registry_root_keys_require_canonical_complete_primitives(aid, regid):
    with openKS() as keeper:
        manager = encrypted_manager(keeper)
        with pytest.raises(ValidationError):
            manager.putRegistryRoot(aid, regid, ROOT)
        with pytest.raises(ValidationError):
            manager.getRegistryRoot(aid, regid)
        assert list(keeper.rroots.getTopItemIter()) == []


def test_registry_root_requires_encryption_and_salt_primitive():
    with openKS() as keeper:
        manager = Manager(ks=keeper)
        assert manager.getRegistryRoot(AID, REGISTRY) is None
        with pytest.raises(AuthError):
            manager.putRegistryRoot(AID, REGISTRY, ROOT)
        assert list(keeper.rroots.getTopItemIter()) == []
        # Refuse an existing cipher even if the store policy was corrupted outside Manager.
        keeper.rroots.put((AID, REGISTRY), Encrypter(verkey=OLD.verfer.qb64).encrypt(prim=ROOT))
        with pytest.raises(AuthError):
            manager.getRegistryRoot(AID, REGISTRY)

    with openKS() as keeper:
        manager = encrypted_manager(keeper)
        with pytest.raises(ValidationError):
            manager.putRegistryRoot(AID, REGISTRY, OLD)
        assert list(keeper.rroots.getTopItemIter()) == []


def test_update_aeid_rewraps_registry_roots_and_reopens(tmp_path):
    options = dict(name='registry-roots-rekey', temp=False, headDirPath=str(tmp_path))
    with openKS(**options) as keeper:
        manager = encrypted_manager(keeper)
        verfers, _ = manager.incept(temp=True)
        manager.putRegistryRoot(AID, REGISTRY, ROOT)
        other_reg = Diger(ser=b'second retained registry').qb64
        manager.putRegistryRoot(AID, other_reg, OTHER)
        before = keeper.rroots.get((AID, REGISTRY)).qb64
        manager.updateAeid(NEW.verfer.qb64, NEW.qb64)
        assert manager.aeid == NEW.verfer.qb64
        assert keeper.rroots.get((AID, REGISTRY)).qb64 != before
        assert manager.getRegistryRoot(AID, REGISTRY).qb64 == ROOT.qb64
        assert manager.getRegistryRoot(AID, other_reg).qb64 == OTHER.qb64
        signatures = manager.sign(ser=b'after rekey', verfers=verfers)
        assert verfers[0].verify(signatures[0].raw, b'after rekey')

    with openKS(**options) as keeper:
        with pytest.raises(AuthError):
            encrypted_manager(keeper, OLD)
        manager = encrypted_manager(keeper, NEW)
        assert manager.getRegistryRoot(AID, REGISTRY).qb64 == ROOT.qb64
        assert manager.getRegistryRoot(AID, other_reg).qb64 == OTHER.qb64
        signatures = manager.sign(ser=b'after reopen', verfers=verfers)
        assert verfers[0].verify(signatures[0].raw, b'after reopen')


def test_update_aeid_cannot_remove_encryption_with_retained_roots():
    with openKS() as keeper:
        manager = encrypted_manager(keeper)
        manager.putRegistryRoot(AID, REGISTRY, ROOT)
        globals_before = list(keeper.gbls.getTopItemIter())
        cipher_before = keeper.rroots.get((AID, REGISTRY)).qb64
        encrypter, decrypter, seed = manager.encrypter, manager.decrypter, manager.seed
        with pytest.raises(AuthError):
            manager.updateAeid('', '')
        assert list(keeper.gbls.getTopItemIter()) == globals_before
        assert keeper.rroots.get((AID, REGISTRY)).qb64 == cipher_before
        assert manager.encrypter is encrypter
        assert manager.decrypter is decrypter
        assert manager.seed == seed
        assert manager.getRegistryRoot(AID, REGISTRY).qb64 == ROOT.qb64


@pytest.mark.parametrize('replacement', [OLD, NEW], ids=['same-aeid', 'new-aeid'])
def test_bad_replacement_key_cannot_mutate_manager_or_keeper(replacement):
    with openKS() as keeper:
        manager = encrypted_manager(keeper)
        globals_before = list(keeper.gbls.getTopItemIter())
        encrypter, decrypter, seed = manager.encrypter, manager.decrypter, manager.seed
        with pytest.raises(AuthError):
            manager.updateAeid(replacement.verfer.qb64, WRONG.qb64)
        assert list(keeper.gbls.getTopItemIter()) == globals_before
        assert manager.encrypter is encrypter
        assert manager.decrypter is decrypter
        assert manager.seed == seed
        assert manager.salt is not None


def test_update_aeid_still_allows_removal_without_registry_roots():
    with openKS() as keeper:
        manager = encrypted_manager(keeper)
        salt = manager.salt
        manager.updateAeid('', '')
        assert manager.aeid == ''
        assert manager.encrypter is manager.decrypter is None
        assert manager.salt == salt
