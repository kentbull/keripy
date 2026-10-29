"""Real encrypted negotiation recovery and atomic root/origin/delivery retention."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from keri.app import registry_salts, registry_salt_replies as replies
from keri.app.group_members import acceptedRoster
from keri.app.registry_custody import EncryptedCustody
from keri.app.registry_salt_state import RegistrySaltState, SaltOrigin, SaltDelivery
from keri.core import Diger, Salter, Signer
from keri.kering import AuthError, ConfigurationError, ValidationError
from tests.app.test_registry_root_retention import roots
from tests.app.test_acdc_v2_wallet import encrypted
from tests.app.test_acdc_v2_groups import members


@pytest.fixture
def negotiation(roots):
    """Build exact two-party replies, independent ephemeral keys, and a DH root."""
    custody, info, _, issuer, discloser = roots
    state = RegistrySaltState(custody)
    left, leftPrivate = registry_salts.generateKeypair()
    right, rightPrivate = registry_salts.generateKeypair()
    init = replies.initReply(sender=issuer.pre, issuer=issuer.pre, discloser=discloser.pre,
        rep=issuer.pre, est=dict(s=f'{issuer.kever.lastEst.s:x}', d=issuer.kever.lastEst.d),
        key=left.qb64)
    rip = custody.rgy.store.seqEvent(info.registry, 0)
    bind = replies.bindReply(init, rip, sender=discloser.pre, rep=discloser.pre,
        est=dict(s=f'{discloser.kever.lastEst.s:x}', d=discloser.kever.lastEst.d), key=right.qb64)
    root = registry_salts.deriveRoot(leftPrivate, right, init.raw, bind.raw)
    confirm = replies.confirmReply(init, bind, rip, root)
    origin = SaltOrigin(info.registry, info.controller, info.discloser, init.said,
                        bind.said, confirm.said, confirm.sad['a']['commitment'])
    jobs = tuple(SaltDelivery(info.registry, hab.pre, hab.pre, hab.kever.lastEst.d, confirm.said)
                 for hab in (issuer, discloser))
    yield SimpleNamespace(state=state, custody=custody, info=info, issuer=issuer,
        discloser=discloser, init=init, bind=bind, root=root, origin=origin,
        private=leftPrivate, otherPrivate=rightPrivate, jobs=jobs, confirm=confirm)


def retainPending(case):
    """Retain the initiating representative's actual exact reply/private key."""
    return case.state.retainPending(case.init.said, case.issuer.pre, case.init.raw, case.private)


def test_pending_reopen_retains_exact_bytes_and_never_plaintext(negotiation, capsys):
    """Reopening the wallet preserves the original private key and reply bytes."""
    case = negotiation
    original = retainPending(case)
    encrypted = case.state.db.saltPending.get((case.init.said, case.issuer.pre))
    assert retainPending(case) == original
    assert case.state.db.saltPending.get((case.init.said, case.issuer.pre)) == encrypted
    case.state.db.close()
    case.state.db.reopen()
    reopened = RegistrySaltState(case.custody).openPending(case.init.said, case.issuer.pre)
    assert reopened == original and reopened.body == case.init.raw
    assert reopened.private == case.private.qb64
    assert case.private.qb64 not in repr(reopened)
    assert case.private.qb64 not in repr(encrypted)
    assert case.private.qb64b not in Path(case.state.db.path, 'data.mdb').read_bytes()
    captured = capsys.readouterr()
    assert case.private.qb64 not in captured.out + captured.err


def test_pending_recovers_after_all_identity_and_wallet_owners_close(tmp_path):
    """A new authenticated Manager recovers saved DH state without private caches."""
    from keri.app.credentialing import WalletBaser
    from keri.app.registry_custody import RegistryCustody

    key = Signer(transferable=False)
    for reopened in (False, True):
        with encrypted('pending-owner-restart', tmp_path, key) as hby:
            db = WalletBaser(name=hby.name, headDirPath=str(tmp_path))
            try:
                # Init precedes registry creation. This operation needs Keeper
                # authentication and local identity, but no TEL state yet.
                state = RegistrySaltState(RegistryCustody(hby, None, db=db))
                if not reopened:
                    rep, other = hby.makeHab(name='rep'), hby.makeHab(name='other')
                    public, private = registry_salts.generateKeypair()
                    init = replies.initReply(sender=rep.pre, issuer=rep.pre, discloser=other.pre,
                        rep=rep.pre, est=dict(s='0', d=rep.kever.lastEst.d), key=public.qb64)
                    saved = state.retainPending(init.said, rep.pre, init.raw, private)
                else:
                    assert hby.habByPre(rep.pre).accepted
                    assert state.openPending(init.said, rep.pre) == saved
                    assert state.retainPending(init.said, rep.pre, init.raw, private) == saved
            finally:
                db.close()


def test_pending_refuses_new_key_or_reply_under_same_attempt(negotiation):
    """An accepted init cannot be resumed using a newly generated bind/private key."""
    case = negotiation
    saved = case.state.retainPending(case.init.said, case.discloser.pre,
                                    case.bind.raw, case.otherPrivate)
    _, different = registry_salts.generateKeypair()
    with pytest.raises(ValidationError, match='inconsistent'):
        case.state.retainPending(case.init.said, case.discloser.pre, case.bind.raw, different)
    public, private = registry_salts.generateKeypair()
    changed = replies.bindReply(case.init, case.custody.rgy.store.seqEvent(case.info.registry, 0),
        sender=case.discloser.pre, rep=case.discloser.pre,
        est=case.bind.sad['a']['est'], key=public.qb64)
    with pytest.raises(ValidationError, match='already retained'):
        case.state.retainPending(case.init.said, case.discloser.pre, changed.raw, private)
    with pytest.raises(ValidationError, match='locally known'):
        case.state.retainPending(case.init.said, Signer().verfer.qb64, case.bind.raw, private)
    assert case.state.openPending(case.init.said, case.discloser.pre) == saved


@pytest.mark.parametrize('corruption', ['cipher', 'row', 'aeid', 'locked'])
def test_pending_private_failures_are_closed_and_static(negotiation, monkeypatch, corruption):
    """Corrupted, old-AEID, and locked state never becomes a new attempt."""
    case = negotiation
    retainPending(case)
    key = (case.init.said, case.issuer.pre)
    if corruption == 'cipher':
        case.state.db.saltPending.pin(key, EncryptedCustody(case.custody.hby.mgr.aeid, 'bad cipher'))
    elif corruption == 'row':
        with case.state.db.env.begin(write=True) as txn:
            txn.put(case.state.db.saltPending._tokey(key), b'not valid JSON',
                    db=case.state.db.saltPending.sdb)
    elif corruption == 'aeid':
        replacement = Signer(transferable=False)
        case.custody.hby.mgr.updateAeid(replacement.verfer.qb64, replacement.qb64)
    else:
        monkeypatch.setattr(case.custody.hby.mgr, 'decrypter', None)
    with pytest.raises(AuthError) as failure:
        case.state.openPending(*key)
    assert case.private.qb64 not in str(failure.value)
    with pytest.raises(AuthError):
        retainPending(case)


def test_establishment_is_one_transaction_and_exact_retry_preserves_progress(negotiation):
    """Root, origin, pending deletion and initial delivery jobs commit together."""
    case = negotiation
    retainPending(case)
    key = case.init.said, case.issuer.pre
    assert case.state.retainEstablished(case.info, case.root, case.origin, case.jobs, key) == case.origin
    with pytest.raises(ConfigurationError):
        case.state.openPending(*key)
    ciphertext = case.state.db.custody.get((case.info.registry,))
    assert case.state.origin(case.info.registry) == case.origin
    assert len(case.state.deliveryCandidates(0, limit=1)) == 1
    first = replace(case.jobs[0], state='confirmed', provision=Diger(ser=b'provision').qb64,
        receipt=Diger(ser=b'receipt').qb64, attempts=2, retryAt=42.0)
    later = replace(case.jobs[1], retryAt=100.0)
    case.state.db.saltDeliveries.pin(first.key, first)
    case.state.db.saltDeliveries.pin(later.key, later)
    case.state.retainEstablished(case.info, case.root, case.origin, case.jobs, key)
    assert case.state.db.custody.get((case.info.registry,)) == ciphertext
    assert case.state.delivery(*first.key) == first
    assert case.state.deliveryCandidates(99.0) == []
    assert case.state.deliveryCandidates(100.0) == [later]
    assert case.state.delivery(*later.key).attempts == 0
    case.state.db.saltDeliveries.pin(later.key, replace(later, state='blocked'))
    assert case.state.deliveryCandidates(1000.0) == []
    stored = Path(case.state.db.path, 'data.mdb').read_bytes()
    assert case.root.qb64b not in stored and case.root.raw not in stored
    changed = replace(case.origin, confirm=Diger(ser=b'other confirm').qb64)
    with pytest.raises(ValidationError, match='different registry-salt origin'):
        case.state.retainEstablished(case.info, case.root, changed)
    with pytest.raises(ValidationError, match='different registry custody'):
        case.state.retainEstablished(case.info, Salter(raw=b'fedcba9876543210'), case.origin)


def test_conflicting_job_aborts_root_origin_jobs_and_pending_deletion(negotiation):
    """A conflict late in the real transaction rolls back every prior write."""
    case = negotiation
    pending = retainPending(case)
    conflicting = replace(case.jobs[1], assignment=Diger(ser=b'rival assignment').qb64)
    case.state.db.saltDeliveries.put(conflicting.key, conflicting)
    with pytest.raises(ValidationError, match='different registry-salt delivery'):
        case.state.retainEstablished(case.info, case.root, case.origin, case.jobs,
                                     (case.init.said, case.issuer.pre))
    assert case.state.db.custody.get((case.info.registry,)) is None
    assert case.state.origin(case.info.registry) is None
    assert case.state.delivery(*case.jobs[0].key) is None
    assert case.state.delivery(*conflicting.key) == conflicting
    assert case.state.openPending(case.init.said, case.issuer.pre) == pending


def test_changed_pending_row_aborts_establishment(negotiation, monkeypatch):
    """Guard the exact encrypted attempt snapshot across the transaction boundary."""
    case = negotiation
    retainPending(case)
    original = case.state._openPending
    key = case.init.said, case.issuer.pre
    replacement = EncryptedCustody(case.custody.hby.mgr.aeid, 'intervening cipher')

    def change_after_read(init, rep, record):
        result = original(init, rep, record)
        case.state.db.saltPending.pin(key, replacement)
        return result

    monkeypatch.setattr(case.state, '_openPending', change_after_read)
    with pytest.raises(ValidationError, match='pending attempt changed'):
        case.state.retainEstablished(case.info, case.root, case.origin, case.jobs, key)
    assert case.state.db.custody.get((case.info.registry,)) is None
    assert case.state.origin(case.info.registry) is None
    assert case.state.deliveryCandidates(0) == []
    assert case.state.db.saltPending.get(key) == replacement


def test_establishment_consumes_only_its_exact_local_bind(negotiation):
    """A different bind under the same init cannot consume this saved private key."""
    case = negotiation
    pending = case.state.retainPending(case.init.said, case.discloser.pre,
                                      case.bind.raw, case.otherPrivate)
    other = replace(case.origin, bind=Diger(ser=b'other bind').qb64)
    with pytest.raises(ValidationError, match='pending reply differs from the origin'):
        case.state.retainEstablished(case.info, case.root, other, pendingKey=
                                     (case.init.said, case.discloser.pre))
    assert case.state.db.custody.get((case.info.registry,)) is None
    assert case.state.openPending(case.init.said, case.discloser.pre) == pending


def test_saved_plain_roster_survives_pending_habord_overwrite(members, tmp_path):
    """Persist accepted local member provenance separately from proposed lists."""
    from keri.app.credentialing import WalletBaser
    from keri.app.registry_custody import RegistryCustody

    hbys, groups, rgys, _ = members
    db = WalletBaser(name=hbys[0].name, headDirPath=str(tmp_path))
    try:
        state = RegistrySaltState(RegistryCustody(hbys[0], rgys[0], db=db))
        roster = acceptedRoster(hbys[0], groups[0].pre, groups[0].smids)
        assert state.retainRoster(roster) == roster
        # Proposed lists may be written before quorum, as the group owner does.
        record = hbys[0].db.habs.get((groups[0].pre,))
        record.smids = list(reversed(record.smids))
        hbys[0].db.habs.pin((groups[0].pre,), record)
        db.close()
        db.reopen()
        saved = state.roster(groups[0].pre)
        assert saved == roster and isinstance(saved.members, tuple)
        assert all(type(member).__name__ == 'Member' for member in saved.members)
        assert acceptedRoster(hbys[0], saved.group, [member.aid for member in saved.members]) == saved
    finally:
        db.close()
