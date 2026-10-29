"""Fresh authenticated provisioning retires only its matching local DH attempt."""

from keri import Vrsn_2_0
from keri.core import Diger
from keri.kering import ConfigurationError, UnverifiedReplyError

import pytest

from tests.app.test_registry_salt_service import network


def delayedProvision(case, *, rotated=False, pendingRoute='init'):
    """Withhold confirmation from an approved init/bind while the issuer establishes the root."""
    issuer, discloser = case.habs[:2]
    source, target = case.services[:2]
    if pendingRoute == 'init':
        init = target.prepareInit(issuer=issuer.pre, discloser=discloser.pre,
                                 party=discloser.pre, representative=discloser.pre)
        source.receive(target.approveReply(init).stream)
        bind = source.prepareBind(init.said, case.rip.said, issuer.pre)
        source.approveReply(bind)
        assert target.state.proof(bind.said) is None
    else:
        init = source.prepareInit(issuer=issuer.pre, discloser=discloser.pre,
                                 party=issuer.pre, representative=issuer.pre)
        target.receive(source.approveReply(init).stream)
        bind = target.prepareBind(init.said, case.rip.said, discloser.pre)
        source.receive(target.approveReply(bind).stream)
    confirm = source.prepareConfirm(init.said, bind.said)
    source.approveReply(confirm)
    assert target.state.proof(confirm.said) is None
    assert target.state.origin(case.rip.said) is None
    unrelated = target.prepareInit(issuer=issuer.pre, discloser=discloser.pre,
                                  party=discloser.pre, representative=discloser.pre)
    otherKey = unrelated.said, discloser.pre
    other = target.state.db.saltPending.get(otherKey)
    if rotated:
        stream = discloser.rotate(version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        source.parser.parse(ims=bytearray(stream), local=False)
        for service in (source, target):
            service.trustRoster(discloser.pre, [discloser.pre])
    job = next(row for row in source.reconcile(case.rip.said, discloser.pre)
               if row.member == discloser.pre)
    provision, signed, _ = source.prepareProvision(job, issuer.pre)
    return source, target, init, provision, signed, otherKey, other


@pytest.mark.parametrize('rotated', [False, True])
@pytest.mark.parametrize('pendingRoute', ['init', 'bind'])
def test_delayed_provision_removes_only_exact_pending_after_commit(network, rotated, pendingRoute):
    """An old representative coordinate is archival; current recipient rotation remains supported."""
    source, target, init, provision, signed, otherKey, other = delayedProvision(
        network, rotated=rotated, pendingRoute=pendingRoute)
    assert target.state.hasPending(init.said, network.habs[1].pre)
    target.receive(signed)
    assert not target.state.hasPending(init.said, network.habs[1].pre)
    assert target.state.db.saltPending.get(otherKey) == other
    assert target.state.receipt(provision.said) is not None
    assert target.state.origin(network.rip.said) == source.state.origin(network.rip.said)
    credential = Diger(ser=b'future after delayed replication').qb64
    assert target.custody.derive(network.rip.said, 7, credential, 'revoked').qb64 == (
        source.custody.derive(network.rip.said, 7, credential, 'revoked').qb64)
    receipt, _, _ = target.prepareReceipt(provision.said)
    assert receipt.sad['a']['retained'] is True


def test_failed_root_transaction_preserves_pending_and_cannot_acknowledge(network, monkeypatch):
    """Rollback keeps both pending rows and recovery later commits cleanup with receipt intent."""
    source, target, init, provision, signed, otherKey, other = delayedProvision(network)
    key = init.said, network.habs[1].pre
    pending = target.state.db.saltPending.get(key)
    original = target.custody.retainPrepared

    def failAfterRoot(prepared, txn):
        """Fail after a real ciphertext write inside the existing wallet transaction."""
        original(prepared, txn)
        raise RuntimeError('injected wallet transaction failure')

    monkeypatch.setattr(target.custody, 'retainPrepared', failAfterRoot)
    with pytest.raises(UnverifiedReplyError, match='pending retry'):
        target.receive(signed)
    assert target.state.db.saltPending.get(key) == pending
    assert target.state.db.saltPending.get(otherKey) == other
    assert target.custody.db.custody.get((network.rip.said,)) is None
    assert target.state.origin(network.rip.said) is None
    assert target.state.receipt(provision.said) is None
    with pytest.raises(ConfigurationError, match='committed intent'):
        target.prepareReceipt(provision.said)
    monkeypatch.setattr(target.custody, 'retainPrepared', original)
    target.process()  # ordinary authenticated reply escrow; no KRAM redrive
    assert target.state.db.saltPending.get(key) is None
    assert target.state.db.saltPending.get(otherKey) == other
    assert target.state.receipt(provision.said) is not None
    assert target.state.origin(network.rip.said) == source.state.origin(network.rip.said)


def test_provision_needs_no_pending_and_preserves_other_requests(network):
    """Replica admission does not acquire an unrelated pending attempt's deletion authority."""
    _, target, init, provision, signed, otherKey, other = delayedProvision(network)
    assert target.state.db.saltPending.rem((init.said, network.habs[1].pre))
    target.receive(signed)
    assert target.state.receipt(provision.said) is not None
    assert target.state.db.saltPending.get(otherKey) == other
