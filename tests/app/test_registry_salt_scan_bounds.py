"""Real wallet LMDB scans stay bounded across completed history and idle ticks."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from keri.app.credentialing import WalletBaser
from keri.app.registry_salt_delivery import RegistrySaltDelivery
from keri.app.registry_salt_state import RegistrySaltState, SaltDelivery, SaltReceiptIntent
from keri.core import Diger


@pytest.fixture
def history(monkeypatch):
    """Write 10,000 completed rows per real table and count actual deserializations."""
    db = WalletBaser(name='salt-scan-bounds', temp=True)
    try:
        state = RegistrySaltState(SimpleNamespace(db=db))
        keys = sorted(Diger(raw=index.to_bytes(32, 'big')).qb64 for index in range(10000))
        aid = Diger(ser=b'scan owner').qb64
        tables = {False: db.saltDeliveries, True: db.saltReceipts}
        with db.env.begin(write=True) as txn:
            for key in keys:
                job = SaltDelivery(key, aid, aid, aid, aid, state='confirmed')
                intent = SaltReceiptIntent(key, aid, aid, aid, aid, aid, '', state='sent')
                txn.put(tables[False]._tokey(job.key), tables[False]._ser(job), db=tables[False].sdb)
                txn.put(tables[True]._tokey((key,)), tables[True]._ser(intent), db=tables[True].sdb)
        counts = {False: 0, True: 0}
        for receipt, table in tables.items():
            decode = table._des

            def counted(value, receipt=receipt, decode=decode):
                """Count each persisted value decoded by the actual Komer/LMDB read."""
                counts[receipt] += 1
                return decode(value)

            monkeypatch.setattr(table, '_des', counted)
        yield SimpleNamespace(state=state, db=db, keys=keys, aid=aid, counts=counts)
    finally:
        db.close(clear=True)


@pytest.mark.parametrize('receipt', [False, True])
def test_resume_near_tail_seeks_without_decoding_completed_prefix(history, receipt):
    """A real cursor near the tail examines only subsequent rows, including a deleted cursor."""
    case = history
    cursor = (case.keys[-10],) if receipt else (case.keys[-10], case.aid, case.aid, case.aid)
    table = case.db.saltReceipts if receipt else case.db.saltDeliveries
    table.rem(cursor)  # a saved volatile cursor may outlive the row it names
    candidates = case.state.receiptCandidates if receipt else case.state.deliveryCandidates
    page = candidates(0, limit=2, after=cursor)
    assert case.counts[receipt] <= 32
    assert page.items == () and page.examined == 9 and page.after is None


@pytest.mark.parametrize('receipt', [False, True])
def test_result_limit_preserves_the_next_unreturned_due_row(history, receipt):
    """Stopping at available I/O capacity resumes before the next due operation."""
    case = history
    table = case.db.saltReceipts if receipt else case.db.saltDeliveries
    keys = [(key,) if receipt else (key, case.aid, case.aid, case.aid) for key in case.keys[:3]]
    for key in keys:
        table.pin(key, replace(table.get(key), state='pending'))
    case.counts[receipt] = 0
    candidates = case.state.receiptCandidates if receipt else case.state.deliveryCandidates
    page = candidates(0, limit=1, scanLimit=7)
    assert len(page.items) == 1 and page.after == keys[0] and page.examined == 1
    second = candidates(0, limit=1, after=page.after, scanLimit=7)
    assert len(second.items) == 1 and second.after == keys[1] and second.examined == 1
    assert case.counts[receipt] == 2


def test_idle_worker_tick_bounds_completed_rows_in_both_tables(history):
    """Completed history consumes the shared 32-row budget and both cursors advance while idle."""
    case = history
    worker = RegistrySaltDelivery(SimpleNamespace(state=case.state), case.aid, limit=1, clock=lambda: 0)
    work = worker.deliveryDo(tymth=lambda: 0)
    next(work)
    try:
        previous = dict(worker.cursors)
        for _ in range(3):
            before = dict(case.counts)
            next(work)
            examined = {kind: case.counts[kind] - before[kind] for kind in (False, True)}
            assert 0 < sum(examined.values()) <= 32
            assert all(examined.values())
            assert all(worker.cursors[kind] != previous[kind] for kind in (False, True))
            previous = dict(worker.cursors)
    finally:
        work.close()


def test_bounded_pages_eventually_reach_due_tail_without_counting_attempts(history, monkeypatch):
    """An unready due tail remains reachable behind completed rows in each workflow."""
    case = history
    key = (case.keys[-1], case.aid, case.aid, case.aid)
    job = replace(case.state.delivery(*key), state='pending')
    intent = replace(case.state.receipt(case.keys[-1]), state='pending')
    case.db.saltDeliveries.pin(key, job)
    case.db.saltReceipts.pin((intent.provision,), intent)
    case.counts.update({False: 0, True: 0})
    worker = RegistrySaltDelivery(SimpleNamespace(state=case.state), case.aid, limit=1, clock=lambda: 0)
    selected = set()
    monkeypatch.setattr(worker, '_start', lambda row, receipt, now: selected.add(receipt))
    work = worker.deliveryDo(tymth=lambda: 0)
    next(work)
    try:
        for _ in range(626):
            before = sum(case.counts.values())
            next(work)
            assert sum(case.counts.values()) - before <= 32
            if selected == {False, True}:
                break
        assert selected == {False, True}
        assert case.state.delivery(*key).attempts == 0
        assert case.state.receipt(intent.provision).attempts == 0
    finally:
        work.close()
