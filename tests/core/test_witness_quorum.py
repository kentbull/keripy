"""Witness quorum belongs to the accepted event and its authenticated receipts."""

import pytest

from keri import kering
from keri.core import coring, eventing, signing
from keri.db import basing


@pytest.fixture(params=[kering.Vrsn_1_0, kering.Vrsn_2_0], ids=["v1", "v2"])
def version(request):
    return request.param


@pytest.fixture
def witnesses():
    return [signing.Signer(raw=bytes([i]) * 32, transferable=False)
            for i in (1, 2, 3)]


def inception(version, witnesses, toad=2, ndigs=None):
    controller = signing.Signer(raw=b'c' * 32)
    serder = eventing.incept(keys=[controller.verfer.qb64],
                            ndigs=ndigs, toad=toad,
                            wits=[wit.verfer.qb64 for wit in witnesses],
                            version=version, kind=kering.Kinds.json)
    return serder, controller.sign(ser=serder.raw, index=0)


@pytest.mark.parametrize("receipt", ["duplicate", "forged", "out-of-range"])
def test_fully_witnessed_rejects_unverified_quorum(version, witnesses, receipt):
    serder, signature = inception(version, witnesses)
    first = witnesses[0].sign(ser=serder.raw, index=0)
    if receipt == "duplicate":
        second = witnesses[0].sign(ser=serder.raw, index=0, only=True)
    elif receipt == "forged":
        second = witnesses[2].sign(ser=serder.raw, index=1)
    else:
        second = witnesses[1].sign(ser=serder.raw, index=3)

    with basing.openDB(name="witness-quorum") as db:
        db.prefixes.add(serder.pre)  # controllers accept their own event before receipts
        eventing.Kevery(db=db).processEvent(local=True, serder=serder, sigers=[signature])
        key = (serder.pre, serder.said)
        db.wigs.pin(keys=key, vals=[first, second])
        assert not db.fullyWitnessed(serder)
        db.wigs.add(keys=key, val=witnesses[1].sign(ser=serder.raw, index=1))
        assert db.fullyWitnessed(serder)


def test_fully_witnessed_uses_historical_quorum(version, witnesses):
    next_signer = signing.Signer(raw=b'n' * 32)
    serder, signature = inception(version, witnesses[:2],
                                 ndigs=[coring.Diger(ser=next_signer.verfer.qb64b).qb64])
    with basing.openDB(name="historical-quorum") as db:
        db.prefixes.add(serder.pre)
        kvy = eventing.Kevery(db=db)
        kvy.processEvent(local=True, serder=serder, sigers=[signature])
        interaction = eventing.interact(pre=serder.pre, dig=serder.said,
                                       sn=1, version=version, kind=kering.Kinds.json)
        controller = signing.Signer(raw=b'c' * 32)
        kvy.processEvent(local=True, serder=interaction,
                         sigers=[controller.sign(ser=interaction.raw, index=0)])
        rotation = eventing.rotate(pre=serder.pre, dig=interaction.said, sn=2,
                                  keys=[next_signer.verfer.qb64],
                                  wits=[wit.verfer.qb64 for wit in witnesses[:2]],
                                  cuts=[witnesses[0].verfer.qb64],
                                  adds=[witnesses[2].verfer.qb64], toad=1,
                                  version=version, kind=kering.Kinds.json)
        kvy.processEvent(local=True, serder=rotation,
                         sigers=[next_signer.sign(ser=rotation.raw, index=0)])
        assert kvy.kevers[serder.pre].toader.num == 1

        for historic in (serder, interaction):
            key = (historic.pre, historic.said)
            db.wigs.pin(keys=key,
                        vals=[witnesses[0].sign(ser=historic.raw, index=0)])
            assert not db.fullyWitnessed(historic)  # old threshold remains two
            db.wigs.add(keys=key, val=witnesses[1].sign(ser=historic.raw, index=1))
            assert db.fullyWitnessed(historic)
            # The new witness at index 0 cannot replace the historical witness.
            db.wigs.pin(keys=key,
                        vals=[witnesses[2].sign(ser=historic.raw, index=0),
                              witnesses[1].sign(ser=historic.raw, index=1)])
            assert not db.fullyWitnessed(historic)

        key = (rotation.pre, rotation.said)
        db.wigs.pin(keys=key, vals=[witnesses[0].sign(ser=rotation.raw, index=0)])
        assert not db.fullyWitnessed(rotation)
        db.wigs.pin(keys=key, vals=[witnesses[2].sign(ser=rotation.raw, index=1)])
        assert db.fullyWitnessed(rotation)


def test_fully_witnessed_requires_accepted_event_even_without_witnesses(version):
    serder, signature = inception(version, [], toad=0)
    with basing.openDB(name="accepted-quorum") as db:
        eventing.Kevery(db=db).processEvent(local=True, serder=serder, sigers=[signature])
        assert db.fullyWitnessed(serder)
        pending = eventing.interact(pre=serder.pre, dig=serder.said,
                                   sn=1, version=version, kind=kering.Kinds.json)
        db.evts.put(keys=(pending.pre, pending.said), val=pending)
        assert not db.fullyWitnessed(pending)


def test_duplicate_witness_index_stays_in_partial_witness_escrow(version, witnesses):
    serder, signature = inception(version, witnesses)
    duplicate = [witnesses[0].sign(ser=serder.raw, index=0),
                 witnesses[0].sign(ser=serder.raw, index=0, only=True)]
    with basing.openDB(name="distinct-witnesses") as db:
        kvy = eventing.Kevery(db=db)
        with pytest.raises(kering.MissingWitnessSignatureError):
            kvy.processEvent(local=True, serder=serder, sigers=[signature], wigers=duplicate)
        assert serder.pre not in kvy.kevers
        assert db.pwes.get(keys=serder.pre, on=0) == [serder.said]
        kvy.processEscrowPartialWigs()
        assert serder.pre not in kvy.kevers
        assert db.pwes.get(keys=serder.pre, on=0) == [serder.said]
        db.wigs.add(keys=(serder.pre, serder.said),
                    val=witnesses[1].sign(ser=serder.raw, index=1))
        kvy.processEscrowPartialWigs()
        assert kvy.kevers[serder.pre].serder.said == serder.said
        assert db.pwes.get(keys=serder.pre, on=0) == []


def test_ksn_query_waits_for_authenticated_witness_quorum(version, witnesses):
    serder, signature = inception(version, witnesses)
    with basing.openDB(name="query-quorum") as db:
        db.prefixes.add(serder.pre)
        kvy = eventing.Kevery(db=db)
        kvy.processEvent(local=True, serder=serder, sigers=[signature])
        key = (serder.pre, serder.said)
        db.wigs.pin(keys=key, vals=[witnesses[0].sign(ser=serder.raw, index=0),
                                   witnesses[0].sign(ser=serder.raw, index=0, only=True)])
        query = eventing.query(pre=serder.pre, route="ksn",
                              query=dict(i=serder.pre, src=witnesses[0].verfer.qb64),
                              version=version, kind=kering.Kinds.json)
        source = coring.Prefixer(qb64=witnesses[0].verfer.qb64)
        with pytest.raises(kering.QueryNotFoundError):
            kvy.processQuery(query, source=source, sigers=[])
        db.wigs.add(keys=key, val=witnesses[1].sign(ser=serder.raw, index=1))
        kvy.cues.clear()
        kvy.processQuery(query, source=source, sigers=[])
        assert kvy.cues.pop()["kin"] == "reply"


def test_fully_witnessed_skips_transferable_witness_prefix(version, witnesses):
    serder, signature = inception(version, witnesses, toad=1)
    stranger = signing.Signer(raw=b's' * 32)  # transferable, never a witness
    with basing.openDB(name="malformed-witness") as db:
        db.prefixes.add(serder.pre)
        eventing.Kevery(db=db).processEvent(local=True, serder=serder, sigers=[signature])
        key = (serder.pre, serder.said)
        db.wits.pin(keys=key, vals=[coring.Prefixer(qb64=stranger.verfer.qb64)])
        db.wigs.pin(keys=key, vals=[stranger.sign(ser=serder.raw, index=0)])
        assert db.fullyWitnessed(serder) is False
