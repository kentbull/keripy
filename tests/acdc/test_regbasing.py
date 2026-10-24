# -*- encoding: utf-8 -*-
"""
tests.acdc.test_regbasing module

"""

import os

import lmdb
import pytest

from keri.acdc import messaging, regbasing
from keri.core import coring, serdering
from keri.db import openLMDB, subing


def test_regbaser_store_contract():
    """Test the ACDC v2 registry TEL six-store database contract."""
    with openLMDB(cls=regbasing.RegBaser,
                  name="test-regbaser", temp=True) as baser:
        assert isinstance(baser, regbasing.RegBaser)
        assert baser.opened
        assert baser.TailDirPath == os.path.join("keri", "acdc", "reg")
        assert any(
            part.startswith(baser.TempPrefix)
            for part in baser.path.split(os.path.sep)
        )

        assert isinstance(baser.evts, subing.SerderSuber)
        assert baser.evts.klas is serdering.SerderACDC
        assert isinstance(baser.ancs, subing.CatCesrSuber)
        assert baser.ancs.klas == (coring.Number, coring.Diger)
        assert isinstance(baser.tels, subing.CesrOnSuber)
        assert baser.tels.klas is coring.Saider
        assert isinstance(baser.heads, subing.CesrSuber)
        assert baser.heads.klas is coring.Saider
        assert isinstance(baser.maes, subing.B64OnIoSetSuber)
        assert isinstance(baser.ooes, subing.B64OnIoSetSuber)

        for name in ("evts", "ancs", "tels", "heads", "maes", "ooes"):
            assert getattr(baser, name).sdb.flags()["dupsort"] is False

        issuer = "EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ"
        serder = messaging.regcept(
            israid=issuer,
            uuid="0AAxyHwW6htOZ_rANOaZb2N2",
            stamp="2020-08-22T17:50:09.988921+00:00",
        )
        saider = coring.Saider(qb64=serder.said)
        source = (coring.Number(num=3), coring.Diger(qb64=serder.said))

        assert baser.evts.put(keys=serder.said, val=serder)
        assert baser.ancs.put(keys=serder.said, val=source)
        assert baser.tels.put(keys=serder.said, on=0, val=saider)
        assert baser.heads.put(keys=serder.said, val=saider)
        assert baser.maes.add(keys=serder.said, on=1, val=serder.said)
        assert baser.ooes.add(keys=serder.said, on=1, val=serder.said)

        assert baser.evts.get(keys=serder.said).raw == serder.raw
        assert baser.ancs.get(keys=serder.said)[0].num == 3
        assert baser.ancs.get(keys=serder.said)[1].qb64 == serder.said
        assert baser.tels.get(keys=serder.said, on=0).qb64 == serder.said
        assert baser.heads.get(keys=serder.said).qb64 == serder.said
        assert baser.maes.get(keys=serder.said, on=1) == [(serder.said,)]
        assert baser.ooes.get(keys=serder.said, on=1) == [(serder.said,)]

    assert baser.opened is False


@pytest.mark.parametrize("sn", [0, 1])
@pytest.mark.parametrize("staged", [False, True])
def test_regbaser_accept_transaction_aborts_on_final_write(monkeypatch, sn, staged):
    """Inject a real LMDB head-write failure and prove body/ordinal/head rollback together while staged evidence survives.

    Parameters:
        monkeypatch: Pytest scoped substitution injecting the final durable head-write failure.
        sn: Inception/update ordinal whose acceptance transaction is exercised.
        staged: Whether the candidate body was already persisted before the failing transaction.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with openLMDB(cls=regbasing.RegBaser, name="registry-atomic", temp=True) as baser:
        rip = messaging.regcept(israid=coring.Diger(ser=b"issuer").qb64)
        update = messaging.blindate(rip.said, rip.said, coring.Diger(ser=b"issued").qb64)
        if sn:
            baser.accept(rip.said, 0, rip)
        event = update if sn else rip
        if staged:
            baser.evts.put(keys=event.said, val=event)
        anchor = (coring.Number(num=3), coring.Diger(ser=b"anchor"))
        baser.ancs.put(keys=event.said, val=anchor)
        baser.env.set_mapsize(1 << 20)

        # Force the last txn.put to exceed this real environment's map. The
        # ordinary body and ordinal writes have already run in that transaction.
        with monkeypatch.context() as patch:
            patch.setattr(baser.heads, "_ser", lambda val: b"x" * (2 << 20))
            with pytest.raises(lmdb.MapFullError):
                baser.accept(rip.said, sn, event)

        body = baser.evts.get(keys=event.said)
        assert (body.raw if body else None) == (event.raw if staged else None)
        assert baser.tels.get(keys=rip.said, on=sn) is None
        head = baser.heads.get(keys=rip.said)
        assert (head.qb64 if head else None) == (rip.said if sn else None)
        assert baser.ancs.get(keys=event.said)[1].qb64 == anchor[1].qb64

        assert baser.accept(rip.said, sn, event) is True
        assert baser.evts.get(keys=event.said).raw == event.raw
        assert baser.tels.get(keys=rip.said, on=sn).qb64 == event.said
        assert baser.heads.get(keys=rip.said).qb64 == event.said


def test_regbaser_accepted_history_survives_reopen(tmp_path):
    """Reopen real accepted history and verify head, exact replay protection, and unchanged Suber wire encodings.

    Parameters:
        tmp_path: Pytest-owned persistent RegBaser directory.

    Returns:
        None. Assertions check the stated evidence boundary."""
    baser = regbasing.RegBaser(name="registry-reopen", temp=False,
                              headDirPath=str(tmp_path))
    rip = messaging.regcept(israid=coring.Diger(ser=b"issuer").qb64)
    update = messaging.blindate(rip.said, rip.said, coring.Diger(ser=b"issued").qb64)
    anchor = (coring.Number(num=3), coring.Diger(ser=b"anchor"))
    try:
        baser.ancs.put(keys=update.said, val=anchor)
        baser.accept(rip.said, 0, rip)
        baser.accept(rip.said, 1, update)
    finally:
        baser.close()

    baser = regbasing.RegBaser(name="registry-reopen", temp=False,
                              headDirPath=str(tmp_path))
    try:
        assert baser.accept(rip.said, 0, rip) is False
        assert baser.heads.get(keys=rip.said).qb64 == update.said
        assert baser.evts.get(keys=rip.said).raw == rip.raw
        assert baser.evts.get(keys=update.said).raw == update.raw
        assert baser.tels.get(keys=rip.said, on=0).qb64 == rip.said
        assert baser.tels.get(keys=rip.said, on=1).qb64 == update.said
        assert baser.ancs.get(keys=update.said)[1].qb64 == anchor[1].qb64
    finally:
        baser.close()
