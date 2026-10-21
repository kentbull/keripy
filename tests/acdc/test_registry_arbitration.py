"""Known conflicting candidates use the same ordering across durable escrows."""

from keri import Vrsn_2_0
from keri.acdc import messaging
from keri.acdc.regeventing import Rever
from keri.acdc.regbasing import RegBaser
from keri.app import openHby
from keri.core import Diger
from keri.db import openLMDB

from tests.acdc.test_observing import _copy_kel, _events, _seal


def test_registry_siblings_across_escrows_use_verified_anchor_order():
    """An earlier eligible missing-anchor candidate is considered before commit."""
    with openHby(name="split-issuer", version=Vrsn_2_0) as ihby, \
            openHby(name="split-receiver", version=Vrsn_2_0) as rhby, \
            openLMDB(cls=RegBaser, name="split-escrows", temp=True) as reger:
        issuer = ihby.makeHab(name="issuer")
        rip, first, _ = _events(issuer)
        early = messaging.blindate(rip.said, first.said,
                                    Diger(ser=b"early").qb64, sn=2)
        late = messaging.blindate(rip.said, first.said,
                                   Diger(ser=b"late").qb64, sn=2)
        for event in (rip, first, early, late):
            _seal(issuer, event)
        rever = Rever(db=rhby.db, reger=reger)

        # The earlier candidate is waiting for KEL evidence when the later
        # candidate arrives with its anchor already locally available.
        assert rever.processEvent(rip) is False
        assert rever.processEvent(early) is False
        _copy_kel(issuer, rhby)
        assert rever.processEvent(late) is False
        assert reger.maes.get(keys=rip.said, on=2) == [(early.said,)]
        assert reger.ooes.get(keys=rip.said, on=2) == [(late.said,)]

        assert rever.processEvent(rip) is True
        assert rever.processEvent(first) is True
        assert rever.store.seqEvent(rip.said, 2).said == early.said
        assert rever.store.headEvent(rip.said).said == early.said
        assert reger.maes.get(keys=rip.said, on=2) == []
        assert reger.ooes.get(keys=rip.said, on=2) == []

        # Replaying the accepted old prefix must preserve the chosen head.
        assert rever.processEvent(rip) is True
        assert rever.store.headEvent(rip.said).said == early.said
