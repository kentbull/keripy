"""Different CESR encodings of one signature never supply another signer."""

import pytest

from keri import Vrsn_1_0, Vrsn_2_0
from keri.app import openHby
from keri.core import IdrDex, Kevery, Parser, Siger, Tholder, messagize


@pytest.mark.parametrize("sith", [2, "2", ["1/2", "1/2"]])
def test_threshold_counts_distinct_verified_indices(sith):
    tholder = Tholder(sith=sith)
    assert tholder.satisfy([0, 0]) is False
    assert tholder.satisfy([1, 1, 1]) is False
    assert tholder.satisfy([1, 0, 1, 0]) is True


@pytest.mark.parametrize("version", [Vrsn_1_0, Vrsn_2_0])
def test_two_key_inception_requires_two_distinct_signers(version):
    with openHby(name="distinct-controller-issuer", version=version) as ihby, \
            openHby(name="distinct-controller-receiver", version=version) as rhby:
        issuer = ihby.makeHab(name="issuer", icount=2, isith=2, ncount=2, nsith=2,
                              version=version)
        inception = issuer.kever.serder
        assert inception.pvrsn == version
        first, second = issuer.sign(inception.raw)
        duplicate = Siger(raw=first.raw, code=IdrDex.Ed25519_Crt_Sig, index=0)
        assert duplicate.qb64 != first.qb64
        assert duplicate.index == first.index == 0
        kvy = Kevery(db=rhby.db, lax=False, local=False)
        parser = Parser(kvy=kvy, version=version)
        parser.parse(ims=messagize(inception, sigers=[first, duplicate], gvrsn=version))

        assert issuer.pre not in rhby.kevers
        assert rhby.db.kels.getLast(keys=issuer.pre, on=0) is None
        assert rhby.db.pses.get(keys=issuer.pre, on=0) == [inception.said]

        # A genuine signature from the other key arrives through the same
        # stream parser. Ordinary partial-signature escrow completes the event.
        parser.parse(ims=messagize(inception, sigers=[second], gvrsn=version))
        kvy.processEscrows()
        assert rhby.kevers[issuer.pre].serder.said == inception.said
        assert rhby.db.kels.getLast(keys=issuer.pre, on=0) == inception.said
        assert rhby.db.pses.get(keys=issuer.pre, on=0) == []
