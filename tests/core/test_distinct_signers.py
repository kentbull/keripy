"""Controller thresholds count verified key indices across signature encodings."""

import pytest

from keri.kering import Kinds, Vrsn_1_0, Vrsn_2_0
from keri.core import coring, eventing, parsing, signing
from keri.db import basing


@pytest.mark.parametrize("version", [Vrsn_1_0, Vrsn_2_0])
@pytest.mark.parametrize("sith", ["2", ["1/2", "1/2"]], ids=["numeric", "weighted"])
def test_duplicate_controller_index_stays_in_partial_signature_escrow(version, sith):
    signers = [signing.Signer(raw=bytes([i]) * 32) for i in (1, 2)]
    serder = eventing.incept(keys=[signer.verfer.qb64 for signer in signers],
                            isith=sith, code=coring.MtrDex.Blake3_256,
                            version=version, kind=Kinds.json)
    # Both CESR encodings verify, but both identify the first controller key.
    siger = signers[0].sign(ser=serder.raw, index=0)
    duplicate = signers[0].sign(ser=serder.raw, index=0, only=True)
    assert siger.qb64 != duplicate.qb64
    assert siger.raw == duplicate.raw
    _, indices = eventing.verifySigs(raw=serder.raw, sigers=[siger, duplicate],
                                    verfers=[signer.verfer for signer in signers])
    assert indices == [0, 0]

    parser = parsing.Parser(version=version)
    with basing.openDB(name="distinct-signers") as db:
        kvy = eventing.Kevery(db=db)
        message = eventing.messagize(serder, sigers=[siger, duplicate],
                                    framed=True, gvrsn=version)
        parser.parse(ims=bytearray(message), kvy=kvy)
        assert serder.pre not in kvy.kevers
        assert db.pses.get(keys=serder.pre, on=0) == [serder.said]

        # Replay must not promote the same two encodings to two signers.
        kvy.processEscrowPartialSigs()
        assert serder.pre not in kvy.kevers
        assert db.pses.get(keys=serder.pre, on=0) == [serder.said]

        # A signature from the second key completes the escrowed event.
        second = signers[1].sign(ser=serder.raw, index=1)
        message = eventing.messagize(serder, sigers=[second],
                                    framed=True, gvrsn=version)
        parser.parse(ims=bytearray(message), kvy=kvy)
        kvy.processEscrowPartialSigs()
        assert kvy.kevers[serder.pre].serder.said == serder.said
        assert db.pses.get(keys=serder.pre, on=0) == []
