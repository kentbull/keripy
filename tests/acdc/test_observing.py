# -*- encoding: utf-8 -*-
"""Foreign native registry intake using independent KEL and registry stores."""

import pytest

from keri import Vrsn_2_0
from keri.acdc import messaging
from keri.acdc.regeventing import Rever
from keri.acdc.regbasing import RegBaser
from keri.app import openHby
from keri.core import Codens, Counter, Diger, IdrDex, Parser, Siger
from keri.core import eventing
from keri.core.eventing import Kevery
from keri.db import openLMDB
from keri.kering import ValidationError


def _seal(hab, event, **kwa):
    """Create a real controller interaction sealing the supplied native TEL event.

    Args:
        hab (Hab): Registry controller whose next key event carries the seal.
        event (SerderACDC): Inception/update whose complete registry triple to seal.
        **kwa: Additional interaction options, used for witness-set scenarios.

    Returns:
        SerderKERI: Newly accepted controller key event."""
    hab.interact(data=[dict(i=event.said if event.ilk == "rip" else event.sad["rd"],
                            s=event.sad["n"], d=event.said)],
                 version=Vrsn_2_0, gvrsn=Vrsn_2_0, **kwa)
    return hab.kever.serder


def _copy_kel(hab, receiver, *, local=False):
    """Transfer signed KEL replay through ordinary foreign validation.

    Args:
        hab (Hab): Source controller whose full KEL to replay.
        receiver (Habery): Independent destination evidence owner.
        local (bool): Protected-source mode for tests of locally witnessed events.

    Returns:
        Kevery: Destination processor with ordinary signature/delegation/witness
        escrows; returning it does not assert all replayed events were accepted."""
    kvy = Kevery(db=receiver.db, lax=False, local=local)
    parser = Parser(kvy=kvy, version=Vrsn_2_0, local=local)
    for msg in hab.db.clonePreIter(pre=hab.pre, fn=0, version=Vrsn_2_0):
        parser.parse(ims=bytearray(msg))
    return kvy


def _events(issuer):
    """Build a linked three-event native TEL without anchoring it.

    Args:
        issuer (Hab): Controller named by the inception.

    Returns:
        tuple[SerderACDC, SerderACDC, SerderACDC]: rip, issued bup, revoked bup,
        using deterministic digest placeholders because these tests concern intake."""
    rip = messaging.regcept(israid=issuer.pre)
    issued = messaging.blindate(rip.said, rip.said, Diger(ser=b"issued").qb64)
    revoked = messaging.blindate(rip.said, issued.said,
                                  Diger(ser=b"revoked").qb64, sn=2)
    return rip, issued, revoked


def _telstream(*events):
    """Frame each supplied native TEL body with its required empty foot.

    Args:
        *events: Ordered native registry event bodies.

    Returns:
        bytearray: Concatenated bodies and explicit v2 zero-count attachment groups."""
    empty = Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b
    return bytearray(b"".join(event.raw + empty for event in events))








def test_foreign_registry_unaccepted_kel_body_cannot_anchor():
    """Refuse a raw stored key-event body that never passed accepted KEL validation.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with openHby(name="foreign-raw-issuer", version=Vrsn_2_0) as ihby, \
            openHby(name="foreign-raw-receiver", version=Vrsn_2_0) as rhby, \
            openLMDB(cls=RegBaser, name="foreign-raw", temp=True) as reger:
        issuer = ihby.makeHab(name="issuer")
        _copy_kel(issuer, rhby)
        rip = messaging.regcept(israid=issuer.pre)
        anchor = _seal(issuer, rip)
        # A parsed event body is not an accepted KEL event. Put only its raw
        # evidence row, leaving accepted KEL ordinals and key state untouched.
        rhby.db.evts.put(keys=(issuer.pre, anchor.said), val=anchor)
        rever = Rever(db=rhby.db, reger=reger)
        assert rever.processEvent(rip) is False
        assert rhby.kevers[issuer.pre].sn == 0
        assert rhby.db.kels.getLast(keys=issuer.pre, on=anchor.sn) is None
        assert rever.store.head(rip.said) is None
        assert rever.store.anchor(rip.said) is None

        _copy_kel(issuer, rhby)
        rever.processEscrows()
        assert rever.store.headEvent(rip.said).said == rip.said


@pytest.mark.parametrize("fields", ["d", "sd", "isd"])
def test_foreign_registry_recognized_digest_seals(fields):
    """Accept each supported digest/couple/triple seal shape only with matching registry coordinates.

    Parameters:
        fields: Supported registry seal fields selected by the vector.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with openHby(name="foreign-seals-issuer", version=Vrsn_2_0) as ihby, \
            openHby(name="foreign-seals-receiver", version=Vrsn_2_0) as rhby, \
            openLMDB(cls=RegBaser, name="foreign-seals", temp=True) as reger:
        issuer = ihby.makeHab(name="issuer")
        rip = messaging.regcept(israid=issuer.pre)
        seal = dict(d=rip.said)
        if "s" in fields:
            seal["s"] = rip.sad["n"]
        if "i" in fields:
            seal["i"] = rip.said
        issuer.interact(data=[seal], version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        _copy_kel(issuer, rhby)
        rever = Rever(db=rhby.db, reger=reger)
        assert rever.processEvent(rip) is True
        assert rever.store.headEvent(rip.said).said == rip.said


def test_foreign_registry_wrong_controller_and_anchor_do_not_accept():
    """Refuse wrong-controller and mismatched KEL anchor evidence without accepting a registry event.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with openHby(name="foreign-anchor-issuer", version=Vrsn_2_0) as ihby, \
            openHby(name="foreign-anchor-receiver", version=Vrsn_2_0) as rhby, \
            openLMDB(cls=RegBaser, name="foreign-anchor", temp=True) as reger:
        issuer = ihby.makeHab(name="issuer")
        other = ihby.makeHab(name="other")
        rip, issued, _ = _events(issuer)
        _seal(other, rip)  # a real signed seal from the wrong controller
        _copy_kel(other, rhby)
        _copy_kel(issuer, rhby)
        rever = Rever(db=rhby.db, reger=reger)
        assert rever.processEvent(rip) is False
        assert rever.store.head(rip.said) is None
        assert rever.store.anchor(rip.said) is None

        _seal(issuer, rip)
        _copy_kel(issuer, rhby)
        rever.processEscrows()
        assert rever.store.headEvent(rip.said).said == rip.said

        # Same digest in an issuer seal with the wrong registry or ordinal is
        # insufficient: the complete (i, s, d) event seal must match.
        issuer.interact(data=[dict(i=other.pre, s=issued.sad["n"], d=issued.said),
                              dict(i=rip.said, s="2", d=issued.said)],
                        version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        _copy_kel(issuer, rhby)
        assert rever.processEvent(issued) is False
        assert rever.store.seqEvent(rip.said, 1) is None
        assert rever.store.anchor(issued.said) is None
        assert rever.store.headEvent(rip.said).said == rip.said






def test_foreign_registry_requires_actual_witness_receipts():
    """Require authentic witness receipt quorum before foreign TEL anchors become usable.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with openHby(name="foreign-witness-issuer", version=Vrsn_2_0) as ihby, \
            openHby(name="foreign-witness-receiver", version=Vrsn_2_0) as rhby, \
            openHby(name="foreign-witness-second", version=Vrsn_2_0) as whby, \
            openLMDB(cls=RegBaser, name="foreign-witness", temp=True) as reger:
        first = rhby.makeHab(name="first", transferable=False)
        second = whby.makeHab(name="second", transferable=False)
        issuer = ihby.makeHab(name="issuer", wits=[first.pre, second.pre], toad=2)
        rip, _, _ = _events(issuer)
        anchor = _seal(issuer, rip)
        # A local witness accepts the controller KEL before all receipts have
        # arrived; the registry must still require the declared witness quorum.
        _copy_kel(issuer, rhby, local=True)
        _copy_kel(issuer, whby, local=True)
        assert issuer.pre in rhby.kevers
        assert rhby.db.fullyWitnessed(anchor) is False
        rever = Rever(db=rhby.db, reger=reger)
        assert rever.processEvent(rip) is False
        assert rever.store.head(rip.said) is None

        first.witness(anchor, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        # A second encoding of the same valid witness signature is still only
        # one witness. Process both through normal receipt validation/storage.
        wiger = rhby.db.wigs.get(keys=(anchor.pre, anchor.said))[0]
        duplicate = Siger(raw=wiger.raw, code=IdrDex.Ed25519_Crt_Sig, index=0)
        rct = eventing.receipt(pre=issuer.pre, sn=anchor.sn, said=anchor.said,
                              version=Vrsn_2_0)
        rhby.psr.parse(ims=eventing.messagize(rct, wigers=[duplicate], gvrsn=Vrsn_2_0))
        assert len(rhby.db.wigs.get(keys=(anchor.pre, anchor.said))) == 2
        assert rhby.db.fullyWitnessed(anchor) is False
        rever.processEscrows()
        assert rever.store.head(rip.said) is None
        receipt = second.witness(anchor, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        rhby.psr.parse(ims=bytearray(receipt))
        assert rhby.db.fullyWitnessed(anchor) is True
        rever.processEscrows()
        assert rever.store.headEvent(rip.said).said == rip.said


@pytest.mark.parametrize("original, rotated", [(2, 1), (1, 2)])
def test_foreign_registry_anchor_keeps_historical_witness_quorum(original, rotated):
    """Use the anchor event historical witness set despite later controller witness rotation.

    Parameters:
        original: Witness quorum configuration when the anchoring key event was accepted.
        rotated: Later witness configuration that must not alter the old quorum.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with openHby(name="historical-issuer", version=Vrsn_2_0) as ihby, \
            openHby(name="historical-receiver", version=Vrsn_2_0) as rhby, \
            openHby(name="historical-second", version=Vrsn_2_0) as whby, \
            openLMDB(cls=RegBaser, name="historical-quorum", temp=True) as reger:
        first = rhby.makeHab(name="first", transferable=False)
        second = whby.makeHab(name="second", transferable=False)
        issuer = ihby.makeHab(name="issuer", wits=[first.pre, second.pre], toad=original)
        rip = messaging.regcept(israid=issuer.pre)
        anchor = _seal(issuer, rip)
        _copy_kel(issuer, rhby, local=True)
        _copy_kel(issuer, whby, local=True)
        first.witness(anchor, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        rever = Rever(db=rhby.db, reger=reger)
        assert rever.processEvent(rip) is (original == 1)
        assert rhby.db.fullyWitnessed(anchor) is (original == 1)

        # Lowering also removes the still-missing historical witness, so the
        # old anchor must retain both its original threshold and witness list.
        cuts = [second.pre] if original == 2 else []
        issuer.rotate(toad=rotated, cuts=cuts, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        _copy_kel(issuer, rhby, local=True)
        assert rhby.kevers[issuer.pre].toader.num == rotated
        assert rhby.db.fullyWitnessed(anchor) is (original == 1)
        rever.processEscrows()
        assert (rever.store.head(rip.said) is not None) is (original == 1)

        # The missing historical witness, rather than the later rotation, can
        # complete a formerly insufficient anchor's receipt quorum.
        receipt = second.witness(anchor, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        rhby.psr.parse(ims=bytearray(receipt))
        assert rhby.db.fullyWitnessed(anchor) is True
        rever.processEscrows()
        assert rever.store.headEvent(rip.said).said == rip.said


def test_foreign_kel_duplicate_witness_index_does_not_satisfy_quorum():
    """Prevent two encodings from one witness from satisfying a two-witness KEL quorum.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with openHby(name="distinct-kel-issuer", version=Vrsn_2_0) as ihby, \
            openHby(name="distinct-kel-witnesses", version=Vrsn_2_0) as whby, \
            openHby(name="distinct-kel-receiver", version=Vrsn_2_0) as rhby:
        first = whby.makeHab(name="first", transferable=False)
        second = whby.makeHab(name="second", transferable=False)
        issuer = ihby.makeHab(name="issuer", wits=[first.pre, second.pre], toad=2)
        inception = issuer.kever.serder
        _copy_kel(issuer, whby, local=True)
        first.witness(inception, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        wiger = whby.db.wigs.get(keys=(issuer.pre, inception.said))[0]
        duplicate = Siger(raw=wiger.raw, code=IdrDex.Ed25519_Crt_Sig, index=0)
        stream = eventing.messagize(inception, sigers=issuer.sign(inception.raw),
                                    wigers=[wiger, duplicate], gvrsn=Vrsn_2_0)
        kvy = Kevery(db=rhby.db, lax=False, local=False)
        parser = Parser(kvy=kvy, version=Vrsn_2_0)
        parser.parse(ims=stream)
        assert issuer.pre not in rhby.kevers
        assert rhby.db.kels.getLast(keys=issuer.pre, on=0) is None
        assert rhby.db.pwes.get(keys=issuer.pre, on=0) == [inception.said]

        receipt = second.witness(inception, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        parser.parse(ims=bytearray(receipt))
        kvy.processEscrows()
        assert issuer.pre in rhby.kevers
        assert rhby.db.kels.getLast(keys=issuer.pre, on=0) == inception.said
        assert rhby.db.fullyWitnessed(inception) is True
        assert rhby.db.pwes.get(keys=issuer.pre, on=0) == []
