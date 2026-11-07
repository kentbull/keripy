"""v2 ACDC foreign registry intake through the parser and ordinary TEL escrows."""

import pytest

from keri import Vrsn_2_0
from keri.acdc import Regery, regcept, blindate
from keri.acdc.regbasing import RegBaser
from keri.app import openHby
from keri.core import (Diger, Kevery, Number, Parser, Prefixer, SealEvent,
                       SealSource, interact, messagize)
from keri.db import openLMDB
from keri.kering import ValidationError


def seal(event, regk):
    return dict(i=regk, s=event.sad['n'], d=event.said)


def message(event, issuer, anchor, triple=False):
    source = (SealEvent(i=issuer, s=anchor.snh, d=anchor.said) if triple else
              SealSource(s=anchor.snh, d=anchor.said))
    return messagize(event, bonds=source, gvrsn=Vrsn_2_0)


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("triple", [False, True])
def test_acdc_v2_foreign_stream_replays_after_registry_reopen(tmp_path, reverse, triple):
    with (openHby(name="issuer", temp=True, version=Vrsn_2_0) as sender,
          openHby(name="verifier", temp=True, version=Vrsn_2_0) as receiver):
        hab = sender.makeHab(name="issuer", version=Vrsn_2_0)
        rip = regcept(israid=hab.pre)
        bup = blindate(regid=rip.said, prior=rip.said,
                       blid=Diger(ser=b"foreign state").qb64, sn=1)
        hab.interact(data=[seal(rip, rip.said), seal(bup, rip.said)])
        anchoring = hab.kever.serder
        options = dict(cls=RegBaser, name="acdc-v2", temp=False,
                       headDirPath=str(tmp_path))

        with openLMDB(**options) as baser:
            rgy = Regery(hby=receiver, baser=baser)
            parser = Parser(rgy=rgy, version=Vrsn_2_0)
            events = (bup, rip) if reverse else (rip, bup)
            for event in events:
                parser.parse(ims=message(event, hab.pre, anchoring, triple))
            assert rgy.store.head(rip.said) is None
            assert rgy.store.event(bup.said) is not None
            assert rgy.store.anchor(bup.said) is None
            assert rgy.regs == rgy.names == {}
            assert list(rgy.store.records.getTopItemIter()) == []

        with openLMDB(**options) as baser:
            rgy = Regery(hby=receiver, baser=baser)
            parser = Parser(rgy=rgy, kvy=Kevery(db=receiver.db, lax=False,
                                               local=False), version=Vrsn_2_0)
            for sn in (0, 1):
                parser.parse(ims=hab.msgOwnEvent(sn=sn, framed=True, gvrsn=Vrsn_2_0))
            rgy.processEscrows()
            assert rgy.store.seqEvent(rip.said, 0).said == rip.said
            assert rgy.store.seqEvent(rip.said, 1).said == bup.said
            assert rgy.store.head(rip.said).qb64 == bup.said
            assert rgy.store.baser.maes.get(keys=rip.said, on=0) == []
            assert rgy.store.baser.maes.get(keys=rip.said, on=1) == []
            assert rgy.store.baser.ooes.get(keys=rip.said, on=1) == []
            parser.parse(ims=message(rip, hab.pre, anchoring, triple))
            assert rgy.store.head(rip.said).qb64 == bup.said
            assert rgy.regs == rgy.names == {}

        later = blindate(regid=rip.said, prior=bup.said,
                         blid=Diger(ser=b"later foreign state").qb64, sn=2)
        hab.interact(data=[seal(later, rip.said)])
        with openLMDB(**options) as baser:
            rgy = Regery(hby=receiver, baser=baser)
            parser = Parser(rgy=rgy, kvy=Kevery(db=receiver.db, lax=False,
                                               local=False), version=Vrsn_2_0)
            parser.parse(ims=hab.msgOwnEvent(sn=2, framed=True, gvrsn=Vrsn_2_0))
            parser.parse(ims=message(later, hab.pre, hab.kever.serder, triple))
            assert rgy.store.seqEvent(rip.said, 2).said == later.said
            assert rgy.store.head(rip.said).qb64 == later.said
            assert rgy.regs == rgy.names == {}


@pytest.mark.parametrize("bad_source", ["controller", "digest", "seal"])
def test_acdc_v2_intake_refuses_resolvable_wrong_source(bad_source):
    with (openHby(name="issuer", temp=True, version=Vrsn_2_0) as sender,
          openHby(name="verifier", temp=True, version=Vrsn_2_0) as receiver,
          openLMDB(cls=RegBaser, name="acdc-v2", temp=True) as baser):
        hab = sender.makeHab(name="issuer", version=Vrsn_2_0)
        stranger = sender.makeHab(name="stranger", version=Vrsn_2_0)
        rip = regcept(israid=hab.pre)
        hab.interact(data=[seal(rip, rip.said)])
        rgy = Regery(hby=receiver, baser=baser)
        parser = Parser(kvy=Kevery(db=receiver.db, lax=False, local=False),
                        version=Vrsn_2_0)
        for event in (hab.msgOwnEvent(sn=0, gvrsn=Vrsn_2_0),
                      hab.msgOwnEvent(sn=1, gvrsn=Vrsn_2_0),
                      stranger.msgOwnEvent(sn=0, gvrsn=Vrsn_2_0)):
            parser.parse(ims=event)
        if bad_source == "controller":
            kwa = dict(ssts=[(Prefixer(qb64=stranger.pre), Number(num=0),
                               Diger(qb64=stranger.kever.serder.said))])
        elif bad_source == "digest":
            kwa = dict(sscs=[(Number(num=1), Diger(ser=b"wrong source"))])
        else:
            kwa = dict(sscs=[(Number(num=0), Diger(qb64=hab.iserder.said))])
        with pytest.raises(ValidationError):
            rgy.processEvent(rip, **kwa)
        assert rgy.store.head(rip.said) is None
        assert rgy.store.anchor(rip.said) is None
        assert rgy.processEvent(rip) is True


def test_acdc_v2_intake_waits_for_partial_signed_kel_source():
    with (openHby(name="issuer", temp=True, version=Vrsn_2_0) as sender,
          openHby(name="verifier", temp=True, version=Vrsn_2_0) as receiver,
          openLMDB(cls=RegBaser, name="acdc-v2", temp=True) as baser):
        hab = sender.makeHab(name="issuer", isith='2', icount=3, version=Vrsn_2_0)
        rgy = Regery(hby=receiver, baser=baser)
        parser = Parser(kvy=Kevery(db=receiver.db, lax=False, local=False),
                        rgy=rgy, version=Vrsn_2_0)
        parser.parse(ims=hab.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0))
        rip = regcept(israid=hab.pre)
        sealing = interact(pre=hab.pre, dig=hab.kever.serder.said, sn=1,
                           data=[seal(rip, rip.said)], version=Vrsn_2_0)
        sigers = hab.mgr.sign(ser=sealing.raw, verfers=hab.kever.verfers, indexed=True)
        parser.parse(ims=messagize(sealing, sigers=sigers[:1], gvrsn=Vrsn_2_0))
        assert receiver.db.evts.get(keys=(hab.pre, sealing.said)) is not None
        assert receiver.db.kels.getLast(keys=hab.pre, on=1) is None
        parser.parse(ims=message(rip, hab.pre, sealing))
        assert rgy.store.head(rip.said) is None
        assert rgy.store.anchor(rip.said) is None
        parser.parse(ims=messagize(sealing, sigers=sigers[:2], gvrsn=Vrsn_2_0))
        rgy.processEscrows()
        assert rgy.store.head(rip.said).qb64 == rip.said


def test_pre_inception_bup_cannot_select_issuer_or_pin_source_hint():
    with (openHby(name="issuer", temp=True, version=Vrsn_2_0) as sender,
          openHby(name="verifier", temp=True, version=Vrsn_2_0) as receiver,
          openLMDB(cls=RegBaser, name="acdc-v2", temp=True) as baser):
        issuer = sender.makeHab(name="issuer", version=Vrsn_2_0)
        stranger = sender.makeHab(name="stranger", version=Vrsn_2_0)
        rip = regcept(israid=issuer.pre)
        bup = blindate(regid=rip.said, prior=rip.said,
                       blid=Diger(ser=b"foreign state").qb64, sn=1)
        stranger.interact(data=[seal(bup, rip.said)])
        rgy = Regery(hby=receiver, baser=baser)
        parser = Parser(kvy=Kevery(db=receiver.db, lax=False, local=False),
                        rgy=rgy, version=Vrsn_2_0)
        for sn in (0, 1):
            parser.parse(ims=stranger.msgOwnEvent(sn=sn, gvrsn=Vrsn_2_0))
        parser.parse(ims=message(bup, stranger.pre, stranger.kever.serder, triple=True))
        assert rgy.store.anchor(bup.said) is None

        # An unavailable sender hint must not constrain authentic later replay.
        hint = SealSource(s="63", d=Diger(ser=b"unavailable hint").qb64)
        parser.parse(ims=messagize(rip, bonds=hint, gvrsn=Vrsn_2_0))
        issuer.interact(data=[seal(rip, rip.said)])
        for sn in (0, 1):
            parser.parse(ims=issuer.msgOwnEvent(sn=sn, gvrsn=Vrsn_2_0))
        rgy.processEscrows()
        assert rgy.store.head(rip.said).qb64 == rip.said
        assert rgy.store.seqEvent(rip.said, 1) is None
        assert rgy.store.anchor(bup.said) is None

        issuer.interact(data=[seal(bup, rip.said)])
        parser.parse(ims=issuer.msgOwnEvent(sn=2, gvrsn=Vrsn_2_0))
        rgy.processEscrows()
        assert rgy.store.head(rip.said).qb64 == bup.said


def test_acdc_v2_foreign_sibling_arbitration_uses_existing_anchor_order():
    with (openHby(name="issuer", temp=True, version=Vrsn_2_0) as sender,
          openHby(name="verifier", temp=True, version=Vrsn_2_0) as receiver,
          openLMDB(cls=RegBaser, name="acdc-v2", temp=True) as baser):
        hab = sender.makeHab(name="issuer", version=Vrsn_2_0)
        rip = regcept(israid=hab.pre)
        early = blindate(regid=rip.said, prior=rip.said,
                         blid=Diger(ser=b"early").qb64, sn=1)
        late = blindate(regid=rip.said, prior=rip.said,
                        blid=Diger(ser=b"late").qb64, sn=1)
        anchors = {}
        for event in (rip, early, late):
            hab.interact(data=[seal(event, rip.said)])
            anchors[event.said] = hab.kever.serder
        rgy = Regery(hby=receiver, baser=baser)
        parser = Parser(kvy=Kevery(db=receiver.db, lax=False, local=False),
                        rgy=rgy, version=Vrsn_2_0)
        for event in (late, early, rip):
            parser.parse(ims=message(event, hab.pre, anchors[event.said]))
        for sn in range(4):
            parser.parse(ims=hab.msgOwnEvent(sn=sn, framed=True, gvrsn=Vrsn_2_0))
        rgy.processEscrows()
        assert rgy.store.seqEvent(rip.said, 1).said == early.said
        assert rgy.store.head(rip.said).qb64 == early.said
        with pytest.raises(ValidationError):
            rgy.processEvent(late)


def test_acdc_v2_wrong_source_refused_without_witness_quorum():
    from keri import kering
    from keri.core import eventing, signing
    with (openHby(name="verifier", temp=True, version=Vrsn_2_0) as receiver,
          openLMDB(cls=RegBaser, name="acdc-v2", temp=True) as baser):
        wit = signing.Signer(raw=b'\x01' * 32, transferable=False)
        ctrl = signing.Signer(raw=b'c' * 32)
        icp = eventing.incept(keys=[ctrl.verfer.qb64], wits=[wit.verfer.qb64], toad=1,
                              version=Vrsn_2_0, kind=kering.Kinds.json)
        receiver.db.prefixes.add(icp.pre)
        Kevery(db=receiver.db).processEvent(
            local=True, serder=icp, sigers=[ctrl.sign(ser=icp.raw, index=0)])
        assert not receiver.db.fullyWitnessed(icp)  # accepted, no receipts
        rgy = Regery(hby=receiver, baser=baser)
        rip = regcept(israid=icp.pre)
        with pytest.raises(ValidationError):  # icp does not seal rip
            rgy.processEvent(rip, sscs=[(Number(num=0), Diger(qb64=icp.said))])
