"""Held exact event openings survive restart without entering public TEL replay."""

import pytest

from keri import Vrsn_2_0 as V2
from keri.acdc import RegBaser, Regery, blindate, regcept
from keri.app import openHby
from keri.core import Blinder, BlindState, BoundState, Diger, Labeler, Noncer, Number
from keri.core.coring import DigDex, NumDex
from keri.db import openLMDB
from keri.kering import ValidationError


def proof(bound=False, public=False):
    clan = BoundState if bound else BlindState
    fields = dict(d="", u="" if public else Noncer().qb64,
                  td=Diger(ser=b"held credential").qb64, ts="issued")
    if bound:
        fields.update(bn=1, bd=Diger(ser=b"held Issuee event").qb64)
    opening = Blinder(crew=clan(**fields), makify=True, saids={"d": DigDex.SHA2_256})
    if bound:
        # Preserve the actual authenticated numeric encoding, not just its value.
        data = opening.data._replace(bn=Number(num=1, code=NumDex.Long))
        raw = b"#" * 44 + b"".join(item.qb64b for item in data[1:])
        data = data._replace(d=Noncer(qb64=Diger(ser=raw, code=DigDex.SHA2_256).qb64))
        opening = Blinder(data=data, verify=False)
    return opening


def accept(hab, rgy, event, regid):
    hab.interact(data=[dict(i=regid, s=event.sad["n"], d=event.said)], gvrsn=V2)
    assert rgy.processEvent(event)


@pytest.mark.parametrize("bound", [False, True])
@pytest.mark.parametrize("public", [False, True])
def test_held_opening_is_explicit_exact_and_private_after_reopen(tmp_path, bound, public):
    held = proof(bound, public)
    with openHby(name="opening-author", version=V2) as hby:
        hab = hby.makeHab(name="author")
        rip = regcept(israid=hab.pre)
        bup = blindate(regid=rip.said, prior=rip.said, sn=1, blid=held.said)
        options = dict(cls=RegBaser, name="held", temp=False, headDirPath=str(tmp_path))
        with openLMDB(**options) as baser:
            rgy = Regery(hby=hby, baser=baser)
            accept(hab, rgy, rip, rip.said)
            accept(hab, rgy, bup, rip.said)
            assert rgy.store.opening(bup.said) is None
            assert rgy.store.putOpening(bup.said, held) is True
            assert rgy.store.putOpening(bup.said, held) is False
            assert rgy.store.opening(bup.said) is not held
            # A later head does not invalidate held evidence for an earlier BUP.
            later = blindate(regid=rip.said, prior=bup.said, sn=2,
                              blid=Diger(ser=b"later state").qb64)
            accept(hab, rgy, later, rip.said)

        with openLMDB(**options) as baser:
            rgy = Regery(hby=hby, baser=baser)
            restored = rgy.store.opening(bup.said)
            assert restored.clan is held.clan and restored.qb64 == held.qb64
            assert rgy.store.cloneTel(rip.said) == rip.raw + bup.raw + later.raw
            assert held.qb64b not in rgy.store.cloneTel(rip.said)
            assert rgy.store.opening(later.said) is None


def test_opening_requires_accepted_event_and_exact_blid():
    held = proof()
    with (openHby(name="opening-refusals", version=V2) as hby,
          openLMDB(cls=RegBaser, name="opening-refusals") as baser):
        hab = hby.makeHab(name="author")
        rgy = Regery(hby=hby, baser=baser)
        rip = regcept(israid=hab.pre)
        bup = blindate(regid=rip.said, prior=rip.said, sn=1, blid=held.said)
        with pytest.raises(ValidationError):
            rgy.store.putOpening(bup.said, held)
        accept(hab, rgy, rip, rip.said)
        with pytest.raises(ValidationError):
            rgy.store.putOpening(rip.said, held)
        assert rgy.processEvent(bup) is False  # stored, but no accepted anchor
        with pytest.raises(ValidationError):
            rgy.store.putOpening(bup.said, held)
        accept(hab, rgy, bup, rip.said)
        invalid = Blinder(data=held.data._replace(ts=Labeler(text="revoked")), verify=False)
        with pytest.raises(ValidationError):
            rgy.store.putOpening(bup.said, invalid)
        assert rgy.store.opening(bup.said) is None
        assert rgy.store.putOpening(bup.said, held)
        with pytest.raises(ValidationError):
            rgy.store.putOpening(bup.said, proof(public=True))
        assert rgy.store.opening(bup.said).qb64 == held.qb64
        # Read-side verification also refuses corrupt or no-longer-accepted rows.
        baser.openings.pin(bup.said, held.qb64 + "1AAP")
        with pytest.raises(ValidationError):
            rgy.store.opening(bup.said)
        with pytest.raises(ValidationError, match="immutable"):
            rgy.store.putOpening(bup.said, held)
        assert baser.openings.get(bup.said) == held.qb64 + "1AAP"
        baser.openings.pin(bup.said, held.qb64)
        baser.tels.rem(keys=rip.said, on=1)
        with pytest.raises(ValidationError):
            rgy.store.opening(bup.said)
