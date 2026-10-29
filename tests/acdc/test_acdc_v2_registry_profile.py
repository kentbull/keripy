"""Approved ACDC v2 registry profile: rip/bup semantics and legacy parsing."""
import pytest

from keri import Vrsn_2_0
from keri.acdc import messaging, regeventing
from keri.acdc.regbasing import RegBaser
from keri.app import openHby
from keri.app.evidencing import EvidenceContext
from keri.core import Blinder, Diger, Saider, SerderACDC
from keri.db import openLMDB
from keri.kering import ValidationError


def test_bup_history_uses_one_acceptance_and_binding_path():
    """Accept anchored bup history, verify selected openings, and prevent replay rollback.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with openHby(name='mixed-profile', version=Vrsn_2_0) as hby, \
            openLMDB(cls=RegBaser, name='mixed-profile', temp=True) as reger:
        hab = hby.makeHab(name='issuer')
        rip = messaging.regcept(israid=hab.pre)
        target = messaging.acdcmap(israid=hab.pre, regid=rip.said,
                                  attribute=dict(d='', entitlement='entry'))
        blind1 = Blinder.blind(acdc=target.said, state='issued', sn=1)
        first = messaging.blindate(rip.said, rip.said, blind1.said)
        blind2 = Blinder.blind(acdc=target.said, state='revoked', sn=2)
        second = messaging.blindate(rip.said, first.said, blind2.said, sn=2)
        blind3 = Blinder.blind(acdc=target.said, state='issued', sn=3)
        third = messaging.blindate(rip.said, second.said, blind3.said, sn=3)
        receiver = regeventing.Rever(db=hby.db, reger=reger)
        for event in (rip, first, second, third):
            hab.interact(data=[dict(s=event.sad['n'], d=event.said)], gvrsn=Vrsn_2_0)
            assert receiver.processEvent(event)
        assert receiver.store.head(rip.said).qb64 == third.said
        assert regeventing.vet(rip, [first, second], db=hby.db,
                               acdc=target, blinder=blind2).state == 'revoked'
        assert regeventing.vetBinds(rip, [first, second], db=hby.db,
            blinders=[blind1, blind2], target=target.said, acdc=target).state == 'revoked'
        assert regeventing.vet(rip, [first, second, third], db=hby.db,
            blinder=blind3, acdc=target).state == 'issued'
        for event in (rip, first, second):
            assert receiver.processEvent(event)
            assert receiver.store.head(rip.said).qb64 == third.said


def test_upd_schema_parses_but_semantic_paths_reject_without_rewriting_history():
    """Parse exact legacy upd bytes while refusing new acceptance, standing, and publication."""
    with openHby(name='retired-upd', version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name='issuer')
        rip = messaging.regcept(israid=hab.pre)
        target = messaging.acdcmap(israid=hab.pre, regid=rip.said,
                                   attribute=dict(d='', entitlement='legacy'))
        upd = messaging.update(rip.said, rip.said, target.said, 'issued')
        parsed = SerderACDC(raw=upd.raw)
        assert parsed.ilk == 'upd'
        assert parsed.raw == upd.raw

        reger = RegBaser(name='retired-upd', temp=True)
        evidence = EvidenceContext(hby, reger=reger)
        try:
            evidence.store.accept(rip.said, 0, rip)
            with pytest.raises(ValidationError, match='retired'):
                evidence.store.accept(rip.said, 1, upd)
            assert evidence.store.event(upd.said) is None
            with pytest.raises(ValidationError, match='retired'):
                evidence.rever.processEvent(upd)
            assert evidence.store.event(upd.said) is None
            orphanRip = messaging.regcept(israid=hab.pre)
            orphanUpd = messaging.update(
                orphanRip.said, orphanRip.said, target.said, 'issued')
            with pytest.raises(ValidationError, match='retired'):
                evidence.rever.processEvent(orphanUpd)
            assert evidence.store.event(orphanUpd.said) is None
            assert reger.ooes.get(keys=orphanRip.said, on=1) == []
            with pytest.raises(ValidationError, match='retired'):
                regeventing.vet(rip, [upd], db=hby.db, acdc=target)

            # Seed the exact shape of a pre-retirement accepted row. Its bytes
            # remain available through explicit store-history reads only.
            reger.evts.pin(keys=upd.said, val=upd)
            reger.tels.pin(keys=rip.said, on=1, val=Saider(qb64=upd.said))
            reger.heads.pin(keys=rip.said, val=Saider(qb64=upd.said))
            assert evidence.store.seqEvent(rip.said, 1).raw == upd.raw
            assert bytes(upd.raw) in evidence.store.cloneTel(rip.said)
            assert evidence.registries() == []
            with pytest.raises(ValidationError, match='retired'):
                evidence.clone([rip.said])
        finally:
            evidence.close()
            reger.close()


@pytest.mark.parametrize('stamp', [
    '2026-10-20T12:00:00+00:00', '2026-10-20T12:00:00.000000Z',
    '2026-13-20T12:00:00.000000+00:00',
])
def test_timestamp_profile_refuses_noncanonical_received_body(stamp):
    """Refuse noncanonical or impossible received timestamps even when the registry event SAID recomputes.

    Parameters:
        stamp: Noncanonical or invalid received timestamp vector.

    Returns:
        None. Assertions check the stated evidence boundary."""
    event = messaging.regcept(israid=Diger(ser=b'issuer').qb64, stamp=stamp)
    with pytest.raises(ValidationError, match='timestamp'):
        regeventing.vetRip(event)


def test_ordinal_profile_refuses_leading_zero():
    """Refuse a leading-zero ordinal in a correctly re-SAIDed inception rather than mistaking it for digest corruption.

    Returns:
        None. Assertions check the stated evidence boundary."""
    event = messaging.regcept(israid=Diger(ser=b'issuer').qb64)
    sad = dict(event.sad, n='00', d='')
    # Recompute the digest so this checks the ordinal, not accidental corruption.
    with pytest.raises(ValidationError):
        regeventing.vetRip(SerderACDC(sad=sad, makify=True))
