"""Approved native registry profile: mixed updates and canonical fields."""
import pytest

from keri import Vrsn_2_0
from keri.acdc import messaging, regeventing
from keri.acdc.regbasing import RegBaser
from keri.app import openHby
from keri.core import Blinder, Diger, SerderACDC
from keri.db import openLMDB
from keri.kering import ValidationError


def test_mixed_history_uses_one_acceptance_and_binding_path():
    """Accept one real anchored mixed bup/upd history, verify selected public/blinded heads, and prevent replay rollback.

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
        second = messaging.update(rip.said, first.said, target.said, 'revoked', sn=2)
        blind3 = Blinder.blind(acdc=target.said, state='issued', sn=3)
        third = messaging.blindate(rip.said, second.said, blind3.said, sn=3)
        receiver = regeventing.Rever(db=hby.db, reger=reger)
        for event in (rip, first, second, third):
            hab.interact(data=[dict(s=event.sad['n'], d=event.said)], gvrsn=Vrsn_2_0)
            assert receiver.processEvent(event)
        assert receiver.store.head(rip.said).qb64 == third.said
        assert regeventing.vet(rip, [first, second], db=hby.db, acdc=target).state == 'revoked'
        assert regeventing.vetBinds(rip, [first, second], db=hby.db,
            blinders=[], target=target.said, acdc=target).state == 'revoked'
        assert regeventing.vet(rip, [first, second, third], db=hby.db,
            blinder=blind3, acdc=target).state == 'issued'
        for event in (rip, first, second):
            assert receiver.processEvent(event)
            assert receiver.store.head(rip.said).qb64 == third.said


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
