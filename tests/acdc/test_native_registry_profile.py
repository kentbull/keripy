"""Approved native registry profile: mixed updates and canonical fields."""
import pytest

from keri import Vrsn_2_0
from keri.acdc import messaging, regeventing
from keri.acdc.regbasing import RegBaser
from keri.app import openHby
from keri.core import Blinder, Diger, SerderACDC
from keri.db import openLMDB
from keri.kering import ValidationError




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
