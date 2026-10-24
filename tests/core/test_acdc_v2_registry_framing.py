"""ACDC v2 registry anchor authentication does not excuse incomplete CESR framing."""

from contextlib import contextmanager

import pytest

from keri import Vrsn_2_0
from keri.acdc.regeventing import Rever
from keri.acdc.regbasing import RegBaser
from keri.app import openHby
from keri.core import Codens, Counter, Diger, Number, Parser, SealEvent, SealSource, messagize
from keri.db import openLMDB

from tests.acdc.test_observing import _copy_kel, _events, _seal


@contextmanager
def _anchored_registry():
    """Yield independent issuer/receiver evidence with a genuinely anchored inception.

    Yields:
        tuple: (Rever, rip, accepted issuer anchor). All temporary KEL/TEL stores are
        closed by their context managers after the framing assertion completes."""
    with openHby(name="framing-issuer", version=Vrsn_2_0) as ihby, \
            openHby(name="framing-receiver", version=Vrsn_2_0) as rhby, \
            openLMDB(cls=RegBaser, name="framing", temp=True) as reger:
        issuer = ihby.makeHab(name="issuer")
        rip, _, _ = _events(issuer)
        anchor = _seal(issuer, rip)
        _copy_kel(issuer, rhby)
        yield Rever(db=rhby.db, reger=reger), rip, anchor


@pytest.mark.parametrize("code", [Codens.AttachmentGroup, Codens.BigAttachmentGroup])
@pytest.mark.parametrize("binary", [False, True])
@pytest.mark.parametrize("supplied", [0, 1])
def test_truncated_native_attachment_group_cannot_accept(code, binary, supplied):
    """Require every byte declared by a nonempty attachment counter before ACDC v2 semantic dispatch.

    Parameters:
        code: Small or big attachment-group counter code.
        binary: Whether counter/source primitives use binary rather than text CESR.
        supplied: Count of bytes supplied from an intentionally incomplete declared foot.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with _anchored_registry() as (rever, rip, _):
        counter = Counter(code, count=1, version=Vrsn_2_0)
        foot = counter.qb2 if binary else counter.qb64b
        parser = Parser(rgy=rever, version=Vrsn_2_0)
        parser.parse(ims=bytearray(rip.raw + foot + b"x" * supplied))
        assert rever.store.event(rip.said) is None
        assert rever.store.head(rip.said) is None


@pytest.mark.parametrize("code", [Codens.AttachmentGroup, Codens.BigAttachmentGroup])
@pytest.mark.parametrize("binary", [False, True])
def test_exact_empty_native_attachment_group_accepts(code, binary):
    """Accept a genuine anchored TEL event with an explicitly complete zero-count attachment foot.

    Parameters:
        code: Small or big attachment-group counter code.
        binary: Whether counter/source primitives use binary rather than text CESR.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with _anchored_registry() as (rever, rip, _):
        counter = Counter(code, count=0, version=Vrsn_2_0)
        foot = counter.qb2 if binary else counter.qb64b
        Parser(rgy=rever, version=Vrsn_2_0).parse(ims=bytearray(rip.raw + foot))
        assert rever.store.headEvent(rip.said).said == rip.said


@pytest.mark.parametrize("binary", [False, True])
def test_fragmented_native_attachment_group_waits_for_complete_source(binary):
    """Keep unframed native intake waiting until the final source-foot byte arrives, then accept normally.

    Parameters:
        binary: Whether counter/source primitives use binary rather than text CESR.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with _anchored_registry() as (rever, rip, anchor):
        number, diger = Number(num=anchor.sn), Diger(qb64=anchor.said)
        couple = number.qb64b + diger.qb64b
        source = Counter(Codens.SealSourceCouples, count=len(couple) // 4,
                         version=Vrsn_2_0)
        group = Counter(Codens.AttachmentGroup,
                        count=(len(source.qb64b) + len(couple)) // 4,
                        version=Vrsn_2_0)
        foot = (group.qb2 + source.qb2 + number.qb2 + diger.qb2 if binary
                else group.qb64b + source.qb64b + couple)
        stream = bytearray(rip.raw + foot[:-1])
        parser = Parser(rgy=rever, version=Vrsn_2_0)
        pending = parser.parsator(ims=stream, framed=False)
        try:
            next(pending)
            assert rever.store.head(rip.said) is None
            stream.extend(foot[-1:])
            next(pending)
            assert rever.store.headEvent(rip.said).said == rip.said
        finally:
            pending.close()


@pytest.mark.parametrize("processive", [False, True])
def test_parse_one_malformed_frame_returns_no_message(processive):
    """Return no stale/unbound parsed message and flush malformed input after extraction failure.

    Parameters:
        processive: Whether parseOne attempts dispatch or only extraction.

    Returns:
        None. Assertions check the stated evidence boundary."""
    stream = bytearray(b"not a CESR message")
    assert Parser(version=Vrsn_2_0).parseOne(
        ims=stream, processive=processive) is None
    assert not stream


@pytest.mark.parametrize('triple,wrong', [
    (False, 'digest'), (False, 'event'), (True, 'digest'),
    (True, 'event'), (True, 'controller'),
])
def test_false_acdc_v2_source_locator_rejects_frame_without_poisoning(triple, wrong):
    """Reject a resolvably false source locator for this frame while allowing later clean authentic replay.

    Parameters:
        triple: Whether the locator explicitly names its controller.
        wrong: False digest, wrong accepted event, or wrong explicit controller mutation.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with _anchored_registry() as (rever, rip, anchor):
        # A real alternative anchor is already accepted, so ignoring the false
        # supplied locator would let the ordinary discovery path accept rip.
        controller = rip.sad['i']
        number = Number(num=anchor.sn)
        diger = Diger(qb64=anchor.said)
        if wrong == 'digest':
            diger = Diger(ser=b'false source digest')
        elif wrong == 'event':
            event = rever.db.evts.get((controller,
                rever.db.kels.getLast(keys=controller, on=0)))
            number, diger = Number(num=0), Diger(qb64=event.said)
        else:
            controller = Diger(ser=b'other controller').qb64
        source = (SealEvent(i=controller, s=number.numh, d=diger.qb64) if triple
                  else SealSource(s=number.numh, d=diger.qb64))
        stream = messagize(rip, bonds=[source], gvrsn=Vrsn_2_0)
        Parser(rgy=rever).parseOne(ims=stream)
        assert rever.store.event(rip.said) is None
        assert rever.store.head(rip.said) is None
        # Locator rejection is a property of that frame. The authentic event
        # remains usable when subsequently supplied without the bogus locator.
        Parser(rgy=rever).parseOne(ims=bytearray(rip.raw + Counter(
            Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b))
        assert rever.store.headEvent(rip.said).said == rip.said


def test_unknown_acdc_v2_source_locator_does_not_override_authentic_discovery():
    """Treat an unavailable unsigned source locator as a hint, allowing independently authenticated anchor discovery.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with _anchored_registry() as (rever, rip, _):
        unavailable = SealSource(s='ffff', d=Diger(ser=b'unknown locator').qb64)
        stream = messagize(rip, bonds=[unavailable], gvrsn=Vrsn_2_0)
        Parser(rgy=rever).parseOne(ims=stream)
        assert rever.store.headEvent(rip.said).said == rip.said
