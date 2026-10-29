"""Borrowed evidence processing must share acceptance without owning lifecycle."""
import pytest
from hio.base import doing

from keri import Vrsn_2_0
from keri.acdc import acdcmap, blindate, regcept, update
from keri.acdc.regbasing import RegBaser
from keri.acdc.regeventing import Rever
from keri.app.evidencing import EvidenceContext, EvidenceProcessor, ServiceConfig
from keri.app.habbing import openHby
from keri.core import (BlindState, Blinder, Codens, Counter, Diger, Kevery,
                       Parser, SerderACDC)
from keri.kering import ConfigurationError, ValidationError


def framed(event, opening=None):
    """Return one exact event with an optional expanded public opening."""
    attachments = Blinder.enclose([opening]) if opening is not None else b''
    return bytes(event.raw) + bytes(Counter.enclose(
        qb64=attachments, code=Codens.AttachmentGroup, version=Vrsn_2_0))


def registry(hab):
    """Create an anchored rip and public bup without hiding its opening."""
    rip = regcept(israid=hab.pre)
    credential = acdcmap(israid=hab.pre, regid=rip.said,
                         attribute={'d': '', 'example': True})
    opening = Blinder.blind(acdc=credential.said, state='issued')
    bup = blindate(rip.said, rip.said, opening.said)
    hab.interact(data=[dict(s=event.sad['n'], d=event.said)
                       for event in (rip, bup)])
    return rip, bup, opening


def test_shared_evidence_authentication_policy_fails_closed():
    """Require exact KRAM validation for every shared evidence composition."""
    with pytest.raises(ConfigurationError):
        ServiceConfig({'kram': {'enabled': False}})
    with pytest.raises(ConfigurationError):
        ServiceConfig({'kram': {'enabled': True, 'denials': [['qry']]}})


def test_borrowed_evidence_acceptance_and_lifecycle():
    """Real remote KEL intake leaves the caller's stores/runtime ownership intact."""
    with openHby(name='borrowed-source', version=Vrsn_2_0) as source, \
            openHby(name='borrowed-target', version=Vrsn_2_0) as target:
        hab = source.makeHab(name='source')
        reger = RegBaser(name='borrowed-target', temp=True)
        try:
            kvy = Kevery(db=target.db, lax=False, local=False)
            rever = Rever(db=target.db, reger=reger)
            intake = EvidenceProcessor(target, kvy=kvy, rever=rever)
            assert not isinstance(intake, doing.Doer)
            assert intake.rever is rever and intake.kvy is kvy
            result = intake.ingest(hab.replay(gvrsn=Vrsn_2_0))
            assert result == dict(accepted={}, pending={}, rejected={}, heads={})
            assert target.db.kels.getLast(keys=hab.pre, on=0) == hab.kever.serder.said
            assert reger.opened and target.db.opened
            for unsafe in (Kevery(db=target.db, lax=True, local=False),
                           Kevery(db=source.db, lax=False, local=False)):
                with pytest.raises(ConfigurationError, match='strict verifiers'):
                    EvidenceProcessor(target, kvy=unsafe, rever=rever)
        finally:
            reger.close()


def test_public_bup_opening_survives_pending_order_restart_and_exact_clone(tmp_path):
    """Retain a bup-first opening, recover after reopen, and clone that exact proof."""
    with (openHby(name='opening-source', version=Vrsn_2_0) as source,
          openHby(name='opening-target', version=Vrsn_2_0) as target):
        hab = source.makeHab(name='source')
        rip, bup, opening = registry(hab)
        baser = RegBaser(name='opening-durable', headDirPath=str(tmp_path), temp=False)
        first = EvidenceContext(target, reger=baser)
        try:
            result = first.ingest(framed(bup, opening) + framed(rip))
            assert result['pending'] == {rip.said: 2}
            assert not result['accepted'] and not result['rejected']
            assert first.store.opening(bup.said) == opening.qb64
            assert first.registries() == []
        finally:
            first.close()
            assert baser.opened
            baser.close()

        baser.reopen()
        second = EvidenceContext(target, reger=baser)
        try:
            assert second.store.opening(bup.said) == opening.qb64
            result = second.ingest(hab.replay(gvrsn=Vrsn_2_0))
            assert not result['rejected']
            assert second.store.headEvent(rip.said).said == bup.said

            remaining = bytearray(second.clone([rip.said]))
            registryFrames = []
            parser = Parser(version=Vrsn_2_0)
            while remaining:
                dom = parser.parseOne(ims=remaining, processive=False, local=False)
                if isinstance(dom.serder, SerderACDC):
                    registryFrames.append(dom)
            assert [dom.serder.said for dom in registryFrames] == [rip.said, bup.said]
            assert registryFrames[0].bsqs == []
            assert len(registryFrames[1].bsqs) == 1
            assert Blinder(data=BlindState(*registryFrames[1].bsqs[0])).qb64 == opening.qb64
        finally:
            second.close()
            assert baser.opened
            baser.close()


def test_private_bup_remains_acceptable_without_public_opening():
    """Absence of a disclosure does not change ordinary blinded TEL acceptance."""
    with (openHby(name='private-source', version=Vrsn_2_0) as source,
          openHby(name='private-target', version=Vrsn_2_0) as target):
        hab = source.makeHab(name='source')
        rip, bup, _ = registry(hab)
        ctx = EvidenceContext(target)
        try:
            result = ctx.ingest(hab.replay(gvrsn=Vrsn_2_0)
                                + framed(rip) + framed(bup))
            assert not result['pending'] and not result['rejected']
            assert ctx.store.opening(bup.said) is None
            remaining = bytearray(ctx.clone([rip.said]))
            parsed = []
            parser = Parser(version=Vrsn_2_0)
            while remaining:
                dom = parser.parseOne(ims=remaining, processive=False, local=False)
                if isinstance(dom.serder, SerderACDC):
                    parsed.append(dom)
            assert parsed[-1].serder.said == bup.said
            assert parsed[-1].bsqs == []
        finally:
            ctx.close()
            assert not ctx.reger.opened
            assert target.db.opened


def test_clone_never_leaks_pending_rival_opening():
    """An exact pending rival proof cannot replace the accepted event's opening."""
    with (openHby(name='rival-source', version=Vrsn_2_0) as source,
          openHby(name='rival-target', version=Vrsn_2_0) as target):
        hab = source.makeHab(name='source')
        rip, accepted, acceptedOpening = registry(hab)
        acceptedKel = hab.replay(gvrsn=Vrsn_2_0)
        rivalOpening = Blinder.blind(acdc=acceptedOpening.acdc, state='revoked')
        rival = blindate(rip.said, rip.said, rivalOpening.said)
        ctx = EvidenceContext(target)
        try:
            assert not ctx.ingest(acceptedKel + framed(rip)
                                  + framed(accepted, acceptedOpening))['rejected']
            result = ctx.ingest(framed(rival, rivalOpening))
            assert result['pending'] == {rip.said: 1}
            assert ctx.store.opening(rival.said) == rivalOpening.qb64

            remaining = bytearray(ctx.clone([rip.said]))
            openings = []
            parser = Parser(version=Vrsn_2_0)
            while remaining:
                dom = parser.parseOne(ims=remaining, processive=False, local=False)
                if isinstance(dom.serder, SerderACDC) and dom.serder.ilk == 'bup':
                    openings.extend(dom.bsqs)
            assert len(openings) == 1
            assert Blinder(data=BlindState(*openings[0])).qb64 == acceptedOpening.qb64
        finally:
            ctx.close()


def test_presented_openings_and_retired_upd_fail_before_persistence():
    """Reject invalid openings and syntactic upd without staging their bodies."""
    with (openHby(name='refusal-source', version=Vrsn_2_0) as source,
          openHby(name='refusal-target', version=Vrsn_2_0) as target):
        hab = source.makeHab(name='source')
        rip, bup, opening = registry(hab)
        ctx = EvidenceContext(target)
        try:
            with pytest.raises(ValidationError, match='exact stored event body'):
                ctx.store.retainOpening(bup, opening)
            wrong = Blinder.blind(acdc=opening.acdc, state='revoked')
            assert ctx.ingest(framed(bup, wrong))['rejected']['stream']
            assert ctx.store.event(bup.said) is None

            attachments = Blinder.enclose([opening, opening])
            multiple = bytes(bup.raw) + bytes(Counter.enclose(
                qb64=attachments, code=Codens.AttachmentGroup, version=Vrsn_2_0))
            assert ctx.ingest(multiple)['rejected']['stream']
            assert ctx.store.event(bup.said) is None

            public = update(rip.said, rip.said, Diger(ser=b'credential').qb64, 'issued')
            rejected = ctx.ingest(framed(public))['rejected']['stream']
            assert 'retired' in rejected
            assert ctx.store.event(public.said) is None

            ctx.reger.openings.pin(keys=bup.said, val=wrong.qb64)
            rejected = ctx.ingest(framed(bup, opening))
            assert 'different public opening' in rejected['rejected']['stream']
            assert ctx.store.event(bup.said) is None
        finally:
            ctx.close()
