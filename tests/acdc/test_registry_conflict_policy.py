"""R6 local TEL conflict reporting over independently authenticated KELs.

Batch verification refuses a bundle containing proven competitors. Durable
ingestion retains its accepted slot and one exact conflicting body plus KEL
reference; it does not resolve forks or archive every competing event.
"""
from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0
from keri.acdc import blindate, regcept
from keri.acdc.regbasing import RegBaser
from keri.acdc.regeventing import Rever, vet, vetAnchor
from keri.app import openHby
from keri.core import Blinder, Diger, Number, Parser, messagize, eventing
from keri.kering import DuplicitousRegistryError, ValidationError


@pytest.fixture
def scene(tmp_path):
    """Yield independent issuer/verifier stores with one accepted inception.

    tmp_path selects persistent verifier storage for reopen scenarios. Returns
    a namespace of real protocol objects; assertion failures expose bad setup.
    All stores close after the test, including when an assertion fails.
    """
    with (openHby(name='conflict-issuer', version=Vrsn_2_0) as issuer,
          openHby(name='conflict-verifier', temp=False, headDirPath=str(tmp_path),
                  version=Vrsn_2_0) as receiver):
        hab = issuer.makeHab(name='issuer')
        reger = RegBaser(name=receiver.name, temp=False, headDirPath=str(tmp_path))
        try:
            rever = Rever(db=receiver.db, reger=reger)
            rip = regcept(israid=hab.pre)
            setup = SimpleNamespace(hab=hab, issuer=issuer, receiver=receiver, reger=reger,
                                    rever=rever, rip=rip, root=str(tmp_path))
            seal(setup, rip)
            assert rever.processEvent(rip)
            yield setup
        finally:
            reger.close()


def candidate(scene, state, sn=1, prior=None):
    """Return a real update for scene's registry with distinct state material.

    state selects the committed state; sn/prior select its chain position.
    Builder errors propagate. No database acceptance occurs here.
    """
    blid = Blinder.blind(acdc=Diger(ser=b'credential').qb64, state=state).said
    return blindate(regid=scene.rip.said, prior=prior or scene.rip.said,
                     blid=blid, sn=sn)


def seal(scene, *events):
    """Seal events in the issuer KEL and independently verify its signed replay.

    scene provides issuer/verifier contexts; events are TEL bodies. Returns
    None; protocol errors propagate or fail the accepted-KEL assertion.
    """
    scene.hab.interact(data=[dict(s=event.sad['n'], d=event.said) for event in events])
    Parser(kvy=scene.receiver.kvy).parse(ims=bytearray(scene.hab.replay(gvrsn=Vrsn_2_0)))
    assert scene.receiver.kevers[scene.hab.pre].serder.said == scene.hab.kever.serder.said


def proof(scene, accepted, rival):
    """Assert the retained exact conflict body, anchor and stable accepted slot.

    scene owns storage; accepted/rival are the two competing events. Returns
    None; assertion failures identify incomplete proof or altered acceptance.
    """
    assert scene.reger.tels.get(keys=scene.rip.said, on=accepted.sn).qb64 == accepted.said
    assert scene.reger.heads.get(keys=scene.rip.said).qb64 == accepted.said
    retained = scene.reger.conflicts.get((scene.rip.said, f'{accepted.sn:x}'))
    assert retained.raw == rival.raw
    number, diger = scene.reger.ancs.get(keys=rival.said)
    assert vetAnchor(rival, db=scene.receiver.db, issuer=scene.hab.pre) == (number.num, diger.qb64)


@pytest.mark.parametrize('reverse', (False, True))
def test_authenticated_first_acceptance_differs_from_strict_batch(scene, reverse):
    """Preserve local arrival choice while batch rejects either proven order.

    reverse selects the direct intake order. Returns None; assertions and
    expected DuplicitousRegistryError checks falsify unstable acceptance.
    """
    left, right = candidate(scene, 'issued'), candidate(scene, 'revoked')
    seal(scene, left)
    seal(scene, right)
    first, second = (right, left) if reverse else (left, right)
    assert scene.rever.processEvent(first)
    with pytest.raises(DuplicitousRegistryError):
        scene.rever.processEvent(second)
    proof(scene, first, second)
    assert scene.rever.processEvent(first)  # accepted replay stays idempotent
    for batch in ([left, right], [right, left]):
        with pytest.raises(DuplicitousRegistryError):
            vet(scene.rip, updates=batch, db=scene.receiver.db)


@pytest.mark.parametrize('reverse', (False, True))
@pytest.mark.parametrize('gap', (False, True))
def test_jointly_queued_candidates_use_local_anchor_order(scene, reverse, gap):
    """Choose among jointly ready queued candidates without a global guarantee.

    reverse selects staging order; gap adds a missing predecessor to exercise
    out-of-order escrow too. Returns None; assertions expose monopolization
    or missing proof for the anchored losing sibling.
    """
    prior = candidate(scene, 'predecessor') if gap else scene.rip
    if gap:
        assert not scene.rever.processEvent(prior)
    left = candidate(scene, 'issued', sn=2 if gap else 1, prior=prior.said)
    right = candidate(scene, 'revoked', sn=2 if gap else 1, prior=prior.said)
    for event in ((right, left) if reverse else (left, right)):
        assert not scene.rever.processEvent(event)
    seal(scene, right)  # the second-stage event may authenticate first
    seal(scene, left)
    scene.rever.processEscrows()
    if gap:
        assert scene.reger.ooes.get(keys=scene.rip.said, on=2)
        seal(scene, prior)
        scene.rever.processEscrows()
    proof(scene, right, left)
    assert scene.reger.maes.get(keys=scene.rip.said, on=right.sn) == []
    assert scene.reger.ooes.get(keys=scene.rip.said, on=right.sn) == []


def test_delayed_anchor_never_replaces_an_authenticated_head(scene):
    """Keep an unknown rival pending until authentication proves its conflict.

    scene supplies real stores. Returns None; assertions expose premature
    conflict labels, junk priority or late replacement of the accepted event.
    """
    early, ready = candidate(scene, 'issued'), candidate(scene, 'revoked')
    assert not scene.rever.processEvent(early)
    seal(scene, ready)
    assert scene.rever.processEvent(ready)
    assert scene.reger.conflicts.get((scene.rip.said, '1')) is None
    assert scene.reger.maes.get(keys=scene.rip.said, on=1) == [(early.said,)]
    seal(scene, early)
    scene.rever.processEscrows()
    proof(scene, ready, early)


def test_invalid_signed_kel_and_wrong_anchor_do_not_prove_conflict(scene):
    """Reject false anchors; unaccepted signed KEL bytes confer no priority.

    scene supplies independent KEL verification. Returns None; assertions
    expose false proof classification or acceptance from a wrong signing key.
    """
    good, rival = candidate(scene, 'issued'), candidate(scene, 'revoked')
    seal(scene, good)
    assert scene.rever.processEvent(good)
    other = scene.issuer.makeHab(name='wrong-signer')
    forged = eventing.interact(pre=scene.hab.pre, dig=scene.hab.kever.serder.said,
        sn=scene.hab.kever.sn + 1, data=[dict(s='1', d=rival.said)], version=Vrsn_2_0)
    message = messagize(forged, sigers=other.sign(forged.raw), gvrsn=Vrsn_2_0)
    Parser(kvy=scene.receiver.kvy).parse(ims=bytearray(message))
    assert scene.receiver.db.kels.getLast(keys=scene.hab.pre, on=forged.sn) is None
    assert not scene.rever.processEvent(rival)
    with pytest.raises(ValidationError):
        scene.rever.processEvent(rival, sscs=[(Number(num=scene.hab.kever.sn),
            Diger(qb64=scene.hab.kever.serder.said))])
    assert scene.reger.conflicts.get((scene.rip.said, '1')) is None
    assert scene.reger.heads.get(keys=scene.rip.said).qb64 == good.said


def test_conflict_proof_and_pending_rival_survive_reopen(scene):
    """Recover pending authentication and retain only the first proven rival.

    scene provides persistent stores. Returns None; assertions and expected
    conflict errors expose lost proof, replacement or repeat-delivery growth.
    """
    first, pending = candidate(scene, 'issued'), candidate(scene, 'revoked')
    seal(scene, first)
    assert scene.rever.processEvent(first)
    assert not scene.rever.processEvent(pending)
    scene.reger.close()
    scene.receiver.close()
    with openHby(name='conflict-verifier', temp=False, headDirPath=scene.root,
                 version=Vrsn_2_0) as receiver:
        reopened = RegBaser(name=receiver.name, temp=False, headDirPath=scene.root)
        try:
            scene.receiver, scene.reger = receiver, reopened
            scene.rever = Rever(db=receiver.db, reger=reopened)
            seal(scene, pending)
            scene.rever.processEscrows()
            proof(scene, first, pending)
            third = candidate(scene, 'accepted')
            seal(scene, third)
            for event in (pending, pending, third):
                with pytest.raises(DuplicitousRegistryError):
                    scene.rever.processEvent(event)
            assert len(list(reopened.conflicts.getTopItemIter())) == 1
            proof(scene, first, pending)
        finally:
            reopened.close()
    # Reopen after the proof itself was recorded, not only while it was pending.
    with (openHby(name='conflict-verifier', temp=False, headDirPath=scene.root,
                  version=Vrsn_2_0) as receiver):
        reopened = RegBaser(name=receiver.name, temp=False, headDirPath=scene.root)
        try:
            scene.receiver, scene.reger = receiver, reopened
            proof(scene, first, pending)
        finally:
            reopened.close()
