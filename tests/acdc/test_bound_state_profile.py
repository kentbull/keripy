"""Exact bound-state KEL references, independent of receiver clock or latest head."""
import pytest

from keri import Vrsn_2_0
from keri.acdc import acdcmap
from keri.acdc.regeventing import vetBound
from keri.app import openHby
from keri.core import Blinder, BoundState, Diger, Kevery, Parser
from keri.kering import MisanchorError, MisbindingError, MissingAnchorError


def opening(acdc='', state='', *, sn=0, dig=''):
    """Build a real bound opening with explicit historical Issuee coordinates.

    Args:
        acdc (str): Target credential SAID; empty for a placeholder.
        state (str): Transaction state; empty for a placeholder.
        sn (int): Issuee KEL ordinal, including zero for inception.
        dig (str): Exact Issuee event digest, empty only for a placeholder.

    Returns:
        Blinder: Serialized BoundState whose digest commits to all supplied fields."""
    return Blinder.blind(acdc=acdc, state=state, bound=True, bsn=sn, bd=dig)


def test_bound_historical_interaction_survives_issuee_rotation():
    """Verify an exact historical interaction after Issuee rotation; distinguish conflicting digest from missing ordinal.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with openHby(name='bound-historical', version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name='issuer')
        issuee = hby.makeHab(name='issuee')
        credential = acdcmap(israid=issuer.pre, iseaid=issuee.pre, attribute=dict(d='', role='authority'))
        issuee.interact(data=[])
        event = issuee.kever.serder
        proof = opening(credential.said, 'issued', sn=event.sn, dig=event.said)
        issuee.rotate()
        assert not event.estive and issuee.kever.sn > event.sn
        assert vetBound(proof, acdc=credential, db=hby.db).said == event.said
        bad = opening(credential.said, 'issued', sn=event.sn, dig=issuee.kever.serder.said)
        with pytest.raises(MisanchorError):
            vetBound(bad, acdc=credential, db=hby.db)
        absent = opening(credential.said, 'issued', sn=9, dig=event.said)
        with pytest.raises(MissingAnchorError):
            vetBound(absent, acdc=credential, db=hby.db)


def test_bound_requires_same_credential_and_its_actual_issuee_kel():
    """Reject substituted credential, foreign KEL, absent Issuee, and incomplete nonvacuous bound coordinates.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with openHby(name='bound-identity', version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name='issuer')
        issuee = hby.makeHab(name='issuee')
        other = hby.makeHab(name='other')
        credential = acdcmap(israid=issuer.pre, iseaid=issuee.pre, attribute=dict(d='', role='authority'))
        event = issuee.kever.serder
        proof = opening(credential.said, 'issued', dig=event.said)
        assert vetBound(proof, acdc=credential, db=hby.db).said == event.said
        wrongKel = opening(credential.said, 'issued', dig=other.kever.serder.said)
        with pytest.raises(MisanchorError):
            vetBound(wrongKel, acdc=credential, db=hby.db)
        substitute = acdcmap(israid=issuer.pre, iseaid=other.pre, attribute=dict(d='', role='authority'))
        with pytest.raises(MisbindingError):
            vetBound(proof, acdc=substitute, db=hby.db)
        untargeted = acdcmap(israid=issuer.pre, attribute=dict(d='', role='authority'))
        with pytest.raises(MisbindingError, match='Issuee'):
            vetBound(opening(untargeted.said, 'issued', dig=event.said), acdc=untargeted, db=hby.db)
        with pytest.raises(MisbindingError, match='requires an Issuee key event'):
            vetBound(opening(credential.said, 'issued'), acdc=credential, db=hby.db)


def test_bound_placeholders_are_strict_and_unbound_openings_are_unchanged():
    """Allow only zero/empty bound placeholders while preserving the existing unbound opening contract.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with openHby(name='bound-placeholder', version=Vrsn_2_0) as hby:
        assert vetBound(opening(), acdc=None, db=hby.db) is None
        assert vetBound(Blinder.blind(), acdc=None, db=hby.db) is None
        # Construct a valid BoundState with a real coordinate but no transaction;
        # hashing all six fields does not make that a valid empty placeholder.
        forged = opening(dig=Diger(ser=b'unrelated-event').qb64)
        with pytest.raises(MisbindingError, match='placeholder'):
            vetBound(forged, acdc=None, db=hby.db)
        malformed = Blinder(crew=BoundState(d='', u=forged.uuid, td='', ts='', bn=1, bd=''), makify=True)
        with pytest.raises(MisbindingError, match='placeholder'):
            vetBound(malformed, acdc=None, db=hby.db)


def test_bound_key_event_requires_actual_witness_receipt():
    """Keep accepted local Issuee events retryable until their real witness receipt quorum is present.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with openHby(name='bound-receipt-issuer', version=Vrsn_2_0) as ihby, \
            openHby(name='bound-receipt-witness', version=Vrsn_2_0) as whby:
        witness = whby.makeHab(name='witness', transferable=False)
        issuee = ihby.makeHab(name='issuee', wits=[witness.pre], toad=1)
        issuer = ihby.makeHab(name='issuer')
        credential = acdcmap(israid=issuer.pre, iseaid=issuee.pre, attribute=dict(d='', role='authority'))
        event = issuee.kever.serder
        proof = opening(credential.said, 'issued', dig=event.said)
        # A local witness can accept the controller's KEL before receipting it.
        kvy = Kevery(db=whby.db, lax=False, local=True)
        Parser(kvy=kvy, version=Vrsn_2_0, local=True).parse(ims=bytearray(issuee.replay(gvrsn=Vrsn_2_0)))
        assert whby.db.kels.getLast(keys=issuee.pre, on=0) == event.said
        with pytest.raises(MissingAnchorError, match='fully witnessed'):
            vetBound(proof, acdc=credential, db=whby.db)
        witness.witness(event, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        assert vetBound(proof, acdc=credential, db=whby.db).said == event.said


@pytest.mark.parametrize('valid', [True, False])
def test_shared_vet_and_ipex_validate_bound_issuee_reference(valid):
    """Apply the same bound-reference checks in common TEL verification and signed Grant intake.

    Parameters:
        valid: Whether the bound digest names the real Issuee event or another controller event.

    Returns:
        None. Assertions check the stated evidence boundary."""
    from keri.acdc import Regery, Registrar, blindate, grant, loadHandlers
    from keri.acdc.regeventing import vet, vetBinds
    from keri.core import messagize
    from keri.peer import Exchanger

    class Notices:
        def add(self, attrs):
            """Ignore accepted-notification attributes for this verifier-only test.

            Args:
                attrs (dict): Notification payload deliberately unused by the test.

            Returns:
                None. No notification side effects are needed to observe acceptance."""
            pass

    with openHby(name='bound-production', version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name='issuer')
        issuee = hby.makeHab(name='issuee')
        other = hby.makeHab(name='other')
        rgy = Regery(hby=hby, temp=True)
        try:
            registry = Registrar(rgy=rgy).makeRegistry(name='bound', prefix=issuer.pre)
            rip = rgy.store.event(registry.regk)
            issuer.interact(data=[dict(s=rip.sad['n'], d=rip.said)])
            assert registry.anchorMsg(rip.said)
            acdc = acdcmap(israid=issuer.pre, iseaid=issuee.pre, regid=registry.regk,
                           attribute=dict(d='', role='authority'))
            bound = issuee.kever.serder if valid else other.kever.serder
            proof = opening(acdc.said, 'issued', sn=bound.sn, dig=bound.said)
            update = blindate(regid=registry.regk, prior=rip.said, blid=proof.said)
            registry.processEvent(update)
            issuer.interact(data=[dict(s=update.sad['n'], d=update.said)])
            assert registry.anchorMsg(update.said)
            if valid:
                assert vet(rip, [update], db=hby.db, acdc=acdc, blinder=proof.qb64b).state == 'issued'
                assert vetBinds(rip, [update], db=hby.db, acdc=acdc,
                                blinders=[proof], target=acdc.said).state == 'issued'
            else:
                with pytest.raises(MisanchorError):
                    vet(rip, [update], db=hby.db, acdc=acdc, blinder=proof.qb64b)
                with pytest.raises(MisanchorError):
                    vetBinds(rip, [update], db=hby.db, acdc=acdc,
                             blinders=[proof], target=acdc.said)
            exc = Exchanger(hby=hby, handlers=[])
            loadHandlers(hby, exc, Notices(), rgy=rgy)
            origin = messagize(acdc, bonds=[proof.data], framed=False, gvrsn=Vrsn_2_0)
            exn, atc = grant(issuer, issuee.pre, 'bound proof', origin=origin)
            Parser(version=Vrsn_2_0, exc=exc).parse(ims=bytearray(exn.raw + atc))
            assert exc.complete(exn.said) is valid
        finally:
            rgy.close()


def test_exact_bound_reference_does_not_prove_current_at_publication():
    """A stale issuer assertion violates ACDC's MUST but retains valid crypto.

    Actual execution deliberately anchors the near issuance before publishing
    the far authorization. There are two independent controller KELs; the far
    bound references an authentic older issuee event, which cannot prove the
    absence of the intervening issuee event. This characterizes the evidence
    boundary, not a compliant issuer or an accepted temporal authorization.
    """
    from keri.acdc import Regery, Registrar, blindate
    from keri.acdc.regeventing import vet

    with openHby(name='bound-cross-kel', version=Vrsn_2_0) as hby:
        authority = hby.makeHab(name='authority')
        issuee = hby.makeHab(name='issuee')
        rgy = Regery(hby=hby, temp=True)
        try:
            registrar = Registrar(rgy=rgy)
            farRegistry = registrar.makeRegistry(name='far', prefix=authority.pre)
            nearRegistry = registrar.makeRegistry(name='near', prefix=issuee.pre)
            for reg in (farRegistry, nearRegistry):
                rip = reg.store.event(reg.regk)
                reg.hab.interact(data=[dict(s=rip.sad['n'], d=rip.said)])
                assert reg.anchorMsg(rip.said)
            farRip = farRegistry.store.event(farRegistry.regk)
            nearRip = nearRegistry.store.event(nearRegistry.regk)
            boundEvent = issuee.kever.serder
            far = acdcmap(israid=authority.pre, iseaid=issuee.pre,
                          regid=farRegistry.regk, attribute=dict(d='', role='delegate'))
            near = acdcmap(israid=issuee.pre, regid=nearRegistry.regk,
                           attribute=dict(d='', role='issued under delegation'),
                           edge=dict(d='', authority=dict(n=far.said)))

            # The near issuance is accepted first, before any far issued bup.
            nearProof = Blinder.blind(acdc=near.said, state='issued')
            nearUpdate = blindate(nearRegistry.regk, nearRip.said, nearProof.said)
            nearRegistry.processEvent(nearUpdate)
            issuee.interact(data=[dict(s=nearUpdate.sad['n'], d=nearUpdate.said)])
            nearAnchor = issuee.kever.serder
            assert nearRegistry.anchorMsg(nearUpdate.said)
            assert farRegistry.sn == 0

            # A dishonest authority now commits the older, authentic event.
            # ACDC f0bd097d :2457/:2476 instead requires the CURRENT event.
            proof = opening(far.said, 'issued', sn=boundEvent.sn, dig=boundEvent.said)
            farUpdate = blindate(farRegistry.regk, farRip.said, proof.said)
            farRegistry.processEvent(farUpdate)
            authority.interact(data=[dict(s=farUpdate.sad['n'], d=farUpdate.said)])
            assert farRegistry.anchorMsg(farUpdate.said)
            assert nearAnchor.sn > boundEvent.sn
            assert issuee.kever.serder.said != boundEvent.said

            # Every named reference is real and both complete TEL chains verify.
            # The ordinal comparison alone would nevertheless authorize near.
            assert vetBound(proof, acdc=far, db=hby.db).said == boundEvent.said
            assert vet(farRip, [farUpdate], db=hby.db, acdc=far, blinder=proof).state == 'issued'
            assert vet(nearRip, [nearUpdate], db=hby.db,
                       acdc=near, blinder=nearProof).state == 'issued'
            assert int(proof.crew.bn, 16) < nearAnchor.sn
        finally:
            rgy.close()


@pytest.mark.parametrize('sn,expected', [(0, False), (1, False), (2, True),
                                           (7, True), (8, True), (9, False)])
def test_bound_interval_has_strict_issuance_and_inclusive_revocation(sn, expected):
    """Check strict issuance and inclusive revocation bounds at their exact ordinal boundaries.

    Parameters:
        sn: Near issuance KEL ordinal relative to the authenticated bounds.
        expected: Expected authority validity at that ordinal.

    Returns:
        None. Assertions check the stated evidence boundary."""
    from keri.acdc.regeventing import boundStateAt
    result = boundStateAt([('issued', 1), ('revoked', 8)],
                          issuee='same', issuer='same', sn=sn)
    assert result.valid is expected
    assert result.assurance == 'issuer-current-event'


def test_bound_interval_does_not_compare_different_kels_or_inconsistent_history():
    """Keep cross-KEL ordinals and contradictory bound histories unknown rather than inventing a temporal ordering.

    Returns:
        None. Assertions check the stated evidence boundary."""
    from keri.acdc.regeventing import boundStateAt
    assert boundStateAt([('issued', 1)], issuee='a', issuer='b', sn=99).valid is None
    for transitions in ([('issued', 8), ('revoked', 1)], [('issued', -1)],
                        [('unknown', 1)], [('issued', True)]):
        assert boundStateAt(transitions, issuee='a', issuer='a', sn=2).valid is None


@pytest.mark.parametrize('when,expected', [('before-issued', False), ('resealed-before-issued', False), ('during', True),
                                          ('after-revoked', False), ('partial', False)])
@pytest.mark.parametrize('registryNear', [False, True])
def test_production_graph_bound_authority_uses_real_anchored_history(when, expected, registryNear):
    """Evaluate bound authority using actual signed KEL/TEL history through direct and registry-backed near issuance.

    Parameters:
        when: Placement of the near issuance relative to authorization/revocation bounds.
        expected: Expected authority validity at that ordinal.
        registryNear: Whether near issuance is authenticated through a registry rather than a direct KEL seal.

    Returns:
        None. Assertions check the stated evidence boundary."""
    from keri.acdc import Regery, Registrar, blindate, grant, loadHandlers
    from keri.core import Codens, Counter, Number, SealSource, messagize
    from keri.peer import Exchanger

    class Notices:
        def add(self, attrs):
            """Ignore accepted-notification attributes for this verifier-only test.

            Args:
                attrs (dict): Notification payload deliberately unused by the test.

            Returns:
                None. No notification side effects are needed to observe acceptance."""
            pass

    with openHby(name='bound-graph-interval', version=Vrsn_2_0) as hby:
        authority = hby.makeHab(name='authority')
        issuee = hby.makeHab(name='issuee')
        holder = hby.makeHab(name='holder')
        rgy = Regery(hby=hby, temp=True)
        try:
            registry = Registrar(rgy=rgy).makeRegistry(name='authority', prefix=authority.pre)
            rip = rgy.store.event(registry.regk)
            authority.interact(data=[dict(s=rip.sad['n'], d=rip.said)])
            assert registry.anchorMsg(rip.said)
            far = acdcmap(israid=authority.pre, iseaid=issuee.pre, regid=registry.regk,
                          attribute=dict(d='', role='delegated authority'))
            nearReg = None
            nearProofs = []
            if registryNear:
                nearReg = rgy.makeRegistry(name='near', prefix=issuee.pre)
                inception = rgy.store.event(nearReg.regk)
                issuee.interact(data=[dict(s=inception.sad['n'], d=inception.said)])
                assert nearReg.anchorMsg(inception.said)
            near = acdcmap(israid=issuee.pre, iseaid=holder.pre,
                           regid=nearReg.regk if nearReg else None,
                           attribute=dict(d='', role='subordinate'),
                           edge=dict(d='', authority=dict(n=far.said)))

            def publish(state):
                """Publish an actual bound authority update at the Issuee's current KEL event.

                Args:
                    state (str): issued/revoked authority state to commit for the far credential.

                Returns:
                    Blinder: Exact opening after the authority TEL and its real KEL anchor accept."""
                bound = issuee.kever.serder
                proof = opening(far.said, state, sn=bound.sn, dig=bound.said)
                event = blindate(registry.regk, registry.regd, proof.said, sn=registry.sn + 1)
                registry.processEvent(event)
                authority.interact(data=[dict(s=event.sad['n'], d=event.said)])
                assert registry.anchorMsg(event.said)
                return proof

            def anchorNear():
                """Anchor near issuance in its real issuer KEL, optionally through its TEL.

                Returns:
                    SealSource: Exact near-issuance anchor coordinates used by graph verification.
                    Assertions require an optional near-registry update to accept before return."""
                event = None
                if nearReg:
                    proof = Blinder.blind(acdc=near.said, state='issued')
                    event = blindate(nearReg.regk, nearReg.regd, proof.said,
                                     sn=nearReg.sn + 1)
                    nearReg.processEvent(event)
                    nearProofs.append(proof)
                seal = dict(s=event.sad['n'], d=event.said) if event else dict(d=near.said)
                issuee.interact(data=[seal])
                if event:
                    assert nearReg.anchorMsg(event.said)
                event = issuee.kever.serder
                return SealSource(s=Number(num=event.sn), d=Diger(qb64=event.said))

            if when in ('before-issued', 'resealed-before-issued'):
                nearSource = anchorNear()
            issued = publish('issued')
            if when in ('during', 'partial', 'resealed-before-issued'):
                nearSource = anchorNear()
            revoked = publish('revoked')
            if when == 'after-revoked':
                nearSource = anchorNear()

            exc = Exchanger(hby=hby, handlers=[])
            loadHandlers(hby, exc, Notices(), rgy=rgy)
            origin = (messagize(near, bonds=[proof.data for proof in nearProofs],
                                framed=False, gvrsn=Vrsn_2_0)
                      if nearReg else messagize(near, bonds=[nearSource], framed=False, gvrsn=Vrsn_2_0))
            proofs = [revoked] if when == 'partial' else [issued, revoked]
            artifact = messagize(far, bonds=[proof.data for proof in proofs],
                                  framed=False, gvrsn=Vrsn_2_0)
            plan = dict(dp=[[near.sad['s']['$id'], '/', []],
                             [far.sad['s']['$id'], '/e/authority/_/', []]])
            exn, atc = grant(issuee, holder.pre, 'historical bound authority',
                              origin=origin, artifacts=[artifact], modifiers=plan)
            Parser(version=Vrsn_2_0, exc=exc).parse(ims=bytearray(exn.raw + atc))
            assert exc.complete(exn.said) is expected
            if when == 'partial':
                # NOT must not turn an undisclosed historical state into proof.
                handler = exc.routes['/ipex/grant']
                parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(artifact), processive=False)[0]
                nodes = {near.said: dict(serder=near, sscs=[(nearSource.s, nearSource.d)]),
                         far.said: parsed}
                assert handler._evaluateLeafEdge(dict(n=far.said, o='NOT'),
                    nodes=nodes, nserder=near) is None
        finally:
            rgy.close()
