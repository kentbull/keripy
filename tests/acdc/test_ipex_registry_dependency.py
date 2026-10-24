"""ACDC v2 IPEX grants distinguish unavailable registry openings from known contradictions.

Fixture construction follows test_ipexing's real anchored registry examples;
independent Haberies and normal processors replace any accepted-table injection.
"""
import pytest

from keri import Vrsn_2_0
from keri.acdc import Regery, acdcmap, blindate, grant, loadHandlers
from keri.app import openHby
from keri.app.evidencing import EvidenceContext as Evidence
from keri.core import Blinder, Counter, Codens, Diger, Noncer, Number, Parser
from keri.peer import Exchanger


class Notices:
    """Receive core notifications without opening an unrelated application store."""

    def add(self, attrs):
        """Ignore transient notifications while testing concrete accepted/escrow evidence.

        Args:
            attrs (dict): Core accepted-notification payload, unused by this test.

        Returns:
            None. Opens no unrelated application store or alternate acceptance path."""
        pass


def anchor(hab, registry, event):
    """Commit the exact staged TEL event with a real controller key-event seal.

    Args:
        hab (Hab): Registry controller creating its next signed interaction.
        registry (Registry): Concrete engine holding the staged TEL event.
        event (SerderACDC): Exact registry event to seal and accept.

    Returns:
        SerderKERI: Accepted sealing key event.

    Raises:
        AssertionError: The real anchor cannot advance registry acceptance."""
    hab.interact(data=[dict(i=registry.regk, s=event.sad['n'], d=event.said)])
    assert registry.anchorMsg(event.said)
    return hab.kever.serder


def public(*events):
    """Frame public ACDC v2 registry TEL bodies for ordinary parser intake.

    Args:
        *events: Ordered TEL events whose exact raw bytes to concatenate.

    Returns:
        bytes: Each body followed by a complete v2 zero-count attachment-group foot.
        The helper neither signs nor injects acceptance for those events."""
    foot = Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b
    return b''.join(event.raw + foot for event in events)


@pytest.mark.parametrize('bound', [False, True])
def test_unknown_target_opening_escrows_then_accepts_without_grant_replay(bound):
    """Recover a signed Grant carrying a valid opening outside the accepted TEL prefix.

    Args:
        bound (bool): Whether openings additionally bind exact recipient KEL coordinates.

    Returns:
        None. Assertions require ordinary EXN escrow at stale event 1 and acceptance
        after real event-2 KEL/TEL arrival without Grant replay. Malformed/wrong-target,
        duplicate/stale-known, resolved-source, and conflicting-bound proofs remain
        permanent refusals; a self-valid opening never published remains unresolved.

    All Haberies/registry/evidence owners close in finally/context-manager paths.
    Neither the fixture nor dependency classification writes synthetic accepted rows,
    infers an unmatched opening's ordinal, or asserts publication time/freshness."""
    with (openHby(name='opening-source', version=Vrsn_2_0) as source,
          openHby(name='opening-verifier', version=Vrsn_2_0) as verifier):
        issuer = source.makeHab(name='issuer')
        recipient = verifier.makeHab(name='recipient')
        sourceRegistry = Regery(source, name=source.name, temp=True)
        evidence = Evidence(verifier)
        verifierRegistry = Regery(verifier, name=verifier.name, baser=evidence.reger, temp=True)
        try:
            registry = sourceRegistry.makeRegistry('authority', issuer.pre)
            rip = sourceRegistry.store.event(registry.regk)
            anchor(issuer, registry, rip)
            credential = acdcmap(israid=issuer.pre, iseaid=recipient.pre,
                regid=registry.regk, attribute=dict(d='', status='authorized'))
            coordinates = dict(bound=True, bsn=0, bd=recipient.kever.serder.said) if bound else {}
            first = Blinder.blind(acdc=credential.said, state='issued', **coordinates)
            event1 = blindate(registry.regk, rip.said, first.said)
            registry.processEvent(event1)
            firstAnchor = anchor(issuer, registry, event1)
            oldKel = bytes(issuer.replay(gvrsn=Vrsn_2_0))

            second = Blinder.blind(acdc=credential.said, state='issued', **coordinates)
            event2 = blindate(registry.regk, event1.said, second.said, sn=2)
            registry.processEvent(event2)
            anchor(issuer, registry, event2)

            exc = Exchanger(verifier, handlers=[])
            loadHandlers(verifier, exc, Notices(), rgy=verifierRegistry)
            parser = Parser(kvy=evidence.kvy, rgy=evidence.rever, exc=exc,
                            local=False, version=Vrsn_2_0)
            parser.parse(ims=bytearray(oldKel + public(rip, event1)))
            assert verifierRegistry.store.headEvent(registry.regk).said == event1.said

            def submission(message, proofs):
                """Build and ingest one signed Grant with exactly the selected node-local proofs.

                Args:
                    message (str): Human payload distinguishing independent test Grants.
                    proofs (Iterable[Blinder]): Supplied openings, including deliberate hostile sets.

                Returns:
                    SerderKERI: Authored exchange after ordinary parser dispatch. Returning it
                    proves no acceptance; callers inspect concrete EXN/escrow state separately."""
                from keri.core import messagize
                origin = messagize(credential, bonds=[proof.data for proof in proofs],
                                   gvrsn=Vrsn_2_0)
                exn, attachment = grant(issuer, recipient.pre, message, origin=origin)
                parser.parse(ims=bytearray(exn.raw + attachment))
                return exn

            unknown = submission('event 2 opening while verifier has event 1', [second])
            assert not exc.complete(unknown.said)
            assert verifier.db.epse.get((unknown.said,)) is not None

            # Only normal public evidence acquisition follows; never replay grant.
            parser.parse(ims=bytearray(issuer.replay(gvrsn=Vrsn_2_0) + public(event2)))
            evidence.kvy.processEscrows()
            evidence.rever.processEscrows()
            exc.processEscrow()
            assert verifierRegistry.store.headEvent(registry.regk).said == event2.said
            assert exc.complete(unknown.said)
            assert verifier.db.epse.get((unknown.said,)) is None
            assert exc.routes['/ipex/grant'].verifyAccepted(unknown.said)

            wrongTarget = Blinder.blind(acdc=Diger(ser=b'another credential').qb64,
                                        state='issued', **coordinates)
            corrupted = Blinder(crew=second.crew._replace(u=Noncer().qb64), verify=False)
            for label, proofs in [('wrong target', [wrongTarget]),
                                  ('corrupted opening', [corrupted]),
                                  ('stale known opening', [first]),
                                  ('duplicate known opening', [second, second])]:
                refused = submission(label, proofs)
                assert not exc.complete(refused.said), label
                assert verifier.db.epse.get((refused.said,)) is None, label

            handler = exc.routes['/ipex/grant']
            unknownThird = Blinder.blind(acdc=credential.said, state='issued', **coordinates)
            # A resolved explicit historical source selects event 1 exactly.
            # An unknown proof cannot turn its contradictory opening into retry.
            assert handler._vetRegistry(registry.regk, [unknownThird], credential.said,
                controller=issuer.pre,
                sourceSeals=[(issuer.kever.prefixer, Number(num=firstAnchor.sn),
                              Diger(qb64=firstAnchor.said))], requireSource=True) is None
            # A self-valid opening is not proof that any TEL ever committed it.
            # Without that acquisition it remains unresolved, never accepted.
            unanchored = submission('no matching TEL event exists locally', [unknownThird])
            exc.processEscrow()
            assert not exc.complete(unanchored.said)
            assert verifier.db.epse.get((unanchored.said,)) is not None
            if bound:
                wrongBound = Blinder.blind(acdc=credential.said, state='issued', bound=True,
                    bsn=0, bd=Diger(ser=b'conflicts with accepted Issuee inception').qb64)
                refused = submission('conflicting bound digest', [wrongBound])
                assert not exc.complete(refused.said)
                assert verifier.db.epse.get((refused.said,)) is None
                # An opaque accepted ancestor can commit an invalid bound claim.
                # A separate unknown proof must not hide that known contradiction.
                bad3 = blindate(registry.regk, event2.said, wrongBound.said, sn=3)
                registry.processEvent(bad3)
                anchor(issuer, registry, bad3)
                fourth = Blinder.blind(acdc=credential.said, state='issued', **coordinates)
                event4 = blindate(registry.regk, bad3.said, fourth.said, sn=4)
                registry.processEvent(event4)
                anchor(issuer, registry, event4)
                parser.parse(ims=bytearray(issuer.replay(gvrsn=Vrsn_2_0) + public(bad3, event4)))
                assert verifierRegistry.store.headEvent(registry.regk).said == event4.said
                for proofs in ([wrongBound, unknownThird], [unknownThird, wrongBound]):
                    refused = submission('known bound contradiction must win ' + proofs[0].said, proofs)
                    assert not exc.complete(refused.said)
                    assert verifier.db.epse.get((refused.said,)) is None
        finally:
            verifierRegistry.close()
            evidence.close()
            sourceRegistry.close()
