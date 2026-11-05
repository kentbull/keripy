"""Issuer-opening repair preserves the immutable Grant and ordinary admission."""

from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0 as V2
from keri.acdc import Regery, Registrar, acdcmap, admit, apply, grant, loadHandlers
from keri.acdc.ipexing import _normalizeNodeStream, _sign
from keri.app import openCF, openHby
from keri.core import (Blinder, Diger, Kevery, Kramer, Noncer, Number, Parser,
                       Schemer, SerderACDC, SerderKERI, messagize)
from keri.kering import MissingSignatureError
from keri.help import helping
from keri.peer import Exchanger
from keri.peer.exchanging import verify


def anchor(hab, registry, event):
    hab.interact(data=[dict(i=registry.regk, s=event.sad["n"], d=event.said)],
                 framed=False, gvrsn=V2)
    assert registry.anchorMsg(event.said)


@pytest.fixture
def history():
    with (openHby(name="pending-presentation", base="test", version=V2) as hby,
          openCF(name="pending-presentation", base="test") as cf):
        issuer = hby.makeHab(name="issuer")
        holder = hby.makeHab(name="holder", icount=2, isith="2", ncount=2, nsith="2")
        verifier = hby.makeHab(name="verifier")
        rgy = Regery(hby=hby, name="pending-presentation", temp=True)
        try:
            registrar = Registrar(rgy=rgy)
            registry = registrar.makeRegistry(name="states", prefix=issuer.pre)
            anchor(issuer, registry, rgy.store.event(registry.regk))
            acdc = acdcmap(israid=issuer.pre, iseaid=holder.pre, regid=registry.regk,
                           attribute=dict(d="", role="member"))
            proofs, events = [], []
            for state in ("issued", "revoked", "", ""):
                proof, event = (registrar.issue(registry, acdc=acdc, state=state)
                                if state else registrar.vacate(registry))
                anchor(issuer, registry, event)
                proofs.append(proof)
                events.append(event)
            exc = Exchanger(hby=hby, handlers=[])
            loadHandlers(hby=hby, exc=exc, rgy=rgy,
                         notifier=SimpleNamespace(add=lambda **_: None))
            # Live auxiliary authority requires accepted KRAM exchange evidence.
            cf.put(dict(kram=dict(enabled=True, denials=[],
                caches={"~": [1000, 5000, 60000, 300000, 5000, 60000, 300000]})))
            kvy = Kevery(db=hby.db, kramer=Kramer(db=hby.db, cf=cf), exc=exc)
            yield SimpleNamespace(hby=hby, issuer=issuer, holder=holder, verifier=verifier,
                rgy=rgy, registrar=registrar, acdc=acdc, proofs=proofs, events=events,
                registry=registry, exc=exc, kvy=kvy)
        finally:
            rgy.close()


def present(h, proofs=(), **kwa):
    origin = (messagize(serder=h.acdc, bonds=[proof.data for proof in proofs], gvrsn=V2)
              if proofs else h.acdc.raw)
    return grant(hab=h.holder, recp=h.verifier.pre, message="present", origin=origin, **kwa)


def receive(h, message, atc):
    Parser(version=V2).parse(ims=bytearray(message.raw + atc), framed=False,
                             kvy=h.kvy, exc=h.exc)


def context(h, message, **kwa):
    scope = dict(xid=message.ked.get("x") or message.said,
                 sender=h.holder.pre, recipient=h.verifier.pre)
    return h.exc.presentationContext(message.said, **(scope | kwa))


def signed(node, hab):
    return messagize(serder=node, tsgs=[(hab.kever.prefixer,
        Number(sn=hab.kever.lastEst.s), Diger(qb64=hab.kever.lastEst.d),
        hab.sign(ser=node.raw, indexed=True))], gvrsn=V2)


@pytest.mark.parametrize("stale", [False, True])
def test_missing_current_openings_retry_same_grant_after_minimal_suffix(history, stale):
    h = history
    message, atc = present(h, h.proofs[:1] if stale else [])
    receive(h, message, atc)
    assert h.hby.db.epse.get((message.said,)) is not None
    assert h.hby.db.exns.get((message.said,)) is None
    assert h.hby.db.exrs.get((message.said, h.acdc.said)) is None
    retained, nests, scope = context(h, message)
    assert retained.raw == message.raw and scope == {h.registry.regk: (h.acdc.said,)}
    assert nests[0].serder.raw == h.acdc.raw
    deadline = h.exc.exchangeDeadline(message)
    assert deadline is not None
    # Only append node-local openings; body and sender signature remain exact.
    nests[0].bsqs.extend(tuple(proof.data) for proof in h.proofs[1:])
    tsgs, cigars = verify(h.hby, retained)
    h.exc.processEvent(serder=retained, tsgs=tsgs, cigars=cigars, nests=nests)
    assert h.hby.db.exns.get((message.said,)).raw == message.raw
    assert h.hby.db.exrs.get((message.said, h.acdc.said)).state == "revoked"
    assert h.hby.db.epse.get((message.said,)) is None
    assert h.exc.exchangeDeadline(message) == deadline
    assert context(h, message) is not None
    reply, ratc = admit(hab=h.verifier, message="received", grant=message)
    receive(h, reply, ratc)
    assert h.hby.db.exns.get((reply.said,)) is not None
    assert context(h, message) is None


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("opener", ["grant", "apply"])
def test_first_accepted_grant_keeps_original_auxiliary_deadline(history, fakeHelpingClock, enabled, opener):
    h = history
    with openCF(name="presentation-deadline", base="test") as cf:
        cf.put(dict(kram=dict(enabled=enabled, denials=[],
            caches={"~": [1000, 5000, 60000, 120000, 5000, 60000, 240000]})))
        kvy = Kevery(db=h.hby.db, kramer=Kramer(db=h.hby.db, cf=cf), exc=h.exc)
        prior = {}
        if opener == "apply":
            request, ratc = apply(hab=h.verifier, recp=h.holder.pre, message="request",
                modifiers=dict(dp=[[[h.acdc.schema["$id"], "/", []]]]))
            Parser(version=V2).parse(ims=bytearray(request.raw + ratc), kvy=kvy)
            prior["apply"] = request
            fakeHelpingClock.advance(seconds=30)
        message, atc = present(h, h.proofs[1:], **prior)
        Parser(version=V2).parse(ims=bytearray(message.raw + atc), kvy=kvy)
    assert h.hby.db.exns.get((message.said,)) is not None
    if opener == "apply":
        other, oatc = present(h, h.proofs[1:])
        receive(h, other, oatc)
        assert h.hby.db.exns.get((other.said,)) is not None
        # Simulate a conflicting retained response index using another real,
        # authenticated Grant. Only this exact accepted response may recheck.
        h.hby.db.erpy.pin((request.said,), Diger(qb64=other.said))
        assert context(h, message) is None
        h.hby.db.erpy.pin((request.said,), Diger(qb64=message.said))
    key = (h.holder.pre, message.ked.get("x") or message.said, message.said)
    if not enabled:
        # KRAM-off intake records no exchange lifetime, so it grants no live authority.
        assert h.hby.db.kramTMSC.get(key) is None
        assert h.exc.exchangeDeadline(message) is None
        assert context(h, message) is None
        return
    cache = h.hby.db.kramTMSC.get(key)
    deadline = helping.fromIso8601(cache.xdt) + timedelta(milliseconds=cache.xl)
    assert h.exc.exchangeDeadline(message) == deadline
    fakeHelpingClock.set(helping.toIso8601(deadline - timedelta(milliseconds=1)))
    result = context(h, message)
    assert result is not None
    if opener == "apply":
        original = h.hby.db.enst.get((message.said,))
        tsgs, cigars = verify(h.hby, message)
        assert h.exc.processEvent(serder=message, tsgs=tsgs, cigars=cigars,
                                  nests=result[1]) is False
        assert h.hby.db.enst.get((message.said,)) == original
    receive(h, message, atc)
    assert h.exc.exchangeDeadline(message) == deadline
    fakeHelpingClock.advance(milliseconds=1)
    assert context(h, message) is None
    receive(h, message, atc)
    assert context(h, message) is None
    h.hby.db.kramTMSC.rem(key)  # Pruned KRAM evidence cannot acquire new lifetime.
    receive(h, message, atc)
    assert h.exc.exchangeDeadline(message) is None
    assert context(h, message) is None


@pytest.mark.parametrize("fault", ["unanchored", "bad-digest", "duplicate", "wrong-target", "wrong-bound"])
def test_supplied_bad_opening_never_becomes_auxiliary_authority(history, fault):
    h = history
    if fault == "unanchored":
        proof = Blinder.blind(acdc=h.acdc.said, state="issued")
    elif fault == "bad-digest":
        proof = SimpleNamespace(data=h.proofs[0].data._replace(u=Noncer()))
    elif fault in ("wrong-target", "wrong-bound"):
        other = (acdcmap(israid=h.issuer.pre, iseaid=h.holder.pre, regid=h.registry.regk,
                         attribute=dict(d="", role="other")) if fault == "wrong-target" else h.acdc)
        bound = dict(bound=True, bsn=h.holder.kever.sn,
                      bd=h.issuer.kever.serder.said) if fault == "wrong-bound" else {}
        proof, event = h.registrar.issue(h.registry, acdc=other, **bound)
        anchor(h.issuer, h.registry, event)
        _, event = h.registrar.vacate(h.registry)
        anchor(h.issuer, h.registry, event)
    else:
        proof = h.proofs[0]
    message, atc = present(h, [proof, proof] if fault == "duplicate" else [proof])
    receive(h, message, atc)
    assert context(h, message) is None
    assert h.hby.db.exns.get((message.said,)) is None
    assert h.hby.db.epse.get((message.said,)) is None
    assert h.hby.db.exrs.get((message.said, h.acdc.said)) is None


def test_presentation_context_rechecks_sender_threshold_and_exact_scope(history):
    h = history
    message, atc = present(h)
    parsed = Parser(version=V2).parse(ims=bytearray(message.raw + atc),
                                     framed=False, processive=False)[0]
    pre, number, diger, sigers = parsed.tsgs[0]
    with pytest.raises(MissingSignatureError):
        h.exc.processEvent(serder=message, tsgs=[(pre, number, diger, sigers[:1])],
                           nests=parsed.nests)
    assert context(h, message) is None
    receive(h, message, atc)
    signatures = [(keys, sig.qb64) for keys, sig in h.hby.db.esigs.getTopItemIter()]
    assert context(h, message) is not None
    for field in ("sender", "recipient", "xid"):
        assert context(h, message, **{field: Diger(ser=b"wrong scope").qb64}) is None
    assert [(keys, sig.qb64) for keys, sig in h.hby.db.esigs.getTopItemIter()] == signatures
    h.hby.db.esigs.trim(keys=(message.said,))
    assert context(h, message) is None


@pytest.mark.parametrize("factor", [None, "signature", "seal"])
def test_separate_discloser_requires_exact_issuer_authorization(history, factor):
    h = history
    h.holder = h.hby.makeHab(name="separate-discloser")
    kwa = ({"endorsers": [h.issuer]} if factor == "signature" else
           {"anchorers": [h.issuer]} if factor == "seal" else {})
    message, atc = present(h, **kwa)
    receive(h, message, atc)
    assert h.hby.db.epse.get((message.said,)) is not None
    assert (context(h, message) is not None) == (factor is not None)
    # A seal is historical authority; a signature endorsement selects current keys.
    h.issuer.rotate()
    assert (context(h, message) is not None) == (factor == "seal")


@pytest.mark.parametrize("fault", [None, "invalid-proof", "missing-rip", "dangling"])
def test_optional_branch_preserves_final_admission_but_not_invalid_auxiliary_scope(history, fault):
    h = history
    child = h.acdc
    if fault == "missing-rip":
        child = acdcmap(israid=h.issuer.pre, iseaid=h.holder.pre,
            regid=Diger(ser=b"absent registry").qb64, attribute=dict(d="", role="optional"))
    raw = child.raw
    if fault == "invalid-proof":
        raw = messagize(serder=child, bonds=[Blinder.blind(acdc=child.said, state="issued").data], gvrsn=V2)
    ready = acdcmap(israid=h.issuer.pre, iseaid=h.holder.pre, attribute=dict(d="", role="ready"))
    origin = acdcmap(israid=h.issuer.pre, iseaid=h.holder.pre, attribute=dict(d="", role="origin"),
        edge=dict(d="", o="OR", ready=dict(d="", n=ready.said, o="E1E"),
                  optional=dict(d="", n=child.said, o="E1E")))
    plan = [[origin.schema["$id"], "/", []], [ready.schema["$id"], "/e/ready/_/", []],
            [child.schema["$id"], "/e/optional/_/", []]]
    message, atc = grant(hab=h.holder, recp=h.verifier.pre, message="optional",
        origin=signed(origin, h.issuer), modifiers=dict(dp=[plan]),
        artifacts=[signed(ready, h.issuer)] + ([] if fault == "dangling" else [raw]))
    receive(h, message, atc)
    assert (h.hby.db.exns.get((message.said,)) is not None) == (fault != "dangling")
    assert (context(h, message) is not None) == (fault is None)


@pytest.mark.parametrize("endorsed", [False, True])
def test_origin_issuer_cannot_authorize_another_issuers_registry(history, endorsed):
    h = history
    h.holder = h.hby.makeHab(name="origin-issuer-discloser")
    origin = acdcmap(israid=h.holder.pre, iseaid=h.verifier.pre,
        attribute=dict(d="", role="origin"),
        edge=dict(d="", child=dict(d="", n=h.acdc.said, o="NI2I")))
    plan = [[origin.schema["$id"], "/", []], [h.acdc.schema["$id"], "/e/child/_/", []]]
    message, atc = grant(hab=h.holder, recp=h.verifier.pre, message="linked",
        origin=signed(origin, h.holder), artifacts=[h.acdc.raw], modifiers=dict(dp=[plan]),
        endorsers=[h.issuer] if endorsed else [])
    receive(h, message, atc)
    assert h.hby.db.exns.get((message.said,)) is None
    assert h.hby.db.epse.get((message.said,)) is not None
    result = context(h, message)
    assert (result is not None) == endorsed
    if endorsed:
        assert result[2] == {h.registry.regk: (h.acdc.said,)}


@pytest.mark.parametrize("fault", ["ax", "disclosure", "schema", "presentation"])
def test_shared_context_remains_required_before_issuer_opening_repair(history, fault):
    h = history
    if fault == "schema":
        h.acdc = acdcmap(israid=h.issuer.pre, iseaid=h.holder.pre, regid=h.registry.regk,
            schema=Diger(ser=b"uncached schema").qb64, attribute=dict(d="", role="member"))
    elif fault == "presentation":
        registry = h.registrar.makeRegistry(name="presentations", prefix=h.holder.pre)
        anchor(h.holder, registry, h.rgy.store.event(registry.regk))
        h.acdc = acdcmap(israid=h.issuer.pre, iseaid=h.holder.pre, regid=h.registry.regk,
            attribute=dict(d="", rd=registry.regk, role="member"))
    message, atc = present(h)
    if fault in ("ax", "disclosure"):
        sad = deepcopy(message.sad)
        if fault == "ax":
            sad["a"]["ax"] = [True]  # A signature alone cannot satisfy anchoring.
        else:
            sad["q"]["dp"] = [[[h.acdc.schema["$id"], "/", ["a/undisclosed/"]]]]
        message = SerderKERI(sad=sad, makify=True)
        atc = _sign(h.holder, message, nests=[_normalizeNodeStream(h.acdc.raw)])[message.size:]
    receive(h, message, atc)
    assert context(h, message) is None
    assert h.hby.db.exns.get((message.said,)) is None
    assert h.hby.db.epse.get((message.said,)) is None


@pytest.mark.parametrize("fresh", [False, True])
def test_expired_evicted_grant_cannot_acquire_a_new_lifetime(history, fakeHelpingClock, fresh):
    h = history
    if fresh:
        h.verifier, h.holder = h.holder, h.issuer
        registry = h.registrar.makeRegistry(name="fresh", prefix=h.issuer.pre)
        anchor(h.issuer, registry, h.rgy.store.event(registry.regk))
        h.acdc = acdcmap(israid=h.issuer.pre, iseaid=h.verifier.pre, regid=registry.regk,
                         attribute=dict(d="", role="new"))
    message, atc = present(h)
    receive(h, message, atc)
    scope = dict(xid=message.said, sender=h.holder.pre, recipient=h.verifier.pre)
    assert (h.exc.pendingGrant(message.said, **scope) is not None) == fresh
    assert (context(h, message) is not None) == (not fresh)
    deadline = h.exc.exchangeDeadline(message)
    fakeHelpingClock.set(helping.toIso8601(deadline))
    h.exc.processEscrow()
    assert h.hby.db.epse.get((message.said,)) is None
    receive(h, message, atc)
    assert h.exc.exchangeDeadline(message) == deadline
    assert h.exc.pendingGrant(message.said, **scope) is None
    assert context(h, message) is None
    newer, natc = present(h)
    assert newer.said != message.said
    receive(h, newer, natc)
    assert h.exc.exchangeDeadline(newer) > deadline


@pytest.mark.parametrize("partial", [False, True])
def test_original_grant_deadline_survives_schema_and_signature_escrows(history, fakeHelpingClock, partial):
    h = history
    schema = deepcopy(h.acdc.schema)
    schema["title"] = "Delayed presentation schema"
    schemer = Schemer(sed=schema)
    full = acdcmap(israid=h.issuer.pre, iseaid=h.holder.pre, regid=h.registry.regk,
        schema=schemer.sed, attribute=dict(d="", role="member"))
    proof, event = h.registrar.issue(h.registry, acdc=full)
    anchor(h.issuer, h.registry, event)
    sad = deepcopy(full.sad)
    sad["s"] = schemer.said
    h.acdc = SerderACDC(sad=sad, makify=True)
    message, atc = present(h, [proof])
    if partial:
        parsed = Parser(version=V2).parse(ims=bytearray(message.raw + atc),
                                         framed=False, processive=False)[0]
        pre, number, diger, sigers = parsed.tsgs[0]
        with pytest.raises(MissingSignatureError):
            h.exc.processEvent(serder=message, tsgs=[(pre, number, diger, sigers[:1])],
                               nests=parsed.nests)
        # A below-threshold proposal has no authenticated exchange lifetime yet.
        assert h.exc.exchangeDeadline(message) is None
    receive(h, message, atc)
    deadline = h.exc.exchangeDeadline(message)
    assert deadline is not None
    fakeHelpingClock.advance(seconds=1)
    receive(h, message, atc)
    assert h.hby.db.emse.get((message.said, schemer.said)) is not None
    h.exc.processEscrowPartialSigned()
    assert h.exc.exchangeDeadline(message) == deadline
    assert context(h, message) is None
    h.hby.db.schema.pin(schemer.said, schemer)
    h.exc.processEscrowMissingSchema()
    assert h.hby.db.exns.get((message.said,)) is not None
    assert h.exc.exchangeDeadline(message) == deadline
    assert context(h, message) is not None
