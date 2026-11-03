"""Bound disclosures authenticate historical Issuee events, not current tips."""

from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0 as V2
from keri.acdc import Regery, Registrar, acdcmap, grant, loadHandlers, regeventing
from keri.app import openHby
from keri.core import Diger, Parser, Signer, messagize
from keri.kering import MisbindingError, MissingAnchorError
from keri.peer import Exchanger


def anchor(hab, registry, event):
    hab.interact(data=[dict(i=registry.regk, s=event.sad["n"], d=event.said)],
                 framed=False, gvrsn=V2)
    assert registry.anchorMsg(event.said)


@pytest.fixture
def bound_history():
    with openHby(name="bound-issuee", base="test", version=V2) as hby:
        issuer = hby.makeHab(name="issuer")
        issuee = hby.makeHab(name="issuee")
        issuee.interact()
        bound = issuee.kever.serder
        rgy = Regery(hby=hby, name="bound-issuee", temp=True)
        try:
            registrar = Registrar(rgy=rgy)
            registry = registrar.makeRegistry(name="bound", prefix=issuer.pre)
            rip = rgy.store.event(registry.regk)
            anchor(issuer, registry, rip)
            acdc = acdcmap(israid=issuer.pre, iseaid=issuee.pre, regid=registry.regk,
                           attribute=dict(d="", role="member"))
            exc = Exchanger(hby=hby, handlers=[])
            loadHandlers(hby=hby, exc=exc, rgy=rgy,
                         notifier=SimpleNamespace(add=lambda **_: None))
            yield SimpleNamespace(hby=hby, issuer=issuer, issuee=issuee, bound=bound,
                rgy=rgy, registrar=registrar, registry=registry, rip=rip, acdc=acdc,
                exc=exc)
        finally:
            rgy.close()


@pytest.mark.parametrize("fault", [None, "wrong-digest", "wrong-ordinal", "missing-event",
                                   "missing-body", "missing-issuee", "empty-digest"])
def test_ipex_bound_opening_requires_accepted_issuee_coordinate(bound_history, fault):
    """A true BLID and accepted issuer TEL cannot authenticate a false Issuee seal."""
    h = bound_history
    sn, said = h.bound.sn, h.bound.said
    if fault == "wrong-digest":
        said = h.issuer.kever.serder.said
    elif fault == "wrong-ordinal":
        sn = 0  # An accepted Issuee event exists here, with another digest.
    elif fault == "missing-event":
        sn, said = 99, Diger(ser=b"unavailable issuee event").qb64
    elif fault == "missing-issuee":
        h.acdc = acdcmap(israid=h.issuer.pre, regid=h.registry.regk,
                         attribute=dict(d="", role="untargeted"))
    elif fault == "empty-digest":
        sn, said = 0, ""
    proof, bup = h.registrar.issue(h.registry, acdc=h.acdc,
                                   bound=True, bsn=sn, bd=said)
    anchor(h.issuer, h.registry, bup)
    # The valid bound event is an interaction, and remains valid after rotation.
    h.issuee.rotate()
    if fault == "missing-body":
        h.hby.db.evts.rem(keys=(h.issuee.pre, h.bound.said))
    assert regeventing.vetBlind(proof, blid=bup.sad["b"]) == (h.acdc.said, "issued")
    origin = messagize(serder=h.acdc, bonds=[proof.data], gvrsn=V2)
    message, atc = grant(hab=h.issuee, recp=h.issuer.pre, message="bound", origin=origin)
    Parser(version=V2).parse(ims=bytearray(message.raw + atc), framed=False, exc=h.exc)
    assert (h.hby.db.exns.get((message.said,)) is not None) == (fault is None)
    assert (h.hby.db.epse.get((message.said,)) is not None) == (fault in ("missing-event", "missing-body"))
    assert (h.hby.db.exrs.get((message.said, h.acdc.said)) is not None) == (fault is None)
    if fault == "missing-body":
        h.hby.db.evts.put(keys=(h.issuee.pre, h.bound.said), val=h.bound)
        h.exc.processEscrowPartialSigned()
        assert h.hby.db.exns.get((message.said,)) is not None


@pytest.mark.parametrize("form", ["object", "text", "bytes"])
def test_vet_bound_checks_target_for_every_wire_form(bound_history, form):
    h = bound_history
    proof, bup = h.registrar.issue(h.registry, acdc=h.acdc, bound=True,
                                   bsn=h.bound.sn, bd=h.bound.said)
    anchor(h.issuer, h.registry, bup)
    supplied = {"object": proof, "text": proof.qb64, "bytes": proof.qb64b}[form]
    record = regeventing.vet(h.rip, [bup], db=h.hby.db, acdc=h.acdc, blinder=supplied)
    assert record.acdc == h.acdc.said and record.state == "issued"
    substitute = acdcmap(israid=h.issuer.pre, iseaid=h.issuer.pre,
                          regid=h.registry.regk, attribute=dict(d="", role="other"))
    for credential in (None, substitute):
        with pytest.raises(MisbindingError):
            regeventing.vet(h.rip, [bup], db=h.hby.db, acdc=credential, blinder=supplied)


@pytest.mark.parametrize("fault", [None, "ordinal", "digest"])
def test_bound_placeholder_requires_empty_coordinates(bound_history, fault):
    h = bound_history
    proof, bup = h.registrar.issue(h.registry, acdc=h.acdc, bound=True,
                                   bsn=h.bound.sn, bd=h.bound.said)
    anchor(h.issuer, h.registry, bup)
    placeholder, vacate = h.registrar.vacate(h.registry, bound=True,
        bsn=1 if fault == "ordinal" else 0, bd=h.bound.said if fault == "digest" else "")
    anchor(h.issuer, h.registry, vacate)
    def verify():
        return regeventing.vetBinds(h.rip, [bup, vacate], db=h.hby.db,
            blinders=[proof, placeholder], target=h.acdc.said, acdc=h.acdc)
    if fault is None:
        assert verify().state == "issued"
    else:
        with pytest.raises(MisbindingError):
            verify()


def test_bound_issuee_waits_for_verified_witness_receipt(bound_history):
    h = bound_history
    witness = Signer(raw=b"w" * 32, transferable=False)
    issuee = h.hby.makeHab(name="witnessed-issuee", wits=[witness.verfer.qb64], toad=1)
    event = issuee.kever.serder
    acdc = acdcmap(israid=h.issuer.pre, iseaid=issuee.pre, regid=h.registry.regk,
                   attribute=dict(d="", role="witnessed"))
    proof, bup = h.registrar.issue(h.registry, acdc=acdc, bound=True,
                                   bsn=event.sn, bd=event.said)
    anchor(h.issuer, h.registry, bup)
    def verify():
        return regeventing.vetBinds(h.rip, [bup], db=h.hby.db,
            blinders=[proof], target=acdc.said, acdc=acdc)
    key = (issuee.pre, event.said)
    with pytest.raises(MissingAnchorError):
        verify()
    # A stored receipt needs a real signature by the historical witness.
    h.hby.db.wigs.add(keys=key, val=Signer(raw=b"f" * 32).sign(ser=event.raw, index=0))
    with pytest.raises(MissingAnchorError):
        verify()
    h.hby.db.wigs.add(keys=key, val=witness.sign(ser=event.raw, index=0))
    assert verify().state == "issued"
