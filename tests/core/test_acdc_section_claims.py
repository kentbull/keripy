"""Authored section placeholders become commitments; received claims must verify."""

from copy import deepcopy

import pytest

from keri.acdc import acdcmap, acdcagg, sectattr
from keri.core import Aggor, Compactor, Diger, SerderACDC
from keri.kering import KeriError, Kinds, ValidationError, versify


Issuer = "EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ"
KindsToTest = [Kinds.json, Kinds.cbor, Kinds.mgpk, Kinds.cesr]


def _sections(kind):
    return acdcmap(israid=Issuer, kind=kind,
                    attribute=dict(d="", name="Alice", contact=dict(d="", city="Rome")),
                    edge=dict(d="", member=dict(d="", n=Diger(ser=b"node").qb64)),
                    rule=dict(d="", terms=dict(d="", l="Keep private")))


def _wire(original, sad):
    """Serialize a forged disclosure without calling the authoring normalizer."""
    raw = original.dumps(sad, kind=original.kind)
    sad["v"] = versify(proto=original.proto, pvrsn=original.pvrsn,
                        gvrsn=original.gvrsn, kind=original.kind, size=len(raw))
    return original.dumps(sad, kind=original.kind)


@pytest.mark.parametrize("kind", KindsToTest)
def test_authoring_fills_expanded_section_claims(kind):
    authored = _sections(kind)
    for label, child in (("a", "contact"), ("e", "member"), ("r", "terms")):
        section = authored.sad[label]
        assert section["d"] and section[child]["d"]
        compactor = Compactor(mad=section, makify=True, kind=kind)
        compactor.compact()
        assert section["d"] == compactor.said
    received = SerderACDC(raw=authored.raw)
    assert received.raw == authored.raw and received.verify()
    assert received.size == len(authored.raw)
    compact = SerderACDC(sad=authored.sad, makify=True, compactify=True)
    assert compact.said == authored.said
    partial = deepcopy(authored.sad)
    partial["a"]["contact"] = partial["a"]["contact"]["d"]
    disclosed = SerderACDC(sad=partial, makify=True)
    assert disclosed.said == authored.said
    assert disclosed.sad["a"]["contact"] == partial["a"]["contact"]
    assert SerderACDC(raw=disclosed.raw).raw == disclosed.raw


@pytest.mark.parametrize("kind", KindsToTest)
@pytest.mark.parametrize("path", [("a", "d"), ("a", "contact", "d"),
                                  ("e", "member", "d"), ("r", "terms", "d"), ("s", "$id")])
@pytest.mark.parametrize("claim", ["", Diger(ser=b"unrelated block").qb64])
def test_received_section_claim_is_refused_without_repair(kind, path, claim):
    original = _sections(kind)
    sad = deepcopy(original.sad)
    target = sad
    for field in path[:-1]:
        target = target[field]
    target[path[-1]] = claim
    raw = _wire(original, sad)
    received = SerderACDC(raw=raw, verify=False)
    assert not received.verify()
    assert received.raw == raw and received.sad == sad
    with pytest.raises(ValidationError):
        SerderACDC(raw=raw)
    repaired = SerderACDC(sad=sad, makify=True)
    assert repaired.said == original.said
    assert repaired.raw == original.raw


@pytest.mark.parametrize("kind", KindsToTest)
def test_omitted_d_and_schema_property_maps_are_preserved(kind):
    schema = {"$id": "", "type": "object", "properties": {
        "d": {"type": "string"}, "record": {"default": {"d": "opaque"}}}}
    leaf = Compactor(mad=dict(d="", note="visible"), makify=True, kind=kind)
    expected = acdcmap(israid=Issuer, schema=schema, kind=kind,
                       attribute=dict(name="Alice", inline=leaf.mad))
    original = acdcmap(israid=Issuer, schema=schema, kind=kind,
                       attribute=dict(name="Alice", inline=dict(d="", note="visible")))
    assert "d" not in original.sad["a"]
    assert original.sad["a"]["inline"] == leaf.mad
    assert original.raw == expected.raw
    assert original.sad["s"]["properties"] == schema["properties"]
    assert SerderACDC(raw=original.raw).raw == original.raw


@pytest.mark.parametrize("kind", KindsToTest)
def test_aggregate_and_section_messages_normalize_known_claims(kind):
    aggor = Aggor(ael=["", dict(d="", name="Alice"), dict(d="", name="Bob")],
                   makify=True, kind=kind)
    supplied = ["", dict(d="", name="Alice"), aggor.ael[2]["d"]]
    original = acdcagg(israid=Issuer, aggregate=supplied, kind=kind)
    assert original.sad["A"] == [aggor.agid, aggor.ael[1], aggor.ael[2]["d"]]
    assert SerderACDC(raw=original.raw).raw == original.raw
    for position in (0, 1):
        if kind == Kinds.cesr:
            # The native serializer itself validates aggregates. Corrupt wire
            # bytes directly, preserving length, to exercise receive refusal.
            old = original.sad["A"][0] if position == 0 else original.sad["A"][1]["d"]
            raw = original.raw.replace(old.encode(), Diger(ser=b"wrong").qb64b, 1)
            with pytest.raises(KeriError):
                SerderACDC(raw=raw)
            continue
        sad = deepcopy(original.sad)
        if position == 0:
            sad["A"][0] = ""
        else:
            sad["A"][1]["d"] = Diger(ser=b"wrong element").qb64
        assert not SerderACDC(raw=_wire(original, sad), verify=False).verify()
    section = sectattr(attribute=dict(d="", name="Alice"), kind=kind)
    assert section.sad["a"]["d"] == aggor.ael[1]["d"]
    assert SerderACDC(raw=section.raw).raw == section.raw
