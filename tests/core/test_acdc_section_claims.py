"""Authored section placeholders become commitments; received claims must verify."""

from copy import deepcopy

import pytest

from keri.acdc import acdcmap, acdcagg, sectattr, sectedge
from keri.core import Aggor, Compactor, Counter, Diger, Mapper, SerderACDC
from keri.kering import KeriError, Kinds, ValidationError, versify


Issuer = "EA2X8Lfrl9lZbCGz8cfKIvM_cqLyTYVLSFLhnttezlzQ"
KindsToTest = [Kinds.json, Kinds.cbor, Kinds.mgpk, Kinds.cesr]


@pytest.mark.parametrize("kind", KindsToTest)
@pytest.mark.parametrize("placement", ["section", "group", "leaf"])
def test_inline_edge_schema_is_opaque_to_section_compaction(kind, placement):
    schema = {"$id": Diger(ser=b"schema").qb64, "type": "object",
              "properties": {"d": {"type": "string"},
                             "record": {"default": {"d": "opaque"}}},
              "$defs": {"value": {"type": "string"}}}
    leaf = dict(d="", n=Diger(ser=b"node").qb64)
    edge = dict(d="", group=dict(d="", o="AND", member=leaf),
                other=dict(d="", n=Diger(ser=b"other").qb64))
    pinned = {"section": edge, "group": edge["group"], "leaf": leaf}[placement]
    pinned["s"] = deepcopy(schema)
    original = acdcmap(israid=Issuer, kind=kind, attribute=dict(d="", name="Alice"),
                       edge=edge)
    disclosed = original.sad["e"]
    pinned = {"section": disclosed, "group": disclosed["group"],
              "leaf": disclosed["group"]["member"]}[placement]
    assert pinned["s"] == schema
    assert SerderACDC(raw=original.raw).raw == original.raw
    compact = SerderACDC(sad=original.sad, makify=True, compactify=True)
    assert compact.said == original.said
    assert compact.sad["e"] == disclosed["d"]
    compactor = SerderACDC.sectionCompactor("e", disclosed, kind=kind)
    compactor.compact(paths=["e/group/"], root="e")
    partial = compactor.partials[("e/group/",)]
    assert partial.opaque == frozenset(("s",))
    assert partial.mad["group"] == disclosed["group"]
    assert partial.mad["other"] == disclosed["other"]["d"]
    sad = deepcopy(original.sad)
    sad["e"] = partial.mad
    received = SerderACDC(sad=sad, makify=True)
    assert received.said == original.said
    assert SerderACDC(raw=received.raw).raw == received.raw
    section = sectedge(edge=disclosed, kind=kind)
    assert section.sad["e"] == disclosed
    assert SerderACDC(raw=section.raw).raw == section.raw
    compactor.expand()
    for variant in compactor.partials.values():
        assert variant.opaque == compactor.opaque
        assert variant.strict == compactor.strict
        assert variant.saids == compactor.saids
        assert variant.saidive == compactor.saidive
        rebuilt = SerderACDC.sectionCompactor("e", variant.mad, kind=kind)
        rebuilt.compact()
        assert rebuilt.said == disclosed["d"]

    # Neither outer nor nested section claims become repairable on intake.
    for path in [("d",), ("group", "d"), ("group", "member", "d")]:
        sad = deepcopy(original.sad)
        target = sad["e"]
        for label in path[:-1]:
            target = target[label]
        target[path[-1]] = Diger(ser=b"altered commitment").qb64
        with pytest.raises(ValidationError):
            SerderACDC(raw=_wire(original, sad))


@pytest.mark.parametrize("kind", KindsToTest)
def test_inline_pin_does_not_change_simple_commitments_or_other_said_maps(kind):
    edge = dict(d="", s=dict(type="object"), member=dict(d="", n=Issuer))
    ordinary = Compactor(mad=edge, makify=True, kind=kind)
    ordinary.compact()
    pinned = SerderACDC.sectionCompactor("e", edge, kind=kind)
    pinned.compact()
    assert pinned.mad == ordinary.mad
    assert pinned.said == ordinary.said
    # Exact commitments captured from the unmodified 594d422a source archive.
    assert pinned.said == {
        Kinds.json: "EGgHc7NhjC_-0gc-Cm1YsLI_U_YbIQEv4PGKRWWhHp-m",
        Kinds.cbor: "EDIZiPdlpeUkZb0O17-s9OQRTy9-IgZqG9_eOyQ51-Pr",
        Kinds.mgpk: "EIqaVMQbGHe23D39QupBU_g1o1Xb3NZc05-7RZA5x8l3",
        Kinds.cesr: "EFR0FevodfV6UPEdWZmJvsMhiEG0Yv9-hH4G9aorTSVZ",
    }[kind]
    # No generic opt-out and no relaxation of malformed d outside a schema pin.
    malformed = dict(d="", member=dict(d={"type": "string"}))
    for compactor in (Compactor(mad=malformed, makify=True, kind=kind),
                      SerderACDC.sectionCompactor("e", malformed, kind=kind)):
        with pytest.raises(KeriError):
            compactor.compact()
    with pytest.raises(KeriError):
        Compactor(mad=dict(d="", s=dict(properties=dict(d=dict(type="string")))),
                  makify=True, kind=kind).compact()


@pytest.mark.parametrize("extra", [{"$bad": "value"},
                                  {"group": {"$bad": "value"}},
                                  {"values": [{"$bad": "value"}]}])
def test_native_edge_unrestricted_labels_are_limited_to_inline_schema(extra):
    original = _sections(Kinds.cesr)
    edge = dict(original.sad["e"], **extra)
    with pytest.raises(KeriError):
        acdcmap(israid=Issuer, kind=Kinds.cesr,
                attribute=dict(d="", name="Alice"), edge=edge)
    with pytest.raises(KeriError):
        original.dumps(dict(original.sad, e=edge), kind=Kinds.cesr)
    # Construct hostile wire with the unrestricted primitive mapper directly;
    # decoding must refuse labels before any commitment verification as well.
    body = bytearray(original.raw)
    counter = Counter(qb64b=body, strip=True, version=original.gvrsn)
    old = Mapper(mad=original.sad["e"]).raw
    new = Mapper(mad=edge, strict=False).raw
    assert bytes(body).count(old) == 1
    raw = Counter.enclose(qb64=bytes(body).replace(old, new),
                          code=counter.code, version=original.gvrsn)
    with pytest.raises(KeriError):
        SerderACDC(raw=raw, verify=False)


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
