"""Independent section evidence is held exactly, without credential admission."""

from copy import deepcopy

import pytest

from keri.acdc import sectschema, sectattr, sectaggr, sectedge, sectrule
from keri.app import openHby
from keri.core import Diger, Parser, SerderACDC
from keri.kering import Kinds, Vrsn_2_0, ValidationError
from keri.peer.exchanging import serializeParsedSubstream
from keri.vdr import openReger, Verifier


@pytest.mark.parametrize("kind", [Kinds.json, Kinds.cbor, Kinds.mgpk, Kinds.cesr])
@pytest.mark.parametrize("label", ["s", "a", "A", "e", "r"])
def test_v2_section_parser_retains_exact_evidence(kind, label, tmp_path):
    makers = {"s": (sectschema, {"$id": "", "version": "1.0.0", "type": "object"}),
              "a": (sectattr, dict(d="", name="Alice", secret=dict(d="", value="held"))),
              "A": (sectaggr, ["", dict(d="", name="Alice"), dict(d="", name="Bob")]),
              "e": (sectedge, dict(d="", link=dict(d="", n=Diger(ser=b"node").qb64))),
              "r": (sectrule, dict(d="", use=dict(d="", text="Keep private")))}
    make, value = makers[label]
    section = make(deepcopy(value), kind=kind)
    with (openHby(name="sections", version=Vrsn_2_0) as hby,
          openReger(temp=False, headDirPath=str(tmp_path)) as reger):
        verifier = Verifier(hby=hby, reger=reger)
        Parser(vry=verifier, version=Vrsn_2_0).parse(
            ims=serializeParsedSubstream(dict(serder=section)), framed=False)
        assert reger.sections.get((section.said,)).raw == section.raw
        value = section.sad[label]
        commitment = value[0] if label == "A" else value["$id" if label == "s" else "d"]
        assert [item.qb64 for item in reger.sectionIds.get((label, commitment))] == [section.said]
        assert list(reger.saved.getTopItemIter()) == []
        assert list(reger.creds.getTopItemIter()) == []
        assert list(hby.db.exns.getTopItemIter()) == []
        reger.close(clear=False)
        reger.reopen()
        assert reger.sections.get((section.said,)).raw == section.raw
        assert [item.qb64 for item in reger.sectionIds.get((label, commitment))] == [section.said]


def test_partial_and_full_sections_remain_distinct_held_views():
    full = sectattr(dict(d="", name="Alice", private=dict(d="", value="later")))
    value = deepcopy(full.sad["a"])
    value["private"] = value["private"]["d"]
    partial = sectattr(value)
    assert full.said != partial.said
    assert full.sad["a"]["d"] == partial.sad["a"]["d"]
    with openHby(name="section-views") as hby, openReger() as reger:
        verifier = Verifier(hby=hby, reger=reger)
        for section in (partial, full, partial):
            verifier.processACDC(serder=section)
        assert reger.sections.get((partial.said,)).raw == partial.raw
        assert reger.sections.get((full.said,)).raw == full.raw
        assert {item.qb64 for item in reger.sectionIds.get(("a", full.sad["a"]["d"]))} == {
            partial.said, full.said}


def test_invalid_nested_section_does_not_leave_parent_evidence():
    parent, child = sectattr(dict(d="", name="Alice")), sectrule(dict(d="", use="private"))
    sad = deepcopy(child.sad)
    sad["r"]["d"] = Diger(ser=b"wrong commitment").qb64
    invalid = SerderACDC(raw=child.dumps(sad), verify=False)
    assert not invalid.verify()
    with openHby(name="section-refusal") as hby, openReger() as reger:
        verifier = Verifier(hby=hby, reger=reger)
        with pytest.raises(ValidationError):
            verifier.processACDC(serder=parent, nests=[dict(serder=invalid, nests=[])])
        assert list(reger.sections.getTopItemIter()) == []
        assert list(reger.sectionIds.getTopItemIter()) == []
        assert invalid.raw == child.dumps(sad)


def test_parser_retains_nested_sections_and_refuses_credential_child():
    from keri.acdc import acdcmap

    parent, child = sectattr(dict(d="", name="Alice")), sectrule(dict(d="", use="private"))
    with openHby(name="nested-sections", version=Vrsn_2_0) as hby, openReger() as reger:
        verifier = Verifier(hby=hby, reger=reger)
        stream = serializeParsedSubstream(dict(serder=parent, nests=[dict(serder=child)]))
        Parser(vry=verifier, version=Vrsn_2_0).parse(ims=stream, framed=False)
        assert reger.sections.get((parent.said,)).raw == parent.raw
        assert reger.sections.get((child.said,)).raw == child.raw
        other = sectattr(dict(d="", name="unrelated"))
        credential = acdcmap(israid=hby.makeHab(name="issuer").pre,
                             attribute=dict(d="", role="not a section"))
        with pytest.raises(ValidationError):
            verifier.processACDC(serder=other, nests=[dict(serder=credential)])
        assert reger.sections.get((other.said,)) is None
        assert reger.creds.get((credential.said,)) is None
