"""Pinned detailed-type ACDC/CESR ACDC v2 form and independent-section profile."""
import copy
from base64 import urlsafe_b64decode

import pytest

from keri import Kinds, Vrsn_2_0
from keri.acdc import messaging, scheming
from keri.acdc.sectioning import SectionBaser, Sectioner
from keri.app import openHby
from keri.db import openLMDB
from keri.core import Aggor, Codens, Compactor, Counter, Diger, Ilker, Parser, messagize, SerderACDC
from keri.kering import DeserializeError, FailedSchemaValidationError, InvalidValueError, ValidationError


KINDS = [Kinds.json, Kinds.cbor, Kinds.mgpk, Kinds.cesr]
FORMS = ['explicit', 'implicit', 'map-aggregate', 'attribute', 'aggregate']
ISSUER = Diger(ser=b'native-profile-issuer').qb64


def credential(kind, form='explicit'):
    """Author one ACDC v2 detailed-type credential with deterministic visible content.

    Args:
        kind (str): JSON, CBOR, MessagePack, or CESR body encoding.
        form (str): Explicit/implicit map, map aggregate, fixed attribute, or aggregate.

    Returns:
        SerderACDC: Credential with section commitments computed in that encoding."""
    attribute = Compactor(mad=dict(d='', name='Alice', score=96), makify=True, kind=kind).mad
    aggregate = Aggor(ael=['', dict(d='', name='Alice'), dict(d='', score=96)], makify=True, kind=kind).ael
    if form == 'attribute':
        return messaging.acdcatt(ISSUER, attribute=attribute, kind=kind)
    if form == 'aggregate':
        return messaging.acdcagg(ISSUER, aggregate=aggregate, kind=kind)
    if form == 'map-aggregate':
        return messaging.acdcmap(ISSUER, aggregate=aggregate, kind=kind)
    return messaging.acdcmap(ISSUER, attribute=attribute, kind=kind,
                             ilk=None if form == 'implicit' else 'acm')


def wire(event):
    """Complete one ACDC v2 event body with the prescribed empty attachment-group foot.

    Args:
        event (SerderACDC): Body whose bytes to frame.

    Returns:
        bytes: Exact body followed by a v2 zero-count AttachmentGroup."""
    return event.raw + Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('form', FORMS)
def test_acdc_v2_form_roundtrip_and_dispatch(kind, form):
    """Round-trip every supported detailed form and route its exact received bytes to Sectioner, including binary CESR.

    Parameters:
        kind: Selected body/section serialization encoding.
        form: Selected ACDC v2 detailed credential form.

    Returns:
        None. Assertions check the stated evidence boundary."""
    event = credential(kind, form)
    assert event.verify()
    assert SerderACDC(raw=event.raw).sad == event.sad
    assert event.pvrsn == Vrsn_2_0
    assert event.gvrsn == Vrsn_2_0
    with openHby(name='native-dispatch', version=Vrsn_2_0) as hby, \
            openLMDB(cls=SectionBaser, name='native-dispatch') as sections:
        owner = Sectioner(db=hby.db, sections=sections)
        Parser(scy=owner).parseOne(ims=bytearray(wire(event)))
        assert owner.received(Diger(ser=event.raw).qb64).raw == event.raw
    if kind == Kinds.cesr:
        code = Counter(qb64b=event.raw, version=Vrsn_2_0).name
        assert code == (Codens.FixBodyGroup if form in ('attribute', 'aggregate') else Codens.MapBodyGroup)
        for raw in (wire(event), urlsafe_b64decode(wire(event))):
            ims = bytearray(raw)
            parsed = Parser(version=Vrsn_2_0).parse(ims=ims, processive=False)
            assert not ims
            assert len(parsed) == 1
            assert parsed[0].serder.said == event.said
            assert parsed[0].serder.raw == event.raw


@pytest.mark.parametrize('kind', KINDS)
def test_acdc_v2_aggregate_selective_disclosure_preserves_agid(kind):
    """Preserve aggregate/credential commitments when hiding members; reject member permutation under the old AGID.

    Parameters:
        kind: Selected body/section serialization encoding.

    Returns:
        None. Assertions check the stated evidence boundary."""
    expanded = credential(kind, 'aggregate')
    selective = copy.deepcopy(expanded.sad)
    hidden = selective['A'][2]['d']
    selective['A'][2] = hidden
    disclosed = SerderACDC(sad=selective, makify=True)
    assert disclosed.said == expanded.said
    assert disclosed.sad['A'][0] == expanded.sad['A'][0]
    assert disclosed.sad['A'][2] == hidden
    assert disclosed.sad['A'][1]['name'] == 'Alice'
    swapped = copy.deepcopy(selective)
    swapped['A'][1], swapped['A'][2] = swapped['A'][2], swapped['A'][1]
    assert Aggor.verifyDisclosure(swapped['A'], kind=kind) is False
    with pytest.raises((ValidationError, InvalidValueError)):
        SerderACDC(sad=swapped, makify=True)
    swapped['A'] = Aggor(ael=swapped['A'], makify=True, kind=kind).ael
    assert SerderACDC(sad=swapped, makify=True).said != expanded.said


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('builder,field,value', [
    (messaging.sectschema, 's', {'$id': '', 'type': 'object'}),
    (messaging.sectattr, 'a', {'d': '', 'name': 'Alice'}),
    (messaging.sectaggr, 'A', ['', {'d': '', 'score': 96}]),
    (messaging.sectedge, 'e', {'d': '', 'authority': {'n': ISSUER}}),
    (messaging.sectrule, 'r', {'d': '', 'usage': {'l': 'For the intended verifier'}}),
])
def test_standalone_section_roundtrip(kind, builder, field, value):
    """Check standalone section field order, ACDC v2 detailed type, commitment, and binary CESR round-trip.

    Parameters:
        kind: Selected body/section serialization encoding.
        builder: Standalone section builder under test.
        field: Normative section label carried by that builder.
        value: Expanded section content before commitment computation.

    Returns:
        None. Assertions check the stated evidence boundary."""
    value = (Aggor(ael=copy.deepcopy(value), makify=True, kind=kind).ael if field == 'A'
             else Compactor(mad=copy.deepcopy(value), makify=True, kind=kind,
                            strict=False if field == 's' else True,
                            saids={'$id': 'E'} if field == 's' else {'d': 'E'}).mad)
    event = builder(value, kind=kind)
    assert event.verify()
    assert list(event.sad) == ['v', 't', 'd', field]
    assert SerderACDC(raw=event.raw).sad == event.sad
    if kind == Kinds.cesr:
        assert Counter(qb64b=event.raw, version=Vrsn_2_0).name == Codens.FixBodyGroup
        parsed = Parser(version=Vrsn_2_0).parse(ims=bytearray(urlsafe_b64decode(wire(event))), processive=False)
        assert parsed[0].serder.sad == event.sad


@pytest.mark.parametrize('kind', KINDS)
def test_acdc_v2_schema_verifies_actual_encoding_without_rewriting(kind):
    """Validate the schema in its actual received encoding and reject altered content without rewriting credential bytes.

    Parameters:
        kind: Selected body/section serialization encoding.

    Returns:
        None. Assertions check the stated evidence boundary."""
    schema = {'$id': '', 'version': '1.0.0', 'type': 'object',
              'properties': {'a': {'type': 'object', 'required': ['name']}}}
    with openHby(name='native-schema-kind', version=Vrsn_2_0) as hby:
        event = messaging.acdcmap(ISSUER, schema=schema,
                                  attribute={'d': '', 'name': 'Alice'}, kind=kind)
        original = event.raw
        assert scheming.validateSchema(event, hby.db)
        assert event.raw == original
        malformed = copy.deepcopy(event.sad['s'])
        malformed['type'] = 'array'
        with pytest.raises(FailedSchemaValidationError, match='content does not match'):
            scheming._verifySchemer(malformed, kind=kind)


@pytest.mark.parametrize('kind', KINDS)
def test_sections_arrive_after_restart_with_explicit_resolution(kind, tmp_path):
    """Persist missing section requests across reopen, resolve only matching sections, and retain the original compact view.

    Parameters:
        kind: Selected body/section serialization encoding.
        tmp_path: Pytest-owned persistent LMDB directory for close/reopen evidence.

    Returns:
        None. Assertions check the stated evidence boundary."""
    schema = {'$id': '', 'version': '1.0.0', 'type': 'object',
              'properties': {'a': {'type': 'object', 'required': ['name']}}}
    compact, sch, att, _, edg, rul = messaging.sectionate(
        ISSUER, schema=schema, attribute={'d': '', 'name': 'Alice'},
        edge={'d': '', 'authority': {'n': ISSUER}},
        rule={'d': '', 'usage': {'l': 'Only the intended verifier'}}, kind=kind)
    required = ('s', 'a', 'e', 'r')
    opts = dict(cls=SectionBaser, name='native-sections', temp=False,
                headDirPath=str(tmp_path))
    with openHby(name='native-section-receiver', version=Vrsn_2_0) as hby:
        with openLMDB(**opts) as sections:
            owner = Sectioner(db=hby.db, sections=sections)
            Parser(scy=owner).parse(ims=bytearray(wire(compact)))
            view = Diger(ser=compact.raw).qb64
            assert owner.received(view).raw == compact.raw
            owner.processCredential(compact, required=required)
            assert owner.resolve(view, required=required) is None
            # Different section type/commitment cannot satisfy the dependency.
            Parser(scy=owner).parse(ims=bytearray(wire(messaging.sectattr(
                {'d': '', 'name': 'Mallory'}, kind=kind))))
            assert owner.resolve(view, required=required) is None
            Parser(scy=owner).parse(ims=bytearray(wire(rul)))
            assert sections.pending.get(view) == view
        with openLMDB(**opts) as sections:
            owner = Sectioner(db=hby.db, sections=sections)
            assert sections.pending.get(view) == view
            parser = Parser(scy=owner)
            for event in (edg, att, sch):
                incoming = wire(event)
                if kind == Kinds.cesr:
                    incoming = urlsafe_b64decode(incoming)
                parser.parseOne(ims=bytearray(incoming))
            expanded = owner.resolve(view, required=required)
            assert expanded.said == compact.said
            assert expanded.sad['a']['name'] == 'Alice'
            assert expanded.sad['r']['usage']['l'] == 'Only the intended verifier'
            assert sections.pending.get(view) is None
            # Neither replay nor a local request alters a later received view.
            parser.parse(ims=bytearray(wire(compact)))
            assert owner.received(view).raw == compact.raw
            assert owner.resolve(view).raw == compact.raw
            minimal = owner.resolve(view, required=('s', 'a'))
            assert isinstance(minimal.sad['r'], str)
            assert isinstance(minimal.sad['e'], str)


def test_fixed_acm_is_rejected_by_acdc_v2_detailed_type_profile():
    """Reject the obsolete fixed-body acm spelling rather than interpreting it as a supported detailed type.

    Returns:
        None. Assertions check the stated evidence boundary."""
    event = credential(Kinds.cesr, 'attribute')
    obsolete = event.raw.replace(Ilker(ilk='act').qb64b, Ilker(ilk='acm').qb64b, 1)
    with pytest.raises(DeserializeError):
        SerderACDC(raw=obsolete)


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('form', FORMS)
def test_acdc_v2_hidden_and_one_way_registry_construction(kind, form):
    """Preserve hidden inner registry declarations across all ACDC v2 forms and compact representations.

    Parameters:
        kind: Selected body/section serialization encoding.
        form: Selected ACDC v2 detailed credential form.

    Returns:
        None. Assertions check the stated evidence boundary."""
    registry = Diger(ser=b'native-hidden-registry').qb64
    if form in ('aggregate', 'map-aggregate'):
        kwargs = dict(aggregate=['', {'d': '', 'rd': registry, 'name': 'Alice'}])
    else:
        kwargs = dict(attribute={'d': '', 'rd': registry, 'name': 'Alice'})
    builder = (messaging.acdcatt if form == 'attribute' else
               messaging.acdcagg if form == 'aggregate' else messaging.acdcmap)
    if form == 'implicit':
        kwargs['ilk'] = None
    event = builder(ISSUER, kind=kind, **kwargs)
    assert event.regid in (None, '')
    assert SerderACDC(raw=event.raw).said == event.said
    compact = SerderACDC(sad=event.sad, makify=True, compactify=True)
    assert compact.said == event.said
    assert registry not in compact.raw.decode(errors='ignore')


@pytest.mark.parametrize('kind', KINDS)
def test_acdc_v2_bundled_schema_commitment_uses_section_encoding(kind):
    """Validate bundled schema resource commitments in the enclosing section encoding and reject content tampering.

    Parameters:
        kind: Selected body/section serialization encoding.

    Returns:
        None. Assertions check the stated evidence boundary."""
    child = SerderACDC.saidifySection(
        {'$id': '', 'version': '1.0.0', 'type': 'string'}, 's', kind)
    schema = {'$id': '', 'version': '1.0.0', 'type': 'object',
              '$defs': {'name': child},
              'properties': {'a': {'type': 'object', 'properties': {
                  'name': {'$ref': child['$id']}}}}}
    with openHby(name='native-bundled-schema', version=Vrsn_2_0) as hby:
        event = messaging.acdcmap(ISSUER, schema=schema,
                                  attribute={'d': '', 'name': 'Alice'}, kind=kind)
        assert scheming.validateSchema(event, hby.db)
        changed = copy.deepcopy(event.sad['s'])
        changed['$defs']['name']['type'] = 'integer'
        # Re-signing the parent schema cannot authorize a false bundled ID.
        changed = SerderACDC.saidifySection(changed, 's', kind)
        invalid = messaging.acdcmap(ISSUER, schema=changed,
                                    attribute={'d': '', 'name': 'Alice'}, kind=kind)
        with pytest.raises(FailedSchemaValidationError, match='bundled schema'):
            scheming.validateSchema(invalid, hby.db)


@pytest.mark.parametrize('kind', KINDS)
def test_standalone_schema_dependency_retries_and_distinguishes_invalid(kind, tmp_path):
    """Distinguish pending missing schema from invalid schema after actual independent section arrival and reopen.

    Parameters:
        kind: Selected body/section serialization encoding.
        tmp_path: Pytest-owned persistent LMDB directory for close/reopen evidence.

    Returns:
        None. Assertions check the stated evidence boundary."""
    dependency = messaging.sectschema(
        {'$id': '', 'version': '1.0.0', 'type': 'string'}, kind=kind)
    schema = {'$id': '', 'version': '1.0.0', 'type': 'object',
              'properties': {'a': {'type': 'object', 'properties': {
                  'name': {'$ref': dependency.sad['s']['$id']}}}}}
    good = messaging.acdcmap(ISSUER, schema=schema,
                             attribute={'d': '', 'name': 'Alice'}, kind=kind)
    bad = messaging.acdcmap(ISSUER, schema=schema,
                            attribute={'d': '', 'name': 42}, kind=kind)
    opts = dict(cls=SectionBaser, name='schema-dependency', temp=False,
                headDirPath=str(tmp_path))
    with openHby(name='schema-dependency', version=Vrsn_2_0) as hby:
        with openLMDB(**opts) as sections:
            owner = Sectioner(db=hby.db, sections=sections)
            goodView = owner.processCredential(good, required=('s', 'a'))
            badView = owner.processCredential(bad, required=('s', 'a'))
            assert sections.pending.get(goodView) == goodView
            assert sections.pending.get(badView) == badView
        with openLMDB(**opts) as sections:
            owner = Sectioner(db=hby.db, sections=sections)
            Parser(scy=owner).parseOne(ims=bytearray(wire(dependency)))
            assert sections.pending.get(goodView) is None
            assert sections.pending.get(badView) is None
            assert sections.failures.get(goodView) is None
            assert sections.failures.get(badView) is not None
            assert owner.resolve(goodView, required=('s', 'a')).said == good.said
            with pytest.raises(FailedSchemaValidationError):
                owner.resolve(badView, required=('s', 'a'))
            assert owner.received(badView).raw == bad.raw


@pytest.mark.parametrize('kind,members,expected', [
    (Kinds.json, [
        'EI2lwi1ZKrs-bDwgEreOhEh-W2O5xrOm5T-QCyMuX5V4',
        'EC-vU19URXX8ztfWdp_j2HHr1lJsqtGa1YHtZrg6-GMR',
        'EKYLUIpDXNT0ujSdoNOT5pLp0okOKW3mAbg-M7K5OO_C'],
     'EN5d44fTNM0M4kmMMVrsH0HwMLRLyb6SoJEV0ogkLdXx'),
    (Kinds.cesr, [
        'EPss9hsx7P5iYjWXNYJM5NiEu5EtPQHdGZ5K-qXK2p5E',
        'EGoIcPap1swfLGRQzTaxf38HsLFuHehBCY5kUSDK8XGs',
        'ED50KTrvT5n20JFTsyZFvBJfH-bOAVP9xHFhtbI5nCN6'],
     'EEL7OTDzXjYoaDE8g8064thOpKdxsJWaG8DhRyOB58qW'),
])
def test_pinned_acdc_agid_worked_vectors(kind, members, expected):
    """Match pinned ACDC f0bd097 AGID worked examples independently of the credential builder.

    Parameters:
        kind: Selected body/section serialization encoding.
        members: Pinned ordered aggregate-member input vector.
        expected: Pinned normative AGID expected for that vector.

    Returns:
        None. Assertions check the stated evidence boundary."""
    assert Aggor(ael=[''] + members, makify=True, kind=kind).agid == expected
    assert Aggor.verifyDisclosure([expected] + members, kind=kind)


@pytest.mark.parametrize('kind', KINDS)
def test_required_aggregate_does_not_expand_an_already_disclosed_view(kind):
    """Keep a partial aggregate view immutable when a fuller matching aggregate arrives independently.

    Parameters:
        kind: Selected body/section serialization encoding.

    Returns:
        None. Assertions check the stated evidence boundary."""
    full = credential(kind, 'aggregate')
    partial = copy.deepcopy(full.sad)
    partial['A'][2] = full.sad['A'][2]['d']
    received = SerderACDC(sad=partial, makify=True)
    with openHby(name='aggregate-disclosure', version=Vrsn_2_0) as hby, \
            openLMDB(cls=SectionBaser, name='aggregate-disclosure') as sections:
        owner = Sectioner(db=hby.db, sections=sections)
        owner.processEvent(messaging.sectaggr(full.sad['A'], kind=kind))
        view = owner.processCredential(received, required=('A',))
        result = owner.resolve(view, required=('A',))
        assert result.sad['A'][2] == full.sad['A'][2]['d']
        assert result.raw == received.raw
        assert owner.received(view).raw == received.raw


def test_fragmented_mixed_acdc_v2_stream_routes_to_concrete_owners():
    """Route fragmented interleaved ACDC v2 registry TEL and section messages through their distinct concrete owners.

    Returns:
        None. Assertions check the stated evidence boundary."""
    from keri.acdc.regeventing import Rever
    from keri.acdc.regbasing import RegBaser
    from tests.acdc.test_observing import _copy_kel, _events, _seal

    with (openHby(name='mixed-native-issuer', version=Vrsn_2_0) as ihby,
          openHby(name='mixed-native-receiver', version=Vrsn_2_0) as rhby,
          openLMDB(cls=RegBaser, name='mixed-native-tel') as reger,
          openLMDB(cls=SectionBaser, name='mixed-native-sections') as sections):
        issuer = ihby.makeHab(name='issuer')
        rip, issued, _ = _events(issuer)
        for event in (rip, issued):
            _seal(issuer, event)
        _copy_kel(issuer, rhby)
        rever = Rever(db=rhby.db, reger=reger)
        owner = Sectioner(db=rhby.db, sections=sections)
        event, sch, att, _, _, _ = messaging.sectionate(
            issuer.pre, attribute={'d': '', 'name': 'Alice'}, kind=Kinds.cesr)
        view = owner.processCredential(event, required=('s', 'a'))
        stream = b''.join(wire(item) for item in (issued, event, sch, rip, att))
        ims = bytearray()
        parser = Parser(rgy=rever, scy=owner, framed=False)
        generator = parser.parsator(ims=ims, framed=False)
        try:
            for offset in range(0, len(stream), 7):
                ims.extend(stream[offset:offset + 7])
                next(generator)
            assert not ims
            assert rever.store.headEvent(rip.said).said == issued.said
            assert owner.resolve(view, required=('s', 'a')).said == event.said
            assert sections.pending.get(view) is None
            assert owner.received(view).raw == event.raw
        finally:
            generator.close()


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('builder,field,empty', [
    (messaging.sectschema, 's', {}), (messaging.sectattr, 'a', {}),
    (messaging.sectaggr, 'A', []), (messaging.sectedge, 'e', {}),
    (messaging.sectrule, 'r', {}),
])
def test_standalone_empty_section_wire_has_prescribed_container(kind, builder, field, empty):
    """Use the mandated empty container for standalone section wire bodies in each encoding.

    Parameters:
        kind: Selected body/section serialization encoding.
        builder: Standalone section builder under test.
        field: Normative section label carried by that builder.
        empty: Prescribed empty section container.

    Returns:
        None. Assertions check the stated evidence boundary."""
    event = builder(empty, kind=kind)
    assert event.sad[field] == empty
    parsed = Parser().parseOne(ims=bytearray(wire(event)), processive=False)
    assert parsed.serder.sad[field] == empty


@pytest.mark.parametrize('kind', KINDS)
def test_independent_sections_in_credential_attachment_foot(kind):
    """Retain independent nested section messages through the ordinary credential attachment parser.

    Parameters:
        kind: Selected body/section serialization encoding.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with openHby(name='native-nested-sections', version=Vrsn_2_0) as hby, \
            openLMDB(cls=SectionBaser, name='native-nested-sections') as sections:
        hab = hby.makeHab(name='issuer')
        event, sch, att, _, _, _ = messaging.sectionate(
            hab.pre, attribute={'d': '', 'name': 'Alice'}, kind=kind)
        owner = Sectioner(db=hby.db, sections=sections)
        view = owner.processCredential(event, required=('s', 'a'))
        assert owner.resolve(view, required=('s', 'a')) is None
        nests = [messagize(section, sigers=hab.sign(ser=section.raw),
                           nested=True, gvrsn=Vrsn_2_0) for section in (sch, att)]
        stream = messagize(event, sigers=hab.sign(ser=event.raw),
                           nests=nests, gvrsn=Vrsn_2_0)
        Parser(scy=owner).parseOne(ims=bytearray(stream))
        assert sections.pending.get(view) is None
        assert owner.resolve(view, required=('s', 'a')).sad['a']['name'] == 'Alice'
        assert owner.received(view).raw == event.raw
        assert owner.resolve(view).raw == event.raw


@pytest.mark.parametrize('kind', KINDS)
def test_ambiguous_section_views_require_explicit_source_selection(kind):
    """Require a named section-message source when one commitment has several disclosed candidate views.

    Parameters:
        kind: Selected body/section serialization encoding.

    Returns:
        None. Assertions check the stated evidence boundary."""
    full = messaging.acdcmap(ISSUER, attribute={'d': '', 'profile': {'d': '', 'name': 'Alice'}}, kind=kind)
    partial = copy.deepcopy(full.sad['a'])
    partial['profile'] = partial['profile']['d']
    complete = messaging.sectattr(full.sad['a'], kind=kind)
    selective = messaging.sectattr(partial, kind=kind)
    assert complete.sad['a']['d'] == selective.sad['a']['d']
    assert complete.said != selective.said
    compact = SerderACDC(sad=full.sad, makify=True, compactify=True)
    with openHby(name='section-source-choice', version=Vrsn_2_0) as hby, \
            openLMDB(cls=SectionBaser, name='section-source-choice') as sections:
        owner = Sectioner(db=hby.db, sections=sections)
        owner.processEvent(complete)
        owner.processEvent(selective)
        owner.processEvent(messaging.sectschema(full.sad['s'], kind=kind))
        view = owner.processCredential(compact, required=('s', 'a'))
        assert owner.resolve(view, required=('s', 'a')) is None
        assert set(owner.candidates(view, 'a')) == {complete.said, selective.said}
        chosen = owner.resolve(view, required=('s', 'a'), sources={'a': selective.said})
        assert chosen.sad['a']['profile'] == partial['profile']
        chosen = owner.resolve(view, required=('s', 'a'), sources={'a': complete.said})
        assert chosen.sad['a']['profile']['name'] == 'Alice'
        owner.processCredential(compact, required=('s', 'a'), sources={'a': complete.said})
        assert sections.pending.get(view) is None
        assert owner.resolve(view).raw == compact.raw
