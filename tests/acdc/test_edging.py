"""Published graph-profile vectors; policy meaning remains explicitly supplied.

ACDC f0bd097d, spec-body.md 1105-1120 and 1172-1211. These tests exercise
the shared semantic owner and accepted KEL delegation without fixture tables.
"""
import pytest

from keri import Vrsn_2_0
from keri.acdc import acdcmap, grant, admit, loadHandlers
from keri.acdc.edging import EdgeEvaluator
from keri.acdc.proving import PresentedEvidence
from keri.app import openHby
from keri.core import (Compactor, Diger, Kevery, Noncer, Number, Parser, Schemer, SealSource, Signer,
                       delcept, messagize)
from keri.kering import MissingChainError, MissingSchemaError, ValidationError
from keri.peer import Exchanger
from keri.peer.exchanging import loadParsedNestedSubstreams


class Notices:
    def add(self, attrs):
        """Ignore accepted-notification attributes for this verifier-only test.

        Args:
            attrs (dict): Notification payload deliberately unused by the test.

        Returns:
            None. No notification side effects are needed to observe acceptance."""
        pass


class DeclaredScorePolicy:
    """Example application policy, not an inferred protocol/EGF rule."""
    def __init__(self, minimum=0.5):
        """Create the test's explicit numeric acceptance rule.

        Args:
            minimum (float): Inclusive lower bound for accepting a computed mean.

        Returns:
            None. Initializes an observation list so tests can check arithmetic separately
            from the boolean verdict."""
        self.minimum = minimum
        self.means = []

    def validity(self, serder):
        """Read this example application's disclosed eligibility predicate.

        Args:
            serder (SerderACDC): Exact disclosed node being evaluated.

        Returns:
            bool | None: Explicit eligible property, default True; None models uncertainty."""
        return serder.sad['a'].get('eligible', True)

    def value(self, *, near, edge, far):
        """Select a score property without creating a protocol-wide numeric meaning.

        Args:
            near (SerderACDC): Near node, unused by this example rule.
            edge (Mapping): Edge metadata, unused by this example rule.
            far (SerderACDC | None): Disclosed far node whose score to read.

        Returns:
            object: Disclosed score, or None when no value is available."""
        return far.sad['a'].get('score') if far is not None else None

    def accept(self, *, near, group, average):
        """Record the engine's mean and apply the configured inclusive threshold.

        Args:
            near (SerderACDC): Near node, unused by this example rule.
            group (Mapping): Evaluated group, unused by this example rule.
            average (float): Mean computed by the production engine.

        Returns:
            bool: Whether average meets minimum; also appends it to means."""
        self.means.append(average)
        return average >= self.minimum


@pytest.fixture
def graph():
    """Yield temporary issuer/other habitats and a concrete semantic evaluator.

    Yields:
        tuple: (Habery, issuer Hab, other Hab, EdgeEvaluator). The fixture closes its
        temporary identity stores after each case; no cached validity table is used."""
    with openHby(name='acdc-v2-graph-profile', version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name='issuer')
        other = hby.makeHab(name='other')
        handler = EdgeEvaluator(PresentedEvidence(hby))
        yield hby, issuer, other, handler


def credential(issuer, *, issuee=None, edge=None, **properties):
    """Build an ACDC v2 credential carrying only the requested graph properties.

    Args:
        issuer (str): Issuer AID.
        issuee (str | None): Optional targeted Issuee.
        edge (Mapping | None): Disclosed graph edge section.
        **properties: Disclosed attribute properties used by the explicit policy.

    Returns:
        SerderACDC: Credential with author-computed section commitments."""
    return acdcmap(israid=issuer, iseaid=issuee,
                   attribute=dict(d='', **properties), edge=edge)


def evaluate(handler, origin, *far):
    """Evaluate exact disclosed views through the production graph evaluator.

    Args:
        handler (EdgeEvaluator): Evaluator whose explicit policy to apply.
        origin (SerderACDC): Root credential, placed first in traversal order.
        *far: Disclosed far-node credentials indexed by their own SAIDs.

    Returns:
        bool: Production graph verdict. MissingChainError/MissingSchemaError remain
        retryable exceptions rather than synthetic false operands."""
    nodes = {serder.said: {'serder': serder} for serder in (origin,) + far}
    return handler.verify(nodes, list(nodes))


@pytest.mark.parametrize('operator,expected', [
    (None, False), ('', False), ([], False), ('I2I', False),
    ('NI2I', True), (['I2I', 'NI2I'], True),
    (['NI2I', 'I2I'], False), ('E1E', False), ('UNKNOWN', False),
])
def test_targeted_defaults_and_last_conflicting_relation(graph, operator, expected):
    """Check targeted I2I defaults and last-wins relation selection against explicit expected vectors.

    Parameters:
        graph: Temporary real habitats/handler fixture defined above.
        operator: Unary relation encoding or unsupported spelling from the test vector.
        expected: Expected concrete verdict or arithmetic mean for the selected vector.

    Returns:
        None. Assertions check the stated evidence boundary."""
    _, issuer, other, handler = graph
    far = credential(issuer.pre, issuee=other.pre)
    leaf = dict(n=far.said)
    if operator is not None:
        leaf['o'] = operator
    near = credential(issuer.pre, edge=dict(d='', proof=leaf))
    assert evaluate(handler, near, far) is expected


@pytest.mark.parametrize('issuee', [
    pytest.param('hidden', id='compact'),
    pytest.param(42, id='number'), pytest.param(True, id='boolean'),
    pytest.param(['not-an-AID'], id='array'),
    pytest.param(dict(invalid='Issuee'), id='map'),
    pytest.param(None, id='null'), pytest.param(0, id='zero'),
    pytest.param(False, id='false'), pytest.param([], id='empty-array'),
    pytest.param({}, id='empty-map'),
])
def test_unresolved_issuee_is_not_an_untargeted_default(graph, issuee):
    """Hidden or non-string Issuee evidence cannot establish identity or defaults."""
    from keri.acdc.scheming import validateSchema

    hby, issuer, other, handler = graph
    schema = Schemer(sed={'$id': '', 'version': '1.0.0', 'type': 'object'}).sed
    hidden = issuee == 'hidden'
    if hidden:
        full = acdcmap(israid=issuer.pre, uuid=Noncer().qb64, iseaid=other.pre,
            schema=schema, attribute=dict(d='', u=Noncer().qb64))
        compact = Compactor(mad=dict(full.sad['a']), makify=True)
        far = acdcmap(israid=issuer.pre, uuid=full.sad['u'],
                       schema=schema, attribute=compact.said)
        assert isinstance(far.attrib, str) and far.iseaid is None
    else:
        far = acdcmap(israid=issuer.pre, schema=schema, attribute=dict(d='', i=issuee))
        assert far.sad['a']['i'] == issuee
    assert far.verify() is True
    assert validateSchema(far, db=hby.db) is True
    for op in ('E1E', None, 'I2I', 'DI2I', 'NOT', ['NI2I', 'E1E']):
        leaf = dict(n=far.said)
        if op is not None:
            leaf['o'] = op
        # Equal malformed identities must not authorize E1E.
        near = acdcmap(israid=issuer.pre, schema=schema,
            attribute=dict(d='', i=other.pre if hidden else issuee),
            edge=dict(d='', proof=leaf))
        assert near.verify() is True
        assert validateSchema(near, db=hby.db) is True
        nodes = {node.said: dict(serder=node) for node in (near, far)}
        assert handler.evaluate(nodes, list(nodes)) is None
        nor = acdcmap(israid=issuer.pre, schema=schema, attribute=dict(d=''),
            edge=dict(d='', o='NOR', proof=leaf))
        nodes = {node.said: dict(serder=node) for node in (nor, far)}
        assert handler.evaluate(nodes, list(nodes)) is None
    near = credential(issuer.pre, edge=dict(d='', proof=dict(n=far.said, o='NI2I')))
    assert evaluate(handler, near, far) is True


@pytest.mark.parametrize('issuee', [None, ''])
def test_untargeted_default_and_edge_properties(graph, issuee):
    """Accept visible untargeted defaults and schema-defined labeled edge properties.

    Parameters:
        graph: Temporary real habitats/handler fixture defined above.

    Returns:
        None. Assertions check the stated evidence boundary."""
    _, issuer, _, handler = graph
    far = credential(issuer.pre, issuee=issuee)
    near = credential(issuer.pre, edge=dict(d='', proof=dict(
        n=far.said, explanation='a schema-defined labeled edge property')))
    assert evaluate(handler, near, far)
    targeted = credential(issuer.pre, issuee=issuer.pre)
    near = credential(issuer.pre, edge=dict(d='', proof=dict(n=targeted.said)))
    assert evaluate(handler, near, targeted)


@pytest.mark.parametrize('op,truths,expected', [
    ('AND', (True, True), True), ('AND', (True, False), False),
    ('OR', (True, False), True), ('OR', (False, False), False),
    ('NAND', (True, True), False), ('NAND', (True, False), True),
    ('NOR', (True, False), False), ('NOR', (False, False), True),
])
def test_boolean_groups_independent_truth_vectors(graph, op, truths, expected):
    """Reduce known AND/OR/NAND/NOR operands independently of relationship authentication.

    Parameters:
        graph: Temporary real habitats/handler fixture defined above.
        op: Group operator from the parametrized truth/arithmetic vectors.
        truths: Independent disclosed far-node eligibility values.
        expected: Expected concrete verdict or arithmetic mean for the selected vector.

    Returns:
        None. Assertions check the stated evidence boundary."""
    _, issuer, _, handler = graph
    handler.graphPolicy = DeclaredScorePolicy()
    first = credential(issuer.pre, marker='first', eligible=truths[0])
    second = credential(issuer.pre, marker='second', eligible=truths[1])
    near = credential(issuer.pre, edge=dict(d='', o=op,
        first=dict(n=first.said), second=dict(n=second.said)))
    assert evaluate(handler, near, first, second) is expected


def test_not_inverts_far_truth_but_never_relation_or_unknown(graph):
    """Negate only known far truth while preserving failed I2I and unknown validity.

    Parameters:
        graph: Temporary real habitats/handler fixture defined above.

    Returns:
        None. Assertions check the stated evidence boundary."""
    _, issuer, other, handler = graph
    handler.graphPolicy = DeclaredScorePolicy()
    for truth, expected in ((True, False), (False, True), (None, False)):
        far = credential(issuer.pre, issuee=issuer.pre, eligible=truth)
        near = credential(issuer.pre, edge=dict(d='', proof=dict(n=far.said, o='NOT')))
        assert evaluate(handler, near, far) is expected
    far = credential(issuer.pre, issuee=other.pre, eligible=False)
    near = credential(issuer.pre, edge=dict(d='', proof=dict(n=far.said, o='NOT')))
    assert evaluate(handler, near, far) is False  # NOT does not negate I2I


def test_far_graph_result_is_used_instead_of_requiring_every_node_true(graph):
    """Allow a root NOT of a false recursive far graph without globally requiring every node true.

    Parameters:
        graph: Temporary real habitats/handler fixture defined above.

    Returns:
        None. Assertions check the stated evidence boundary."""
    _, issuer, other, handler = graph
    tail = credential(issuer.pre, issuee=other.pre)
    middle = credential(issuer.pre, edge=dict(d='', tail=dict(n=tail.said)))
    assert evaluate(handler, middle, tail) is False  # default I2I fails
    root = credential(issuer.pre, edge=dict(d='', middle=dict(n=middle.said, o='NOT')))
    assert evaluate(handler, root, middle, tail) is True


@pytest.mark.parametrize('op', ['OR', 'NAND', 'NOR'])
def test_unknown_operator_or_missing_node_cannot_become_truth(graph, op):
    """Refuse unknown operator operands and keep absent far nodes retryable under negative group operators.

    Parameters:
        graph: Temporary real habitats/handler fixture defined above.
        op: Group operator from the parametrized truth/arithmetic vectors.

    Returns:
        None. Assertions check the stated evidence boundary."""
    _, issuer, _, handler = graph
    far = credential(issuer.pre)
    near = credential(issuer.pre, edge=dict(d='', o=op,
        okay=dict(n=far.said), unknown=dict(n=far.said, o='UNKNOWN')))
    assert evaluate(handler, near, far) is False
    near = credential(issuer.pre, edge=dict(d='', o=op, missing=dict(n=far.said, o='NOT')))
    with pytest.raises(MissingChainError):
        evaluate(handler, near)


@pytest.mark.parametrize('op,weights,expected', [
    ('AVG', (1, 3), 0.5), ('WAVG', (1, 3), 0.65),
])
def test_arithmetic_requires_explicit_property_and_mean_policy(graph, op, weights, expected):
    """Require explicit value/accept rules and independently check AVG/WAVG arithmetic before thresholding.

    Parameters:
        graph: Temporary real habitats/handler fixture defined above.
        op: Group operator from the parametrized truth/arithmetic vectors.
        weights: Declared per-edge numeric weights.
        expected: Expected concrete verdict or arithmetic mean for the selected vector.

    Returns:
        None. Assertions check the stated evidence boundary."""
    _, issuer, _, handler = graph
    first = credential(issuer.pre, score=0.2)
    second = credential(issuer.pre, score=0.8)
    root = credential(issuer.pre, edge=dict(d='', o=op,
        first=dict(n=first.said, w=weights[0]), second=dict(n=second.said, w=weights[1])))
    assert evaluate(handler, root, first, second) is False
    policy = handler.graphPolicy = DeclaredScorePolicy(minimum=0.45)
    assert evaluate(handler, root, first, second) is True
    assert policy.means == pytest.approx([expected])
    policy.minimum = 0.75
    assert evaluate(handler, root, first, second) is False


def test_nested_weighted_group_uses_computed_member_mean(graph):
    """Use the computed child mean as the weighted parent operand, rather than a second far-node lookup.

    Parameters:
        graph: Temporary real habitats/handler fixture defined above.

    Returns:
        None. Assertions check the stated evidence boundary."""
    _, issuer, _, handler = graph
    policy = handler.graphPolicy = DeclaredScorePolicy(minimum=0)
    first = credential(issuer.pre, score=0.2)
    second = credential(issuer.pre, score=0.8)
    last = credential(issuer.pre, score=1.0)
    root = credential(issuer.pre, edge=dict(d='', o='WAVG', subgroup=dict(
        o='AVG', w=3, first=dict(n=first.said), second=dict(n=second.said)),
        last=dict(n=last.said, w=1)))
    assert evaluate(handler, root, first, second, last)
    assert policy.means == pytest.approx([0.5, 0.625])


@pytest.mark.parametrize('weight', [None, -1, True, '1', float('inf'), float('nan'), 0, 10**400])
def test_bad_or_zero_weight_is_not_a_numeric_verdict(graph, weight):
    """Return unknown for malformed/nonfinite/zero/overflow weights, including inputs serialization would refuse.

    Parameters:
        graph: Temporary real habitats/handler fixture defined above.
        weight: Malformed, zero, nonfinite, or overflowing weight under test.

    Returns:
        None. Assertions check the stated evidence boundary."""
    _, issuer, _, handler = graph
    handler.graphPolicy = DeclaredScorePolicy(minimum=0)
    far = credential(issuer.pre, score=1)
    # Evaluate independently of serialization: nonfinite numbers are rejected
    # by the evaluator even if supplied by an application's value adapter.
    group = dict(o='WAVG', proof=dict(n=far.said, w=weight))
    assert handler._evaluateGroupEdge(group, nodes={far.said: {'serder': far}},
        nserder=far, nested=False) is None


def test_top_level_weight_and_empty_groups_refused(graph):
    """Refuse meaningless root weights and operand-free operator groups.

    Parameters:
        graph: Temporary real habitats/handler fixture defined above.

    Returns:
        None. Assertions check the stated evidence boundary."""
    _, issuer, _, handler = graph
    far = credential(issuer.pre)
    for group in (dict(o='AND'), dict(o='NOR'), dict(w=1, proof=dict(n=far.said))):
        assert handler._evaluateGroupEdge(group, nodes={far.said: {'serder': far}},
            nserder=far, nested=False) is None


def test_schema_pins_are_cumulative_and_missing_schema_retryable(graph):
    """Enforce ancestor and child schema pins together and preserve MissingSchemaError for unavailable evidence.

    Parameters:
        graph: Temporary real habitats/handler fixture defined above.

    Returns:
        None. Assertions check the stated evidence boundary."""
    hby, issuer, _, handler = graph
    far = credential(issuer.pre, score=1)
    own = far.sad['s']
    # An authentic additional schema with an unsatisfied required property.
    from keri.core import Schemer
    restrictive = Schemer(sed={'$id': '', '$schema': 'https://json-schema.org/draft/2020-12/schema',
                              'type': 'object', 'required': ['absent']})
    hby.db.schema.pin((restrictive.said,), restrictive)
    group = dict(o='AND', s=restrictive.said,
                 proof=dict(n=far.said, s=own))
    assert handler._evaluateGroupEdge(group, nodes={far.said: {'serder': far}},
        nserder=far, nested=True) is False
    missing = Diger(ser=b'missing-schema').qb64
    with pytest.raises(MissingSchemaError):
        handler._evaluateLeafEdge(dict(n=far.said, s=missing),
            nodes={far.said: {'serder': far}}, nserder=far)


def test_malformed_schema_pin_cannot_be_inverted(graph):
    """Keep invalid schema commitments unknown instead of allowing NOR to bless them.

    Parameters:
        graph: Temporary real habitats/handler fixture defined above.

    Returns:
        None. Assertions check the stated evidence boundary."""
    _, issuer, _, handler = graph
    far = credential(issuer.pre)
    invalid = Schemer(sed={'$id': '', 'version': 'invalid-version', 'type': 'object'})
    for pin in (None, 'not-a-said', 5, {'$id': 'not-a-said'}, invalid.sed):
        group = dict(o='NOR', proof=dict(n=far.said, s=pin))
        assert handler._evaluateGroupEdge(group, nodes={far.said: {'serder': far}},
            nserder=far, nested=False) is None
    assert handler._evaluateLeafEdge(dict(n=far.said, s=far.sad['s']['$id']),
        nodes={far.said: {'serder': far}}, nserder=far) is True


def test_di2i_uses_real_accepted_delegation_not_unaccepted_dip(graph):
    """Require ordinary foreign KEL delegation acceptance and a real delegator seal before DI2I succeeds.

    Parameters:
        graph: Temporary real habitats/handler fixture defined above.

    Returns:
        None. Assertions check the stated evidence boundary."""
    hby, issuer, other, handler = graph
    with openHby(name='delegation-observer', version=Vrsn_2_0) as observer:
        kvy = Kevery(db=observer.db, lax=False, local=False)
        parser = Parser(kvy=kvy, version=Vrsn_2_0)
        parser.parse(ims=bytearray(issuer.replay(gvrsn=Vrsn_2_0)))
        signer, nextkey = Signer(), Signer()
        dip = delcept(keys=[signer.verfer.qb64], delpre=issuer.pre,
            ndigs=[Diger(ser=nextkey.verfer.qb64b).qb64], version=Vrsn_2_0)
        parser.parse(ims=messagize(dip, sigers=[signer.sign(dip.raw, index=0)], gvrsn=Vrsn_2_0))
        assert observer.db.kels.getLast(keys=dip.pre, on=0) is None
        checker = EdgeEvaluator(PresentedEvidence(observer))
        with pytest.raises(MissingChainError):
            checker._delegatedIssuer(dip.pre, issuer.pre)
        anchor = issuer.interact(data=[dict(i=dip.pre, s='0', d=dip.said)])
        parser.parse(ims=bytearray(anchor))
        bond = SealSource(s=Number(num=issuer.kever.sn), d=Diger(qb64=issuer.kever.serder.said))
        parser.parse(ims=messagize(dip, sigers=[signer.sign(dip.raw, index=0)],
            bonds=[bond], gvrsn=Vrsn_2_0))
        kvy.processEscrows()
        assert observer.db.kels.getLast(keys=dip.pre, on=0) == dip.said
        assert checker._delegatedIssuer(dip.pre, issuer.pre)
        far = credential(issuer.pre, issuee=issuer.pre)
        near = credential(dip.pre, edge=dict(d='', proof=dict(n=far.said, o='DI2I')))
        assert evaluate(checker, near, far)
        assert not checker._delegatedIssuer(dip.pre, other.pre)


def test_local_delegated_inception_is_not_authorization_before_delegator_seal(graph):
    """Reject local delegated inception as DI2I authority until its actual delegator approval exists.

    Parameters:
        graph: Temporary real habitats/handler fixture defined above.

    Returns:
        None. Assertions check the stated evidence boundary."""
    hby, issuer, _, handler = graph
    child = hby.makeHab(name='locally-unapproved-delegate', delpre=issuer.pre)
    inception = child.kever.serder
    assert hby.db.kels.getLast(keys=child.pre, on=0) == inception.said
    with pytest.raises(MissingChainError, match='delegation authorization'):
        handler._delegatedIssuer(child.pre, issuer.pre)
    issuer.interact(data=[dict(i=child.pre, s='0', d=inception.said)])
    assert handler._delegatedIssuer(child.pre, issuer.pre)


def signed(serder, hab):
    """Attach real issuer signatures to one disclosed credential node.

    Args:
        serder (SerderACDC): Exact node bytes to authenticate.
        hab (Hab): Issuer whose current keys sign those bytes.

    Returns:
        bytearray: ACDC v2 credential node stream carrying current-establishment signatures."""
    return messagize(serder, tsgs=[(hab.kever.prefixer,
        Number(sn=hab.kever.lastEst.s), Diger(qb64=hab.kever.lastEst.d),
        hab.sign(ser=serder.raw))], gvrsn=Vrsn_2_0, framed=False)


def test_production_grant_uses_shared_graph_policy_and_rejects_bad_proof(graph):
    """Exercise signed Grant intake with the configured graph policy and independently invalid issuer proof.

    Parameters:
        graph: Temporary real habitats/handler fixture defined above.

    Returns:
        None. Assertions check the stated evidence boundary."""
    hby, issuer, other, _ = graph
    with openHby(name='graph-grant-receiver', version=Vrsn_2_0) as receiver:
        holder = receiver.makeHab(name='holder')
        kvy = Kevery(db=receiver.db, lax=False, local=False)
        exc = Exchanger(hby=receiver, handlers=[])
        policy = DeclaredScorePolicy()
        loadHandlers(receiver, exc, Notices())
        # Preserve the handler's existing policy binding after route construction.
        exc.routes['/ipex/grant'].graphPolicy = policy
        parser = Parser(kvy=kvy, exc=exc, version=Vrsn_2_0)
        parser.parse(ims=bytearray(issuer.replay(gvrsn=Vrsn_2_0)))
        far = credential(issuer.pre, eligible=False)
        near = credential(issuer.pre, issuee=holder.pre,
            edge=dict(d='', proof=dict(n=far.said, o='NOT')))
        plan = dict(dp=[[near.sad['s']['$id'], '/', []],
                         [far.sad['s']['$id'], '/e/proof/_/', []]])
        exn, atc = grant(issuer, holder.pre, 'negative authenticated predicate',
            origin=signed(near, issuer), artifacts=[signed(far, issuer)], modifiers=plan)
        parser.parse(ims=bytearray(exn.raw + atc))
        assert exc.complete(exn.said)
        # Invalid issuer authentication is not a false claim that NOT can bless.
        bad, batc = grant(issuer, holder.pre, 'invalid proof is not false',
            origin=signed(near, issuer), artifacts=[signed(far, other)], modifiers=plan)
        parser.parse(ims=bytearray(other.replay(gvrsn=Vrsn_2_0)))
        parser.parse(ims=bytearray(bad.raw + batc))
        assert not exc.complete(bad.said)


@pytest.mark.parametrize('shape,accepted', [
    ('string', True), ('nested', True), ('reference', True), ('expanded', True),
    ('worked', True), ('worked-map-leaf', False), ('nested-ancestor', True),
    ('ambiguous-ancestor', False), ('scoped-string', True), ('scoped-map', False),
    ('map-admitting', False), ('open', False), ('missing-far', False),
    ('leaf-property-hop', False),
    ('property-before-reserved', False), ('reserved-out-of-order', False),
])
def test_schema_authorized_edges_through_signed_grant(graph, shape, accepted):
    """Authenticate exact compact/expanded edges without interpreting opaque strings."""
    from copy import deepcopy
    hby, issuer, _, evaluator = graph
    far = credential(issuer.pre, marker='far')
    body = deepcopy(far.schema)
    leaf = {'type': 'string', 'description': 'Far Node SAID'}
    if shape == 'map-admitting':
        leaf = {'oneOf': [{'type': 'string'}, {'type': 'object'}]}
    elif shape == 'open':
        leaf = {}
    elif shape == 'reference':
        body['$defs'] = {'far': leaf}
        leaf = {'$ref': '#/$defs/far'}
    elif shape in ('expanded', 'property-before-reserved', 'reserved-out-of-order',
                   'leaf-property-hop'):
        leaf = {'type': 'object'}
    props = {'d': {'type': 'string'}, 'proof': leaf}
    edge = dict(d='', proof=far.said)
    prefix = '/e/proof/_/'
    if shape == 'nested':
        props = {'d': {'type': 'string'}, 'group': {
            'type': 'object', 'properties': {'proof': leaf}}}
        edge = dict(d='', group=dict(proof=far.said))
        prefix = '/e/group/proof/_/'
    elif shape == 'expanded':
        edge['proof'] = dict(n=far.said, explanation='retained property')
    elif shape == 'property-before-reserved':
        edge['proof'] = dict(explanation='misordered', n=far.said)
    elif shape == 'reserved-out-of-order':
        edge['proof'] = dict(o='NI2I', n=far.said)
    attribute = dict(d='', marker=shape)
    if shape == 'leaf-property-hop':
        edge['proof'] = dict(n=far.said, shadow=dict(n=far.said))
        prefix = '/e/proof/shadow/_/'
    body['properties']['e'] = {'type': 'object', 'properties': props}
    if shape in ('worked', 'worked-map-leaf'):
        target = (leaf if shape == 'worked' else
                  {'oneOf': [{'type': 'string'}, {'type': 'object'}]})
        detail = dict(type='object', additionalProperties=False,
            required=['d', 'u', 'accreditation', 'reports'], properties=dict(
                d=dict(type='string'), u=dict(type='string'), accreditation=target,
                reports=dict(type='object', additionalProperties=False,
                    required=['research', 'project'], properties=dict(research=leaf, project=leaf))))
        # Pinned simpleTranscriptSchema: section SAID or expanded object, with
        # string-only accreditation and reports/research, reports/project edges.
        body['properties']['e'] = {'oneOf': [dict(type='string'), detail]}
        edge = dict(d='', u=Noncer().qb64, accreditation=far.said,
                    reports=dict(research=far.said, project=far.said))
        prefix = '/e/accreditation/_/'
    elif shape in ('nested-ancestor', 'ambiguous-ancestor'):
        detail = dict(type='object', properties=dict(proof=leaf))
        other = dict(type='string') if shape == 'nested-ancestor' else dict(type='object')
        body['properties']['e']['properties'] = dict(group={'oneOf': [other, detail]})
        edge = dict(d='', group=dict(proof=far.said))
        prefix = '/e/group/proof/_/'
    elif shape in ('scoped-string', 'scoped-map'):
        opaque = {'oneOf': [dict(type='string'), dict(type='object')]}
        local = leaf if shape == 'scoped-string' else opaque
        root = opaque if shape == 'scoped-string' else leaf
        bundle = Schemer(sed={'$id': '', 'version': '1.0.0', 'type': 'object',
            'properties': dict(d=dict(type='string'), proof={'$ref': '#/$defs/target'}),
            '$defs': dict(target=local)})
        body['$defs'] = dict(target=root)
        body['properties']['e'] = bundle.sed
    schema = Schemer(sed=body)
    near = acdcmap(israid=issuer.pre, schema=schema.sed,
                   attribute=attribute, edge=edge)
    before = (near.raw, far.raw)
    with openHby(name='schema-edge-receiver', version=Vrsn_2_0) as receiver:
        holder = receiver.makeHab(name='holder')
        exc = Exchanger(hby=receiver, handlers=[])
        loadHandlers(receiver, exc, Notices())
        parser = Parser(kvy=Kevery(db=receiver.db, lax=False, local=False),
                        exc=exc, version=Vrsn_2_0)
        parser.parse(ims=bytearray(issuer.replay(gvrsn=Vrsn_2_0)))
        artifacts = [] if shape == 'missing-far' else [signed(far, issuer)]
        plan = [[schema.said, '', []]]
        if artifacts:
            plan.append([far.schema['$id'], prefix, []])
        exn, atc = grant(issuer, holder.pre, shape, origin=signed(near, issuer),
                         artifacts=artifacts, modifiers=dict(dp=plan))
        retained = bytes(exn.raw + atc)
        ims = bytearray(retained)
        parser.parse(ims=ims)
        assert not ims
        assert exc.complete(exn.said) is accepted
        assert (near.raw, far.raw) == before
        assert bytes(exn.raw + atc) == retained
        if accepted:
            nests = loadParsedNestedSubstreams(receiver, exn.said)
            assert [nest.serder.raw for nest in nests] == list(before)
        if not accepted:
            assert receiver.db.epse.get((exn.said,)) is None
        # The semantic owner independently applies the same edge classification.
        if shape != 'missing-far':
            assert evaluate(evaluator, near, far) is (accepted or shape == 'leaf-property-hop')


@pytest.mark.parametrize('farTruth,operator,verdict', [
    (False, 'NI2I', False), (None, 'NOT', None), (False, 'NOT', True),
])
def test_authenticated_graph_retention_is_separate_from_wallet_use(graph, farTruth, operator, verdict):
    """Retain signed false/unknown graphs, but only explicit root True admits."""
    from keri.app.credentialing import Wallet
    _, issuer, _, _ = graph
    with openHby(name='graph-use-receiver', version=Vrsn_2_0) as receiver:
        holder = receiver.makeHab(name='holder')
        exc = Exchanger(hby=receiver, handlers=[])
        policy = DeclaredScorePolicy()
        verification = loadHandlers(receiver, exc, Notices(), graphPolicy=policy)
        parser = Parser(kvy=Kevery(db=receiver.db, lax=False, local=False),
                        exc=exc, version=Vrsn_2_0)
        parser.parse(ims=bytearray(issuer.replay(gvrsn=Vrsn_2_0)))
        far = credential(issuer.pre, eligible=farTruth)
        near = credential(issuer.pre, issuee=holder.pre,
                          edge=dict(d='', proof=dict(n=far.said, o=operator)))
        exn, atc = grant(issuer, holder.pre, 'authenticated graph is evidence',
            origin=signed(near, issuer), artifacts=[signed(far, issuer)],
            modifiers=dict(dp=[[near.schema['$id'], '/', []],
                               [far.schema['$id'], '/e/proof/_/', []]]))
        parser.parse(ims=bytearray(exn.raw + atc))
        assert exc.complete(exn.said)
        retained = tuple(receiver.db.enst.get((exn.said,)))
        assert verification.verifyAccepted(exn.said, '/ipex/grant')
        assert verification.evaluateGrant(exn.said) is verdict
        assert verification.evaluateSelected(signed(near, issuer), [signed(far, issuer)]) is verdict
        with pytest.raises(ValidationError):
            verification.evaluateSelected(signed(near, issuer) + signed(far, issuer))
        with pytest.raises(ValidationError):
            verification.evaluateSelected(signed(near, issuer), [signed(far, holder)])
        issuer.interact(data=[dict(d=far.said)], version=Vrsn_2_0)
        anchor = issuer.kever.serder
        anchoredFar = messagize(far, bonds=[SealSource(s=Number(num=anchor.sn),
            d=Diger(qb64=anchor.said))], gvrsn=Vrsn_2_0)
        with pytest.raises(MissingChainError):
            verification.evaluateSelected(signed(near, issuer), [anchoredFar])
        parser.parse(ims=bytearray(issuer.replay(gvrsn=Vrsn_2_0)))
        assert verification.evaluateSelected(signed(near, issuer), [anchoredFar]) is verdict
        reply, ratc = admit(holder, 'explicit local consent', exn)
        parser.parse(ims=bytearray(reply.raw + ratc))
        assert exc.complete(reply.said)
        wallet = Wallet(receiver, None, exc=exc, verification=verification)
        try:
            if verdict is not True:
                with pytest.raises(ValidationError, match='semantic acceptance'):
                    wallet.recordAdmission(exn.said, reply.said, consent=True)
                assert wallet.db.admitted.get((exn.said,)) is None
                policy.validity = lambda node: node.said == near.said or operator == 'NI2I'
            row = wallet.recordAdmission(exn.said, reply.said, consent=True)
            policy.validity = lambda node: None
            assert verification.evaluateGrant(exn.said) is None
            assert wallet.recordAdmission(exn.said, reply.said, consent=True) == row
            assert tuple(receiver.db.enst.get((exn.said,))) == retained
        finally:
            wallet.close()
