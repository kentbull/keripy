"""Published graph-profile vectors; policy meaning remains explicitly supplied.

ACDC f0bd097d, spec-body.md 1105-1120 and 1172-1211. These tests exercise
production IPEX evaluation and accepted KEL delegation without fixture tables.
"""
import pytest

from keri import Vrsn_2_0
from keri.acdc import IpexHandler, acdcmap, grant, loadHandlers
from keri.app import openHby
from keri.core import (Compactor, Diger, Kevery, Noncer, Number, Parser, SealSource, Signer,
                       delcept, messagize)
from keri.kering import MissingChainError, MissingSchemaError
from keri.peer import Exchanger


class Notices:
    def add(self, attrs):
        pass


class DeclaredScorePolicy:
    """Example application policy, not an inferred protocol/EGF rule."""
    def __init__(self, minimum=0.5):
        self.minimum = minimum
        self.means = []

    def validity(self, serder):
        return serder.sad['a'].get('eligible', True)

    def value(self, *, near, edge, far):
        return far.sad['a'].get('score') if far is not None else None

    def accept(self, *, near, group, average):
        self.means.append(average)
        return average >= self.minimum


@pytest.fixture
def graph():
    with openHby(name='native-graph-profile', version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name='issuer')
        other = hby.makeHab(name='other')
        handler = IpexHandler('/ipex/grant', hby, Notices())
        yield hby, issuer, other, handler


def credential(issuer, *, issuee=None, edge=None, **properties):
    return acdcmap(israid=issuer, iseaid=issuee,
                   attribute=dict(d='', **properties), edge=edge)


def evaluate(handler, origin, *far):
    nodes = {serder.said: {'serder': serder} for serder in (origin,) + far}
    return handler._verifyGraphSemantics(nodes, list(nodes))


@pytest.mark.parametrize('operator,expected', [
    (None, False), ('', False), ([], False), ('I2I', False),
    ('NI2I', True), (['I2I', 'NI2I'], True),
    (['NI2I', 'I2I'], False), ('E1E', False), ('UNKNOWN', False),
])
def test_targeted_defaults_and_last_conflicting_relation(graph, operator, expected):
    _, issuer, other, handler = graph
    far = credential(issuer.pre, issuee=other.pre)
    leaf = dict(n=far.said)
    if operator is not None:
        leaf['o'] = operator
    near = credential(issuer.pre, edge=dict(d='', proof=leaf))
    assert evaluate(handler, near, far) is expected


def test_hidden_issuee_is_unknown_not_an_untargeted_default(graph):
    _, issuer, other, handler = graph
    full = acdcmap(israid=issuer.pre, uuid=Noncer().qb64, iseaid=other.pre,
        attribute=dict(d='', u=Noncer().qb64))
    compact = Compactor(mad=dict(full.sad['a']), makify=True)
    far = acdcmap(israid=issuer.pre, uuid=full.sad['u'],
                   schema=full.schema, attribute=compact.said)
    assert isinstance(far.attrib, str) and far.iseaid is None
    for op in (None, 'I2I', 'DI2I', 'NOT'):
        leaf = dict(n=far.said)
        if op is not None:
            leaf['o'] = op
        near = credential(issuer.pre, edge=dict(d='', o='NOR', proof=leaf))
        assert evaluate(handler, near, far) is False
    near = credential(issuer.pre, edge=dict(d='', proof=dict(n=far.said, o='NI2I')))
    assert evaluate(handler, near, far) is True


def test_untargeted_default_and_edge_properties(graph):
    _, issuer, _, handler = graph
    far = credential(issuer.pre)
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
    _, issuer, _, handler = graph
    handler.graphPolicy = DeclaredScorePolicy()
    first = credential(issuer.pre, marker='first', eligible=truths[0])
    second = credential(issuer.pre, marker='second', eligible=truths[1])
    near = credential(issuer.pre, edge=dict(d='', o=op,
        first=dict(n=first.said), second=dict(n=second.said)))
    assert evaluate(handler, near, first, second) is expected


def test_not_inverts_far_truth_but_never_relation_or_unknown(graph):
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
    _, issuer, other, handler = graph
    tail = credential(issuer.pre, issuee=other.pre)
    middle = credential(issuer.pre, edge=dict(d='', tail=dict(n=tail.said)))
    assert evaluate(handler, middle, tail) is False  # default I2I fails
    root = credential(issuer.pre, edge=dict(d='', middle=dict(n=middle.said, o='NOT')))
    assert evaluate(handler, root, middle, tail) is True


@pytest.mark.parametrize('op', ['OR', 'NAND', 'NOR'])
def test_unknown_operator_or_missing_node_cannot_become_truth(graph, op):
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
    _, issuer, _, handler = graph
    handler.graphPolicy = DeclaredScorePolicy(minimum=0)
    far = credential(issuer.pre, score=1)
    # Evaluate independently of serialization: nonfinite numbers are rejected
    # by the evaluator even if supplied by an application's value adapter.
    group = dict(o='WAVG', proof=dict(n=far.said, w=weight))
    assert handler._evaluateGroupEdge(group, nodes={far.said: {'serder': far}},
        nserder=far, nested=False) is None


def test_top_level_weight_and_empty_groups_refused(graph):
    _, issuer, _, handler = graph
    far = credential(issuer.pre)
    for group in (dict(o='AND'), dict(o='NOR'), dict(w=1, proof=dict(n=far.said))):
        assert handler._evaluateGroupEdge(group, nodes={far.said: {'serder': far}},
            nserder=far, nested=False) is None


def test_schema_pins_are_cumulative_and_missing_schema_retryable(graph):
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
    _, issuer, _, handler = graph
    far = credential(issuer.pre)
    for pin in (None, 'not-a-said', 5, {'$id': 'not-a-said'}):
        group = dict(o='NOR', proof=dict(n=far.said, s=pin))
        assert handler._evaluateGroupEdge(group, nodes={far.said: {'serder': far}},
            nserder=far, nested=False) is None
    assert handler._evaluateLeafEdge(dict(n=far.said, s=far.sad['s']['$id']),
        nodes={far.said: {'serder': far}}, nserder=far) is True


def test_di2i_uses_real_accepted_delegation_not_unaccepted_dip(graph):
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
        checker = IpexHandler('/ipex/grant', observer, Notices())
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
    hby, issuer, _, handler = graph
    child = hby.makeHab(name='locally-unapproved-delegate', delpre=issuer.pre)
    inception = child.kever.serder
    assert hby.db.kels.getLast(keys=child.pre, on=0) == inception.said
    with pytest.raises(MissingChainError, match='delegation authorization'):
        handler._delegatedIssuer(child.pre, issuer.pre)
    issuer.interact(data=[dict(i=child.pre, s='0', d=inception.said)])
    assert handler._delegatedIssuer(child.pre, issuer.pre)


def signed(serder, hab):
    return messagize(serder, tsgs=[(hab.kever.prefixer,
        Number(sn=hab.kever.lastEst.s), Diger(qb64=hab.kever.lastEst.d),
        hab.sign(ser=serder.raw))], gvrsn=Vrsn_2_0, framed=False)


def test_production_grant_uses_shared_graph_policy_and_rejects_bad_proof(graph):
    hby, issuer, other, _ = graph
    with openHby(name='graph-grant-receiver', version=Vrsn_2_0) as receiver:
        holder = receiver.makeHab(name='holder')
        kvy = Kevery(db=receiver.db, lax=False, local=False)
        exc = Exchanger(hby=receiver, handlers=[])
        policy = DeclaredScorePolicy()
        loadHandlers(receiver, exc, Notices(), graphPolicy=policy)
        parser = Parser(kvy=kvy, exc=exc, version=Vrsn_2_0)
        parser.parse(ims=bytearray(issuer.replay(gvrsn=Vrsn_2_0)))
        far = credential(issuer.pre, eligible=False)
        near = credential(issuer.pre, issuee=holder.pre,
            edge=dict(d='', proof=dict(n=far.said, o='NOT')))
        plan = dict(dp=[[[near.sad['s']['$id'], '/', []],
                         [far.sad['s']['$id'], '/e/proof/_/', []]]])
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
