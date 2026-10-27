"""Whole-node IPEX claims require schema-proven recursive closure.

The bounded profile refuses open schemas and aggregates; visible blocks alone
cannot prove recursive completeness. Explicit leaf paths remain usable.
"""
from copy import deepcopy

from keri import Vrsn_2_0
from keri.acdc import IpexHandler, acdcagg, acdcmap
from keri.app import openHby
from keri.core import Compactor, Diger, Noncer, SerderACDC


def test_whole_root_plan_refuses_aggregate_completeness_claims():
    """Refuse both expanded and selectively hidden aggregates as whole nodes.

    Returns:
        None. Both views verify and keep the same credential SAID; node-presence
        requests allow either, but aggregate closure is outside this profile.
    """
    issuer = Diger(ser=b'whole-disclosure-issuer').qb64
    full = acdcagg(israid=issuer, uuid=Noncer().qb64, aggregate=[
        '', dict(d='', u=Noncer().qb64, value='visible'),
        dict(d='', u=Noncer().qb64, value='withheld')])
    sad = deepcopy(full.sad)
    sad['A'][2] = full.sad['A'][2]['d']
    partial = SerderACDC(sad=sad, makify=True)
    assert full.verify() and partial.verify() and full.said == partial.said
    schema = full.schema['$id']
    with openHby(name='whole-root-aggregate', base='test', version=Vrsn_2_0) as hby:
        handler = IpexHandler('/ipex/grant', hby=hby, notifier=None)
        for credential in (full, partial):
            nodes = {credential.said: {'serder': credential}}
            assert handler._verifyDisclosurePlan(
                [[schema, '/', []]], credential.said, nodes, [credential.said])
            for path in ('', 'd/'):
                assert handler._verifyDisclosurePlan(
                    [[schema, '/', [path]]], credential.said, nodes,
                    [credential.said]) is False


def test_whole_root_opaque_attribute_is_not_recursive_completeness_proof():
    """Preserve legitimate digest scalars and demonstrate their byte-identical ambiguity.

    Returns:
        None. The open schema cannot prove whole-node closure for any view, and
        explicit private/value disclosure cannot be satisfied by a string. No
        cache or received-view expansion invents the missing information.
    """
    issuer = Diger(ser=b'opaque-attribute-issuer').qb64
    full = acdcmap(israid=issuer, uuid=Noncer().qb64, attribute=dict(d='',
        visible=dict(d='', u=Noncer().qb64, value='visible'),
        private=dict(d='', u=Noncer().qb64, value='withheld')))
    compactor = Compactor(mad=deepcopy(full.sad['a']), makify=True, kind=full.kind)
    paths = ['a/visible/']
    compactor.compact(paths=paths, root='a')
    attributes = compactor.partials[tuple(paths)].mad
    partial = acdcmap(israid=full.israid, uuid=full.sad['u'], schema=full.schema,
                      attribute=attributes)
    assert full.verify() and partial.verify() and full.said == partial.said
    assert isinstance(partial.sad['a']['private'], str)
    # An independently authored ordinary scalar has exactly the same bytes as
    # the partial interpretation. Rejecting on digest spelling would reject it.
    scalar = acdcmap(israid=full.israid, uuid=full.sad['u'], schema=full.schema,
        attribute=dict(d='', visible=full.sad['a']['visible'],
                       private=partial.sad['a']['private']))
    assert scalar.raw == partial.raw
    schema = full.schema['$id']
    with openHby(name='whole-root-opaque', base='test', version=Vrsn_2_0) as hby:
        handler = IpexHandler('/ipex/grant', hby=hby, notifier=None)
        for credential, expected in ((full, True), (partial, False), (scalar, False)):
            nodes = {credential.said: {'serder': credential}}
            assert handler._verifyDisclosurePlan(
                [[schema, '/', []]], credential.said, nodes, [credential.said])
            for path in ('', 'd/'):
                assert handler._verifyDisclosurePlan(
                    [[schema, '/', [path]]], credential.said, nodes,
                    [credential.said]) is False
            assert handler._verifyDisclosurePlan(
                [[schema, '/', ['a/visible/value', 'a/private/value']]],
                credential.said, nodes, [credential.said]) is expected


def test_existing_node_schema_can_require_disclosed_attribute_structure():
    """Use ordinary schema validation to distinguish a required object from a scalar.

    Returns:
        None. An application schema requiring private/value rejects its compact
        string form without a new recursive-type inference or cache expansion.
    """
    import pytest
    from keri.acdc.scheming import validateSchema
    from keri.kering import FailedSchemaValidationError

    schema = {'$id': '', 'version': '1.0.0', 'type': 'object', 'properties': {
        'a': {'type': 'object', 'required': ['private'], 'properties': {
            'private': {'type': 'object', 'required': ['value']}}}}}
    full = acdcmap(israid=Diger(ser=b'typed-attribute-issuer').qb64,
        uuid=Noncer().qb64, schema=schema, attribute=dict(d='',
            private=dict(d='', u=Noncer().qb64, value='required content')))
    partial = acdcmap(israid=full.israid, uuid=full.sad['u'], schema=full.schema,
        attribute=dict(d='', private=full.sad['a']['private']['d']))
    assert full.verify() and partial.verify() and full.said == partial.said
    # Every schema resource is inline; no database dependency can supply content.
    assert validateSchema(full, db=None)
    with pytest.raises(FailedSchemaValidationError):
        validateSchema(partial, db=None)
