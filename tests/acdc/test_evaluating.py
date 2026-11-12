# -*- encoding: utf-8 -*-
"""Tests for protocol-independent ACDC Edge Section evaluation."""

from copy import deepcopy

from keri import Kinds, Vrsn_2_0
from keri.acdc import (EdgeEvaluator, SchemaEvaluator, Verdicts, acdcmap,
                       valid)
from keri.app.habbing import openHby
from keri.core import Compactor, Schemer, SealEvent


class _Forged:
    """Received-node stand-in whose Edge Section carries a false commitment."""

    def __init__(self, serder, **fields):
        self.sad = dict(deepcopy(serder.sad), **fields)
        self.said = serder.said
        self.kind = serder.kind
        self.schema = serder.schema
        self.israid = serder.israid
        self.iseaid = serder.iseaid


def test_leaf_edge_accepts_inline_schema_pin():
    """A leaf edge may pin its far node's schema with an inline schema document."""
    with openHby(name="inline-schema-pin", base="test",
                 version=Vrsn_2_0) as hby:
        # Create near and far nodes
        issuer = hby.makeHab(name="issuer")
        child = acdcmap(israid=issuer.pre,
                        attribute=dict(d="", role="member"),
                        iseaid=issuer.pre)
        origin = acdcmap(israid=issuer.pre,
                         attribute=dict(d="", LEI="254900OPPU84GM83BG36"),
                         iseaid=issuer.pre)

        # Use the far node's embedded schema as the Edge pin
        schema = dict(child.sad["s"])
        assert isinstance(schema.get("$id"), str)

        # Keep node authentication outside this schema-pin test
        def verifyNode(serder, nest, *, records=None):
            return valid(f"node {serder.said} authenticated for edge test")

        evaluator = EdgeEvaluator(
            schemaEvaluator=SchemaEvaluator(hby.db),
            verifyNode=verifyNode,
            isDelegated=hby.kvy.isDelegated,
        )

        # Building a wire ACDC with this pin fails in the compactor, so the
        # leaf is evaluated directly
        leaf = dict(d="", n=child.said, s=schema)
        verdict = evaluator._evaluateLeafEdge(
            leaf,
            nodes={child.said: {"serder": child}},
            nserder=origin,
            memo={child.said: valid("far node vetted elsewhere")},
            inheritedPins=())
        assert verdict is not None
        assert verdict.verdict == Verdicts.valid


def test_node_schema_verdicts_follow_edge_group_reduction():
    """Treat a far node's own schema as part of its Edge-group member verdict."""
    with openHby(name="edge-node-schema-reduction", base="test",
                 version=Vrsn_2_0) as hby:
        issuer = hby.makeHab(name="issuer", kind=Kinds.cesr)

        # Keep node authentication outside this schema-reduction test.
        def verifyNode(serder, nest, *, records=None):
            return valid(f"node {serder.said} authenticated for schema reduction")

        schemaEvaluator = SchemaEvaluator(hby.db)
        evaluator = EdgeEvaluator(schemaEvaluator=schemaEvaluator,
                                  verifyNode=verifyNode,
                                  isDelegated=hby.kvy.isDelegated)

        # This far node satisfies its own schema.
        validFar = acdcmap(
            israid=issuer.pre,
            attribute=dict(d="", role="valid"),
        )

        # This far node is missing a field required by its schema.
        invalidSchema = deepcopy(validFar.schema)
        invalidSchema["$id"] = ""
        invalidSchema["title"] = "Schema requiring an absent top-level field"
        invalidSchema["required"] = [*invalidSchema["required"], "missing"]
        invalidSchemer = Schemer(sed=invalidSchema)
        invalidFar = acdcmap(
            israid=issuer.pre,
            schema=invalidSchemer.sed,
            attribute=dict(d="", role="schema-invalid"),
        )

        # This far node references a schema that is not cached.
        missingSchema = deepcopy(validFar.schema)
        missingSchema["$id"] = ""
        missingSchema["title"] = "Uncached far-node schema"
        missingSchemer = Schemer(sed=missingSchema)
        missingFar = acdcmap(
            israid=issuer.pre,
            schema=missingSchemer.said,
            attribute=dict(d="", role="schema-missing"),
        )
        undisclosedFar = acdcmap(
            israid=issuer.pre,
            attribute=dict(d="", role="undisclosed"),
        )

        # Place both far-node verdicts inside the same logical group.
        def evaluateGroup(operator, optionalFar, discloseOptional=True):
            origin = acdcmap(
                israid=issuer.pre,
                attribute=dict(d="", role="origin"),
                edge=dict(
                    d="",
                    alternatives=dict(
                        d="",
                        o=operator,
                        valid=dict(d="", n=validFar.said, o="NI2I"),
                        optional=dict(d="", n=optionalFar.said, o="NI2I"),
                    ),
                ),
            )
            nodes = {
                origin.said: {"serder": origin},
                validFar.said: {"serder": validFar},
            }
            if discloseOptional:
                nodes[optionalFar.said] = {"serder": optionalFar}
            return evaluator.evaluate(origin.said, nodes=nodes)

        # One valid branch satisfies OR despite an invalid branch.
        verdict = evaluateGroup("OR", invalidFar)
        assert verdict.verdict == Verdicts.valid

        # AND propagates the invalid branch.
        verdict = evaluateGroup("AND", invalidFar)
        assert verdict.verdict == Verdicts.invalid

        # One valid branch satisfies OR without waiting for missing evidence.
        verdict = evaluateGroup("OR", missingFar)
        assert verdict.verdict == Verdicts.valid

        # AND remains retryable while a required schema is missing.
        verdict = evaluateGroup("AND", missingFar)
        assert verdict.verdict == Verdicts.unknown
        assert verdict.retryable is True

        # Missing far nodes participate in the same OR/AND reduction.
        verdict = evaluateGroup("OR", undisclosedFar, discloseOptional=False)
        assert verdict.verdict == Verdicts.valid
        verdict = evaluateGroup("AND", undisclosedFar, discloseOptional=False)
        assert verdict.verdict == Verdicts.unknown
        assert verdict.retryable is True


def test_delegation_refusal_cycle_is_decided():
    """A delegation cycle in a corrupt local store is refused, not left pending."""
    from types import SimpleNamespace
    from keri.core.eventing import delegationRefusal

    kevers = {
        "A": SimpleNamespace(delpre="B", doNotDelegate=False),
        "B": SimpleNamespace(delpre="A", doNotDelegate=False),
    }

    class Store:
        """Every hop finds its inception and a first-seen anchor."""

        def __init__(self):
            self.evts = SimpleNamespace(get=lambda keys: SimpleNamespace(
                pre=keys[0], snh="0", said=keys[0]))
            self.fons = SimpleNamespace(get=lambda keys: 0)

    for kever in kevers.values():
        kever.fetchDelegatingEvent = (lambda delpre, serder, **kwa:
                                      SimpleNamespace(pre=delpre, said="anchor"))

    refusal = delegationRefusal(kevers, Store(), "A", "C")
    assert refusal and "cycles" in refusal
