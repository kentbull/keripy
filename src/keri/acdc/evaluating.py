# -*- encoding: utf-8 -*-
"""
keri.acdc.evaluating module

ACDC Edge Section and schema evaluation, independent of any disclosure protocol.

IPEX (acdc.ipexing) owns exchange authentication, evidence loading, escrow
disposition, disclosure-plan enforcement and persistence. What an Edge Section
*means* -- graph shape and closure, the unary Operators and their defaults and
conflict groups, the m-ary reductions, and schema pins -- is decided here, over
evidence a caller supplies through two adapters:

- ``verifyNode(serder, nest, records=records)`` returns one node's
  authentication verdict, and
- ``isDelegated(pre, delpre)`` answers True, False or None for whether ``pre``
  is an anchored delegated descendant of ``delpre`` (see
  ``core.eventing.Kevery.isDelegated``).

Verdicts are acdc.chaining EdgeVerdicts. A malformed shape is not a truth value,
so it returns None rather than entering the Kleene lattice where a satisfied OR
sibling could outvote it.
"""

from collections import deque, namedtuple
from collections.abc import Mapping
from copy import deepcopy

from ..core import Saider, Schemer, SerderACDC
from ..kering import (FailedSchemaValidationError, MissingChainError,
                      MissingSchemaError, ValidationError)
from . import chaining, scheming


# An Edge Section is itself an Edge-group, so it carries the same reserved labels --
# including keripy's `s` pin, which binds every edge below it exactly as one on a
# nested group does. It may not carry an Edge's `n`, and as the top-level group it
# has no enclosing reduction for a weight `w` to apply to.
EdgeSectionLabels = ("d", "u", "s", "o", "w")
EdgeGroupLabels = ("d", "u", "s", "o", "w")
EdgeNodeLabels = ("d", "u", "n", "s", "o", "w")
UnaryEdgeOps = ("I2I", "NI2I", "DI2I", "E1E", "I1I", "DI1I", "NOT")

# The delegative operators constrain the near issuer against the far issuee; they
# conflict with one another, so the latest of them in `o` wins.
DelegativeEdgeOps = ("I2I", "NI2I", "DI2I")

# The SEDI issuer-identity operators (WebOfTrust/keripy discussion #1515) constrain
# the near issuer against the far *issuer*. They form their own latest-wins
# conflict group, independent of the delegative one and of E1E.
IssuerIdentityEdgeOps = ("I1I", "DI1I")

# Unary operators whose presence suppresses the default rule (I2I for a targeted far
# node, NI2I otherwise). An explicit I1I or DI1I suppresses it too, so neither
# requires either ACDC to have an issuee.
DefaultSuppressingEdgeOps = DelegativeEdgeOps + ("E1E",) + IssuerIdentityEdgeOps

# How a walk treats a far node that an Edge names but the disclosure does not carry.
# A disclosure's nests are fixed bytes, so nothing can deliver that node later and
# its absence is never retryable (no MissingChainError, no escrow).
#   open:   the walk accepts the graph and the missing far node evaluates to a
#           non-retryable unknown, so an OR group with a valid sibling accepts while
#           an AND group or a sole Edge refuses.
#   closed: the walk refuses the graph outright.
# Either way a node a disclosure plan selects must be carried; that is the plan
# check's rule, not the walk's.
WalkPolicyDex = namedtuple("WalkPolicyDex", "open closed")
WalkPolicies = WalkPolicyDex(open="open", closed="closed")
DefaultWalkPolicy = WalkPolicies.open


def validateWalkPolicy(walkPolicy):
    """Return ``walkPolicy`` when it names a WalkPolicies member.

    Raises:
        ValueError: When ``walkPolicy`` is not ``"open"`` or ``"closed"``.
    """
    if walkPolicy not in WalkPolicies:
        raise ValueError(f"walk policy must be one of {list(WalkPolicies)}, "
                         f"not {walkPolicy!r}")
    return walkPolicy


def verifyExpandedSection(section, *, kind, label="e"):
    """Verify every carried SAID in one expanded ACDC section.

    Recompute the section and nested-block commitments with the same section
    compactor authors use (``SerderACDC.sectionCompactor``, which keeps inline
    Edge schema pins opaque) and compare each carried ``d`` value with the
    canonical result. A non-mapping value has no expanded commitments to inspect.

    Parameters:
        section (Mapping | Any): Expanded section mapping, or another section form.
        kind (str): Serialization kind used when recomputing the commitments.
        label (str): Top-level section label, ``e`` by default.

    Returns:
        bool: True when every carried commitment matches, False when recomputation
            fails or a claimed commitment is false.
    """
    if not isinstance(section, Mapping):
        return True

    try:
        compactor = SerderACDC.sectionCompactor(label, deepcopy(section), kind=kind)
        compactor.compact()
        for path, leaf in compactor.leaves.items():
            carried = compactor.getTail(path, mad=section)
            if (not isinstance(carried, Mapping)
                    or (carried.get("d") and carried["d"] != leaf.said)):
                return False
    except Exception:
        return False

    return True


def _validSaid(value):
    """Return True when ``value`` is a qb64 SAID string in canonical form."""
    if not isinstance(value, str):
        return False
    try:
        return Saider(qb64=value).qb64 == value
    except Exception:
        return False


def _nestSerder(nest):
    """Return the ACDC serder of a parsed nest or nest-like mapping."""
    return nest["serder"] if isinstance(nest, Mapping) else nest.serder


class SchemaEvaluator:
    """Map ACDC schema validation results into edge-evaluation verdicts."""

    def __init__(self, db):
        """Initialize schema evaluation with the schema cache database.

        Parameters:
            db: Database used to resolve referenced schema SAIDs.
        """
        self.db = db

    def evaluate(self, acdc, *, schema=None, context="ACDC"):
        """Evaluate one ACDC against its declared or supplied schema.

        Parameters:
            acdc: ACDC serder to validate.
            schema (str | Mapping | None): Optional edge-pinned schema. ``None``
                validates the ACDC against its own declared schema.
            context (str): Description used in the returned verdict reason.

        Returns:
            EdgeVerdict: Valid on success, retryable unknown when a referenced
                schema is missing, or invalid for a proven schema mismatch.
        """
        try:
            scheming.validateSchema(acdc=acdc, db=self.db, schema=schema)
        except MissingSchemaError as ex:
            return chaining.unknown(
                f"{context} schema is not in cache", retryable=True, cause=ex)
        except (FailedSchemaValidationError, ValidationError, ValueError) as ex:
            return chaining.invalid(f"{context} does not satisfy its schema: {ex}")

        return chaining.valid(f"{context} satisfies its schema")

    def edgeKind(self, acdc, path):
        """Return the schema-declared meaning of a string-valued Edge.

        Parameters:
            acdc: Near-node ACDC whose schema defines the Edge Section.
            path (tuple | list): Edge labels from the Edge Section to the member.

        Returns:
            str | None: ``simple`` for a far-node SAID, ``compact`` for an
                Edge-block SAID, or ``None`` when the schema is ambiguous.

        Raises:
            MissingSchemaError: When classification needs an unavailable schema.
        """
        try:
            return scheming.classifyEdge(acdc=acdc, db=self.db, path=path)
        except MissingSchemaError:
            raise
        except (FailedSchemaValidationError, RecursionError, TypeError,
                ValidationError, ValueError):
            return None

    def validateSchemas(self, *, nodes, order):
        """Validate every walked ACDC against its own declared schema.

        Parameters:
            nodes (Mapping): ACDC SAID to parsed nest or nest-like object mapping.
            order (list | tuple): Walk order containing every node to validate.

        Returns:
            EdgeVerdict: Valid when all schemas pass, retryable unknown when a
                declared schema is unavailable, or invalid for malformed input or
                a schema mismatch.
        """
        if not isinstance(nodes, Mapping) or not isinstance(order, (list, tuple)):
            return chaining.invalid("disclosed nodes or graph order are malformed")

        for said in order:
            if not isinstance(said, str) or said not in nodes:
                return chaining.invalid(f"graph order contains unknown node {said}")
            nest = nodes.get(said)
            try:
                nserder = _nestSerder(nest)
            except (AttributeError, KeyError, TypeError):
                return chaining.invalid(f"node {said} has no ACDC body")

            verdict = self.evaluate(nserder, context=f"node {said}")
            if verdict.verdict != chaining.Verdicts.valid:
                return verdict

        return chaining.valid("all disclosed nodes satisfy their own schemas")


class EdgeEvaluator:
    """Evaluate a disclosed ACDC graph using caller-provided evidence.

    Holds no storage of its own. Everything it needs beyond the disclosed bytes
    arrives through the schema evaluator and the two adapters, so the same rules
    serve IPEX, a discloser checking its own selection, or any other caller.
    """

    def __init__(self, schemaEvaluator, verifyNode, isDelegated, reducers=None):
        """Initialize an evaluator over caller-supplied evidence.

        Parameters:
            schemaEvaluator (SchemaEvaluator): Independent schema-policy layer.
            verifyNode (Callable): Adapter called as ``verifyNode(serder=serder,
                nest=nest, records=records)`` and returning the node's
                authentication verdict.
            isDelegated (Callable): Adapter called as ``isDelegated(pre, delpre)``.
                It returns True for a proven anchored delegation at any depth,
                False for a proven mismatch, and None when required KEL or
                anchor evidence is missing.
            reducers (Mapping | None): m-ary Operator reducers by token. Defaults
                to ``acdc.chaining.MAryReducers``.
        """
        self.schemaEvaluator = schemaEvaluator
        self.verifyNode = verifyNode
        self.isDelegated = isDelegated
        self.reducers = chaining.MAryReducers if reducers is None else reducers

    def walk(self, origin, *, nodes, walkPolicy=DefaultWalkPolicy):
        """Validate and walk a disclosed ACDC graph in breadth-first order.

        The walk verifies Edge Section commitments and shapes and follows expanded
        Edges and schema-declared simple Edges. A compact Edge Section (its SAID in
        place of the section) is an opaque terminal and contributes no references.
        Every disclosed node must be reachable from ``origin``.

        Shape rules: ``e`` is absent, an empty field map, a compact SAID, or an
        expanded Edge-group map. A list, or any other falsy non-map value, is
        malformed. The top-level group may carry neither ``n`` nor ``w``.

        Parameters:
            origin (str): SAID of the disclosed graph's root ACDC.
            nodes (Mapping): ACDC SAID to parsed nest or nest-like object mapping.
            walkPolicy (str): ``WalkPolicies.closed`` requires every far node an
                Edge references to be disclosed; ``WalkPolicies.open`` permits
                undisclosed far nodes.

        Returns:
            list[str] | None: Breadth-first node SAIDs, or None when the graph,
                an Edge Section, or a reference is malformed or violates closure.

        Raises:
            ValueError: When ``walkPolicy`` is not a WalkPolicies member.
            MissingSchemaError: When classifying a string Edge member needs a
                near-node schema that is not cached.
        """
        closed = validateWalkPolicy(walkPolicy) == WalkPolicies.closed
        if not isinstance(nodes, Mapping) or not _validSaid(origin):
            return None
        if origin not in nodes:
            return None

        seen = set()
        order = []
        queue = deque([origin])
        while queue:
            said = queue.popleft()
            if said in seen:
                continue

            try:
                nserder = _nestSerder(nodes.get(said))
                if nserder.said != said:
                    return None
                sad = nserder.sad
            except (AttributeError, KeyError, TypeError):
                return None

            seen.add(said)
            order.append(said)
            if "e" not in sad:
                continue
            edges = sad["e"]
            if isinstance(edges, Mapping) and not edges:
                continue  # the specified empty Edge Section

            # A string is a compact Edge Section: valid only as a SAID.
            if isinstance(edges, str):
                if not _validSaid(edges):
                    return None
                continue

            if not isinstance(edges, Mapping):
                return None
            if not verifyExpandedSection(edges, kind=nserder.kind):
                return None

            groups = deque([(edges, (), False)])
            while groups:
                group, path, nested = groups.popleft()
                labels = EdgeGroupLabels if nested else EdgeSectionLabels
                if not nested and ("n" in group or "w" in group):
                    return None
                if "n" in group:
                    if any(label not in EdgeNodeLabels for label in group):
                        return None
                    edgeSaid = group.get("n")
                    if not _validSaid(edgeSaid):
                        return None
                    if edgeSaid not in nodes:
                        if closed:
                            return None
                        continue
                    if edgeSaid not in seen:
                        queue.append(edgeSaid)
                    continue

                for label, node in group.items():
                    if label in labels:
                        continue
                    childPath = path + (label,)
                    if isinstance(node, str):
                        if not _validSaid(node):
                            return None
                        # Only the near schema says whether a SAID names a far node
                        # (simple Edge) or a hidden Edge block (compact Edge).
                        if self.schemaEvaluator.edgeKind(nserder, childPath) == "simple":
                            if node not in nodes:
                                if closed:
                                    return None
                                continue
                            if node not in seen:
                                queue.append(node)
                        continue
                    if not isinstance(node, Mapping):
                        return None
                    groups.append((node, childPath, True))

        if len(seen) != len(nodes):
            return None
        return order

    def evaluate(self, origin, *, nodes, records=None, walkPolicy=DefaultWalkPolicy):
        """Walk and evaluate a disclosed graph rooted at ``origin`` to one verdict.

        Parameters:
            origin (str): SAID of the graph's root ACDC.
            nodes (Mapping): ACDC SAID to parsed nest or nest-like object mapping.
            records (dict | None): Optional caller-owned collection populated by
                the node-authentication adapter.
            walkPolicy (str): Passed to ``walk``. ``WalkPolicies.open`` lets an
                undisclosed far node enter its Edge-group as a non-retryable
                unknown member; ``WalkPolicies.closed`` refuses the graph.

        Returns:
            EdgeVerdict | None: Root verdict, or None when the disclosed graph or
                any Edge shape is malformed.
        """
        if self.walk(origin, nodes=nodes, walkPolicy=walkPolicy) is None:
            return None

        return self.evaluateNode(origin, nodes=nodes, memo={}, records=records)

    def evaluateNode(self, said, *, nodes, memo, records=None):
        """Evaluate one disclosed node and its Edge Section recursively.

        Assumes ``nodes`` already passed ``walk``. A node's authentication and
        own-schema verdicts are conjoined with the reduction of its Edge Section,
        so neither can be outvoted within the node, while the whole conjunction is
        one member of whatever Edge-group reached it. An opaque compact Edge
        Section contributes a non-retryable unknown because its hidden Operators
        cannot be evaluated.

        Memoised by node SAID, so a node named by several Edges is evaluated once.
        A temporary non-retryable unknown placeholder guards against re-entry; a
        digest-linked graph cannot cycle, so the placeholder only turns a surprise
        into an undecided verdict rather than unbounded recursion.

        Parameters:
            said (str): SAID of the node to evaluate.
            nodes (Mapping): Disclosed graph indexed by ACDC SAID.
            memo (dict): Shared node-SAID to verdict memo for this evaluation.
            records (dict | None): Optional authentication records passed through
                to the caller-provided node verifier.

        Returns:
            EdgeVerdict | None: Combined node verdict, or None for malformed Edge
                structure.
        """
        if said in memo:
            return memo[said]

        memo[said] = chaining.unknown(
            f"node {said} is already being evaluated", retryable=False)

        nest = nodes[said]
        nserder = _nestSerder(nest)

        auth = self.verifyNode(serder=nserder, nest=nest, records=records)
        schema = self.schemaEvaluator.evaluate(nserder, context=f"node {said}")

        sad = nserder.sad
        edges = sad.get("e")
        if "e" not in sad or (isinstance(edges, Mapping) and not edges):
            section = chaining.valid(f"node {said} carries no edges")
        elif isinstance(edges, str):
            if not _validSaid(edges):
                return None
            section = chaining.unknown(
                f"node {said} carries compact Edge Section SAID {edges}, "
                f"whose hidden section this verifier cannot evaluate",
                retryable=False)
        elif isinstance(edges, Mapping):
            section = self._evaluateGroupEdge(
                edges, nodes=nodes, nserder=nserder, nested=False,
                memo=memo, records=records, inheritedPins=(), path=())
            if section is None:
                return None
        else:
            return None

        memo[said] = chaining.reduceAnd([auth, schema, section])
        return memo[said]

    def _delegation(self, operator, edgeSaid, nearIssuer, ancestor, role):
        """Map one delegation query to a relation verdict.

        Parameters:
            operator (str): DI2I or DI1I, for the verdict reason.
            edgeSaid (str): Far-node SAID, for the verdict reason.
            nearIssuer (str): Near ACDC issuer AID.
            ancestor (str): Far AID the near issuer must descend from.
            role (str): ``issuee`` or ``issuer``, naming the far AID's role.

        Returns:
            EdgeVerdict: valid when delegation is proven, invalid when it is
                disproven, retryable unknown (MissingChainError cause) when KEL or
                anchor evidence is missing.
        """
        delegated = self.isDelegated(nearIssuer, ancestor)
        if delegated is True:
            return chaining.valid(
                f"{operator} edge to node {edgeSaid} has near issuer {nearIssuer} "
                f"delegated from far {role} {ancestor}")
        if delegated is False:
            return chaining.invalid(
                f"{operator} edge to node {edgeSaid} fails because near issuer "
                f"{nearIssuer} is not delegated from far {role} {ancestor}")
        reason = (f"{operator} edge to node {edgeSaid} is missing KEL or "
                  f"delegation-anchor evidence between near issuer {nearIssuer} "
                  f"and far {role} {ancestor}")
        return chaining.unknown(reason, retryable=True,
                                cause=MissingChainError(reason))

    def _evaluateLeafEdge(self, group, *, nodes, nserder, memo, records=None,
                          inheritedPins=()):
        """Evaluate one unary Edge and the far node it references.

        Resolve unary Operator defaults and conflict groups, evaluate every
        resulting relation, enforce all inherited and local schema pins, and
        conjoin that with the recursively evaluated far-node verdict. Relations
        are Kleene-ANDed without short-circuit: an unrecognized Operator or NOT is
        a non-retryable unknown member beside the relations that are evaluable,
        so a decided refusal among those still decides the Edge.

        Parameters:
            group (Mapping): Expanded Edge block containing its required ``n``.
            nodes (Mapping): Disclosed graph indexed by ACDC SAID.
            nserder: Serder for the near-node ACDC that carries this Edge.
            memo (dict): Shared node-verdict memo for recursive evaluation.
            records (dict | None): Optional authentication-record collection.
            inheritedPins (tuple): Schema constraints inherited from enclosing
                Edge-groups. Conjunction, not override: a leaf cannot release
                itself from a pin its group placed.

        Returns:
            EdgeVerdict | None: Edge relation, schema, and far-node verdict, or
                None when the Edge block or a schema pin is malformed.
        """
        if any(label not in EdgeNodeLabels for label in group):
            return None

        edgeSaid = group.get("n")
        if not _validSaid(edgeSaid):
            return None

        # One unary Operator or a list of them; anything else is malformed.
        operator = group.get("o")
        if operator is None:
            operators = []
        elif isinstance(operator, str):
            operators = [operator]
        elif (isinstance(operator, (list, tuple))
              and all(isinstance(item, str) for item in operator)):
            operators = list(operator)
        else:
            return None

        # Pins are resolved before any verdict, because a pin whose shape this
        # verifier cannot read is malformed input whatever the Operator says.
        pins = tuple(inheritedPins)
        if "s" in group:
            pins = pins + (group["s"],)

        resolvedPins = []
        for edgeSchema in pins:
            if isinstance(edgeSchema, str):
                if not _validSaid(edgeSchema):
                    return None
                resolvedPins.append((edgeSchema, edgeSchema))
            elif isinstance(edgeSchema, Mapping):
                declared = edgeSchema.get("$id")
                if not isinstance(declared, str):
                    return None
                try:
                    edgeSchemer = Schemer(sed=deepcopy(edgeSchema))
                except (RecursionError, TypeError, ValidationError, ValueError):
                    return None
                if edgeSchemer.said != declared:
                    return None
                resolvedPins.append((edgeSchemer.said, edgeSchema))
            else:
                return None

        relations = []
        unrecognized = [item for item in operators if item not in UnaryEdgeOps]
        if unrecognized:
            relations.append(chaining.unknown(
                f"unrecognized unary Operator(s) {unrecognized} on edge to node "
                f"{edgeSaid}; recognized are {list(UnaryEdgeOps)}",
                retryable=False))

        if "NOT" in operators:
            relations.append(chaining.unknown(
                f"unimplemented unary Operator NOT on edge to node {edgeSaid}",
                retryable=False))

        # The disclosure's bytes are fixed, so nothing outside it can supply this
        # far node later: undecided, and not retryable.
        if edgeSaid not in nodes:
            relations.append(chaining.unknown(
                f"edge is missing undisclosed far node {edgeSaid}", retryable=False))
            return chaining.reduceAnd(relations)

        fserder = _nestSerder(nodes[edgeSaid])
        farSchema = fserder.schema if pins else None
        if isinstance(farSchema, Mapping):
            farSchemaId = farSchema.get("$id")
        elif isinstance(farSchema, str):
            farSchemaId = farSchema
        else:
            farSchemaId = None
        if pins and not isinstance(farSchemaId, str):
            return None

        # The default rule: a bare edge is not an unconstrained edge.
        if not any(item in DefaultSuppressingEdgeOps for item in operators):
            operators.append("I2I" if fserder.iseaid is not None else "NI2I")

        # Latest-wins applies only among conflicting Operators, so each conflict
        # group keeps its own last member and the groups compose by AND.
        delegativeOperator = None
        issuerIdentityOperator = None
        for item in operators:
            if item in DelegativeEdgeOps:
                delegativeOperator = item
            if item in IssuerIdentityEdgeOps:
                issuerIdentityOperator = item

        if "E1E" in operators:
            if (nserder.iseaid and fserder.iseaid
                    and nserder.iseaid == fserder.iseaid):
                relations.append(chaining.valid(
                    f"E1E edge to node {edgeSaid} has equal issuees"))
            else:
                relations.append(chaining.invalid(
                    f"E1E edge to node {edgeSaid} requires equal issuees; near "
                    f"issuee {nserder.iseaid} != far issuee {fserder.iseaid}"))

        if delegativeOperator == "I2I":
            if not fserder.iseaid:
                relations.append(chaining.invalid(
                    f"I2I edge to node {edgeSaid} requires a targeted far node, "
                    f"which has no issuee"))
            elif nserder.israid != fserder.iseaid:
                relations.append(chaining.invalid(
                    f"I2I edge to node {edgeSaid} requires the near issuer to be "
                    f"the far issuee; issuer {nserder.israid} != far issuee "
                    f"{fserder.iseaid}"))
            else:
                relations.append(chaining.valid(
                    f"I2I edge to node {edgeSaid} links issuer to far issuee"))

        # DI2I widens I2I: the near issuer may be the far issuee or an anchored
        # delegated descendant of it, at any depth.
        if delegativeOperator == "DI2I":
            nearIssuer, farIssuee = nserder.israid, fserder.iseaid
            if not nearIssuer or not farIssuee:
                relations.append(chaining.invalid(
                    f"DI2I edge to node {edgeSaid} requires a near issuer and a "
                    f"targeted far node; near issuer {nearIssuer}, far issuee "
                    f"{farIssuee}"))
            elif nearIssuer == farIssuee:
                relations.append(chaining.valid(
                    f"DI2I edge to node {edgeSaid} links issuer to far issuee"))
            else:
                relations.append(self._delegation(
                    "DI2I", edgeSaid, nearIssuer, farIssuee, "issuee"))

        # I1I: equal issuers. DI1I widens it to an anchored delegated descendant
        # of the far issuer, at any depth.
        if issuerIdentityOperator is not None:
            nearIssuer, farIssuer = nserder.israid, fserder.israid
            if not nearIssuer or not farIssuer:
                relations.append(chaining.invalid(
                    f"{issuerIdentityOperator} edge to node {edgeSaid} requires "
                    f"both nodes to have issuers"))
            elif nearIssuer == farIssuer:
                relations.append(chaining.valid(
                    f"{issuerIdentityOperator} edge to node {edgeSaid} has equal "
                    f"issuers"))
            elif issuerIdentityOperator == "I1I":
                relations.append(chaining.invalid(
                    f"I1I edge to node {edgeSaid} requires equal issuers; near "
                    f"issuer {nearIssuer} != far issuer {farIssuer}"))
            else:
                relations.append(self._delegation(
                    "DI1I", edgeSaid, nearIssuer, farIssuer, "issuer"))

        relation = (chaining.reduceAnd(relations) if relations else
                    chaining.valid(f"edge to node {edgeSaid} satisfies its Operator"))

        # Every pin is evaluated unless the relation is already refused; a pin
        # whose SAID equals the far node's own schema is still validated, since
        # skipping it would let the far node satisfy the pin by asserting its type.
        pinVerdicts = []
        if relation.verdict != chaining.Verdicts.invalid:
            for edgeSchemaId, edgeSchema in resolvedPins:
                if (isinstance(edgeSchema, str) and edgeSchema == farSchemaId
                        and isinstance(farSchema, Mapping)):
                    edgeSchema = farSchema
                pinVerdicts.append(self.schemaEvaluator.evaluate(
                    fserder, schema=edgeSchema,
                    context=f"far node {edgeSaid} against edge schema {edgeSchemaId}"))

        own = chaining.reduceAnd([relation] + pinVerdicts)

        # The far node is evaluated whatever this leaf came to: its verdict cannot
        # rescue a refused relation, but its shape is not a truth value.
        farVerdict = self.evaluateNode(edgeSaid, nodes=nodes, memo=memo,
                                       records=records)
        if farVerdict is None:
            return None
        return chaining.reduceAnd([own, farVerdict])

    def _evaluateGroupEdge(self, group, *, nodes, nserder, nested, memo,
                           records=None, inheritedPins=(), path=()):
        """Evaluate an Edge-group and reduce its child verdicts.

        Recurse through expanded child groups and Edges. The near-node schema
        determines whether a string member is a simple far-node reference or an
        opaque compact Edge-block commitment; when it does not say, the member is
        a non-retryable unknown. Schema pins accumulate through nested groups.

        Parameters:
            group (Mapping): Top-level Edge Section or nested Edge-group.
            nodes (Mapping): Disclosed graph indexed by ACDC SAID.
            nserder: Serder for the near-node ACDC that owns this group.
            nested (bool): False for the top-level Edge Section, True otherwise.
            memo (dict): Shared node-verdict memo for recursive evaluation.
            records (dict | None): Optional authentication-record collection.
            inheritedPins (tuple): Schema constraints inherited from parent groups.
            path (tuple): Edge labels from the Edge Section to this group.

        Returns:
            EdgeVerdict | None: Group verdict reduced by its m-ary Operator, or
                None when the group or one of its children is malformed.
        """
        if not nested and ("n" in group or "w" in group):
            return None
        labels = EdgeGroupLabels if nested else EdgeSectionLabels

        # An Edge-group's `o` is a single m-ary Operator; the list form is defined
        # only for an Edge's unary `o`.
        groupOperator = group.get("o", "AND")
        if not isinstance(groupOperator, str):
            return None

        nextPins = tuple(inheritedPins)
        if "s" in group:
            nextPins = nextPins + (group["s"],)

        results = []
        for label, node in group.items():
            if label in labels:
                continue
            childPath = path + (label,)
            if isinstance(node, str):
                if not _validSaid(node):
                    return None
                edgeKind = self.schemaEvaluator.edgeKind(nserder, childPath)
                if edgeKind == "simple":
                    verdict = self._evaluateLeafEdge(
                        {"n": node}, nodes=nodes, nserder=nserder, memo=memo,
                        records=records, inheritedPins=nextPins)
                    if verdict is None:
                        return None
                    results.append(verdict)
                elif edgeKind == "compact":
                    results.append(chaining.unknown(
                        f"compact edge {label} carries Edge-block SAID {node}, "
                        f"whose hidden block this verifier cannot evaluate",
                        retryable=False))
                else:
                    results.append(chaining.unknown(
                        f"schema does not distinguish whether edge {label} "
                        f"carries a far-node or Edge-block SAID",
                        retryable=False))
                continue
            if not isinstance(node, Mapping):
                return None

            if "n" in node:
                verdict = self._evaluateLeafEdge(
                    node, nodes=nodes, nserder=nserder, memo=memo,
                    records=records, inheritedPins=nextPins)
            else:
                verdict = self._evaluateGroupEdge(
                    node, nodes=nodes, nserder=nserder, nested=True, memo=memo,
                    records=records, inheritedPins=nextPins, path=childPath)
            if verdict is None:
                return None
            results.append(verdict)

        # An Edge-group with no members reduces to nothing, so it is malformed.
        if not results:
            return None

        # Answered after the members are evaluated, so a malformed member cannot
        # ride in behind an Operator this verifier does not reduce.
        if groupOperator not in self.reducers:
            return chaining.unknown(
                f"Edge-group Operator {groupOperator!r} is not reduced by this "
                f"verifier; reducible are {sorted(self.reducers)}", retryable=False)

        return chaining.reduce(groupOperator, results, reducers=self.reducers)
