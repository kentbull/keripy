"""The existing ACDC v2 semantic verdict over authenticated disclosed nodes.

The caller authenticates issuer proofs, own schemas and graph closure before
invoking this evaluator. It owns no IPEX acceptance or evidence-store lifecycle.
Boolean, bound-history and arithmetic policy retain their existing behavior.
"""
from collections.abc import Mapping
from math import isfinite

from referencing.jsonschema import DRAFT202012

from ..core import BoundState, Diger, Number, Saider
from ..kering import (FailedSchemaValidationError, Ilks, KeriError, MissingAnchorError,
                      MissingChainError, MissingSchemaError, MissingSenderKeyStateError,
                      ValidationError)
from . import scheming
from .proving import PresentedEvidence


EdgeSectionLabels = ("d", "u", "o", "w")
EdgeGroupLabels = ("d", "u", "s", "o", "w")
EdgeNodeLabels = ("d", "u", "n", "s", "o", "w")
UnaryEdgeOps = ("I2I", "NI2I", "DI2I", "E1E", "NOT")
DelegativeEdgeOps = ("I2I", "NI2I", "DI2I")
EdgeGroupOps = ("AND", "OR", "NAND", "NOR", "AVG", "WAVG")


def _edgeSchema(near, evidence, sections):
    """Reuse authenticated local schema resources; never fetch or expand nodes."""
    source = near.schema
    schemer = (scheming._verifySchemer(source, kind=near.kind)
               if isinstance(source, Mapping) else
               scheming._cachedSchema(evidence.hby.db, source, sections=sections))
    if schemer is None:
        raise MissingSchemaError(source)
    registry = scheming._registry(schemer, evidence.hby.db, sections=sections)
    return schemer.sed, registry.resolver(base_uri=schemer.said)


def _staticEdgeSchema(schema, resolver, depth=64, *, expanded=False):
    """Resolve static types/refs in their resource scope, with bounded ancestors.

    Only an already expanded ancestor may select the unique object branch of a
    string/object oneOf. A digest-valued leaf never uses that selection.
    """
    if depth <= 0 or not isinstance(schema, Mapping):
        return None
    resolver = resolver.in_subresource(DRAFT202012.create_resource(schema))
    if '$ref' in schema:
        annotations = {'$ref', '$id', '$schema', 'title', 'description', '$comment',
                       'deprecated', 'readOnly', 'writeOnly', 'examples', 'default'}
        if set(schema) - annotations:
            return None
        try:
            resolved = resolver.lookup(schema['$ref'])
        except Exception:
            return None
        return _staticEdgeSchema(resolved.contents, resolved.resolver, depth - 1,
                                 expanded=expanded)
    if any(key in schema for key in ('anyOf', 'allOf', 'not', 'if',
            'then', 'else', 'dependentSchemas', 'patternProperties')):
        return None
    if 'oneOf' in schema:
        annotations = {'oneOf', '$id', '$schema', 'title', 'description', '$comment',
                       'deprecated', 'readOnly', 'writeOnly', 'examples', 'default'}
        branches = schema['oneOf']
        if (not expanded or set(schema) - annotations
                or not isinstance(branches, list) or len(branches) != 2):
            return None
        selected = [_staticEdgeSchema(branch, resolver, depth - 1) for branch in branches]
        if any(branch is None for branch in selected):
            return None
        types = [branch[0].get('type') for branch in selected]
        if types not in (['object', 'string'], ['string', 'object']):
            return None
        return next(branch for branch in selected if branch[0]['type'] == 'object')
    return schema, resolver


def edgeTarget(near, path, value, *, evidence, sections=None):
    """Return the exact far SAID for an expanded or schema-proven simple edge.

    Only declared nonreserved edge/group children with a statically string-only
    schema are simple edges. Open/map-admitting/ambiguous schemas cannot turn
    opaque strings into hops. Expanded leaf reserved fields precede application
    properties in normative order. No received bytes are rewritten.

    Returns None for groups/unsupported strings; malformed expanded leaves raise
    ValueError. Missing authenticated schema resources remain dependencies.
    """
    if (len(path) < 2 or path[0] != 'e'
            or any(part in EdgeNodeLabels for part in path[1:])):
        return None
    ancestor = near.sad
    for part in path:
        if isinstance(ancestor, Mapping):
            if 'n' in ancestor:
                return None  # application properties never extend a leaf edge
            ancestor = ancestor.get(part)
        elif isinstance(ancestor, list) and part.isdigit() and int(part) < len(ancestor):
            ancestor = ancestor[int(part)]
        else:
            break  # standalone evaluator operands need no stored instance path
    if isinstance(value, Mapping):
        if 'n' not in value:
            return None
        reserved = [label for label in value if label in EdgeNodeLabels]
        expected = [label for label in EdgeNodeLabels if label in value]
        if reserved != expected or list(value)[:len(reserved)] != reserved:
            raise ValueError('edge reserved fields must precede properties in order')
        target = value['n']
    elif isinstance(value, str):
        schema, resolver = _edgeSchema(near, evidence, sections)
        instance = near.sad
        for part in path:
            selected = _staticEdgeSchema(schema, resolver, expanded=True)
            if selected is None or not isinstance(instance, Mapping):
                return None
            schema, resolver = selected
            if schema.get('type') != 'object' or 'n' in instance:
                return None  # leaf application properties are never graph edges
            properties = schema.get('properties', {})
            if part not in properties or part not in instance:
                return None
            schema, instance = properties[part], instance[part]
        selected = _staticEdgeSchema(schema, resolver)
        if selected is None or selected[0].get('type') != 'string':
            return None
        target = value
    else:
        return None
    try:
        if not isinstance(target, str) or Saider(qb64=target).qb64 != target:
            raise ValueError('edge target must be a SAID')
    except (KeriError, ValueError, TypeError) as ex:
        raise ValueError('edge target must be a SAID') from ex
    return target


def fixedEdgeOrder(near, *, evidence, sections=None):
    """Prove a closed required edge/group shape before positional selection.

    Present optional members do not establish fixed issuance shape. Unsupported
    schemas conservatively fail this proof; explicit prefixes remain available.
    This inspects the schema hierarchy, not a second credential graph traversal.
    """
    schema, resolver = _edgeSchema(near, evidence, sections)

    def fixed(schema, resolver, *, root=False, depth=64):
        if depth <= 0 or (selected := _staticEdgeSchema(schema, resolver)) is None:
            return False
        schema, resolver = selected
        if schema.get('type') == 'string':
            return not root
        if schema.get('type') != 'object':
            return False
        props = schema.get('properties', {})
        required = schema.get('required', [])
        if 'n' in required and 'n' in props:
            return not root
        if schema.get('additionalProperties') is not False:
            return False
        labels = EdgeSectionLabels if root else EdgeGroupLabels
        children = [key for key in props if key not in labels]
        return (all(key in required for key in children)
                and all(fixed(props[key], resolver, depth=depth - 1)
                        for key in children))

    selected = _staticEdgeSchema(schema, resolver)
    if selected is None or selected[0].get('type') != 'object':
        return False
    schema, resolver = selected
    props = schema.get('properties', {})
    if 'e' not in props:
        return schema.get('additionalProperties') is False
    return ('e' in schema.get('required', [])
            and fixed(props['e'], resolver, root=True))


class EdgeEvaluator:
    """Evaluate one disclosed graph using concrete borrowed evidence and policy.

    ``evidence`` is PresentedEvidence for the caller's accepted KEL/TEL stores.
    ``graphPolicy`` supplies the existing optional validity/value/accept methods;
    ``sections`` is the caller's independent schema store. No policy is inferred.
    Truth caches are local to each verification call.
    """
    def __init__(self, evidence: PresentedEvidence, *, graphPolicy=None, sections=None):
        self.evidence = evidence
        self.graphPolicy = graphPolicy
        self.sections = sections

    def _delegatedIssuer(self, issuer, issuee):
        """Resolve DI2I only through accepted, fully witnessed inception events.

        The KEL processor already verifies the delegator's authorization before
        accepting a foreign dip. A mutable Kever attribute or an unaccepted dip
        body is not delegation evidence. Follow the accepted chain transitively.

        Args:
            issuer (str): Near-node issuer whose accepted delegation chain to follow.
            issuee (str): Far-node Issuee expected at any point in that chain.

        Returns:
            bool: Whether the Issuee is the issuer or a verified ancestor delegator.

        Raises:
            MissingChainError: An inception, witness quorum, or delegator seal is absent."""
        seen = set()
        while issuer and issuer not in seen:
            if issuer == issuee:
                return True
            seen.add(issuer)
            dig = self.evidence.hby.db.kels.getLast(keys=issuer, on=0)
            if dig is None:
                raise MissingChainError(f"DI2I requires accepted KEL for {issuer}")
            inception = self.evidence.hby.db.evts.get(keys=(issuer, dig))
            if inception is None or not self.evidence.hby.db.fullyWitnessed(inception):
                raise MissingChainError(f"DI2I requires witnessed inception for {issuer}")
            delegator = inception.sad.get("di")
            if delegator:
                # Local controllers/witnesses may store their own dip before
                # delegation completes. Require the actual delegator seal too.
                seal = dict(i=inception.pre, s=inception.snh, d=inception.said)
                if self.evidence.hby.db.fetchLastSealingEventByEventSeal(delegator, seal) is None:
                    raise MissingChainError(f"DI2I requires delegation authorization for {issuer}")
            issuer = delegator
        return False


    def _evaluateGraphNode(self, said, *, nodes, memo, active, averages, historical=False):
        """Evaluate authenticated node validity once, retaining unknown as None.

        Issuer authentication and own-schema validation precede this evaluator
        in Grant verification. Policy validity is optional; it may impose
        standing, expiry or trust requirements and must return bool or None.
        Missing/malformed evidence is never logical False and cannot be negated.

        Args:
            said (str): Authenticated disclosed node SAID to evaluate.
            nodes (dict): Exact parsed node views indexed by SAID.
            memo (dict): Shared completed truth values, updated in place.
            active (set): Current recursion path, restored on every exit.
            averages (dict): Shared computed numeric group results.

        Returns:
            bool | None: Known node truth, or unknown for cycles, unsupported structure,
            or a policy result other than a concrete bool. Policy exceptions propagate;
            callers must supply trusted application configuration."""
        if said in memo:
            return memo[said]
        if said in active or said not in nodes:
            return None
        nest = nodes[said]
        serder = nest["serder"] if isinstance(nest, dict) else nest.serder
        if serder.said != said:
            return None
        active.add(said)
        try:
            own = True
            validity = getattr(self.graphPolicy, "validity", None)
            if validity is not None:
                own = validity(serder)
                if type(own) is not bool:
                    return None
            edges = serder.sad.get("e")
            results = []
            if edges:
                blocks = [edges] if isinstance(edges, Mapping) else edges
                if not isinstance(blocks, list) or not all(isinstance(e, Mapping) for e in blocks):
                    return None
                for index, edge in enumerate(blocks):
                    if "n" in edge:
                        return None  # the edge section is always a group
                    result = self._evaluateGroupEdge(edge, nodes=nodes, nserder=serder,
                        nested=False, path=("e",) if isinstance(edges, Mapping) else ("e", str(index)),
                        inheritedSchema=None, memo=memo,
                        active=active, averages=averages, historical=historical)
                    if result is None:
                        return None
                    results.append(result)
            memo[said] = own and all(results)
            return memo[said]
        finally:
            active.remove(said)


    @staticmethod
    def _edgeIssuee(serder):
        """Distinguish known untargeted from an undisclosed issuee section.

        Args:
            serder (SerderACDC): Exact disclosed far-node credential.

        Returns:
            tuple[bool, str | None]: Whether the selected Issuee is known, and its
            string value when present. A visible block without i is known untargeted;
            a compact block or present non-string i is unresolved."""
        if "a" in serder.sad:
            block = serder.sad["a"]
        else:
            aggregate = serder.sad.get("A")
            if not isinstance(aggregate, list) or len(aggregate) < 2:
                return False, None
            block = aggregate[1]
        if not isinstance(block, Mapping):
            return False, None
        if "i" not in block:
            return True, None
        issuee = block["i"]
        return (True, issuee) if isinstance(issuee, str) else (False, None)


    def _boundEdgeValidity(self, near, far, *, nodes, historical=False):
        """Evaluate supplied bound authority using authenticated local histories.

        ACDC's current-event assertion supplies the temporal premise; this does
        not establish an independent observation/publication time. Every far
        update needs an opening, so omitted revocations cannot become absence.
        The earliest near issuance anchor within the verified selected TEL or
        known accepted issuer KEL supplies its ordinal. This does not establish
        globally first publication or rule out other undisclosed evidence.

        Args:
            near (SerderACDC): Authenticated credential making the authority assertion.
            far (SerderACDC): Authenticated authority credential with optional bounds.
            nodes (dict): Exact disclosed node views and node-local openings.

        Returns:
            bool | None: True for ordinary unbounded relations, otherwise the known
            bound-history predicate; None for incomplete, incomparable, or invalid proof.

        Raises:
            MissingChainError: A required accepted KEL/TEL dependency is unavailable."""
        from . import regeventing
        farNest = nodes[far.said]
        proofs = self.evidence.blindProofs(farNest)
        if not any(proof.clan == BoundState for proof in proofs):
            return True  # ordinary relationships make no bound-time assertion
        regk = self.evidence.graphRegistry(far, farNest)
        if not regk or (evidence := self.evidence.registryEvidence(
                regk, proofs=proofs if historical else None, target=far.said, acdc=far)) is None:
            return None
        try:
            record = regeventing.vet(*evidence, db=self.evidence.hby.db)
            if record.issuer != far.israid:
                return None
            transitions = []
            for event in sorted(evidence[1], key=lambda e: Number(numh=e.sad['n']).num):
                if event.ilk != Ilks.bup:
                    return None  # public updates have no bound temporal coordinate
                matches = [proof for proof in proofs if proof.said == event.sad['b']]
                if len(matches) != 1:
                    return None  # every update could conceal a revocation
                proof = matches[0]
                target, state = regeventing.vetBlind(proof, blid=event.sad['b'])
                bound = regeventing.vetBound(proof, acdc=far, db=self.evidence.hby.db)
                if not target and not state:
                    continue
                if target != far.said or bound is None:
                    return None
                transitions.append((state, bound.sn))

            # DI2I may establish a valid relationship across different KELs,
            # but it does not make their event ordinals comparable.
            if near.israid != far.iseaid:
                return None
            nearNest = nodes[near.said]
            nearRegk = self.evidence.graphRegistry(near, nearNest)
            anchors = []
            if nearRegk:
                nearProofs = self.evidence.blindProofs(nearNest)
                if (nearEvidence := self.evidence.registryEvidence(
                        nearRegk, proofs=nearProofs if historical else None,
                        target=near.said, acdc=near)) is None:
                    return None
                nearRecord = regeventing.vet(*nearEvidence, db=self.evidence.hby.db)
                if nearRecord.issuer != near.israid:
                    return None
                for event in sorted(nearEvidence[1], key=lambda e: Number(numh=e.sad['n']).num):
                    regeventing.requireSupportedEvent(event)
                    matches = [proof for proof in nearProofs if proof.said == event.sad['b']]
                    if len(matches) != 1:
                        return None  # cannot locate first issuance through a hidden prefix
                    target, state = regeventing.vetBlind(matches[0], blid=event.sad['b'])
                    regeventing.vetBound(matches[0], acdc=near, db=self.evidence.hby.db)
                    if target == near.said and state == 'issued':
                        anchors.append(nearRecord.anchors[Number(numh=event.sad['n']).num][0])
            else:
                parsed = nearNest if isinstance(nearNest, dict) else nearNest.__dict__
                supplied = bool(parsed.get('sscs')) or any(prefixer.qb64 == near.israid
                    for prefixer, _, _ in parsed.get('ssts', []))
                if supplied:
                    # A presenter cannot hide an earlier seal already in this
                    # verified KEL merely by attaching a later source couple.
                    kever = self.evidence.hby.kevers[near.israid] if near.israid in self.evidence.hby.kevers else None
                    if kever is None:
                        return None
                    for sn in range(kever.sn + 1):
                        dig = self.evidence.hby.db.kels.getLast(keys=near.israid, on=sn)
                        if dig is not None and self.evidence.verifySourceAnchor(near, near.israid,
                                Number(num=sn), Diger(qb64=dig)):
                            anchors.append(sn)
            if not anchors:
                return None  # a current signature supplies no historical ordinal
            return regeventing.boundStateAt(transitions, issuee=far.iseaid,
                issuer=near.israid, sn=min(anchors)).valid
        except (MissingAnchorError, MissingSenderKeyStateError) as ex:
            raise MissingChainError('bound authority requires referenced KEL evidence') from ex
        except MissingChainError:
            raise
        except (ValidationError, ValueError, TypeError):
            return None


    def _evaluateLeafEdge(self, group, *, nodes, nserder, inheritedSchema=None,
                          memo=None, active=None, averages=None, historical=False):
        """Apply relation, all schema constraints, and optionally NOT of far truth.

        ACDC f0bd097d lines 1186-1211: latest conflicting relation wins;
        missing/empty operators default to I2I for targeted nodes, NI2I otherwise.
        NOT affects far-node validity only, never the edge's relation or schema.

        Args:
            group (Mapping): Disclosed edge naming its far node and constraints.
            nodes (dict): Authenticated disclosed nodes indexed by SAID.
            nserder (SerderACDC): Near credential establishing this edge.
            inheritedSchema: Additional ancestor schema pins, if any.
            memo (dict | None): Already evaluated node truth values.
            active (set | None): Nodes currently being evaluated, to reject cycles.
            averages (dict | None): Computed child group numeric results.

        Returns:
            bool | None: Edge validity, or None when semantics are unresolved.

        Raises:
            MissingChainError: Required far node or delegation evidence is absent.
            MissingSchemaError: A pinned schema is unavailable in KEL/section stores.
        """
        memo = {} if memo is None else memo
        active = set() if active is None else active
        averages = {} if averages is None else averages
        said = group.get("n")
        if not isinstance(said, str) or said not in nodes:
            raise MissingChainError(f"edge requires disclosed far node {said}")
        nest = nodes[said]
        far = nest["serder"] if isinstance(nest, dict) else nest.serder
        if far.said != said:
            return None
        op = group.get("o")
        if op is None or op == "":
            ops = []
        elif isinstance(op, str):
            ops = [op]
        elif isinstance(op, list):
            ops = op
        else:
            return None
        if any(not isinstance(item, str) or item not in UnaryEdgeOps for item in ops):
            return None
        known, issuee = self._edgeIssuee(far)
        identity = "E1E" in ops
        relation = next((item for item in reversed(ops) if item in DelegativeEdgeOps), None)
        # E1E constrains subject identity without imposing an issuer relation.
        # When it appears alone, use the nondelegative relation while preserving
        # the independent issuee-equality check below.
        if relation is None and identity:
            relation = "NI2I"
        if relation != "NI2I" and not known:
            return None  # hidden issuee is not evidence of an untargeted node
        relation = relation or ("I2I" if issuee else "NI2I")
        matched = True
        if identity:
            nearKnown, nearIssuee = self._edgeIssuee(nserder)
            if not known or not nearKnown:
                return None
            matched = bool(issuee and nearIssuee) and nearIssuee == issuee
        if relation == "I2I":
            matched = matched and bool(issuee) and nserder.israid == issuee
        elif relation == "DI2I":
            matched = (matched and bool(issuee)
                       and self._delegatedIssuer(nserder.israid, issuee))

        # Existing group-level schema pins remain additional constraints; a
        # child's own pin cannot release a constraint inherited from its group.
        pins = () if inheritedSchema is None else inheritedSchema
        if not isinstance(pins, tuple):
            pins = (pins,)
        if "s" in group:
            pins += (group["s"],)
        for schema in pins:
            schemaKind = nserder.kind
            # A malformed/tampered constraint is not an ordinary false claim.
            try:
                if isinstance(schema, str):
                    if Saider(qb64=schema).qb64 != schema:
                        return None
                    if isinstance(far.schema, Mapping) and far.schema.get("$id") == schema:
                        schema = far.schema
                        schemaKind = far.kind
                elif not isinstance(schema, Mapping):
                    return None
                if isinstance(schema, Mapping):
                    scheming._checkProfile(scheming._verifySchemer(schema, kind=schemaKind))
            except (KeriError, ValueError, TypeError):
                return None
            try:
                scheming.validateSchema(acdc=far, db=self.evidence.hby.db, schema=schema, schemaKind=schemaKind,
                                        sections=self.sections)
            except MissingSchemaError:
                raise
            except (FailedSchemaValidationError, ValidationError, ValueError):
                matched = False
        truth = self._evaluateGraphNode(said, nodes=nodes, memo=memo,
                                        active=active, averages=averages, historical=historical)
        if truth is None:
            return None
        if relation != 'NI2I' and matched:
            temporal = self._boundEdgeValidity(nserder, far, nodes=nodes, historical=historical)
            if temporal is None:
                return None
            truth = truth and temporal
        if "NOT" in ops:
            truth = not truth
        return matched and truth


    @staticmethod
    def _finiteGraphNumber(value):
        """Accept JSON numeric values without bools, infinities or overflow.

        Args:
            value: Candidate policy-selected numeric property or arithmetic result.

        Returns:
            bool: Whether value is an int/float safely representable as a finite float.
            Arithmetic conversion failures are treated as invalid input."""
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        try:
            return isfinite(value)
        except OverflowError:
            return False


    def _evaluateGroupEdge(self, group, *, nodes, nserder, nested,
                           inheritedSchema=None, memo=None, active=None, averages=None,
                           historical=False, path=("e",)):
        """Reduce all members; uncertainty cannot be laundered by OR/NAND/NOR.

        AVG/WAVG require explicit graphPolicy.value(near, edge, far) and
        graphPolicy.accept(near, group, average). The engine computes arithmetic;
        policy selects the numeric property and interprets the resulting mean.
        Nested AVG/WAVG results supply their computed mean to their parent.

        Args:
            group (Mapping): Disclosed operator group or leaf edge.
            nodes (dict): Exact authenticated nodes indexed by SAID.
            nserder (SerderACDC): Near node establishing the edge.
            nested (bool): Whether group is below the section root.
            path (tuple): Node-relative edge/group location for schema resolution.
            inheritedSchema: Additional ancestor constraints, preserved at every child.
            memo (dict | None): Shared node truth cache for this evaluation only.
            active (set | None): Shared recursion path used to detect cycles.
            averages (dict | None): Mutable group-id-to-mean results for nested averages.

        Returns:
            bool | None: Reduced truth, or unknown for any unresolved/malformed operand.

        Raises:
            MissingChainError: Required disclosed/authenticated far-node evidence is absent.
            MissingSchemaError: A pinned schema is unavailable. Trusted policy exceptions
            propagate instead of being mistaken for authenticated credential truth."""
        memo = {} if memo is None else memo
        active = set() if active is None else active
        averages = {} if averages is None else averages
        if "n" in group or (not nested and "w" in group):
            return None
        labels = EdgeGroupLabels if nested else EdgeSectionLabels
        op = group.get("o", "AND")
        if not isinstance(op, str) or op not in EdgeGroupOps:
            return None
        pins = () if inheritedSchema is None else inheritedSchema
        if not isinstance(pins, tuple):
            pins = (pins,)
        if nested and "s" in group:
            pins += (group["s"],)
        members, results = [], []
        for label, member in group.items():
            if label in labels:
                continue
            try:
                target = edgeTarget(nserder, (*path, label), member,
                                    evidence=self.evidence, sections=self.sections)
            except MissingSchemaError:
                raise
            except (ValueError, TypeError, KeriError):
                return None
            if target is not None:
                # A transient interpretation, never a rewrite of retained bytes.
                member = member if isinstance(member, Mapping) else dict(n=target)
                result = self._evaluateLeafEdge(member, nodes=nodes, nserder=nserder,
                    inheritedSchema=pins, memo=memo, active=active, averages=averages,
                    historical=historical)
            elif isinstance(member, Mapping):
                result = self._evaluateGroupEdge(member, nodes=nodes, nserder=nserder,
                    nested=True, path=(*path, label), inheritedSchema=pins, memo=memo, active=active, averages=averages,
                    historical=historical)
            else:
                return None
            if result is None:
                return None
            members.append(member)
            results.append(result)
        if not results:
            return None
        if op == "AND":
            return all(results)
        if op == "OR":
            return any(results)
        if op == "NAND":
            return not all(results)
        if op == "NOR":
            return not any(results)

        value = getattr(self.graphPolicy, "value", None)
        accept = getattr(self.graphPolicy, "accept", None)
        if value is None or accept is None:
            return None
        # An invalid relation or pin cannot be made valid by its numeric score.
        if not all(results):
            return False
        values, weights = [], []
        for member in members:
            far = None
            if "n" in member:
                nest = nodes[member["n"]]
                far = nest["serder"] if isinstance(nest, dict) else nest.serder
            number = (averages[id(member)] if id(member) in averages else
                      value(near=nserder, edge=member, far=far))
            weight = member.get("w") if op == "WAVG" else 1
            if (not self._finiteGraphNumber(number)
                    or not self._finiteGraphNumber(weight) or weight < 0):
                return None
            values.append(number)
            weights.append(weight)
        total = sum(weights)
        if not total or not self._finiteGraphNumber(total):
            return None
        mean = sum(number * (weight / total) for number, weight in zip(values, weights))
        if not isfinite(mean):
            return None
        result = accept(near=nserder, group=group, average=mean)
        if type(result) is not bool:
            return None
        averages[id(group)] = mean
        return result


    def evaluate(self, nodes, order, *, historical=False):
        """Use the same recursive evaluator for the presented origin and far nodes.

        Authenticate and schema-check all disclosed nodes before calling this
        method. A false far-node predicate may contribute to NOT/NAND/NOR; an
        unknown or malformed node may not. No default ecosystem trust is implied.

        Args:
            nodes (dict): Exact issuer-authenticated and own-schema-checked node views.
            order (list[str]): Reachable traversal order, with the origin first.

        Returns:
            bool | None: The complete root verdict, preserving unresolved truth.

        Raises:
            MissingChainError, MissingSchemaError: Required edge evidence is unavailable.
            Exceptions from trusted local graph policy propagate."""
        if not order or set(order) != set(nodes):
            return None
        memo, active, averages = {}, set(), {}
        result = self._evaluateGraphNode(order[0], nodes=nodes, memo=memo,
                                         active=active, averages=averages, historical=historical)
        return result if set(memo) == set(nodes) else None

    def verify(self, nodes, order, *, historical=False):
        """Require explicit root True without collapsing intermediate unknowns."""
        return self.evaluate(nodes, order, historical=historical) is True
