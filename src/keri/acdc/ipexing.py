# -*- encoding: utf-8 -*-
"""
keri.acdc.ipexing module

IPEx protocol service support (Issuance and Presentation Exchange)

"""

from collections import deque, namedtuple
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass

from hio.help import ogler

from .. import Kinds, Protocols
from ..kering import (Colds, ConfigurationError, DuplicitousRegistryError,
                      FailedSchemaValidationError,
                      Ilks, KeriError, MisanchorError, MisbindingError,
                      MissingAnchorError, MissingChainError, MissingSchemaError,
                      MisdigestError, MisregistryError,
                      MissequenceError, RootSealError, UnverifiedBlindError,
                      ValidationError, Vrsn_2_0, sniff)
from ..core import (Aggor, Compactor, Counter,
                    Codens, Diger, GenDex, Noncer, Number, Pather, Prefixer,
                    Parser, Saider, SealEvent, SealSource, SerderACDC, Serdery, Texter, exchange,
                    messagize)
from ..peer.exchanging import (cloneMessage, loadParsedNestedSubstreams, serializeParsedSubstream,
                               verifyAttachments)
from . import scheming
from .edging import (EdgeEvaluator, EdgeSectionLabels, EdgeGroupLabels,
                     edgeTarget, fixedEdgeOrder)
from .proving import PresentedEvidence

logger = ogler.getLogger()

Ipexage = namedtuple("Ipexage", "apply offer agree grant admit spurn")
Ipex = Ipexage(apply="apply", offer="offer", agree="agree",
               grant="grant", admit="admit", spurn="spurn")

PreviousRoutes = {
    Ipex.offer: (Ipex.apply,),
    Ipex.agree: (Ipex.offer,),
    Ipex.grant: (Ipex.apply, Ipex.agree),
    Ipex.admit: (Ipex.grant,),
    Ipex.spurn: (Ipex.apply, Ipex.offer, Ipex.agree, Ipex.grant),
}

FieldMapIlks = (None, Ilks.acm, Ilks.ace)
DisclosedNodeIlks = FieldMapIlks + (Ilks.act, Ilks.acg)
# Parsed attachment fields forbidden on Offer ACDC nodes.
NodeAttachmentFields = ("sigers", "wigers", "cigars", "tsgs", "lsgs", "frcs",
                        "sscs", "ssts", "tdcs", "bsqs", "bsss", "tmqs",
                        "essrs", "ptds", "nests")


def _streamSerder(stream):
    """Extract the message serder from a bare or nested artifact stream.

    Parameters:
        stream (Serder | bytes | bytearray): Artifact body, artifact stream, or
            already-parsed serder-like object.

    Returns:
        Serder: Deserialized message serder for the provided artifact.
    """

    # if the input already looks like a serder with .said and .raw, just return it
    if hasattr(stream, "said") and hasattr(stream, "raw"):
        return stream

    # If the input has .raw, use that; otherwise treat the input itself as bytes
    ims = bytearray(stream.raw) if hasattr(stream, "raw") else bytearray(stream)

    # If the input is a nested stream, unwrap it to get the inner message for parsing
    if _isNestedStream(ims):
        ctr = Counter(qb64b=ims, version=Vrsn_2_0, strip=True)
        if ctr.name in (
            Codens.NonNativeBodyGroup,
            Codens.BigNonNativeBodyGroup,
        ):
            return Serdery(version=Vrsn_2_0).reap(ims=Texter(qb64b=ims, strip=True).raw,
                                                  genus=GenDex.KERI,
                                                  svrsn=Vrsn_2_0)
        if ims and sniff(ims) != Colds.msg:
            ctr = Counter(qb64b=ims, version=Vrsn_2_0, strip=True)
            if ctr.name in (
                Codens.NonNativeBodyGroup,
                Codens.BigNonNativeBodyGroup,
            ):
                return Serdery(version=Vrsn_2_0).reap(ims=Texter(qb64b=ims, strip=True).raw,
                                                      genus=GenDex.KERI,
                                                      svrsn=Vrsn_2_0)

    return Serdery(version=Vrsn_2_0).reap(ims=ims,
                                          genus=GenDex.KERI,
                                          svrsn=Vrsn_2_0)


def _isNestedStream(stream):
    """Determine whether a stream already uses a supported nested wrapper.

    Parameters:
        stream (Serder | bytes | bytearray): Candidate artifact stream to inspect.

    Returns:
        bool: True when the stream starts with a nested body wrapper supported
            by the V2 parser, False when it is a bare message body.

    Raises:
        ValueError: If the stream starts with an unsupported leading CESR frame
            that this implementation refuses to reinterpret as a bare artifact.
    """
    ims = bytearray(stream.raw) if hasattr(stream, "raw") else bytearray(stream)
    if not ims or sniff(ims) == Colds.msg:
        return False

    try:
        ctr = Counter(qb64b=ims, version=Vrsn_2_0)
    except Exception as ex:
        raise ValueError("unsupported leading frame for nested artifact stream") from ex

    if ctr.name in (
        Codens.BodyWithAttachmentGroup,
        Codens.BigBodyWithAttachmentGroup,
        Codens.NonNativeBodyGroup,
        Codens.BigNonNativeBodyGroup,
    ):
        return True

    raise ValueError(f"unsupported leading frame code for nested artifact stream: {ctr.name}")


def _normalizeNestedStream(stream):
    """Convert a carried artifact into a parser-friendly V2 nested substream.

    Parameters:
        stream (Serder | bytes | bytearray): Artifact body or artifact stream to
            carry inside an outer IPEX exchange.

    Returns:
        bytearray: V2 nested substream framed as a body-with-attachments group.
    """

    # Check if already a nested CESR substream, if so return as is
    if _isNestedStream(stream):
        return bytearray(stream.raw) if hasattr(stream, "raw") else bytearray(stream)

    # If not make the input into raw bytes
    raw = bytes(stream.raw) if hasattr(stream, "raw") else bytes(stream)

    # Parse the raw bytes into a Serder to get the body and attachments
    serder = _streamSerder(raw)

    body = raw[:serder.size]
    atc = raw[serder.size:]

    # Check if body is NOT CESR, if so wrap it in a NonNativeBodyGroup counter
    if serder.kind != Kinds.cesr:
        body = Counter.enclose(qb64=Texter(raw=body).qb64b,
                               code=Codens.NonNativeBodyGroup,
                               version=Vrsn_2_0)

    # Check if attachments are empty, if so create an empty AttachmentGroup counter
    nested = bytearray(body)
    if atc:
        nested.extend(atc)
    else:
        empty = Counter.enclose(qb64=b'',
                                code=Codens.ControllerIdxSigs,
                                version=Vrsn_2_0)
        nested.extend(Counter.enclose(qb64=empty,
                                      code=Codens.AttachmentGroup,
                                      version=Vrsn_2_0))

    # Return the body and attachments
    return Counter.enclose(qb64=nested,
                           code=Codens.BodyWithAttachmentGroup,
                           version=Vrsn_2_0)


def _normalizeNodeStream(stream, attachment=None, *, allowAttachments=True):
    """Normalize one disclosed ACDC node into a nested V2 substream.

    Parameters:
        stream (Serder | bytes | bytearray): ACDC body, body+attachments
            stream, or already-nested node stream.
        attachment (bytes | bytearray | None): Optional attachment section to
            pair with the ACDC body when ``stream`` is not already a stream
            carrying attachments.
        allowAttachments (bool): False rejects any attachment material carried
            by the normalized node.

    Returns:
        bytearray: Nested V2 body-with-attachments group for one ACDC node.
    """
    # Preserve a caller-supplied node substream when it is already framed the
    # way IPEX expects: one ACDC body plus that node's attachment section.
    if _isNestedStream(stream):
        serder = _streamSerder(stream)
        if serder.proto != Protocols.acdc or serder.ilk not in DisclosedNodeIlks:
            raise ValueError("IPEX node nests must carry disclosed ACDC nodes")
        if attachment:
            raise ValueError("cannot append attachment bytes to a pre-nested ACDC node")
        nested = bytearray(stream.raw) if hasattr(stream, "raw") else bytearray(stream)
    else:
        raw = bytes(stream.raw) if hasattr(stream, "raw") else bytes(stream)
        serder = _streamSerder(raw)
        if serder.proto != Protocols.acdc or serder.ilk not in DisclosedNodeIlks:
            raise ValueError("IPEX node nests must carry disclosed ACDC nodes")

        # Rebuild plain ACDC input into the same per-node framing so later proof
        # groups can live on the owning node without changing the outer layout.
        atc = raw[serder.size:] if attachment is None else bytes(attachment)
        nested = _normalizeNestedStream(raw[:serder.size] + atc)

    if not allowAttachments:
        # Parse only to inspect the CESR groups; do not process or store them.
        ims = bytearray(nested)
        parsed = Parser(version=Vrsn_2_0).parse(ims=ims,
                                                framed=True,
                                                processive=False)
        hasAttachments = False
        if len(parsed) == 1:
            node = parsed[0]
            parsedNode = node if isinstance(node, Mapping) else node.__dict__
            hasAttachments = any(parsedNode.get(field)
                                 for field in NodeAttachmentFields)
        if ims or len(parsed) != 1 or hasAttachments:
            raise ValueError("offer ACDC nodes must not carry attachments")

    return nested


def _validSingleDagList(value, itemtype):
    """Validate one of the single-item list fields used by single-DAG IPEX.

    Parameters:
        value: Candidate wire value for a single-DAG field such as ``o`` or
            ``ax``.
        itemtype (type): Required Python type for each outer-list entry.
    Returns:
        bool: True when ``value`` matches the current single-DAG wire shape,
            False otherwise.
    """

    # The single-DAG outer-wire contract for `o` and `ax` is a list that can
    # later grow for multi-DAG without changing field type.
    if not isinstance(value, list):
        return False

    # We currently only support one DAG (until Multi DAG), so exactly one entry is required.
    if len(value) != 1:
        return False

    # The inner item type differs by field:
    # - `o` carries one origin SAID string
    # - `ax` carries one boolean
    return all(isinstance(item, itemtype) for item in value)


def _disclosurePathError(value):
    """Return the validation error for one normative disclosure-path plan."""
    if not isinstance(value, list):
        return "q.dp must be a flat list of disclosure-path triples"

    # The earlier local profile wrapped the one supported DAG in another list.
    # Its signed bytes retain that historical meaning; never reinterpret them as
    # the maintained v1.1 flat profile.
    if (len(value) == 1 and isinstance(value[0], list)
            and (not value[0]
                 or all(isinstance(item, list) and len(item) == 3
                        for item in value[0]))):
        return ("the historical nested q.dp profile is unsupported; "
                "q.dp must be the flat list of disclosure-path triples")

    for item in value:
        if not isinstance(item, list) or len(item) != 3:
            return "each q.dp entry must be a three-element array"

        schema, prefix, paths = item
        if not isinstance(schema, str):
            return "each q.dp schema SAID must be a string"
        try:
            Saider(qb64=schema)
        except Exception:
            return "each q.dp schema must be a qualified SAID"

        if not isinstance(prefix, str):
            return "each q.dp path prefix must be a string"
        if prefix not in ("", "/"):
            if not (prefix.startswith("/e/") and prefix.endswith("/_/")):
                return ("a non-empty non-origin q.dp prefix must start at /e/ "
                        "and end at a far-node _/ hop")

            segments = prefix.strip("/").split("/")
            if any(not segment for segment in segments):
                return "q.dp path prefixes may not contain empty components"
            for idx, segment in enumerate(segments):
                if segment == "_" and idx != len(segments) - 1:
                    if segments[idx + 1] != "e":
                        return "each intermediate q.dp far-node hop must resume at e"

        if not isinstance(paths, list):
            return "each q.dp path collection must be a list"
        if any(not isinstance(path, str) for path in paths):
            return "each q.dp path must be a string"
        for path in paths:
            if path.startswith("/"):
                return "q.dp tuple paths must be ACDC-relative"
            if not path:
                continue
            try:
                Pather(path=path, relative=True)
            except Exception:
                return f"invalid relative q.dp path {path!r}"

    return None


def _validDisclosurePath(value):
    """Validate one flat normative disclose-path plan.

    Callers interpret an empty plan only as inheriting a prior plan. Within a
    plan entry, an empty path list requests nothing from that node. An empty
    path under a non-empty prefix or the relative path ``d/`` requests the
    whole selected ACDC. Other paths request their disclosure closures.

    Parameters:
        value: Candidate disclose-path list for one DAG.

    Returns:
        bool: True when ``value`` is the flat list of disclosure-path triples
            ``[schema SAID, path prefix, ACDC-relative paths]``.
    """
    return _disclosurePathError(value) is None


def _sign(hab, serder, *, nests=None, anchor=False, endorsers=None,
          anchorers=None, gvrsn=None):
    """Authenticate and messagize an outer IPEX exchange with optional nests.

    Parameters:
        hab (Hab): Habitat used to sign the outer exchange.
        serder (Serder): Outer exchange serder to sign.
        nests (list[bytes | bytearray] | None): Optional nested substreams to
            append in the outer attachment section.
        anchor (bool): True creates a permitted KEL event sealing
            ``serder.said`` and attaches its source-seal couple instead of a
            redundant sender signature.
        endorsers (list[Hab] | None): Additional local habitats that sign the
            same outer exchange as non-sender endorsers (e.g. principal AIDs).
        anchorers (list[Hab] | None): Additional local transferable habitats
            whose KELs seal the same outer exchange.
        gvrsn (Versionage | None): Optional CESR genus version override for the
            attachment and nesting groups.

    Returns:
        bytearray: Full authenticated exchange stream including the outer message
            body, attachments, and any nested substreams.
    """
    gvrsn = gvrsn if gvrsn is not None else Vrsn_2_0
    nests = nests if nests else None

    # Copy caller lists before filtering or iterating them.
    endorsers = list(endorsers or [])
    anchorers = list(anchorers or [])

    # Collect sender and non-sender source references together.
    bonds = []

    # Validate every additional Grant authentication habitat.
    for endorser in endorsers + anchorers:

        # Local signing requires access to the same hab
        if endorser.db is not hab.db:
            raise ValueError(
                "additional authentication habitats must belong to the sender's Habery")

        # The sender is already authenticated separately
        if endorser.pre == hab.pre:
            raise ValueError(
                "sender must not be repeated as an additional endorser or anchorer")

    if anchor:
        # Only transferable identifiers can append the KEL event that carries the seal.
        if not hab.kever.prefixer.transferable:
            raise ValueError("anchored IPEX exchanges require a transferable sender")

        kwa = dict(data=[dict(d=serder.said)],
                   kind=hab.kever.serder.kind,
                   version=hab.kever.serder.pvrsn,
                   gvrsn=gvrsn)

        anc = None
        if hab.kever.estOnly:
            # Establishment Only KELs reject interactions, so advance key state with a rotation.
            anc = hab.rotate(**kwa)
        else:
            # Normal KELs use a cheaper interaction that leaves key state unchanged.
            anc = hab.interact(**kwa)

        aserder = _streamSerder(anc)

        # Add the seal to the exchange's source-seal list
        bonds.append(SealSource(s=aserder.snh, d=aserder.said))

    # Create one explicit source seal for each additional anchorer.
    for anchorer in anchorers:

        # Non-transferable AIDs cannot create KEL anchors.
        if not anchorer.kever.prefixer.transferable:
            raise ValueError("anchored IPEX endorsements require transferable AIDs")

        # Seal the immutable outer EXN SAID in the anchorer's KEL.
        kwa = dict(data=[dict(d=serder.said)],
                   kind=anchorer.kever.serder.kind,
                   version=anchorer.kever.serder.pvrsn,
                   gvrsn=gvrsn)

        # Respect Establishment Only KEL policy when creating the seal.
        anc = anchorer.rotate(**kwa) if anchorer.kever.estOnly else anchorer.interact(**kwa)

        # Parse the emitted KEL event for attachment coordinates.
        aserder = _streamSerder(anc)

        # Explicitly name the non-sender anchorer in a source triple.
        bonds.append(SealEvent(i=anchorer.pre, s=aserder.snh, d=aserder.said))

    # Collect transferable signature groups separately from cigars.
    tsgs = []
    cigars = []

    # A direct sender KEL anchor already authenticates the outer EXN. Sign only
    # when no sender anchor was created so the wire carries one sender factor.
    if not anchor:
        if hab.kever.prefixer.transferable:
            # Transferable senders produce indexed signatures.
            sigers = hab.sign(ser=serder.raw, indexed=True)

            # Bind those signatures to the sender's latest establishment event.
            tsgs.append((hab.kever.prefixer,
                         Number(sn=hab.kever.lastEst.s),
                         Diger(qb64=hab.kever.lastEst.d),
                         sigers))
        else:
            # Non-transferable senders authenticate with cigars.
            cigars.extend(hab.sign(ser=serder.raw, indexed=False))

    # Add each requested non-sender signature endorsement.
    for endorser in endorsers:

        # Transferable endorsers identify their current establishment state.
        if endorser.kever.prefixer.transferable:
            tsgs.append((endorser.kever.prefixer,
                         Number(sn=endorser.kever.lastEst.s),
                         Diger(qb64=endorser.kever.lastEst.d),
                         endorser.sign(ser=serder.raw, indexed=True)))
        else:
            # Non-transferable endorsers contribute unindexed signatures.
            cigars.extend(endorser.sign(ser=serder.raw, indexed=False))

    # Serialize the EXN with all selected authentication factors and nests.
    return messagize(serder=serder,
                     tsgs=tsgs or None,
                     cigars=cigars or None,
                     bonds=bonds or None,
                     nests=nests,
                     framed=False,
                     gvrsn=gvrsn)


class IpexHandler:
    """Verify and handle the linear V2 IPEX `exn` workflow."""

    # Receive validated sender source couples from Exchanger.
    acceptsSscs = True
    # Receive route-filtered non-sender evidence from Exchanger.
    acceptsEvidence = True

    def __init__(self, resource, hby, notifier, rgy=None, *, graphPolicy=None,
                 sections=None, verification=None):
        """Create a handler for one IPEX route.

        Parameters:
            resource (str): Route string handled by this instance.
            hby (Habery): Habitat environment and backing database.
            notifier: Notifier-like object with an ``add`` method.
            rgy (Regery | None): Optional local registry manager used when a
                disclosed node's ``rd`` requires verifier-side issuer-auth checks.
            graphPolicy: Optional application policy. ``validity(serder)`` may
                return bool or None. AVG/WAVG require ``value(near, edge, far)``
                selecting a finite numeric property and ``accept(near, group,
                average)`` interpreting the computed mean as bool or None.
                Methods receive the named arguments shown. No policy is inferred.
            sections (SectionBaser | None): Independently received schema evidence
                shared with the application's parser. Lookup never expands the
                retained credential's disclosed fields.
            verification (AcdcV2IpexVerification | None): Concrete shared context.
                When supplied, its policy and section store take precedence.

        Returns:
            None

        Raises:
            ConfigurationError: A supplied concrete context belongs to another
                Habery/Regery or is not an AcdcV2IpexVerification instance.
        """
        if verification is not None and (type(verification) is not AcdcV2IpexVerification
                or verification.hby is not hby or verification.rgy is not rgy):
            raise ConfigurationError('ACDC v2 IPEX verifier context must belong to this Habery and Regery')
        self.resource = resource
        self.hby = hby
        self.notifier = notifier
        self.rgy = rgy
        self.verification = verification if verification is not None else AcdcV2IpexVerification(
            hby, rgy, graphPolicy=graphPolicy, sections=sections)
        self.graphPolicy = self.verification.graphPolicy
        self.sections = self.verification.sections
        # Only Grant treats unresolved non-sender evidence as optional. Other
        # IPEX verbs continue rejecting foreign evidence before persistence.
        # Store this policy per route-specific handler instance.
        self.acceptsMissingEvidence = resource == "/ipex/grant"

    def verify(self, serder, attachments=None, nests=None, sscs=None,
               evidence=None, *, historical=False):
        """Validate the verb, prior link, and single-response rule.

        Parameters:
            serder (Serder): Incoming IPEX exchange message.
            attachments (list | None): Parsed attachment payloads, unused in the
                current linear workflow validation.
            nests (list | None): Parsed V2 nested artifacts. In the current
                single-DAG workflow ``offer`` may carry an ACDC DAG subset and
                ``grant`` may carry the final disclosed DAG.
            sscs (list | None): Sender source-seal couples retained after KRAM.
            evidence (tuple | None): Post-KRAM signature groups, cigars, and
                source-seal triples accepted for route validation.
            historical (bool): Select exact retained-opening TEL prefixes instead
                of current heads. Reserved for explicit retained-proof inspection.

        Returns:
            bool: True when the message is valid for the linear IPEX workflow,
                False otherwise.

        Raises:
            MissingChainError: When a disclosed ACDC's issuer-auth proof needs
                evidence that is not yet available locally and the exchange
                should be retried from escrow later.
            MissingSchemaError: When a disclosed ACDC names a schema that is not
                yet available locally and the exchange should be retried later.
            MissingSenderKeyStateError: When a required sender anchor refers
                to KEL evidence that is not yet available locally.
        """
        nests = nests if nests is not None else []
        sscs = sscs if sscs is not None else []

        # Normalize absent supplemental evidence to an empty accepted set.
        evidence = evidence if evidence is not None else ([], [], [])
        q = serder.ked.get("q")
        attrs = serder.ked["a"]
        dig = serder.ked["p"]

        route = serder.ked["r"]
        parts = route.split("/")
        if len(parts) != 3 or parts[:2] != ["", "ipex"]:
            return False

        verb = parts[2]
        if verb not in (Ipex.apply, *PreviousRoutes.keys()):
            return False

        # Stage 1: every inbound IPEX message must at least carry an attrs map
        # with a human message and a query/modifier map. `ax` is the only shared
        # optional list field.
        if not isinstance(attrs, dict) or "m" not in attrs or not isinstance(q, dict):
            return False
        if "ax" in attrs and not _validSingleDagList(attrs["ax"], bool):
            return False

        # Stage 2: disclosure messages carry the maintained flat disclose-path
        # list.  Empty is a ditto only on a reply; an opener cannot inherit.
        if verb in (Ipex.apply, Ipex.offer, Ipex.agree, Ipex.grant):
            if "dp" not in q:
                return False
            if error := _disclosurePathError(q["dp"]):
                logger.error("rejected IPEX %s disclosure profile: %s",
                             verb, error)
                return False
            if not q["dp"] and not dig:
                return False

        # Agree changes no disclosure terms; its empty plan always means ditto.
        if verb == Ipex.agree and q["dp"]:
            return False

        if verb == Ipex.offer:
            if "o" in attrs:
                if not _validSingleDagList(attrs["o"], str):
                    return False
                try:
                    Saider(qb64=attrs["o"][0])
                except Exception:
                    return False
            elif nests:
                return False
        # The other verbs never disclose nested ACDC nodes.
        elif verb != Ipex.grant and nests:
            return False

        # Stage 3: opener flows validate directly from the message itself,
        # while replies must first resolve and validate their prior exchange.
        pserder = None
        if not dig:
            if verb == Ipex.apply:
                # Apply is always a thread opener, so it must provide both
                # receiver and transaction id on the message body.
                if not (serder.ked.get("ri", "") and serder.ked.get("x", "")):
                    return False
            elif verb in (Ipex.offer, Ipex.grant):
                # Offer and grant may also open a thread, but must then carry
                # both the receiver and the generated exchange id themselves.
                if not (serder.ked.get("ri", "") and serder.ked.get("x", "")):
                    return False
            else:
                # Agree, admit, and spurn can only appear as replies.
                return False
        elif verb == Ipex.apply:
            return False
        else:
            # Retrieve prior serder
            pserder = self._verifyReplyChain(verb=verb, serder=serder, dig=dig)
            if pserder is None:
                return False

        if (verb == Ipex.offer and not q["dp"]
                and self._resolveDisclosurePlan(pserder) is None):
            logger.error("rejected IPEX offer: empty q.dp cannot inherit a "
                         "supported flat plan from its prior")
            return False

        # Stage 4: enforce the anchoring negotiation and verify direct sender
        # KEL anchors on the messages that make the binding commitments.
        messageAx = attrs.get("ax", [False])
        messageRequiresAnchor = messageAx[0] is True
        priorRequiresAnchor = False
        if pserder is not None:
            priorAx = pserder.ked.get("a", {}).get("ax", [False])
            priorRequiresAnchor = priorAx[0] is True

            if verb in (Ipex.agree, Ipex.grant, Ipex.admit):
                # Binding replies must exactly preserve the negotiated state.
                if messageRequiresAnchor != priorRequiresAnchor:
                    return False
            elif verb == Ipex.offer:
                # An offer may initiate anchoring, but may not drop it.
                if priorRequiresAnchor and not messageRequiresAnchor:
                    return False

        # Inherit anchoring when either the message or its prior requires it.
        requiresAnchor = messageRequiresAnchor or priorRequiresAnchor

        # Agree and Admit satisfy anchoring directly through their sender.
        if verb in (Ipex.agree, Ipex.admit) and requiresAnchor:
            # Anchored replies must carry a validated sender source couple.
            if not sscs:
                return False
            # Verify the newest supplied sender source reference.
            if not self._verifySourceAnchor(serder=serder,
                                            aid=serder.pre,
                                            number=sscs[-1][0],
                                            diger=sscs[-1][1]):
                return False

        # Stage 5: validate the ACDC subgraph carried by the Offer.
        if verb == Ipex.offer and nests:
            walked = self._walkGraph(origin=attrs["o"][0], nests=nests, closed=False)
            if walked is None:
                return False

            offerNodes, offerOrder = walked
            # Keep issuer proofs on the later Grant.
            hasAttachments = False
            for said in offerOrder:
                node = offerNodes[said]
                parsed = node if isinstance(node, Mapping) else node.__dict__
                hasAttachments = any(parsed.get(field) for field in NodeAttachmentFields)
                if hasAttachments:
                    break
            if hasAttachments:
                return False

            if not self._verifyNodeSchemas(nodes=offerNodes, order=offerOrder):
                return False

        # If the message is a Grant, resolve dp if it is empty or not
        elif verb == Ipex.grant:
            plan = self._resolveDisclosurePlan(serder)
            if plan is None:
                return False

            # A Grant may repeat but may not renegotiate an accepted prior plan.
            if pserder is not None:
                priorPlan = self._resolveDisclosurePlan(pserder)
                if priorPlan is None or plan != priorPlan:
                    return False

            origins = attrs.get("o")

            # If dp is empty
            if not plan:
                # With nothing to disclose, both the origin and body are empty.
                if origins != [] or nests:
                    return False

                # With no credential AID, only the sender can satisfy Grant ax.
                if requiresAnchor:
                    if not sscs or not self._verifySourceAnchor(
                            serder=serder,
                            aid=serder.pre,
                            number=sscs[-1][0],
                            diger=sscs[-1][1]):
                        return False
            else:
                # A non-empty dp requires one disclosed origin DAG.
                if not _validSingleDagList(origins, str) or not nests:
                    return False
                try:
                    Saider(qb64=origins[0])
                except Exception:
                    return False

                walked = self._walkGraph(origin=origins[0], nests=nests, closed=True)
                if walked is None:
                    return False
                grantNodes, grantOrder = walked

                # A Grant may not replay field-map metadata as the credential.
                for grantNode in grantNodes.values():
                    grantSerder = (grantNode["serder"] if isinstance(grantNode, dict)
                                   else grantNode.serder)
                    if (grantSerder.ilk in FieldMapIlks
                            and grantSerder.sad.get("u") == ""):
                        return False

                # First enforce what was requested, then enforce what the
                # accepted Offer promised before authenticating the Grant.
                if not self._verifyDisclosurePlan(plan=plan,
                                                  origin=origins[0],
                                                  nodes=grantNodes,
                                                  order=grantOrder):
                    return False
                if not self._verifyOfferFulfillment(agree=pserder,
                                                    grantOrigin=origins[0],
                                                    grantNodes=grantNodes):
                    return False

                # Authenticate the exact disclosure, independently of edge truth.
                if not self._authenticateGraph(grantNodes, grantOrder, historical=historical):
                    return False

                try:
                    _, _, extraSeals = evidence
                except (TypeError, ValueError):
                    return False

                # Verify every presentation registry declared for this disclosure.
                tethered = self._verifyPresentationAuthGraph(
                    serder=serder,
                    nodes=grantNodes,
                    order=grantOrder,
                )
                if tethered is None:
                    return False

                # A truthy ax requires one permitted Grant anchorer.
                if requiresAnchor:
                    origin = grantNodes[origins[0]]
                    origin = origin["serder"] if isinstance(origin, dict) else origin.serder
                    anchorers = set(tethered)

                    if sscs and self._verifySourceAnchor(serder=serder,
                                                        aid=serder.pre,
                                                        number=sscs[-1][0],
                                                        diger=sscs[-1][1]):
                        anchorers.add(serder.pre)

                    for prefixer, number, diger in extraSeals:
                        if self._verifySourceAnchor(serder=serder,
                                                    aid=prefixer.qb64,
                                                    number=number,
                                                    diger=diger):
                            anchorers.add(prefixer.qb64)

                    candidates = (serder.pre, origin.iseaid, origin.israid)
                    if not any(aid and aid in anchorers for aid in candidates):
                        return False

        return True

    def _verifySourceAnchor(self, serder, aid, number, diger):
        """Delegate existing IPEX source checks to the shared evidence owner."""
        return PresentedEvidence(self.hby, self.rgy).verifySourceAnchor(serder, aid, number, diger)

    def _validNodeNest(self, origin, nests):
        """Validate disclosed node nests and index them by ACDC SAID.

        Parameters:
            origin (str): SAID of the origin node named in ``a.o[0]``.
            nests (list): Parsed nested ACDC node substreams.

        Returns:
            dict | None: Mapping of disclosed node SAID to its parsed nest when
                every nest is a unique ACDC node and the first nest matches the
                origin; otherwise None.
        """
        nodes = {}
        for idx, nest in enumerate(nests):
            nserder = nest["serder"] if isinstance(nest, dict) else nest.serder
            if not nserder.verify():
                return None
            # Each nest must carry a real disclosed credential node, not just
            # any ACDC-protocol message such as a registry TEL event.
            if nserder.proto != Protocols.acdc or nserder.ilk not in DisclosedNodeIlks:
                return None

            # Verify every expanded section SAID, including nested blocks.
            for label in ("a", "e", "r"):
                section = nserder.sad.get(label)
                if not isinstance(section, Mapping):
                    continue
                try:
                    compactor = Compactor(mad=deepcopy(section), makify=True,
                                          kind=nserder.kind)
                    compactor.compact()
                    for path, leaf in compactor.leaves.items():
                        carried = compactor.getTail(path, mad=section)
                        if (not isinstance(carried, Mapping) or
                                (carried.get("d") and
                                 carried["d"] != leaf.said)):
                            return None
                except Exception:
                    return None

            # Verify an expanded aggregate's AGID and each element SAID.
            aggregate = nserder.sad.get("A")
            if isinstance(aggregate, list) and aggregate:
                try:
                    aggor = Aggor(ael=deepcopy(aggregate), makify=True,
                                  kind=nserder.kind)
                except Exception:
                    return None
                if aggregate[0] and aggregate[0] != aggor.agid:
                    return None
                for carried, computed in zip(aggregate[1:], aggor.ael[1:]):
                    if (isinstance(carried, Mapping) and carried.get("d") and
                            carried["d"] != computed.get("d")):
                        return None

            if idx == 0 and not nserder.compare(origin):
                return None
            # Each disclosed DAG node must occupy exactly one nest so the node
            # body cannot appear twice with conflicting attachment groups.
            if nserder.said in nodes:
                return None
            nodes[nserder.said] = nest

        return nodes

    def _verifyReplyChain(self, verb, serder, dig):
        """Validate the prior-link rules for a reply inside an IPEX thread.

        Parameters:
            verb (str): IPEX route suffix for the reply being checked.
            serder (Serder): Incoming reply exchange message.
            dig (str): SAID of the prior message named by ``serder.ked["p"]``.

        Returns:
            Serder | None: The accepted prior when the reply points to an
                allowed message, keeps sender/receiver roles consistent, and
                does not duplicate an existing response; otherwise None.
        """
        pserder, _ = cloneMessage(self.hby, said=dig)
        if pserder is None:
            return None

        # Replies must point at the allowed prior verb in the linear IPEX chain.
        proute = pserder.ked["r"]
        pparts = proute.split("/")
        if len(pparts) != 3 or pparts[:2] != ["", "ipex"]:
            return None
        pverb = pparts[2]
        if pverb not in PreviousRoutes[verb]:
            return None
        if verb == Ipex.spurn and pverb == Ipex.grant and pserder.ked.get("p", ""):
            return None

        # Replies must target the prior sender and come from the prior receiver
        if serder.ked.get("ri", "") != pserder.ked.get("i", ""):
            return None
        preceiver = pserder.ked.get("ri", "")
        if not preceiver:
            return None
        if serder.ked.get("i", "") != preceiver:
            return None
        if serder.ked.get("x", "") != pserder.ked.get("x", ""):
            return None

        response = self.response(pserder)
        if response is not None and response.said != serder.said:
            return None

        return pserder

    def _resolveDisclosurePlan(self, serder):
        """Resolve one disclosure plan through empty prior-message dittos."""
        seen = set()
        current = serder

        # Walk the prior chain until we find a non-empty dp
        while current is not None:
            if current.said in seen:
                return None
            seen.add(current.said)

            route = current.ked.get("r")
            if route not in ("/ipex/apply", "/ipex/offer",
                             "/ipex/agree", "/ipex/grant"):
                return None

            # Retrieve the current message's dp and validate it
            plan = current.ked.get("q", {}).get("dp")
            if not _validDisclosurePath(plan):
                return None

            # If dp is non-empty, return it
            if plan:
                return plan

            # Otherwise continue the chain
            prior = current.ked.get("p", "")
            if not prior:
                return None
            current, _ = cloneMessage(self.hby, said=prior)

        return None

    def _verifyDisclosurePlan(self, plan, origin, nodes, order):
        """Check exact disclosed nodes against the negotiated local path contract.

        Args:
            plan (list): Ordered (schema SAID, graph prefix, field-path list)
                entries, one per node in the disclosed breadth-first traversal.
            origin (str): Root credential SAID from the Grant.
            nodes (dict): Exact received parsed node views indexed by SAID.
            order (list[str]): Reachable node order already checked by _walkGraph.

        Returns:
            bool: Whether every selected node/schema and requested disclosure
                closure matches, without resolving or expanding received views.

        An empty path list requires node presence at any valid compaction level.
        Whole-node paths require schema-proven recursive closure for field-map
        sections and visible aggregate members. An open or otherwise ambiguous
        schema cannot distinguish ordinary string data from a compacted nested
        block's SAID, so this bounded profile refuses that whole-node claim.
        Ordinary node-schema validation still runs separately afterward.

        Other paths require their canonical Compactor disclosure closure. Cached
        fuller sections never satisfy an omitted path or enlarge these bytes.
        """
        if not plan or not order or order[0] != origin:
            return False

        selected = []
        selectedIndexes = []
        hasPositional = False
        for position, (schema, prefix, fields) in enumerate(plan):
            if prefix == "":
                # Empty prefixes use the tuple's BFS position as the node id.
                if position >= len(order):
                    return False
                said = order[position]
                hasPositional = hasPositional or position > 0
            else:
                said = origin

            nest = nodes.get(said)
            if nest is None:
                return False
            nserder = nest["serder"] if isinstance(nest, dict) else nest.serder
            value = nserder.sad
            edgePath = []

            # Follow each virtual `_` hop from a near edge to its far ACDC.
            if prefix not in ("", "/"):
                for part in prefix.strip("/").split("/"):
                    if part == "_":
                        try:
                            said = edgeTarget(nserder, tuple(edgePath), value,
                                evidence=PresentedEvidence(self.hby, self.rgy), sections=self.sections)
                        except (ValueError, TypeError):
                            return False
                        nest = nodes.get(said)
                        if nest is None:
                            return False
                        nserder = nest["serder"] if isinstance(nest, dict) else nest.serder
                        value = nserder.sad
                        edgePath = []
                    elif isinstance(value, Mapping):
                        if part not in value:
                            return False
                        value = value[part]
                        edgePath.append(part)
                    elif isinstance(value, list) and part.isdigit():
                        index = int(part)
                        if index >= len(value):
                            return False
                        value = value[index]
                        edgePath.append(part)
                    else:
                        return False

            try:
                selectedIndex = order.index(said)
            except ValueError:
                return False
            if selectedIndexes and selectedIndex <= selectedIndexes[-1]:
                return False
            selected.append(said)
            selectedIndexes.append(selectedIndex)

            # The tuple's schema must identify the selected disclosed node.
            nodeSchema = nserder.schema
            if isinstance(nodeSchema, Mapping):
                nodeSchema = nodeSchema.get("$id")
            if nodeSchema != schema:
                return False

            # A non-empty prefix plus an empty tuple path names the whole ACDC.
            # With an empty prefix, d/ is the shortest relative whole-ACDC path;
            # an empty path names nothing because it has no node terminator.
            whole = ((prefix != "" and "" in fields) or "d/" in fields)
            if whole:
                for label in ("a", "e", "r"):
                    section = nserder.sad.get(label)
                    if section and not isinstance(section, Mapping):
                        return False
                aggregate = nserder.sad.get("A")
                if aggregate and (not isinstance(aggregate, list)
                        or any(not isinstance(member, Mapping)
                               for member in aggregate[1:])):
                    # Aggregate positions are structurally blocks, unlike an
                    # arbitrary attribute scalar. A bare member digest is known
                    # selective withholding and cannot fulfill this request.
                    return False
                if not self._verifyWholeDisclosure(nserder, paths=("d/",)):
                    return False
                continue

            # Group paths by top-level section for canonical partial checks.
            sections = {}
            for field in fields:
                if not field:
                    continue
                try:
                    pather = Pather(path=field, relative=True)
                    pather.resolve(nserder.sad)
                except Exception:
                    return False

                parts = pather.rparts
                if parts:
                    sections.setdefault(parts[0], []).append(field)

            for root, paths in sections.items():
                section = nserder.sad.get(root)
                if not isinstance(section, Mapping):
                    continue
                try:
                    compactor = Compactor(mad=deepcopy(section),
                                          makify=True,
                                          kind=nserder.kind)
                    compactor.compact(paths=paths, root=root)
                    partial = compactor.partials.get(tuple(paths))
                except Exception:
                    return False
                if partial is None:
                    return False
                expected = partial.mad
                if section.get("d") == "" and expected.get("d"):
                    expected = dict(expected)
                    expected["d"] = ""
                if expected != section:
                    return False

            # Compactor verifies the canonical visible partial, but cannot tell
            # whether a digest-valued child is data or a hidden field-map block.
            # A trailing separator asks for that subtree whole, so require the
            # negotiated node schema to prove its recursive closure as well.
            wholePaths = tuple(field for field in fields if field.endswith("/"))
            if wholePaths and not self._verifyWholeDisclosure(nserder,
                                                               paths=wholePaths):
                return False

        # A nonorigin positional selector requires schema-proven fixed shape
        # and a gapless BFS list. Explicit far prefixes may omit unrequested nodes,
        # but the selected nodes must remain in BFS order and start at origin.
        return (selected[0] == origin
                and (not hasPositional or (selected == order and all(
                    fixedEdgeOrder(nodes[said]["serder"] if isinstance(nodes[said], dict)
                                   else nodes[said].serder,
                        evidence=PresentedEvidence(self.hby, self.rgy), sections=self.sections)
                    for said in order))))

    def _verifyWholeDisclosure(self, serder, *, paths):
        """Verify whole-path closure under the bounded explicit acm profile.

        The received bytes alone cannot distinguish a legitimate SAID-valued
        string from a compacted nested field-map. This check therefore follows
        the authenticated JSON Schema instead of inspecting string spelling.
        Only explicit object schemas with closed or schema-valued additional
        properties are supported. Ambiguous combinators and open objects refuse
        the whole-node claim.
        """
        if serder.ilk != Ilks.acm:
            return False

        source = serder.schema
        try:
            if isinstance(source, Mapping):
                schemer = scheming._verifySchemer(source, kind=serder.kind)
            elif isinstance(source, str):
                schemer = scheming._cachedSchema(self.hby.db, source,
                                                 sections=self.sections)
                if schemer is None:
                    raise MissingSchemaError(source)
            else:
                return False
            registry = scheming._registry(schemer, self.hby.db,
                                          sections=self.sections)
            resolver = registry.resolver(base_uri=schemer.said)
        except MissingSchemaError:
            raise
        except (KeriError, TypeError, ValueError):
            return False

        for path in paths:
            parts = list(Pather(path=path, relative=True).rparts)
            if parts and not parts[-1]:
                parts.pop()

            # d/ is the normative whole-ACDC selector. The schema and aggregate
            # sections have their own evidence rules; field-map closure applies
            # to the compactable a/e/r sections present in this acm node.
            if parts == ["d"]:
                # Aggregate members can contain nested field maps, but the
                # bounded acm profile below does not yet interpret array item
                # schemas. Refuse rather than mistake visible members for
                # recursively complete members.
                if "A" in serder.sad:
                    return False
                for label in ("a", "e", "r"):
                    if label not in serder.sad:
                        continue
                    located = self._disclosureSubschema(
                        schemer.sed, serder.sad, (label,), resolver)
                    if located is None:
                        return False
                    value, subschema, subresolver = located
                    if not self._closedBySchema(value, subschema, subresolver):
                        return False
                continue

            located = self._disclosureSubschema(
                schemer.sed, serder.sad, tuple(parts), resolver)
            if located is None:
                return False
            value, subschema, subresolver = located
            if not self._closedBySchema(value, subschema, subresolver):
                return False

        return True

    def _disclosureSubschema(self, schema, value, parts, resolver):
        """Locate the schema and instance selected by one disclosure path."""
        for part in parts:
            selected = self._selectDisclosureSchema(schema, value, resolver)
            if selected is None or not isinstance(value, Mapping):
                return None
            schema, resolver = selected
            properties = schema.get("properties")
            if isinstance(properties, Mapping) and part in properties:
                schema = properties[part]
            else:
                additional = schema.get("additionalProperties")
                if not isinstance(additional, Mapping) and not isinstance(additional, bool):
                    return None
                if additional is False:
                    return None
                schema = additional
            if part not in value:
                return None
            value = value[part]
        return value, schema, resolver

    def _selectDisclosureSchema(self, schema, value, resolver, depth=64):
        """Select one unambiguous schema branch for an already received value."""
        if depth <= 0:
            return None
        if isinstance(schema, bool):
            return (schema, resolver) if schema is False else None
        if not isinstance(schema, Mapping):
            return None

        if "$ref" in schema:
            # Draft 2020-12 permits siblings beside $ref. Supporting their
            # intersection needs a general schema evaluator, so keep this
            # security boundary explicit instead of silently ignoring them.
            annotations = {"$ref", "$id", "$schema", "title", "description",
                           "$comment", "deprecated", "readOnly", "writeOnly",
                           "examples", "default"}
            if set(schema) - annotations:
                return None
            try:
                resolved = resolver.lookup(schema["$ref"])
            except Exception:
                return None
            return self._selectDisclosureSchema(resolved.contents, value,
                                                resolved.resolver, depth - 1)

        # Bounded profile: select a single declared oneOf branch. Other
        # applicators need intersection/conditional reasoning and are refused.
        if any(keyword in schema for keyword in
               ("anyOf", "allOf", "not", "if", "then", "else",
                "dependentSchemas", "patternProperties")):
            return None
        if "oneOf" in schema:
            branches = schema["oneOf"]
            if not isinstance(branches, list) or len(branches) > 16:
                return None
            matches = [branch for branch in branches
                       if self._schemaTypeMatches(branch, value)]
            if len(matches) != 1:
                return None
            return self._selectDisclosureSchema(matches[0], value, resolver,
                                                depth - 1)

        return schema, resolver

    @staticmethod
    def _schemaTypeMatches(schema, value):
        """Return whether a bounded schema branch declares value's JSON type."""
        if schema is True:
            return True
        if schema is False or not isinstance(schema, Mapping):
            return False
        typ = schema.get("type")
        if isinstance(value, Mapping):
            return typ == "object"
        if isinstance(value, list):
            return typ == "array"
        if isinstance(value, str):
            return typ == "string"
        if isinstance(value, bool):
            return typ == "boolean"
        if value is None:
            return typ == "null"
        if isinstance(value, int):
            return typ in ("integer", "number")
        if isinstance(value, float):
            return typ == "number"
        return False

    def _closedBySchema(self, value, schema, resolver, depth=64):
        """Prove that every schema-declared field-map below value is expanded."""
        if depth <= 0:
            return False

        # A string at a location which also admits an object is the explicit
        # compact-or-expanded shape used for field-map blocks. Whole disclosure
        # requires the object branch. A string-only location remains ordinary
        # scalar data even when its value happens to be a valid SAID.
        if (isinstance(value, str)
                and self._schemaMayMap(schema, resolver, depth=depth)):
            return False
        selected = self._selectDisclosureSchema(schema, value, resolver,
                                                depth=depth)
        if selected is None:
            return False
        schema, resolver = selected

        # Scalars are safe only when explicitly typed as scalars. This accepts
        # legitimate SAID-valued data without treating its characters as proof
        # that the value is a hidden block.
        if not isinstance(value, Mapping):
            return self._schemaTypeMatches(schema, value)

        if schema.get("type") != "object":
            return False
        properties = schema.get("properties")
        if not isinstance(properties, Mapping):
            return False
        additional = schema.get("additionalProperties")
        if additional is not False and not isinstance(additional, Mapping):
            return False

        for label, child in value.items():
            childSchema = properties.get(label)
            if childSchema is None:
                if additional is False:
                    return False
                childSchema = additional
            if not self._closedBySchema(child, childSchema, resolver, depth - 1):
                return False
        return True

    def _schemaMayMap(self, schema, resolver, depth=64):
        """Return whether the bounded schema explicitly admits an object."""
        if depth <= 0 or schema is True:
            return True
        if schema is False or not isinstance(schema, Mapping):
            return False
        if schema.get("type") == "object":
            return True
        if "$ref" in schema:
            try:
                resolved = resolver.lookup(schema["$ref"])
            except Exception:
                return True
            return self._schemaMayMap(resolved.contents, resolved.resolver,
                                      depth - 1)
        branches = schema.get("oneOf")
        if branches is None:
            return False
        if not isinstance(branches, list) or len(branches) > 16:
            return True
        return any(self._schemaMayMap(branch, resolver, depth - 1)
                   for branch in branches)

    @staticmethod
    def _canonicalSectionCommitment(label, section, *, kind):
        """Compute the canonical commitment represented by an ACDC section."""
        # Aggregate sections use an AGID instead of a normal section SAID.
        if label == "A":
            if isinstance(section, str):
                try:
                    Diger(qb64=section)
                except Exception:
                    return None
                return section
            if isinstance(section, list):
                try:
                    return Aggor(ael=deepcopy(section), makify=True,
                                 kind=kind).agid
                except Exception:
                    return None
            return None

        # A string is already the compact SAID form of a section.
        if isinstance(section, str):
            try:
                Diger(qb64=section)
            except Exception:
                return None
            return section
        if not isinstance(section, Mapping):
            return None

        # Recompute the commitment from an expanded SAD instead of trusting
        # the SAID carried inside it. Schemas use `$id`; other sections use `d`.
        try:
            if label == "s":
                compactor = Compactor(mad=deepcopy(section), makify=True,
                                      strict=False, saids={"$id": "E"},
                                      kind=kind)
            else:
                compactor = Compactor(mad=deepcopy(section), makify=True,
                                      kind=kind)
                compactor.compact()
        except Exception:
            return None
        return compactor.said

    def _verifyOfferFulfillment(self, agree, grantOrigin, grantNodes):
        """Verify that a Grant fulfills the ACDC accepted in its Offer.

        An exact root SAID fulfills the Offer directly. When a metadata Offer
        names a different root, its section commitments must match the Grant.

        Returns:
            bool: True when the promise is fulfilled or no ACDC-specific Offer
                exists, and False for a permanent contradiction or malformed
                evidence.

        Raises:
            MissingChainError: The accepted Offer names metadata needed for the
                comparison but its body is not locally available yet.
        """
        # Direct Grants have no accepted Offer commitment to compare.
        if agree is None or agree.ked.get("r") != "/ipex/agree":
            return True

        # Follow the Agree to the exact Offer accepted by the disclosee
        offerSaid = agree.ked.get("p", "")
        offer, _ = cloneMessage(self.hby, said=offerSaid)
        if offer is None:
            raise MissingChainError(
                f"missing accepted Offer message {offerSaid}")

        # An Offer without an origin does not promise a particular ACDC
        offerOrigins = offer.ked.get("a", {}).get("o")
        if offerOrigins is None:
            return True
        if not _validSingleDagList(offerOrigins, str):
            return False

        offerOrigin = offerOrigins[0]

        # The same root SAID directly fulfills the Offer.
        if offerOrigin == grantOrigin:
            return True

        # A different root needs the offered metadata body for comparison.
        try:
            offerNests = loadParsedNestedSubstreams(self.hby, offer.said)
        except (KeriError, TypeError, ValueError):
            return False
        if not offerNests:
            raise MissingChainError(
                f"missing metadata ACDC for accepted Offer {offer.said}")

        # Reuse normal graph validation before reading the offered root node.
        walked = self._walkGraph(origin=offerOrigin, nests=offerNests, closed=False)
        if walked is None:
            return False
        offeredNodes, offeredOrder = walked
        offeredNest = offeredNodes[offerOrigin]
        grantNest = grantNodes.get(grantOrigin)
        if grantNest is None:
            return False
        offeredSerder = (offeredNest["serder"] if isinstance(offeredNest, dict)
                         else offeredNest.serder)
        grantSerder = (grantNest["serder"] if isinstance(grantNest, dict)
                       else grantNest.serder)

        # Only field-map metadata can promise a different credential root.
        if (offeredSerder.ilk not in FieldMapIlks
                or offeredSerder.sad.get("u") != ""):
            return False

        # Metadata loaded after the Offer must pass the same schema checks as
        # metadata carried with the original Offer.
        if not self._verifyNodeSchemas(nodes=offeredNodes, order=offeredOrder):
            return False

        # The metadata promises the issuer independently of its sections.
        if offeredSerder.israid != grantSerder.israid:
            return False

        # A non-empty metadata registry SAID is also part of the promise.
        offeredRegistry = offeredSerder.sad.get("rd")
        if offeredRegistry and offeredRegistry != grantSerder.sad.get("rd"):
            return False

        # Every non-empty offered section must have the same canonical
        # commitment in the Grant; empty sections make no disclosure promise.
        for label in ("s", "a", "A", "e", "r"):
            offeredSection = offeredSerder.sad.get(label)

            if offeredSection in (None, "", [], {}):
                continue

            offeredCommitment = self._canonicalSectionCommitment(
                label, offeredSection, kind=offeredSerder.kind)
            grantCommitment = self._canonicalSectionCommitment(
                label, grantSerder.sad.get(label), kind=grantSerder.kind)

            if offeredCommitment is None or offeredCommitment != grantCommitment:
                return False

        return True

    def _walkGraph(self, origin, nests, *, closed):
        """Walk the disclosed origin DAG and return the visited node order.

        Parameters:
            origin (str): SAID of the origin node named by ``a.o[0]``.
            nests (list): Parsed nested ACDC node substreams carried by the
                offer or grant message.
            closed (bool): True requires every referenced edge target to be
                carried in ``nests``. False allows undisclosed far nodes, but
                every carried nest must still be reachable from ``origin``.

        Returns:
            tuple | None: ``(nodes, order)`` when the disclosed nests form one
                reachable disclosed graph rooted at ``origin`` under the
                selected closure rule; otherwise ``None``.
        """
        # Reuse the disclosed-node validation so graph walking starts from a
        # well-formed set of unique ACDC nests.
        nodes = self._validNodeNest(origin=origin, nests=nests)
        if nodes is None:
            return None

        # Reject if origin is not carried in the nests
        if origin not in nodes:
            return None

        # Use deque for BFS traversal so we start at the disclosed origin and
        # then fan out across every referenced child node in graph order.
        seen = set()
        order = []
        queue = deque([origin])

        # Walk the graph BFS. Grant fails closed on dangling references, while
        # offer may omit farther undisclosed nodes as long as carried nodes
        # still form one root-reachable subgraph.
        while queue:
            said = queue.popleft()
            if said in seen:
                continue
            seen.add(said)
            order.append(said)

            nest = nodes[said]
            nserder = nest["serder"] if isinstance(nest, dict) else nest.serder

            # Retrieve the edges from the node
            edges = nserder.sad.get("e")
            if edges:
                if isinstance(edges, Mapping):
                    blocks = [edges]
                elif isinstance(edges, list) and all(isinstance(edge, Mapping) for edge in edges):
                    blocks = edges
                else:
                    return None

                # Expanded edge sections may contain nested edge groups
                for index, edge in enumerate(blocks):
                    path = ("e",) if isinstance(edges, Mapping) else ("e", str(index))
                    groups = deque([(edge, False, path)])
                    while groups:
                        group, nested, path = groups.popleft()
                        labels = EdgeGroupLabels if nested else EdgeSectionLabels
                        try:
                            edgeSaid = edgeTarget(nserder, path, group,
                                evidence=PresentedEvidence(self.hby, self.rgy), sections=self.sections)
                        except (ValueError, TypeError):
                            return None
                        if edgeSaid is not None:
                            if edgeSaid not in nodes:
                                if closed:
                                    # Nested Grant bytes are immutable.  Retrying
                                    # cannot add a missing far node to this EXN, so
                                    # reject the incomplete graph permanently rather
                                    # than misclassifying it as external evidence.
                                    return None
                                continue
                            if edgeSaid not in seen:
                                queue.append(edgeSaid)
                            continue

                        if not isinstance(group, Mapping):
                            return None
                        for label, node in group.items():
                            if label in labels:
                                continue
                            groups.append((node, True, (*path, label)))

        # Even when offer omits farther nodes, every carried nest must still be
        # part of the root-reachable disclosed graph.
        if len(seen) != len(nodes):
            return None

        return nodes, order


    def _graphRegistry(self, serder, nest):
        """Transitional delegate retained for Dolly's pending caller migration."""
        return PresentedEvidence(self.hby, self.rgy).graphRegistry(serder, nest)


    def _verifyNodeSchemas(self, nodes, order):
        """Validate disclosed nodes without expanding their retained views.

        Args:
            nodes (dict): Authenticated disclosed nodes indexed by SAID.
            order (list): Reachable node SAIDs to validate in graph order.

        Returns:
            bool: Whether every node satisfies its embedded or cached own schema.

        Raises:
            MissingSchemaError: Required schema evidence is not yet available.
        """
        for said in order:
            nest = nodes[said]
            nserder = nest["serder"] if isinstance(nest, dict) else nest.serder
            try:
                scheming.validateSchema(acdc=nserder, db=self.hby.db, sections=self.sections)
            except MissingSchemaError:
                raise
            except (FailedSchemaValidationError, ValidationError, ValueError):
                return False

        return True

    def _authenticateGraph(self, nodes, order, *, historical=False):
        """Share issuer and own-schema proof checks with explicit graph use."""
        return (self._verifyIssuerAuthGraph(nodes, order, historical=historical)
                and self._verifyNodeSchemas(nodes, order))

    def _verifyIssuerAuthGraph(self, nodes, order, *, historical=False):
        """Verify issuer-auth proof groups for each walked disclosed DAG node.

        Parameters:
            nodes (dict): Mapping of disclosed node SAID to parsed nest.
            order (list): Breadth-first walk order returned by ``_walkGraph``.

        Returns:
            bool: True when every walked node has a valid issuer registry,
                direct KEL anchor, or current issuer signature factor.

        Raises:
            MissingChainError: When an issuer factor names KEL or TEL evidence
                that the verifier has not loaded locally yet.
        """
        # Run proof verification in graph order so each registry-backed node is
        # checked against the exact nested substream that carried its body.
        for said in order:

            # Resolve the node-local body and attachments.
            nest = nodes[said]

            # Read the ACDC body from either parsed representation.
            nserder = nest["serder"] if isinstance(nest, dict) else nest.serder

            # Require one valid issuer authentication factor per node.
            if not self._verifyIssuerAuthNode(serder=nserder, nest=nest, historical=historical):
                return False

        # Every disclosed node passed issuer authentication.
        return True

    def _verifyIssuerAuthNode(self, serder, nest, *, historical=False):
        """Verify one disclosed ACDC's selected issuer authentication factor.

        Args:
            serder (SerderACDC): Exact disclosed credential view.
            nest: Parsed object or dictionary carrying that view's attachments.

        Returns:
            bool: Whether the selected registry, anchor, or signature authenticates
                the issuer. Invalid selected evidence never falls back to another
                factor.

        Raises:
            MissingChainError: Required authenticated KEL/TEL evidence is absent.
            KeriError: Invalid registry opening or binding evidence.
        """
        # Authentication Factor 1: Registry
        # First check if a registry was declared, if so verify it
        regk = serder.sad.get("rd")
        if regk:
            record = self._vetRegistry(regk=regk,
                                       proofs=self._blindProofs(nest),
                                       target=serder.said,
                                       acdc=serder, historical=historical)
            if record is None:
                return False
            return True

        # An inner rd without a top-level rd selects the unsupported hidden
        # issuer-registry form; it must not fall through to another factor.
        if self._presentationRegistries(serder) is None:
            return False

        # Authentication Factor 2: Seal Anchor
        # Registry-less ACDCs must identify a direct issuer AID.
        issuer = serder.israid

        # Reject a credential with no issuer authentication identity.
        if not issuer:
            return False

        # Parse the issuer identifier before processing attachments.
        try:
            prefixer = Prefixer(qb64=issuer)
        except Exception:
            return False

        # Normalize object and dictionary nest representations.
        parsed = nest if isinstance(nest, dict) else nest.__dict__

        # Check for any Seal anchor attachments that may be supplied by the issuer.
        # Convert issuer-implied source couples into explicit triples.
        sourceSeals = [(prefixer, number, diger)
                       for number, diger in parsed.get("sscs", [])]

        # Keep only explicit source triples from the issuer.
        sourceSeals.extend((sealer, number, diger)
                           for sealer, number, diger in parsed.get("ssts", [])
                           if sealer.qb64 == issuer)

        # A supplied issuer seal selects anchor authentication.
        if sourceSeals:
            # Verify every candidate seal against local issuer KEL evidence.
            _, _, validSeals, _, missing = verifyAttachments(
                hby=self.hby,
                serder=serder,
                sourceSeals=sourceSeals,
            )
            # Missing KEL evidence makes this node retryable.
            if missing:
                raise MissingChainError(
                    f"missing issuer KEL evidence for ACDC {serder.said}")

            # A supplied issuer anchor is the selected factor. An invalid anchor
            # must not silently downgrade the ACDC to signature authentication.
            return bool(validSeals)

        # Authentication Factor 3: Signatures
        # Fall back to signature verification when no registry or anchor is supplied
        tsgs = []

        # Membership performs the existing statedict read-through from verified
        # persisted state. Its get() only sees warmed in-memory entries, so it
        # would incorrectly require replay of an already retained KEL on restart.
        kever = self.hby.kevers[issuer] if issuer in self.hby.kevers else None

        # Read bare indexed signatures from the node stream.
        sigers = parsed.get("sigers", [])

        # Keep explicit signature groups belonging to the issuer.
        issuerTsgs = [tsg for tsg in parsed.get("tsgs", [])
                      if tsg[0].qb64 == issuer]

        # Keep last-establishment groups belonging to the issuer.
        issuerLsgs = [lsg for lsg in parsed.get("lsgs", [])
                      if lsg[0].qb64 == issuer]

        # Transferable evidence must resolve against current issuer keys.
        if prefixer.transferable and (sigers or issuerTsgs or issuerLsgs):

            # Missing current state makes signature verification retryable.
            if kever is None:
                raise MissingChainError(
                    f"missing current issuer key state for ACDC {serder.said}")

            # Build the current establishment coordinates once.
            number = Number(sn=kever.lastEst.s)
            diger = Diger(qb64=kever.lastEst.d)

            # Bind bare signatures to the current issuer state.
            if sigers:
                tsgs.append((prefixer, number, diger, sigers))

            # Keep explicit groups that already name the current state.
            tsgs.extend(tsg for tsg in issuerTsgs
                        if tsg[1].sn == kever.lastEst.s
                        and tsg[2].qb64 == kever.lastEst.d)

            # Resolve last-establishment groups to the current state.
            tsgs.extend((sealer, number, diger, lsigers)
                        for sealer, lsigers in issuerLsgs)

        # Keep only non-transferable signatures made by the issuer.
        cigars = [cigar for cigar in parsed.get("cigars", [])
                  if cigar.verfer.qb64 == issuer]

        # Cryptographically verify all selected issuer signatures.
        validTsgs, validCigars, _, _, missing = verifyAttachments(
            hby=self.hby,
            serder=serder,
            tsgs=tsgs,
            cigars=cigars,
        )
        # Missing establishment events make verification retryable.
        if missing:
            raise MissingChainError(
                f"missing current issuer KEL evidence for ACDC {serder.said}")

        # Require at least one valid current issuer signature.
        return bool(validTsgs or validCigars)

    @staticmethod
    def _blindProofs(nest):
        """Transitional delegate retained for current Dolly and CLI callers."""
        return PresentedEvidence.blindProofs(nest)

    def _registryEvidence(self, regk, *, proofs=None, target=None, acdc=None):
        """Transitional shared-history delegate for IPEX and current Dolly callers."""
        return PresentedEvidence(self.hby, self.rgy).registryEvidence(
            regk, proofs=proofs, target=target, acdc=acdc)

    def _vetRegistry(self, regk, proofs, target, controller=None, acdc=None,
                     cutoff=None, sourceSeals=None, requireSource=False, historical=False):
        """Vet one issuer or presentation registry using matching BLIDs.

        Args:
            regk (str): Selected issuer or presentation registry identifier.
            proofs (Iterable[Blinder]): Node-local disclosures, matched to TEL BLIDs.
            target (str): Credential/exchange SAID the selected binding must commit to.
            controller (str | None): Required registry-controlling AID.
            acdc (SerderACDC | None): Credential for issuer-registry mutual binding.
            cutoff: Legacy timestamp selector; common verification rejects it.
            sourceSeals (Iterable | None): Explicit Issuee KEL source triples.
            requireSource (bool): Require an authenticated historical binding source.
            historical (bool): Select the unique accepted prefix identified by
                retained openings. Generic node source locators do not select it.

        Returns:
            RegStateRecord | None: Verified selected binding, or None for permanent
            structural/binding failure or no injected registry owner.

        Raises:
            MissingChainError: The accepted chain, selected KEL anchor, or TEL event
                for a self-verified target opening is unavailable. An unmatched
                opening proves no newer ordinal, state, or freshness; even a
                self-valid foreign opening may remain unresolved without acceptance.

        The common verifier authenticates the TEL and openings. Neither a cache hit nor
        an unsigned source locator is an independent claim of acceptance."""

        # Require disclosed proofs and a locally available TEL chain.
        proofs = list(proofs)
        if (evidence := self._registryEvidence(regk, proofs=proofs if historical else None,
                                              target=target, acdc=acdc)) is None:
            return None

        # Import lazily to avoid the ACDC module cycle.
        from . import regeventing
        try:
            # Resolve node-local source triples into exact TEL anchor claims.
            sources = {}
            unresolved = False
            if requireSource:
                for prefixer, number, diger in sourceSeals or []:
                    if prefixer.qb64 != controller:
                        continue

                    # Resolve the claimed source event from the Issuee's KEL.
                    eventSaid = self.hby.db.kels.getLast(
                        keys=prefixer.qb64b, on=number.sn)
                    if eventSaid is None:
                        unresolved = True
                        continue

                    # A known different event makes this source claim invalid.
                    if eventSaid != diger.qb64:
                        continue

                    # The event body may arrive after its KEL coordinate is known.
                    event = self.hby.db.evts.get(
                        keys=(prefixer.qb64b, diger.qb64b))
                    if event is None:
                        unresolved = True
                        continue

                    # Match the source only to TEL events it actually seals.
                    for update in evidence[1]:
                        if regeventing._verifyAnchorCouple(
                                update,
                                db=self.hby.db,
                                issuer=controller,
                                number=number,
                                diger=diger):
                            sources[update.said] = diger.qb64

                # An unavailable attached source is retryable after KEL retrieval.
                if not sources and unresolved:
                    raise MissingChainError(
                        f"missing presentation anchor source for registry {regk}")

            # A presentation proof names its historical KEL source. Resolve
            # that source to an exact TEL prefix; request timeliness does not
            # select registry history. Current issuer standing uses the head.
            at = evidence[1][-1].said if historical else None
            if requireSource and sources:
                at = max((update for update in evidence[1] if update.said in sources),
                         key=lambda update: Number(numh=update.sad['n']).num).said

            # Verify the TEL and its latest disclosed target binding.
            record = regeventing.vetBinds(rip=evidence[0],
                                          updates=evidence[1],
                                          db=self.hby.db,
                                          blinders=proofs,
                                          target=target,
                                          controller=controller,
                                          acdc=acdc,
                                          cutoff=cutoff,
                                          at=at,
                                          sources=sources,
                                          requireSource=requireSource)

            # Require the vetted chain to be the registry named by the ACDC.
            if record.regid != regk:
                raise MisregistryError(
                    f"verified registry {record.regid} does not match "
                    f"declared registry {regk}")

            return record

        # Missing KEL anchors can be resolved by later evidence retrieval.
        except MissingAnchorError as ex:
            raise MissingChainError(f"registry {regk} is missing anchored TEL evidence") from ex

        # An unresolved attached source may later prove the selected binding.
        except MisanchorError as ex:
            if requireSource and unresolved:
                raise MissingChainError(
                    f"missing presentation anchor source for registry {regk}") from ex
            return None

        except UnverifiedBlindError as ex:
            # A resolved historical source selects an exact accepted event;
            # another opening cannot replace that event's required commitment.
            if requireSource:
                return None
            known = {update.sad['b'] for update in evidence[1]
                     if update.ilk == Ilks.bup}
            unresolved = None
            try:
                if acdc is not None:
                    regeventing.vetBindings(acdc, regid=regk,
                        issuer=evidence[0].sad['i'], td=target)
                checked = []
                for proof in proofs:
                    disclosed, _ = regeventing.vetBlind(proof, blid=proof.said)
                    if proof.said in known and sum(item.said == proof.said for item in proofs) != 1:
                        return None  # Known commitments still require one opening.
                    checked.append((proof, disclosed))
                missingBound = None
                for proof, disclosed in checked:
                    if disclosed != target:
                        continue
                    try:
                        regeventing.vetBound(proof, acdc=acdc, db=self.hby.db)
                    except MissingAnchorError as error:
                        # Scan all target proofs before returning a dependency:
                        # a known contradiction wins regardless of proof order.
                        missingBound = error
                    if proof.said not in known:
                        unresolved = proof.said
            except (UnverifiedBlindError, MisbindingError, MisanchorError):
                return None
            if unresolved is not None:
                if missingBound is not None:
                    raise MissingChainError(
                        f"registry {regk} opening is missing bound KEL evidence") from missingBound
                # This is only an authenticated disclosure with no matching
                # accepted TEL event. Fetch/retry through normal EXN escrow;
                # do not infer its ordinal, issuer publication time, or validity.
                raise MissingChainError(
                    f"registry {regk} is missing TEL evidence for disclosed blid={unresolved}") from ex
            return None

        # Structurally invalid or misbound TEL evidence fails permanently.
        except (MisdigestError, MissequenceError, MisregistryError,
                RootSealError, MisbindingError, DuplicitousRegistryError):
            return None

    @staticmethod
    def _presentationRegistries(serder):
        """Extract the disclosed Issuee presentation-registry declaration.

        Return ``None`` for an unsupported hidden issuer registry or when a
        registry-backed ACDC hides the top-level attribute block that carries
        the presentation requirement.
        """
        attribute = serder.sad.get("a")

        if not serder.sad.get("rd"):
            # A disclosed inner rd without top-level rd is an unsupported
            # hidden issuer registry, not a presentation registry.
            if isinstance(attribute, Mapping) and attribute.get("rd"):
                return None

            # A genuinely registry-less ACDC has no presentation declaration.
            return []

        # The presentation signal lives at the top level of the attribute
        # block, so that block must be disclosed for IPEX to enforce it.
        if isinstance(attribute, str):
            return None

        if not isinstance(attribute, Mapping):
            return []

        # Both fields are required to select a presentation registry.
        regk = attribute.get("rd")
        issuee = attribute.get("i")
        if not regk or not issuee:
            return []

        # Validate both identifiers before trusting the declaration.
        try:
            Saider(qb64=regk)
            Prefixer(qb64=issuee)
        except Exception:
            return None

        return [(issuee, regk)]

    def _verifyPresentationAuthGraph(self, serder, nodes, order):
        """Verify presentation registries declared by the disclosed DAG."""

        originSaid = order[0]
        origin = nodes[originSaid]
        origin = origin["serder"] if isinstance(origin, dict) else origin.serder

        issuance = (serder.pre == origin.israid
                    and serder.ked.get("ri", "") == origin.iseaid)

        required = []

        # Walk the already validated DAG in deterministic order.
        for said in order:

            # Resolve this node and its attached proof stream.
            nest = nodes[said]

            # Read the ACDC body from either parsed representation.
            acdc = nest["serder"] if isinstance(nest, dict) else nest.serder

            # Extract this node's Issuee registry declarations.
            declarations = self._presentationRegistries(acdc)

            # Reject hidden or malformed declarations.
            if declarations is None:
                return None

            # Only the origin being issued is exempt. Linked credentials are
            # existing disclosures whose presentation requirements still apply.
            if issuance and said == originSaid:
                continue

            # Keep each declaration with its node-local proof stream.
            for issuee, regk in declarations:
                required.append((issuee, regk, nest))

        # KRAM receipt time is not an ordering proof for KEL-anchored state.
        cache = self.hby.db.kramTMSC.get(
            keys=(serder.pre, serder.ked.get("x", ""), serder.said))

        # A presentation requirement needs a completed KRAM acceptance.
        if required and (cache is None or not cache.rdt):
            return None

        # Collect Issuees authenticated through presentation registries.
        tethered = set()

        # Vet every declared registry independently.
        for issuee, regk, nest in required:
            # Resolve the binding through its verified KEL source reference.
            sourceSeals = nest.get("ssts", []) if isinstance(nest, dict) else nest.ssts
            record = self._vetRegistry(regk=regk,
                                       proofs=self._blindProofs(nest),
                                       target=serder.said,
                                       controller=issuee,
                                       sourceSeals=sourceSeals,
                                       requireSource=True)

            # This proves anchored authorization, not publication before receipt.
            if record is None:
                return None

            # Record the Issuee authenticated by this registry.
            tethered.add(issuee)

        # Return all presentation-authenticated Issuees.
        return tethered

    def verifyEvidence(self, serder, *, tsgs=None, cigars=None, sourceSeals=None,
                       invalid=False, missing=None):
        """Select verified non-sender evidence accepted by this IPEX route.

        Exchanger first removes cryptographically invalid attachments.  Grants
        then require signatures from each endorser's current Kever while keeping
        perpetually verifiable historical seals, and prefer a valid seal over
        signatures from the same AID.
        Grants drop unresolved optional evidence after Exchanger requests the
        missing KEL. Other verbs reject foreign, invalid, or unresolved evidence.

        Args:
            serder (Serder): Sender-authenticated exchange under this handler's route.
            tsgs (Iterable | None): Verified non-sender transferable signature groups.
            cigars (Iterable | None): Verified non-sender nontransferable signatures.
            sourceSeals (Iterable | None): Verified non-sender KEL source triples.
            invalid (bool): Whether cryptographic attachment validation found bad evidence.
            missing (Iterable | None): Attachment dependencies not yet resolved by KRAM.

        Returns:
            tuple | None: Accepted (tsgs, cigars, sourceSeals), or None for inadmissible
            supplemental evidence. This filters evidence; it does not validate a Grant DAG."""
        # Normalize optional evidence collections for filtering.
        tsgs = tsgs if tsgs is not None else []
        cigars = cigars if cigars is not None else []
        sourceSeals = sourceSeals if sourceSeals is not None else []

        # Keep unresolved coordinates distinct from invalid attachments.
        missing = missing if missing is not None else []

        # Derive the policy branch from the concrete IPEX route.
        verb = serder.ked["r"].rsplit("/", 1)[-1]

        # Only Grant accepts supplemental grantor evidence.
        if verb == Ipex.grant:
            # Collect endorsements tied to current endorser key states.
            freshTsgs = []
            for prefixer, number, diger, sigers in tsgs:
                # Resolve the endorser's current verified state.
                kever = (self.hby.kevers[prefixer.qb64]
                         if prefixer.qb64 in self.hby.kevers else None)
                # Require exact current establishment coordinates.
                if (kever is not None
                        and number.sn == kever.lastEst.s
                        and diger.qb64 == kever.lastEst.d):
                    # Preserve this current transferable endorsement.
                    freshTsgs.append((prefixer, number, diger, sigers))

            # Exchanger already verified each source seal against the referenced
            # historical KEL event and this exact grant. A later key rotation does
            # not invalidate that permanent commitment.
            validSeals = list(sourceSeals)

            # A valid seal is the stronger factor for an AID, so do not
            # retain a redundant signature endorsement from that same AID.
            sealers = {prefixer.qb64 for prefixer, _, _ in validSeals}
            freshTsgs = [tsg for tsg in freshTsgs if tsg[0].qb64 not in sealers]
            freshCigars = [cigar for cigar in cigars
                           if cigar.verfer.qb64 not in sealers]

            # Return only verified factors; unresolved extras are dropped.
            return freshTsgs, freshCigars, validSeals

        # Reject supplemental evidence on every non-Grant IPEX verb.
        if tsgs or cigars or sourceSeals or invalid or missing:
            return None

        # Accept an evidence-free non-Grant message.
        return [], [], []

    def verifyAccepted(self, said, *, historical=False):
        """Revalidate retained IPEX authentication and protocol without graph policy.

        An EXN body in Baser proves neither route registration nor credential
        acceptance: generic Exchangers may retain authenticated unknown routes.
        Reuse the same proof and transition checks, allowing only an identical
        already recorded response. By default use current registry heads;
        historical=True selects unique accepted prefixes from the retained
        openings. Neither mode proves a past policy decision or publication time.

        Args:
            said (str): SAID of the retained ACDC v2 IPEX exchange to revalidate.
            historical (bool): Verify retained proof prefixes without claiming
                current registry standing. Live intake retains the default False.

        Returns:
            bool: Whether retained sender authentication, exact nests, and current
            protocol checks all verify. Unknown/wrong-route bodies return False.
            Edge truth is assessed separately by evaluateGrant.

        Raises:
            KeriError: Retained authentication or dependent evidence is missing/invalid,
            including MissingChainError and MissingSchemaError for retryable dependencies."""
        from ..peer.exchanging import verify
        serder = self.hby.db.exns.get((said,))
        if serder is None or serder.route != self.resource or serder.pvrsn.major != 2:
            return False
        tsgs, cigars = verify(self.hby, serder)
        seals = [(Prefixer(qb64=keys[1]), number, diger)
                 for keys, (number, diger) in self.hby.db.ests.getTopItemIter((said, ''))]
        evidence = self.verifyEvidence(serder,
            tsgs=[item for item in tsgs if item[0].qb64 != serder.pre],
            cigars=[item for item in cigars if item.verfer.qb64 != serder.pre],
            sourceSeals=[item for item in seals if item[0].qb64 != serder.pre])
        if evidence is None:
            return False
        return self.verify(serder, nests=loadParsedNestedSubstreams(self.hby, said),
            sscs=[(number, diger) for prefixer, number, diger in seals
                  if prefixer.qb64 == serder.pre], evidence=evidence, historical=historical)

    def response(self, serder):
        """Look up the recorded response to a prior IPEX exchange.

        Parameters:
            serder (Serder): Prior IPEX exchange to check for an existing reply.

        Returns:
            Serder | None: The previously recorded response serder, or None when
                no response has been recorded.
        """
        saider = self.hby.db.erpy.get(keys=(serder.said,))
        if saider:
            rserder, _ = cloneMessage(self.hby, saider.qb64)
            return rserder

        return None

    def handle(self, serder, attachments=None, nests=None, sscs=None):
        """Emit a notifier record for an accepted IPEX message.

        Parameters:
            serder (Serder): Accepted IPEX exchange message.
            attachments (list | None): Parsed attachment payloads, unused by the
                current notifier path.
            nests (list | None): Parsed V2 nested artifacts, unused by the
                notifier path.
            sscs (list | None): Sender source-seal couples, unused after verify.

        Returns:
            None
        """
        attrs = serder.ked["a"]
        self.notifier.add(attrs=dict(
            r=f"/exn{serder.ked['r']}",
            d=serder.said,
            m=attrs["m"],
        ))


@dataclass
class AdmittedCredential:
    """Explicit local consent to one exact grant/admit disclosure pair.

        credential and holder identify its origin/recipient; grant and admit retain
        exchange provenance. admitted is the signed Admit timestamp, not a local
        observation or issuer-publication time.

        The original reference view was adapted from KERI Foundation Locksmith
        3a5ad9ebcf98b4ec03baf1bbb91d928d49c168e4 (Apache-2.0). This local view
        is reconstructed from Exchanger records and introduces no wallet storage.
    """
    credential: str
    grant: str
    admit: str
    holder: str
    admitted: str


@dataclass(frozen=True)
class AcdcV2IpexVerification:
    """Concrete ACDC v2 IPEX semantic context shared by intake and fresh admission.

    This context carries evidence and policy, never a caller assertion of
    acceptance. Retained inspection may outlive it; fresh acceptance may not.

    Parameters:
        hby (Habery): Owner of authenticated KEL and retained EXN evidence.
        rgy (Regery | None): Registry evidence used for issuer authentication.
        graphPolicy: Explicit local graph validity/averaging policy, or None.
        sections (SectionBaser | None): Parser-owned independent schema store.
    """
    hby: object
    rgy: object = None
    graphPolicy: object = None
    sections: object = None

    def handler(self, resource, notifier=None):
        """Return a route handler using this context's evidence and policy.

        Args:
            resource (str): ACDC v2 IPEX route to validate.
            notifier: Optional receiver of accepted-message notifications.

        Returns:
            IpexHandler: Concrete route processor with no independent defaults.
        """
        return IpexHandler(resource, self.hby, notifier, rgy=self.rgy,
                           verification=self)

    def verifyAccepted(self, said, route, *, historical=False):
        """Re-run retained authentication and protocol checks, without edge policy.

        Args:
            said (str): Retained exchange identifier.
            route (str): Expected ACDC v2 IPEX route.
            historical (bool): Select retained opening prefixes; False preserves
                current-head verification.

        Returns:
            bool: Whether retained authentication and protocol checks pass.

        Raises:
            MissingSchemaError: A required independently supplied schema is absent.
            KeriError: Retained authentication or dependent evidence is invalid.
        """
        return self.handler(route).verifyAccepted(said, historical=historical)

    def admission(self, grant, admit, *, historical=False):
        """Read one authenticated local Grant/Admit pair from exchange storage.

        Args:
            grant (str): Retained Grant identifier.
            admit (str): Retained Admit identifier.
            historical (bool): Select retained TEL prefixes for inspection.

        Returns:
            AdmittedCredential: A view of signed consent, never a new stored row.

        Raises:
            ValidationError: Signature, recipient, response linkage or credential
                proof is invalid. Evidence dependency errors propagate.

        A signed local Admit is the consent artifact. Neither receipt of a Grant
        nor a notification supplies consent. This view asserts no graph-policy
        decision; fresh use must separately evaluate the configured policy.
        """
        gexn, aexn = self.hby.db.exns.get((grant,)), self.hby.db.exns.get((admit,))
        for said, exn, route in ((grant, gexn, '/ipex/grant'), (admit, aexn, '/ipex/admit')):
            if (exn is None or exn.said != said or exn.route != route or exn.pvrsn.major != 2):
                raise ValidationError('accepted ACDC v2 IPEX evidence is required')
        holder = gexn.sad.get('ri')
        response = self.hby.db.erpy.get((grant,))
        if (self.hby.habByPre(holder) is None or aexn.pre != holder or aexn.sad.get('p') != grant
                or aexn.sad.get('ri') != gexn.pre or response is None or response.qb64 != admit):
            raise ValidationError('admit must be the local intended holder response to this grant')
        origins = gexn.sad['a'].get('o')
        if not isinstance(origins, list) or len(origins) != 1:
            raise ValidationError('admission requires one disclosed origin credential')
        for route, message in (('/ipex/grant', gexn), ('/ipex/admit', aexn)):
            if not self.verifyAccepted(message.said, route, historical=historical):
                raise ValidationError('ACDC v2 IPEX semantic acceptance is required before admission')
        return AdmittedCredential(origins[0], grant, admit, holder, aexn.sad['dt'])

    def validateAdmission(self, grant, admit, *, consent=False):
        """Validate fresh admission without a second application consent ledger.

        Args:
            grant (str): Retained Grant identifier.
            admit (str): Holder-signed response identifier.
            consent (bool): Explicit local approval for this fresh validation.

        Returns:
            AdmittedCredential: View of the already signed and retained pair.

        Raises:
            ValidationError: Consent, authentication or current graph policy fails.

        The existing Exchanger owns persistence. Repeating this operation creates
        no record, index, journal or delivery authorization. Current policy is
        checked every time; use heldCredential for historical inspection.
        """
        if consent is not True:
            raise ValidationError('explicit consent is required before admission')
        record = self.admission(grant, admit, historical=False)
        if self.evaluateGrant(grant) is not True:
            raise ValidationError('ACDC v2 graph semantic acceptance is required before admission')
        return record

    def heldCredential(self, grant):
        """Read one admitted grant's exact retained proof without merging later views.

            Args:
                grant (str): Grant SAID with existing explicit local consent.

            Returns:
                dict: Exact credential, serialized origin proof, other original artifacts,
                    retained grant, and admit SAID. No cached fuller section is substituted.

            Raises:
                ValidationError: Consent, authenticated exchange evidence, or origin is absent.

            Current graph policy and private custody are unnecessary for historical proof
            retrieval; onward acceptance still invokes the receiving semantic verifier."""
        response = self.hby.db.erpy.get((grant,))
        if response is None:
            raise ValidationError('this grant has no signed local admission')
        record = self.admission(grant, response.qb64, historical=True)
        exn = self.hby.db.exns.get((grant,))
        nests = loadParsedNestedSubstreams(self.hby, grant)
        for nest in nests:
            if nest.serder.said == record.credential:
                return {'credential': nest.serder,
                        'proof': serializeParsedSubstream(nest),
                        'artifacts': [serializeParsedSubstream(other) for other in nests
                                      if other.serder.said != record.credential],
                        'grant': exn, 'admit': record.admit}
        raise ValidationError('admitted grant origin evidence is missing')

    def admissions(self, credential=None):
        """Read authenticated local Grant/Admit pairs from ordinary exchange storage.

        Args:
            credential (str | None): Restrict to this credential commitment, or
                return all local admissions. Distinct disclosure views stay separate.

        Returns:
            list[AdmittedCredential]: Historical signed-consent views, not current
                standing or remembered graph-policy decisions. No index is written.

        Invalid or unrelated responses are omitted; missing evidence dependencies
        propagate through the existing protocol exceptions.
        """
        held = []
        for (grant,), response in self.hby.db.erpy.getTopItemIter():
            exn = self.hby.db.exns.get((response.qb64,))
            if (exn is None or exn.route != '/ipex/admit' or exn.pvrsn.major != 2
                    or self.hby.habByPre(exn.pre) is None):
                continue
            try:
                record = self.admission(grant, response.qb64, historical=True)
            except ValidationError:
                continue
            if credential is None or record.credential == credential:
                held.append(record)
        return held

    def _evaluateGraph(self, nodes, order, *, historical):
        """Invoke the single evaluator with this action's concrete policy/evidence."""
        return EdgeEvaluator(PresentedEvidence(self.hby, self.rgy),
            graphPolicy=self.graphPolicy, sections=self.sections).evaluate(
                nodes, order, historical=historical)

    def evaluateGrant(self, said, *, historical=False):
        """Evaluate a retained, protocol-authenticated nonempty Grant's root.

        Revalidate sender, disclosure, issuer, own schema, presentation and AX
        checks first. Invalid authentication/structure raises ValidationError;
        existing dependency exceptions propagate. Return bool or unresolved None.
        historical selects retained proof prefixes, never current standing or a
        remembered policy decision. Empty protocol grants are not graph uses.
        """
        if not self.verifyAccepted(said, '/ipex/grant', historical=historical):
            raise ValidationError('authenticated ACDC v2 Grant is required for graph use')
        exn = self.hby.db.exns.get((said,))
        origins = exn.sad['a'].get('o')
        if not _validSingleDagList(origins, str):
            raise ValidationError('graph use requires one disclosed origin')
        # Authentication above already checked these immutable retained nests.
        walked = self.handler('/ipex/grant')._walkGraph(origins[0],
            loadParsedNestedSubstreams(self.hby, said), closed=True)
        if walked is None:
            raise ValidationError('invalid retained disclosure graph')
        return self._evaluateGraph(*walked, historical=historical)

    def evaluateDisclosure(self, origin, nests, *, historical=False):
        """Authenticate exact parsed node views, then return complete root truth.

        nests are ordinary Parser MsgParseDom objects (or their dictionaries),
        not an assertion of accepted EXN state. No outer Grant/presentation/AX
        authentication is claimed. Malformed structure, invalid issuer proofs
        and own-schema failures raise ValidationError. Missing KEL/TEL/schema
        dependencies retain their existing exceptions; semantic unknown is None.
        """
        if (not isinstance(origin, str) or not isinstance(nests, list)
                or any(not isinstance(nest.get('serder') if isinstance(nest, Mapping)
                                      else getattr(nest, 'serder', None), SerderACDC)
                       for nest in nests)):
            raise ValidationError('graph use requires parsed ACDC node streams')
        handler = self.handler('/ipex/grant')
        walked = handler._walkGraph(origin, nests, closed=True)
        if walked is None:
            raise ValidationError('invalid disclosed graph')
        if not handler._authenticateGraph(*walked, historical=historical):
            raise ValidationError('disclosed graph authentication failed')
        return self._evaluateGraph(*walked, historical=historical)

    def evaluateSelected(self, origin, artifacts=None, *, historical=False):
        """Check selected credential streams before a caller signs its Grant.

        Use the builder's existing nesting normalization and parse-only Parser;
        require exactly one fully consumed node per input. This creates no EXN,
        signatures, anchors, accepted rows or cached fuller disclosure. A bare
        body without a selected issuer proof is not authenticated by local custody.
        """
        if origin is None or (artifacts is not None and not isinstance(artifacts, list)):
            raise ValidationError('graph use requires an origin and a list of artifacts')
        nests = []
        for stream in [origin, *(artifacts or [])]:
            try:
                ims = _normalizeNodeStream(stream)
                node = Parser(version=Vrsn_2_0).parseOne(ims=ims, framed=True, processive=False)
                if node is None or ims:
                    raise ValueError('expected one fully consumed node stream')
            except (KeriError, ValueError, TypeError) as ex:
                raise ValidationError('invalid selected credential stream') from ex
            nests.append(node)
        return self.evaluateDisclosure(nests[0].serder.said, nests, historical=historical)


def apply(hab, recp, message, modifiers=None, attrs=None, dt=None, kind=None, gvrsn=None, *, ax=None):
    """Create a signed V2 IPEX ``apply`` exchange.

    Parameters:
        hab (Hab): Habitat creating and signing the exchange.
        recp (str): Recipient AID for the application.
        message (str): Human-readable application message.
        attrs (dict | None): Optional application body payload stored in ``a``.
        dt (str | None): Optional RFC-3339 timestamp override.
        kind (str | None): Optional serialization kind override.
        gvrsn (Versionage | None): Optional CESR genus version override.
        modifiers (dict | None): Query-section fields for ``q``. ``apply``
            requires an explicit flat disclosure-path plan at
            ``modifiers["dp"]``.
        ax (list[bool] | None): Single-DAG anchoring requirement. None omits
            the field; otherwise exactly one boolean is required.

    Returns:
        tuple[Serder, bytearray]: Outer exchange serder and detached attachment
            bytes for the signed V2 stream.
    """
    if not recp:
        raise ValueError("recp is required when apply starts a flow")
    xid = Diger(ser=Noncer().qb64b).qb64
    if attrs is not None and not isinstance(attrs, dict):
        raise TypeError("attrs must be a dict when provided")

    data = dict(attrs) if attrs is not None else {}

    # ax should be passed as a separate parameter, not in the attrs
    if "ax" in data:
        raise ValueError("use the ax parameter instead of attrs['ax']")
    data["m"] = message
    mods = dict(modifiers) if modifiers else {}

    if "dp" not in mods:
        raise ValueError("modifiers['dp'] is required")
    if error := _disclosurePathError(mods["dp"]):
        raise ValueError(error)
    if not mods["dp"]:
        raise ValueError("an apply opener must carry a non-empty q.dp plan")

    # Validate ax and add it to the body
    if ax is not None:
        if not _validSingleDagList(ax, bool):
            raise ValueError("ax must be a one-item list of booleans")
        data["ax"] = ax

    # Build the body
    serder = exchange(
        sender=hab.pre,
        receiver=recp,
        xid=xid,
        route="/ipex/apply",
        modifiers=mods,
        stamp=dt,
        attributes=data,
        pvrsn=Vrsn_2_0,
        gvrsn=gvrsn if gvrsn is not None else Vrsn_2_0,
        kind=kind if kind is not None else hab.kever.serder.kind,
    )
    
    # Sign the full stream
    atc = bytearray(_sign(hab=hab, serder=serder, gvrsn=gvrsn))
    
    # Strip the body so we only get the attachments
    del atc[:serder.size]

    return serder, atc


def offer(hab, message, origin, artifacts=None, apply=None, recp=None, dt=None,
          kind=None, gvrsn=None, modifiers=None, attrs=None, *, ax=None):
    """Create a signed V2 IPEX ``offer`` exchange.

    Parameters:
        hab (Hab): Habitat creating and signing the exchange.
        message (str): Human-readable offer message.
        origin (Serder | bytes | bytearray | None): Optional ACDC root for the
            offer DAG. When provided, its SAID is copied into ``a.o[0]``. When
            omitted, the offer may negotiate only through its disclose-path
            plan.
        artifacts (list[Serder | bytes | bytearray] | None): Optional
            additional ACDC DAG nodes carried after ``origin``. Passing a list,
            including ``[]``, means the offer carries ``origin`` as a nested
            ACDC, so an expanded origin provides full disclosure in the Offer.
        apply (Serder | None): Optional prior ``apply`` exchange.
        recp (str | None): Recipient AID. Defaults to the prior ``apply``
            sender; must be supplied directly for an offer-first exchange
            opened with no prior.
        dt (str | None): Optional RFC-3339 timestamp override.
        kind (str | None): Optional serialization kind override.
        gvrsn (Versionage | None): Optional CESR genus version override.
        modifiers (dict | None): Optional query-section fields for ``q``.
        attrs (dict | None): Optional extra payload fields.
        ax (list[bool] | None): Single-DAG anchoring requirement. None omits
            the field; otherwise exactly one boolean is required.

    Returns:
        tuple[Serder, bytearray]: Outer exchange serder and detached attachment
            bytes for the signed V2 stream.
    """
    # Get the prior event (apply) and the party to address (its sender)
    prior = apply.said if apply is not None else ""

    # If offer is starting the flow, recp must be provided and xid is
    # generated locally. Otherwise infer both from the prior apply.
    if apply is None:
        if not recp:
            raise ValueError("recp is required when no prior apply is provided")
        xid = Diger(ser=Noncer().qb64b).qb64
        receiver = recp
    else:
        if not apply.ked.get("ri", ""):
            raise ValueError("prior exchange has no explicit receiver")
        if hab.pre != apply.ked["ri"]:
            raise ValueError("sender does not match prior exchange receiver")
        if recp is not None and recp != apply.ked["i"]:
            raise ValueError("recp does not match prior exchange sender")
        receiver = apply.ked["i"]
        pxid = apply.ked.get("x", "")
        if pxid:
            xid = pxid
        else:
            xid = ""
    data = dict(attrs) if attrs is not None else {}
    if "ax" in data:
        raise ValueError("use the ax parameter instead of attrs['ax']")
    data["m"] = message

    # A solicited Offer may use the normative empty-list ditto. An unsolicited
    # Offer has no predecessor to inherit from and must state its plan.
    mods = dict(modifiers) if modifiers else {}
    if "dp" not in mods:
        if apply is not None:
            inherited = apply.ked.get("q", {}).get("dp")
            if error := _disclosurePathError(inherited):
                raise ValueError(f"cannot inherit prior disclosure plan: {error}")
            if not inherited:
                raise ValueError("cannot inherit an empty prior disclosure plan")
            mods["dp"] = []
        else:
            raise ValueError("modifiers['dp'] is required when no prior apply is provided")

    if error := _disclosurePathError(mods["dp"]):
        raise ValueError(error)
    if not mods["dp"] and apply is None:
        raise ValueError("an unsolicited offer must carry a non-empty q.dp plan")
    if not mods["dp"]:
        inherited = apply.ked.get("q", {}).get("dp")
        if error := _disclosurePathError(inherited):
            raise ValueError(f"cannot inherit prior disclosure plan: {error}")
        if not inherited:
            raise ValueError("cannot inherit an empty prior disclosure plan")

    # Validate ax if present
    if ax is not None:
        if not _validSingleDagList(ax, bool):
            raise ValueError("ax must be a one-item list of booleans")
        data["ax"] = ax

    # If prior apply is present, validate ax consistency between the offer and the prior
    if apply is not None:

        # Retrieve the ax field of the prior
        applyAx = apply.ked.get("a", {}).get("ax", [False])
        offerAx = data.get("ax", [False])
        applyRequiresAnchor = applyAx[0] is True
        offerRequiresAnchor = offerAx[0] is True

        if applyRequiresAnchor and not offerRequiresAnchor:
            raise ValueError("offer must echo the prior apply's anchoring requirement")

    # The usual Offer is metadata or partial, but other ACDC variants work too.
    nests = None
    if origin is not None:
        originSerder = _streamSerder(origin)
        if originSerder.proto != Protocols.acdc or originSerder.ilk not in DisclosedNodeIlks:
            raise ValueError("offer origin must identify a disclosed ACDC node")
        data["o"] = [originSerder.said]
    elif artifacts:
        raise ValueError("offer artifacts require an origin")

    if artifacts is not None:
        if not isinstance(artifacts, list):
            raise TypeError("artifacts must be a list when provided")
        if origin is None:
            if artifacts:
                raise ValueError("offer artifacts require an origin")
        else:
            nests = [_normalizeNodeStream(origin, allowAttachments=False)]
            for artifact in artifacts:
                artifactSerder = _streamSerder(artifact)
                if (artifactSerder.proto != Protocols.acdc or
                        artifactSerder.ilk not in DisclosedNodeIlks):
                    raise ValueError("offer artifacts must identify disclosed ACDC nodes")
                nests.append(_normalizeNodeStream(artifact,
                                                  allowAttachments=False))

    # Build the body
    serder = exchange(
        sender=hab.pre,
        receiver=receiver,
        xid=xid,
        prior=prior,
        route="/ipex/offer",
        modifiers=mods,
        stamp=dt,
        attributes=data,
        pvrsn=Vrsn_2_0,
        gvrsn=gvrsn if gvrsn is not None else Vrsn_2_0,
        kind=kind if kind is not None else hab.kever.serder.kind,
    )

    atc = bytearray(_sign(hab=hab, serder=serder, nests=nests, gvrsn=gvrsn))
    del atc[:serder.size]
    return serder, atc


def agree(hab, message, offer, recp=None, dt=None, kind=None, gvrsn=None):
    """Create a signed V2 IPEX ``agree`` exchange.

    Parameters:
        hab (Hab): Habitat creating and signing the exchange.
        message (str): Human-readable agreement message.
        offer (Serder): Prior ``offer`` exchange being accepted.
        recp (str | None): Optional recipient AID. Defaults to the prior
            ``offer`` sender.
        dt (str | None): Optional RFC-3339 timestamp override.
        kind (str | None): Optional serialization kind override.
        gvrsn (Versionage | None): Optional CESR genus version override.

    Returns:
        tuple[Serder, bytearray]: Outer exchange serder and detached attachment
            bytes for the signed V2 stream.
    """
    if not offer.ked.get("ri", ""):
        raise ValueError("prior exchange has no explicit receiver")
    if hab.pre != offer.ked["ri"]:
        raise ValueError("sender does not match prior exchange receiver")
    if recp is not None and recp != offer.ked["i"]:
        raise ValueError("recp does not match prior exchange sender")
    receiver = offer.ked["i"]
    pxid = offer.ked.get("x", "")
    if pxid:
        xid = pxid
    else:
        xid = ""

    data = dict(m=message)
    
    offerAx = offer.ked.get("a", {}).get("ax", [False])
    offerRequiresAnchor = offerAx[0] is True
    if offerRequiresAnchor:
        data["ax"] = [True]

    serder = exchange(
        sender=hab.pre,
        receiver=receiver,
        xid=xid,
        prior=offer.said,
        route="/ipex/agree",
        modifiers=dict(dp=[]),
        stamp=dt,
        attributes=data,
        pvrsn=Vrsn_2_0,
        gvrsn=gvrsn if gvrsn is not None else Vrsn_2_0,
        kind=kind if kind is not None else hab.kever.serder.kind,
    )
    atc = bytearray(_sign(hab=hab, serder=serder,
                          anchor=offerRequiresAnchor, gvrsn=gvrsn))
    del atc[:serder.size]
    return serder, atc


def grant(hab, recp, message, origin=None, artifacts=None, agree=None,
          dt=None, kind=None, gvrsn=None, attrs=None, *, apply=None, ax=None,
          modifiers=None, endorsers=None, anchorers=None):
    """Create a signed V2 IPEX ``grant`` exchange with nested disclosure artifacts.

    Parameters:
        hab (Hab): Habitat creating and signing the exchange.
        recp (str): Recipient AID for the disclosure.
        message (str): Human-readable disclosure message.
        origin (Serder | bytes | bytearray | None): Origin ACDC node identified
            in ``a.o[0]`` and carried as the first nested artifact. A Grant that
            fulfills a disclosure plan requires this origin.
        artifacts (list[Serder | bytes | bytearray] | None): Optional
            additional disclosed ACDC nodes carried after ``origin``.
        agree (Serder | None): Optional prior ``agree`` exchange.
        dt (str | None): Optional RFC-3339 timestamp override.
        kind (str | None): Optional serialization kind override.
        gvrsn (Versionage | None): Optional CESR genus version override.
        attrs (dict | None): Optional extra payload fields.
        apply (Serder | None): Optional prior ``apply`` for a direct
            apply-to-grant flow. Mutually exclusive with ``agree``.
        ax (list[bool] | None): Single-DAG anchoring requirement. None omits
            the field; otherwise exactly one boolean is required.
        modifiers (dict | None): Query-section fields. A prior-linked Grant
            defaults to an empty ``dp`` ditto. A bare one-node Grant derives a
            root-presence plan; a multi-node Grant requires an explicit plan.
        endorsers (list[Hab] | None): Additional local AIDs that sign the Grant.
            The sender remains the Discloser and KRAM-authenticated outer sender.
        anchorers (list[Hab] | None): Explicit local AIDs that KEL-anchor the
            grant. None preserves the truthy-``ax`` sender-anchor default; an
            empty list leaves anchoring to a presentation registry.

    Returns:
        tuple[Serder, bytearray]: Outer exchange serder and detached attachment
            bytes for the signed V2 stream.
    """
    # Make sure there is only one prior
    if agree is not None and apply is not None:
        raise ValueError("agree and apply are mutually exclusive grant priors")

    previous = agree if agree is not None else apply
    prior = previous.said if previous is not None else ""
    
    if previous is None:
        if not recp:
            raise ValueError("recp is required when no prior exchange is provided")
        xid = Diger(ser=Noncer().qb64b).qb64
    else:
        if not previous.ked.get("ri", ""):
            raise ValueError("prior exchange has no explicit receiver")
        if hab.pre != previous.ked["ri"]:
            raise ValueError("sender does not match prior exchange receiver")
        if recp != previous.ked["i"]:
            raise ValueError("recp does not match prior exchange sender")
        pxid = previous.ked.get("x", "")
        if pxid:
            xid = pxid
        else:
            xid = ""
    data = dict(attrs) if attrs is not None else {}
    if "ax" in data:
        raise ValueError("use the ax parameter instead of attrs['ax']")
    data["m"] = message

    originSerder = None
    if origin is not None:
        originSerder = _streamSerder(origin)
        if (originSerder.proto != Protocols.acdc
                or originSerder.ilk not in DisclosedNodeIlks):
            raise ValueError("grant origin and artifacts must be disclosed ACDC nodes")

    if artifacts is not None:
        if not isinstance(artifacts, list):
            raise TypeError("artifacts must be a list when provided")
        for artifact in artifacts:
            artifactSerder = _streamSerder(artifact)
            if (artifactSerder.proto != Protocols.acdc
                    or artifactSerder.ilk not in DisclosedNodeIlks):
                raise ValueError("grant origin and artifacts must be disclosed ACDC nodes")

    mods = dict(modifiers) if modifiers else {}
    if "dp" not in mods:
        if previous is not None or origin is None:
            mods["dp"] = []   # ditto the prior's disclosure plan
        elif not artifacts:
            schema = originSerder.schema
            if isinstance(schema, Mapping):
                schema = schema.get("$id")
            mods["dp"] = [[schema, "/", []]]
        else:
            raise ValueError("a bare multi-node Grant requires an explicit disclosure plan")
    if error := _disclosurePathError(mods["dp"]):
        raise ValueError(error)

    if previous is None:
        if mods["dp"] and origin is None:
            raise ValueError("a non-empty disclosure plan requires an origin")
        if not mods["dp"]:
            raise ValueError("a bare Grant may not use empty q.dp without a prior")

    if ax is not None:
        if not _validSingleDagList(ax, bool):
            raise ValueError("ax must be a one-item list of booleans")
        data["ax"] = ax

    grantAx = data.get("ax", [False])
    grantRequiresAnchor = grantAx[0] is True
    if previous is not None:
        previousAx = previous.ked.get("a", {}).get("ax", [False])
        previousRequiresAnchor = previousAx[0] is True
        if grantRequiresAnchor != previousRequiresAnchor:
            raise ValueError("grant must echo the prior exchange's anchoring requirement")

    # A vacuous Grant explicitly names no origin and carries no nested body.
    if origin is None:
        if artifacts:
            raise ValueError("grant artifacts require an origin")
        data["o"] = []
        nests = None
    else:
        data["o"] = [originSerder.said]
        nests = [_normalizeNodeStream(origin)]

    if artifacts is not None:
        for artifact in artifacts:
            nests.append(_normalizeNodeStream(artifact))

    serder = exchange(
        sender=hab.pre,
        receiver=recp,
        xid=xid,
        prior=prior,
        route="/ipex/grant",
        modifiers=mods,
        stamp=dt,
        attributes=data,
        pvrsn=Vrsn_2_0,
        gvrsn=gvrsn if gvrsn is not None else Vrsn_2_0,
        kind=kind if kind is not None else hab.kever.serder.kind,
    )
    # Preserve None as the signal for default sender anchoring.
    explicitAnchorers = None if anchorers is None else list(anchorers)

    # Anchor with the sender only when ax is true and no list overrides it.
    senderAnchor = grantRequiresAnchor and explicitAnchorers is None

    # Allow callers to name the sender explicitly among anchorers.
    if explicitAnchorers is not None:
        # Iterate over a copy because the sender entry is removed in place.
        for anchorer in list(explicitAnchorers):
            # Convert an explicit sender entry into the implied source couple.
            if anchorer.pre == hab.pre:
                senderAnchor = True

                # Avoid emitting a redundant explicit source triple.
                explicitAnchorers.remove(anchorer)

    # Sign and attach all selected sender, endorser, and anchorer factors.
    atc = bytearray(_sign(hab=hab, serder=serder, nests=nests,
                          anchor=senderAnchor,
                          endorsers=endorsers,
                          anchorers=explicitAnchorers,
                          gvrsn=gvrsn))
    # Return attachments separately from the immutable EXN body.
    del atc[:serder.size]
    return serder, atc


def admit(hab, message, grant, recp=None, dt=None, kind=None, gvrsn=None):
    """Create a signed V2 IPEX ``admit`` exchange.

    Parameters:
        hab (Hab): Habitat creating and signing the exchange.
        message (str): Human-readable admission message.
        grant (Serder): Prior ``grant`` exchange being acknowledged.
        recp (str | None): Optional recipient AID. Defaults to the prior
            ``grant`` sender.
        dt (str | None): Optional RFC-3339 timestamp override.
        kind (str | None): Optional serialization kind override.
        gvrsn (Versionage | None): Optional CESR genus version override.

    Returns:
        tuple[Serder, bytearray]: Outer exchange serder and detached attachment
            bytes for the signed V2 stream.
    """
    if not grant.ked.get("ri", ""):
        raise ValueError("prior exchange has no explicit receiver")
    if hab.pre != grant.ked["ri"]:
        raise ValueError("sender does not match prior exchange receiver")
    if recp is not None and recp != grant.ked["i"]:
        raise ValueError("recp does not match prior exchange sender")
    receiver = grant.ked["i"]
    pxid = grant.ked.get("x", "")
    if pxid:
        xid = pxid
    else:
        xid = ""
    grantAx = grant.ked.get("a", {}).get("ax", [False])
    grantRequiresAnchor = grantAx[0] is True
    data = dict(m=message)
    if grantRequiresAnchor:
        data["ax"] = [True]

    serder = exchange(
        sender=hab.pre,
        receiver=receiver,
        xid=xid,
        prior=grant.said,
        route="/ipex/admit",
        stamp=dt,
        attributes=data,
        pvrsn=Vrsn_2_0,
        gvrsn=gvrsn if gvrsn is not None else Vrsn_2_0,
        kind=kind if kind is not None else hab.kever.serder.kind,
    )
    atc = bytearray(_sign(hab=hab, serder=serder,
                          anchor=grantRequiresAnchor, gvrsn=gvrsn))
    del atc[:serder.size]
    return serder, atc


def spurn(hab, message, spurned, recp=None, dt=None, kind=None, gvrsn=None):
    """Create a signed V2 IPEX ``spurn`` exchange.

    Parameters:
        hab (Hab): Habitat creating and signing the exchange.
        message (str): Human-readable rejection message.
        spurned (Serder): Prior exchange being rejected.
        recp (str | None): Optional recipient AID. Defaults to the spurned
            message's sender.
        dt (str | None): Optional RFC-3339 timestamp override.
        kind (str | None): Optional serialization kind override.
        gvrsn (Versionage | None): Optional CESR genus version override.

    Returns:
        tuple[Serder, bytearray]: Outer exchange serder and detached attachment
            bytes for the signed V2 stream.
    """
    if not spurned.ked.get("ri", ""):
        raise ValueError("prior exchange has no explicit receiver")
    if spurned.ked["r"] == "/ipex/grant" and spurned.ked.get("p", ""):
        raise ValueError("only flow-starting grants may be spurned")
    if hab.pre != spurned.ked["ri"]:
        raise ValueError("sender does not match prior exchange receiver")
    if recp is not None and recp != spurned.ked["i"]:
        raise ValueError("recp does not match prior exchange sender")
    receiver = spurned.ked["i"]
    pxid = spurned.ked.get("x", "")
    if pxid:
        xid = pxid
    else:
        xid = ""
    serder = exchange(
        sender=hab.pre,
        receiver=receiver,
        xid=xid,
        prior=spurned.said,
        route="/ipex/spurn",
        stamp=dt,
        attributes=dict(m=message),
        pvrsn=Vrsn_2_0,
        gvrsn=gvrsn if gvrsn is not None else Vrsn_2_0,
        kind=kind if kind is not None else hab.kever.serder.kind,
    )
    atc = bytearray(_sign(hab=hab, serder=serder, gvrsn=gvrsn))
    del atc[:serder.size]
    return serder, atc


def loadHandlers(hby, exc, notifier, rgy=None, *, graphPolicy=None, sections=None):
    """Register ACDC v2 IPEX routes with one explicit semantic context.

    Schema lookup uses the same section store as the application's parser.

    Args:
        hby (Habery): Owner of KEL and EXN evidence.
        exc (Exchanger): Router receiving the six ACDC v2 IPEX handlers.
        notifier: Receiver of accepted-message notifications.
        rgy (Regery | None): Issuer registry evidence owner.
        graphPolicy: Explicit local graph policy, or None for default semantics.
        sections (SectionBaser | None): Independent schema store used by parsing.

    Returns:
        AcdcV2IpexVerification: Shared semantic context for explicit wallet injection.
    """
    verification = AcdcV2IpexVerification(hby, rgy, graphPolicy=graphPolicy, sections=sections)
    for verb in Ipex:
        exc.addHandler(verification.handler(f"/ipex/{verb}", notifier))
    return verification
