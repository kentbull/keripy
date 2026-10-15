# -*- coding: utf-8 -*-
"""
keri.core.annotating module

Provides support for annotating CESR streams.
"""
import json
import re
from base64 import urlsafe_b64encode as encodeB64
from dataclasses import dataclass

from ..kering import (sniff, smell, Colds, Kinds, Version, Vrsn_1_0, Vrsn_2_0,
                      DeserializeError, ExtractionError, ColdStartError,
                      InvalidVersionError, ProtocolError, VersionError)

from .coring import (Matter, Verser, Ilker, Prefixer, Verfer, Diger, Saider,
                     Number, Seqner, Dater, Texter, Pather, Cigar, Labeler,
                     Traitor)
from .counting import Counter, Codens, GenDex, ProGen
from .indexing import Indexer, Siger
from .serdering import Serder, Serdery


@dataclass(frozen=True)
class AnnotCodex:
    """Annotation parser counter code groups selected by CESR version."""
    FrameGroups: frozenset
    WrapperGroups: frozenset
    AttachmentWrappers: frozenset
    AttachmentGroups: frozenset
    FrameStarts: frozenset
    NonNativeBodyGroups: frozenset
    GenusVersion: str


@dataclass(frozen=True)
class AnnotLine:
    """One semantically classified annotation output line."""
    value: str
    comment: str | None = None
    indent: int = 0
    kind: str = "primitive"


_ANSI_RESET = "\033[0m"

_DEFAULT_THEME = {
    "group": "\033[36m",
    "body": "\033[32m",
    "signature": "\033[33m",
    "opaque": "\033[91m",
    "primitive": "",
    "comment": "\033[90m",
    "said": "\033[94m",
    "json_key": "\033[94m",
    "json_string": "\033[32m",
    "json_number": "\033[33m",
    "json_literal": "\033[96m",
    "json_punct": "\033[90m",
}

_JSON_NUMBER_RE = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")
_SAID_RE = re.compile(r"(said=)(\S+)")
_DENOT_WHITESPACE = " \t\r\n\v\f"


_FRAME_GROUP_CODENS = (
    Codens.FixBodyGroup,
    Codens.BigFixBodyGroup,
    Codens.MapBodyGroup,
    Codens.BigMapBodyGroup,
    Codens.NonNativeBodyGroup,
    Codens.BigNonNativeBodyGroup,
)

_WRAPPER_GROUP_CODENS = (
    Codens.GenericGroup,
    Codens.BigGenericGroup,
    Codens.BodyWithAttachmentGroup,
    Codens.BigBodyWithAttachmentGroup,
)

_ATTACHMENT_WRAPPER_CODENS = (
    Codens.AttachmentGroup,
    Codens.BigAttachmentGroup,
)

_NON_NATIVE_BODY_CODENS = (
    Codens.NonNativeBodyGroup,
    Codens.BigNonNativeBodyGroup,
)

_ATTACHMENT_GROUP_CODENS = (
    Codens.ControllerIdxSigs,
    Codens.BigControllerIdxSigs,
    Codens.WitnessIdxSigs,
    Codens.BigWitnessIdxSigs,
    Codens.NonTransReceiptCouples,
    Codens.BigNonTransReceiptCouples,
    Codens.TransReceiptQuadruples,
    Codens.BigTransReceiptQuadruples,
    Codens.FirstSeenReplayCouples,
    Codens.BigFirstSeenReplayCouples,
    Codens.TransIdxSigGroups,
    Codens.BigTransIdxSigGroups,
    Codens.TransLastIdxSigGroups,
    Codens.BigTransLastIdxSigGroups,
    Codens.SealSourceCouples,
    Codens.BigSealSourceCouples,
    Codens.SealSourceTriples,
    Codens.BigSealSourceTriples,
    Codens.SealSourceLastSingles,
    Codens.BigSealSourceLastSingles,
    Codens.PathedMaterialCouples,
    Codens.BigPathedMaterialCouples,
    Codens.DigestSealSingles,
    Codens.BigDigestSealSingles,
    Codens.MerkleRootSealSingles,
    Codens.BigMerkleRootSealSingles,
    Codens.BackerRegistrarSealCouples,
    Codens.BigBackerRegistrarSealCouples,
    Codens.TypedDigestSealCouples,
    Codens.BigTypedDigestSealCouples,
    Codens.BlindedStateQuadruples,
    Codens.BigBlindedStateQuadruples,
    Codens.BoundStateSextuples,
    Codens.BigBoundStateSextuples,
    Codens.TypedMediaQuadruples,
    Codens.BigTypedMediaQuadruples,
    Codens.ESSRPayloadGroup,
    Codens.BigESSRPayloadGroup,
)


def _codex_codes(codex, codenames):
    """Return code values from ``codex`` for available counter code names."""
    return frozenset(code for name in codenames
                     if (code := getattr(codex, name, None)) is not None)


def _latest_minor(table, version):
    """Return latest supported minor version after validating ``version``."""
    if version.major not in table:
        raise InvalidVersionError(f"Unsupported major version={version.major}.")

    latest = list(table[version.major])[-1]
    if version.minor > latest:
        raise InvalidVersionError(f"Minor version={version.minor} exceeds "
                                  f"latest supported minor version={latest}.")

    return latest


def _annot_codex(version):
    """Return annotation parser code groups for ``version``."""
    latest = _latest_minor(Counter.Codes, version)
    codes = Counter.Codes[version.major][latest]
    sucodes = Counter.SUCodes[version.major][latest]
    mucodes = Counter.MUCodes[version.major][latest]

    frame_groups = _codex_codes(mucodes, _FRAME_GROUP_CODENS)
    wrapper_groups = _codex_codes(sucodes, _WRAPPER_GROUP_CODENS)
    attachment_wrappers = _codex_codes(sucodes, _ATTACHMENT_WRAPPER_CODENS)

    return AnnotCodex(
        FrameGroups=frame_groups,
        WrapperGroups=wrapper_groups,
        AttachmentWrappers=attachment_wrappers,
        AttachmentGroups=_codex_codes(codes, _ATTACHMENT_GROUP_CODENS),
        FrameStarts=frame_groups | wrapper_groups,
        NonNativeBodyGroups=_codex_codes(mucodes, _NON_NATIVE_BODY_CODENS),
        GenusVersion=getattr(codes, Codens.KERIACDCGenusVersion),
    )


def annot(ims, *, pretty=False):
    """Annotate CESR stream.

    Returns:
        annotation (str): annotation of input CESR stream

    Parameters:
        ims (str | bytes | bytearray | memoryview): CESR incoming message stream
           as qb64 or qb2
        pretty (bool): True means pretty-print field-map message bodies when
           possible. Pretty output is intended for display, not byte-exact
           deannotation.
    """
    if isinstance(ims, str):
        ims = bytearray(ims.encode("utf-8"))
    elif not isinstance(ims, bytearray):
        ims = bytearray(ims)

    return Annotator(pretty=pretty).annotate(ims)


def denot(ams):
    """De-annotate CESR stream.

    Returns:
        dms (bytes): deannotation of input annotated CESR message stream

    Parameters:
        ams (str | bytes | bytearray | memoryview): CESR annotated message
           stream text
    """
    if isinstance(ams, str):
        text = ams
    elif isinstance(ams, memoryview):
        text = ams.tobytes().decode("utf-8")
    elif isinstance(ams, (bytes, bytearray)):
        text = bytes(ams).decode("utf-8")
    else:
        raise TypeError(f"Invalid annotated stream type={type(ams)}.")

    dms = bytearray()
    in_string = False
    escaped = False
    in_comment = False

    for char in text:
        if in_comment:
            if char in "\r\n":
                in_comment = False
            continue

        if in_string:
            dms.extend(char.encode("utf-8"))
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == "#":
            in_comment = True
            continue

        if char == '"':
            in_string = True
            dms.extend(b'"')
            continue

        if char in _DENOT_WHITESPACE:
            continue

        dms.extend(char.encode("utf-8"))

    return bytes(dms)


def _ansi(value, code):
    """Wrap ``value`` in ANSI color ``code`` when configured."""
    if not value or not code:
        return value
    return f"{code}{value}{_ANSI_RESET}"


def _plain_line(line):
    """Render one annotation line without display color."""
    prefix = "  " * line.indent
    if line.comment:
        return f"{prefix}{line.value} # {line.comment}"
    return f"{prefix}{line.value}"


def _colored_line(line, theme):
    """Render one annotation line with semantic display color."""
    prefix = "  " * line.indent
    value = _colored_value(line.value, line.kind, theme)
    if line.comment:
        return f"{prefix}{value} # {_colored_comment(line.comment, theme)}"
    return f"{prefix}{value}"


def _colored_value(value, kind, theme):
    """Color an annotation value according to its semantic line kind."""
    if kind == "json":
        return _colored_json(value, theme)
    return _ansi(value, theme.get(kind, ""))


def _colored_comment(comment, theme):
    """Color annotation comments, giving SAIDs a stronger accent."""
    parts = []
    start = 0
    for match in _SAID_RE.finditer(comment):
        parts.append(_ansi(comment[start:match.start()], theme["comment"]))
        parts.append(_ansi(match.group(1), theme["comment"]))
        parts.append(_ansi(match.group(2), theme["said"]))
        start = match.end()
    parts.append(_ansi(comment[start:], theme["comment"]))
    return "".join(parts)


def _colored_json(value, theme):
    """Token-color one pretty JSON line without changing its text content."""
    out = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == '"':
            end = _json_string_end(value, i)
            token = value[i:end]
            look = end
            while look < len(value) and value[look].isspace():
                look += 1
            key = look < len(value) and value[look] == ":"
            out.append(_ansi(token, theme["json_key" if key else "json_string"]))
            i = end
            continue

        if char == "-" or char.isdigit():
            match = _JSON_NUMBER_RE.match(value, i)
            if match is not None:
                out.append(_ansi(match.group(0), theme["json_number"]))
                i = match.end()
                continue

        matched = False
        for literal in ("true", "false", "null"):
            if value.startswith(literal, i):
                out.append(_ansi(literal, theme["json_literal"]))
                i += len(literal)
                matched = True
                break
        if matched:
            continue

        if char in "{}[]:,":
            out.append(_ansi(char, theme["json_punct"]))
        else:
            out.append(char)
        i += 1

    return "".join(out)


def _json_string_end(value, start):
    """Return the exclusive end offset of a JSON string token."""
    i = start + 1
    escaped = False
    while i < len(value):
        char = value[i]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            return i + 1
        i += 1
    return len(value)


def _infer_kind(comment):
    """Infer a semantic line kind from existing annotation comments."""
    if not comment:
        return "primitive"

    lowered = comment.lower()
    if "opaque" in lowered:
        return "opaque"
    if ("signature" in lowered or "siger" in lowered or
            "cigar" in lowered or "_sig" in lowered):
        return "signature"
    if comment.startswith("Counter "):
        return "group"
    if comment.startswith("SERDER "):
        return "body"
    return "primitive"


class Annotator:
    """Small annotation-only CESR stream parser.

    This parser intentionally stops at splitting and rendering CESR frames. It
    does not route parsed messages into KEL/TEL/EXN/RPY processors.
    """

    def __init__(self, *, pretty=False):
        self.pretty = pretty
        self.lines = []
        self.genus = GenDex.KERI
        self.serdery = Serdery(version=Version)

    def annotate(self, ims, *, colored=False, theme=None):
        """Render annotated text for ``ims`` while consuming the input stream."""
        self.parse_stream(ims=ims, indent=0, version=Vrsn_2_0)
        return self.render(colored=colored, theme=theme)

    def render(self, *, colored=False, theme=None):
        """Render parsed annotation lines as plain or colored display text."""
        if colored:
            theme = {**_DEFAULT_THEME, **(theme or {})}
            return "\n".join(_colored_line(line, theme) for line in self.lines)
        return "\n".join(_plain_line(line) for line in self.lines)

    def parse_stream(self, ims, indent=0, version=Vrsn_2_0):
        """Parse one complete stream or one already-bounded wrapper payload."""
        while ims:
            cold = sniff(ims)

            if cold == Colds.msg:
                version = self.parse_message(ims=ims, indent=indent,
                                             version=version)
                self.parse_attachments(ims=ims, indent=indent,
                                       version=version)
                continue

            if cold not in (Colds.txt, Colds.bny):
                raise ColdStartError(f"Expecting stream tritet={cold}")

            ctr, version = self.peek_counter(ims=ims, cold=cold,
                                             version=version,
                                             role="frame")
            acodex = _annot_codex(version)

            if ctr.code == acodex.GenusVersion:
                self.consume_counter(ims=ims, cold=cold, ctr=ctr,
                                     indent=indent)
                version = Counter.b64ToVer(ctr.countToB64(l=3))
                continue

            if ctr.code in acodex.WrapperGroups:
                self.parse_wrapper(ims=ims, cold=cold, ctr=ctr,
                                   indent=indent, version=version)
                continue

            if ctr.code in acodex.FrameGroups:
                version = self.parse_body_group(ims=ims, cold=cold, ctr=ctr,
                                                indent=indent,
                                                version=version)
                self.parse_attachments(ims=ims, indent=indent,
                                       version=version)
                continue

            if (ctr.code in acodex.AttachmentWrappers or
                    ctr.code in acodex.AttachmentGroups):
                self.parse_attachment_group(ims=ims, cold=cold, ctr=ctr,
                                            indent=indent, version=version)
                continue

            raise ExtractionError(f"Unexpected counter={ctr.name} at stream start")

    def parse_attachments(self, ims, indent, version):
        """Parse trailing attachment groups until the next frame boundary."""
        while ims:
            cold = sniff(ims)
            if cold == Colds.msg:
                return
            if cold not in (Colds.txt, Colds.bny):
                return

            ctr, aversion = self.peek_counter(ims=ims, cold=cold,
                                              version=version,
                                              role="attachment")
            acodex = _annot_codex(aversion)
            if ctr.code == acodex.GenusVersion:
                return
            if ctr.code in acodex.FrameStarts:
                return
            if (ctr.code in acodex.AttachmentWrappers or
                    ctr.code in acodex.AttachmentGroups):
                self.parse_attachment_group(ims=ims, cold=cold, ctr=ctr,
                                            indent=indent, version=aversion)
                version = aversion
                continue
            return

    def parse_message(self, ims, indent, version):
        """Parse a JSON/CBOR/MGPK message-domain body."""
        _annot_codex(version)
        smellage = smell(ims)
        self.check_message_versions(proto=smellage.proto, pvrsn=smellage.pvrsn,
                                    gvrsn=smellage.gvrsn, svrsn=version)
        serder = self.serdery.reap(ims=ims, genus=self.genus, svrsn=version,
                                   verify=False)
        raw = serder.raw
        comment = self.serder_comment(serder=serder)

        if self.pretty and serder.kind == Kinds.json:
            try:
                pretty = json.dumps(serder.sad, indent=2)
            except Exception:
                pretty = raw.decode("utf-8", "replace")
            lines = pretty.splitlines()
            for i, line in enumerate(lines):
                self.emit(line, comment if i == len(lines) - 1 else None,
                          indent, kind="json")
        else:
            self.emit(raw.decode("utf-8", "replace"), comment, indent,
                      kind="body")

        return self.version_from_serder(serder=serder, current=version)

    def parse_body_group(self, ims, cold, ctr, indent, version):
        """Parse a native or non-native body group."""
        qb64, payload = self.consume_counter_payload(ims=ims, cold=cold,
                                                     ctr=ctr)
        self.emit(qb64, self.counter_comment(ctr=ctr, cold=cold), indent)

        if ctr.code in _annot_codex(version).NonNativeBodyGroups:
            self.parse_non_native_payload(payload=payload, cold=cold,
                                          indent=indent + 1,
                                          version=version)
            return version

        full = self.text_domain(qb64=qb64, payload=payload, cold=cold)
        name = ctr.name.removeprefix("Big")
        fixed = name == Codens.FixBodyGroup
        try:
            self.check_native_versions(raw=full, ctr=ctr, fixed=fixed,
                                       svrsn=version)
        except (DeserializeError, InvalidVersionError, ProtocolError):
            raise
        except Exception:
            pass

        try:
            serder = self.serdery.reap(ims=bytearray(full), genus=self.genus,
                                       svrsn=version, ctr=ctr, size=len(full),
                                       fixed=fixed, verify=False)
            version = self.version_from_serder(serder=serder, current=version)
        except Exception:
            serder = None

        self.parse_token_stream(ims=bytearray(full[ctr.fullSize:]),
                                indent=indent + 1, version=version,
                                cold=Colds.txt)

        return version

    def parse_non_native_payload(self, payload, cold, indent, version):
        """Render a non-native body, falling back to opaque CESR payload."""
        work = bytearray(payload)
        try:
            texter = self.extract(Texter, ims=work, cold=cold)
            if work:
                raise ExtractionError("Non-native Texter left trailing bytes")
            body = bytearray(texter.raw)
            try:
                smellage = smell(body)
                self.check_message_versions(proto=smellage.proto,
                                            pvrsn=smellage.pvrsn,
                                            gvrsn=smellage.gvrsn,
                                            svrsn=version)
            except (DeserializeError, InvalidVersionError, ProtocolError):
                raise
            except Exception:
                pass

            serder = self.serdery.reap(ims=body, genus=self.genus,
                                       svrsn=version, verify=False)
            self.emit(texter.qb64, f"Texter {texter.name}", indent)
            self.emit(serder.raw.decode("utf-8", "replace"),
                      self.serder_comment(serder=serder), indent + 1,
                      kind="body")
            return
        except (DeserializeError, InvalidVersionError, ProtocolError):
            raise
        except Exception:
            pass

        self.emit_opaque(payload=payload, cold=cold, indent=indent,
                         comment="OPAQUE CESR body (non-serder fallback)")

    def parse_wrapper(self, ims, cold, ctr, indent, version):
        """Parse one stream wrapper and recursively render its bounded payload."""
        qb64, payload = self.consume_counter_payload(ims=ims, cold=cold,
                                                     ctr=ctr)
        self.emit(qb64, self.counter_comment(ctr=ctr, cold=cold), indent)

        sub = bytearray(payload)
        try:
            self.parse_stream(ims=sub, indent=indent + 1, version=version)
            if sub:
                raise ExtractionError("Wrapper payload not fully consumed")
        except Exception:
            self.emit_opaque(payload=payload, cold=cold, indent=indent + 1,
                             comment="opaque wrapper payload")

    def parse_attachment_group(self, ims, cold, ctr, indent, version):
        """Parse one attachment counter group or wrapper."""
        if ctr.name.removeprefix("Big") in (Codens.ControllerIdxSigs,
                                            Codens.WitnessIdxSigs):
            if self.can_parse_indexed_signature_count(ims=ims, cold=cold,
                                                      ctr=ctr):
                self.parse_indexed_signature_count(ims=ims, cold=cold,
                                                   ctr=ctr, indent=indent)
                return

        acodex = _annot_codex(version)
        if (version.major == Vrsn_1_0.major and
                ctr.code not in acodex.AttachmentWrappers):
            if self.parse_v1_attachment_count_group(ims=ims, cold=cold,
                                                    ctr=ctr, indent=indent,
                                                    version=version):
                return

        qb64, payload = self.consume_counter_payload(ims=ims, cold=cold,
                                                     ctr=ctr)
        self.emit(qb64, self.counter_comment(ctr=ctr, cold=cold), indent)

        sub = bytearray(payload)
        if ctr.code in acodex.AttachmentWrappers:
            try:
                self.parse_attachment_payload(ims=sub, cold=cold,
                                              indent=indent + 1,
                                              version=version)
                if sub:
                    raise ExtractionError("Attachment wrapper left bytes")
            except Exception:
                self.emit_opaque(payload=payload, cold=cold,
                                 indent=indent + 1,
                                 comment="opaque wrapper payload")
            return

        self.parse_attachment_payload_by_counter(ctr=ctr, ims=sub, cold=cold,
                                                 indent=indent + 1,
                                                 version=version)
        if sub:
            self.emit_opaque(payload=bytes(sub), cold=cold, indent=indent + 1,
                             comment="opaque attachment tail")
            sub.clear()

    def parse_attachment_payload(self, ims, cold, indent, version):
        """Parse the payload of an AttachmentGroup wrapper."""
        while ims:
            nested_cold = sniff(ims)
            if nested_cold == Colds.msg:
                self.parse_message(ims=ims, indent=indent, version=version)
                continue
            if nested_cold not in (Colds.txt, Colds.bny):
                self.emit_opaque(payload=bytes(ims), cold=cold, indent=indent,
                                 comment="opaque wrapper payload")
                ims.clear()
                return

            ctr, version = self.peek_counter(ims=ims, cold=nested_cold,
                                             version=version,
                                             role="attachment")
            acodex = _annot_codex(version)
            if ctr.code == acodex.GenusVersion:
                self.consume_counter(ims=ims, cold=nested_cold, ctr=ctr,
                                     indent=indent)
                version = Counter.b64ToVer(ctr.countToB64(l=3))
                continue

            self.parse_attachment_group(ims=ims, cold=nested_cold, ctr=ctr,
                                        indent=indent, version=version)

    def parse_attachment_payload_by_counter(self, ctr, ims, cold, indent,
                                            version):
        """Dispatch annotation of covered attachment group tuple shapes."""
        name = ctr.name.removeprefix("Big")

        if name in (Codens.ControllerIdxSigs, Codens.WitnessIdxSigs):
            self.parse_repeating(ims=ims, cold=cold, indent=indent,
                                 classes=(Siger,),
                                 labels=("indexed signature",))
        elif name == Codens.NonTransReceiptCouples:
            self.parse_repeating(ims=ims, cold=cold, indent=indent,
                                 classes=(Verfer, Cigar),
                                 labels=("receipt verifier",
                                         "non-transferable receipt"))
        elif name == Codens.TransReceiptQuadruples:
            self.parse_repeating(ims=ims, cold=cold, indent=indent,
                                 classes=(Prefixer, Seqner, Saider, Siger),
                                 labels=("receipt signer", "establishment sn",
                                         "establishment digest",
                                         "indexed receipt"))
        elif name == Codens.FirstSeenReplayCouples:
            self.parse_repeating(ims=ims, cold=cold, indent=indent,
                                 classes=(Seqner, Dater),
                                 labels=("first seen sn", "first seen time"))
        elif name == Codens.TransIdxSigGroups:
            while ims:
                self.emit_extracted(Prefixer, ims, cold, indent,
                                    "signer prefix")
                self.emit_extracted(Seqner, ims, cold, indent,
                                    "establishment sn")
                self.emit_extracted(Saider, ims, cold, indent,
                                    "establishment digest")
                ictr = self.extract(Counter, ims=ims, cold=cold,
                                    version=version)
                self.emit(ictr.qb64, self.counter_comment(ictr, cold), indent)
                count = ictr.byteCount(cold=cold)
                nested = bytearray(ims[:count])
                del ims[:count]
                self.parse_attachment_payload_by_counter(ictr, nested, cold,
                                                         indent + 1, version)
        elif name == Codens.TransLastIdxSigGroups:
            while ims:
                self.emit_extracted(Prefixer, ims, cold, indent,
                                    "signer prefix")
                ictr = self.extract(Counter, ims=ims, cold=cold,
                                    version=version)
                self.emit(ictr.qb64, self.counter_comment(ictr, cold), indent)
                count = ictr.byteCount(cold=cold)
                nested = bytearray(ims[:count])
                del ims[:count]
                self.parse_attachment_payload_by_counter(ictr, nested, cold,
                                                         indent + 1, version)
        elif name == Codens.SealSourceCouples:
            self.parse_repeating(ims=ims, cold=cold, indent=indent,
                                 classes=(Seqner, Saider),
                                 labels=("source sn", "source digest"))
        elif name == Codens.SealSourceTriples:
            self.parse_repeating(ims=ims, cold=cold, indent=indent,
                                 classes=(Prefixer, Seqner, Saider),
                                 labels=("source prefix", "source sn",
                                         "source digest"))
        elif name == Codens.SealSourceLastSingles:
            self.parse_repeating(ims=ims, cold=cold, indent=indent,
                                 classes=(Prefixer,),
                                 labels=("source prefix",))
        elif name in (Codens.DigestSealSingles, Codens.MerkleRootSealSingles):
            self.parse_repeating(ims=ims, cold=cold, indent=indent,
                                 classes=(Diger,), labels=("seal digest",))
        elif name == Codens.TypedDigestSealCouples:
            self.parse_repeating(ims=ims, cold=cold, indent=indent,
                                 classes=(Verser, Diger),
                                 labels=("seal type", "seal digest"))
        elif name == Codens.BackerRegistrarSealCouples:
            self.parse_repeating(ims=ims, cold=cold, indent=indent,
                                 classes=(Prefixer, Diger),
                                 labels=("registry prefix", "seal digest"))
        elif name == Codens.PathedMaterialCouples:
            self.parse_pathed_material(ims=ims, cold=cold, indent=indent,
                                       version=version)
        elif name == Codens.ESSRPayloadGroup:
            self.parse_token_stream(ims=ims, indent=indent, version=version,
                                    cold=cold)
        elif name in (Codens.BlindedStateQuadruples, Codens.BoundStateSextuples,
                      Codens.TypedMediaQuadruples):
            self.parse_token_stream(ims=ims, indent=indent, version=version,
                                    cold=cold)
        else:
            self.parse_token_stream(ims=ims, indent=indent, version=version,
                                    cold=cold)

    def can_parse_indexed_signature_count(self, ims, cold, ctr):
        """Return True when count can be interpreted as number of sigers."""
        if ctr.count <= 0:
            return False

        size = ctr.byteSize(cold=cold)
        if len(ims) < size:
            return False

        copy = bytearray(ims[size:])
        try:
            for _ in range(ctr.count):
                self.extract(Siger, ims=copy, cold=cold)
            return True
        except Exception:
            return False

    def parse_indexed_signature_count(self, ims, cold, ctr, indent):
        """Parse indexed signatures when group count is an element count."""
        size = ctr.byteSize(cold=cold)
        del ims[:size]
        self.emit(ctr.qb64, self.counter_comment(ctr=ctr, cold=cold), indent)
        for _ in range(ctr.count):
            self.emit_extracted(Siger, ims, cold, indent + 1,
                                "indexed signature")

    def parse_v1_attachment_count_group(self, ims, cold, ctr, indent, version):
        """Parse v1 attachment counters whose count is an element count."""
        name = ctr.name.removeprefix("Big")
        size = ctr.byteSize(cold=cold)

        def emit_counter():
            del ims[:size]
            self.emit(ctr.qb64, self.counter_comment(ctr=ctr, cold=cold),
                      indent)

        if name in (Codens.ControllerIdxSigs, Codens.WitnessIdxSigs):
            emit_counter()
            for _ in range(ctr.count):
                self.emit_extracted(Siger, ims, cold, indent + 1,
                                    "indexed signature")
            return True
        if name == Codens.NonTransReceiptCouples:
            emit_counter()
            self.parse_repeating_count(ims=ims, cold=cold, indent=indent + 1,
                                       count=ctr.count,
                                       classes=(Verfer, Cigar),
                                       labels=("receipt verifier",
                                               "non-transferable receipt"))
            return True
        if name == Codens.TransReceiptQuadruples:
            emit_counter()
            self.parse_repeating_count(ims=ims, cold=cold, indent=indent + 1,
                                       count=ctr.count,
                                       classes=(Prefixer, Seqner, Saider,
                                                Siger),
                                       labels=("receipt signer",
                                               "establishment sn",
                                               "establishment digest",
                                               "indexed receipt"))
            return True
        if name == Codens.FirstSeenReplayCouples:
            emit_counter()
            self.parse_repeating_count(ims=ims, cold=cold, indent=indent + 1,
                                       count=ctr.count,
                                       classes=(Seqner, Dater),
                                       labels=("first seen sn",
                                               "first seen time"))
            return True
        if name == Codens.SealSourceCouples:
            emit_counter()
            self.parse_repeating_count(ims=ims, cold=cold, indent=indent + 1,
                                       count=ctr.count,
                                       classes=(Seqner, Saider),
                                       labels=("source sn", "source digest"))
            return True
        if name == Codens.SealSourceTriples:
            emit_counter()
            self.parse_repeating_count(ims=ims, cold=cold, indent=indent + 1,
                                       count=ctr.count,
                                       classes=(Prefixer, Seqner, Saider),
                                       labels=("source prefix", "source sn",
                                               "source digest"))
            return True
        if name == Codens.TransIdxSigGroups:
            emit_counter()
            for _ in range(ctr.count):
                self.emit_extracted(Prefixer, ims, cold, indent + 1,
                                    "signer prefix")
                self.emit_extracted(Seqner, ims, cold, indent + 1,
                                    "establishment sn")
                self.emit_extracted(Saider, ims, cold, indent + 1,
                                    "establishment digest")
                ictr = self.extract(Counter, ims=ims, cold=cold,
                                    version=version)
                self.emit(ictr.qb64, self.counter_comment(ictr, cold),
                          indent + 1)
                for _ in range(ictr.count):
                    self.emit_extracted(Siger, ims, cold, indent + 2,
                                        "indexed signature")
            return True
        if name == Codens.TransLastIdxSigGroups:
            emit_counter()
            for _ in range(ctr.count):
                self.emit_extracted(Prefixer, ims, cold, indent + 1,
                                    "signer prefix")
                ictr = self.extract(Counter, ims=ims, cold=cold,
                                    version=version)
                self.emit(ictr.qb64, self.counter_comment(ictr, cold),
                          indent + 1)
                for _ in range(ictr.count):
                    self.emit_extracted(Siger, ims, cold, indent + 2,
                                        "indexed signature")
            return True

        return False

    def parse_repeating_count(self, ims, cold, indent, count, classes, labels):
        """Parse exactly ``count`` repeated tuple material."""
        for _ in range(count):
            for klas, label in zip(classes, labels):
                self.emit_extracted(klas, ims, cold, indent, label)

    def parse_pathed_material(self, ims, cold, indent, version):
        """Parse a path token followed by one or more attachment tokens."""
        while ims:
            try:
                obj, consumed = self.try_extract(Pather, ims=ims, cold=cold)
                comment = self.primitive_comment(obj=obj, label="path")
                self.emit(obj.qb64, comment, indent)
                del ims[:consumed]
            except Exception:
                self.parse_token_stream(ims=ims, indent=indent,
                                        version=version, cold=cold)
                return

            if not ims:
                return

            self.parse_token_stream(ims=ims, indent=indent + 1,
                                    version=version, cold=cold)

    def parse_repeating(self, ims, cold, indent, classes, labels):
        """Parse repeated tuple material until its bounded payload is empty."""
        while ims:
            for klas, label in zip(classes, labels):
                self.emit_extracted(klas, ims, cold, indent, label)

    def parse_token_stream(self, ims, indent, version, cold=None):
        """Parse generic counted or primitive material from an already bounded payload."""
        while ims:
            nested_cold = cold if cold is not None else sniff(ims)
            if nested_cold == Colds.msg:
                self.parse_message(ims=ims, indent=indent, version=version)
                continue
            if nested_cold not in (Colds.txt, Colds.bny):
                self.emit_opaque(payload=bytes(ims), cold=nested_cold,
                                 indent=indent, comment="opaque token")
                ims.clear()
                return

            counter = self.peek_bounded_counter(ims=ims, cold=nested_cold,
                                                version=version)
            if counter is not None:
                ctr, size, count = counter
                self.emit(ctr.qb64, self.counter_comment(ctr, nested_cold),
                          indent)
                del ims[:size]
                payload = bytearray(ims[:count])
                del ims[:count]
                self.parse_token_stream(ims=payload, indent=indent + 1,
                                        version=version, cold=nested_cold)
                continue

            self.emit_any_primitive(ims=ims, cold=nested_cold, indent=indent)

    def peek_bounded_counter(self, ims, cold, version):
        """Return a counter only when its declared payload fits this boundary."""
        try:
            ctr = self.extract(Counter, ims=bytearray(ims), cold=cold,
                               version=version)
            size = ctr.byteSize(cold=cold)
            count = ctr.byteCount(cold=cold)
            if len(ims) < size + count:
                return None
            return ctr, size, count
        except Exception:
            return None

    def emit_any_primitive(self, ims, cold, indent):
        """Extract and render the next primitive with a conservative class order."""
        for klas in (Verser, Ilker, Traitor, Dater, Seqner, Number, Siger,
                     Indexer, Pather, Texter, Diger, Saider, Prefixer, Verfer,
                     Cigar, Matter):
            try:
                obj, consumed = self.try_extract(klas, ims=ims, cold=cold)
                comment = self.primitive_comment(obj=obj)
                self.emit(obj.qb64, comment, indent)
                del ims[:consumed]
                return
            except Exception:
                continue

        self.emit_opaque(payload=bytes(ims), cold=cold, indent=indent,
                         comment="opaque token")
        ims.clear()

    def try_extract(self, klas, ims, cold, version=None):
        """Extract from a copy and report how many source bytes to consume."""
        copy = bytearray(ims)
        obj = self.extract(klas, ims=copy, cold=cold, version=version)
        consumed = len(ims) - len(copy)
        if consumed <= 0:
            raise ExtractionError(f"{klas.__name__} consumed no bytes")
        return obj, consumed

    def emit_extracted(self, klas, ims, cold, indent, label=None):
        """Extract one object, then emit its canonical qb64 text."""
        obj = self.extract(klas, ims=ims, cold=cold)
        self.emit(obj.qb64, self.primitive_comment(obj=obj, label=label),
                  indent)
        return obj

    def extract(self, klas, ims, cold, version=None):
        """Extract one KERIpy primitive/counter in text or binary domain."""
        if klas is Counter:
            if cold == Colds.bny:
                return Counter(qb2=ims, strip=True,
                               version=version or Vrsn_2_0)
            return Counter(qb64b=ims, strip=True,
                           version=version or Vrsn_2_0)

        if cold == Colds.bny:
            return klas(qb2=ims, strip=True)
        return klas(qb64b=ims, strip=True)

    def peek_counter(self, ims, cold, version, role):
        """Peek at a counter with bounded legacy-v1 fallback."""
        current = self.extract(Counter, ims=bytearray(ims), cold=cold,
                               version=version)
        acodex = _annot_codex(version)
        allowed = acodex.FrameStarts if role == "frame" else (
            acodex.AttachmentWrappers | acodex.AttachmentGroups)
        if role == "attachment" and current.code in acodex.FrameStarts:
            return current, version
        if (current.code in allowed or
                current.code == acodex.GenusVersion or
                version.major == Vrsn_1_0.major):
            return current, version

        try:
            legacy = self.extract(Counter, ims=bytearray(ims), cold=cold,
                                  version=Vrsn_1_0)
        except Exception:
            return current, version

        legacy_acodex = _annot_codex(Vrsn_1_0)
        legacy_allowed = legacy_acodex.FrameStarts if role == "frame" else (
            legacy_acodex.AttachmentWrappers | legacy_acodex.AttachmentGroups)
        if (legacy.code in legacy_allowed or
                legacy.code == legacy_acodex.GenusVersion):
            return legacy, Vrsn_1_0

        return current, version

    def consume_counter(self, ims, cold, ctr, indent=None):
        """Consume an already-peeked counter and optionally emit it."""
        size = ctr.byteSize(cold=cold)
        del ims[:size]
        if indent is not None:
            self.emit(ctr.qb64, self.counter_comment(ctr, cold), indent)

    def consume_counter_payload(self, ims, cold, ctr):
        """Consume an already-peeked counted group and return qb64, payload."""
        size = ctr.byteSize(cold=cold)
        count = ctr.byteCount(cold=cold)
        if len(ims) < size + count:
            raise ExtractionError(f"Counter={ctr.name} exceeds stream size")

        if cold == Colds.bny:
            qb64 = ctr.qb64
        else:
            qb64 = bytes(ims[:size]).decode("utf-8")

        del ims[:size]
        payload = bytes(ims[:count])
        del ims[:count]
        return qb64, payload

    def text_domain(self, qb64, payload, cold):
        """Return canonical qb64 bytes for one counter plus payload."""
        if cold == Colds.bny:
            return qb64.encode("utf-8") + encodeB64(payload)
        return qb64.encode("utf-8") + payload

    def emit_opaque(self, payload, cold, indent, comment):
        """Emit opaque payload while preserving text-domain deannotation."""
        if not payload:
            return
        if cold == Colds.bny:
            value = encodeB64(payload).decode("utf-8")
        else:
            value = payload.decode("utf-8", "replace")
        self.emit(value, comment, indent, kind="opaque")

    def emit(self, value, comment, indent, kind=None):
        """Append one annotated output line."""
        self.lines.append(AnnotLine(value=value, comment=comment,
                                    indent=indent,
                                    kind=kind or _infer_kind(comment)))

    @staticmethod
    def counter_comment(ctr, cold):
        unit = "triplets" if cold == Colds.bny else "quadlets"
        return f"Counter {ctr.name} count={ctr.count} {unit}"

    @staticmethod
    def serder_comment(serder):
        said = f" said={serder.said}" if serder.said is not None else ""
        ilk = f" ilk={serder.ilk}" if serder.ilk is not None else ""
        return f"SERDER {serder.proto} {serder.kind}{ilk}{said}"

    def check_native_versions(self, raw, ctr, fixed, svrsn):
        """Validate a native body's protocol/genus versions before fallback."""
        offset = ctr.fullSize
        if not fixed:
            labeler = Labeler(qb64b=raw[offset:])
            offset += labeler.fullSize

        proto, pvrsn, gvrsn = Verser(qb64b=raw[offset:]).versage
        self.check_message_versions(proto=proto, pvrsn=pvrsn, gvrsn=gvrsn,
                                    svrsn=svrsn)

    def check_message_versions(self, proto, pvrsn, gvrsn, svrsn):
        """Mirror Parser/Serdery protocol and genus compatibility checks."""
        if pvrsn.major > svrsn.major:
            raise DeserializeError(f"Incompatible message protocol major "
                                   f"version={pvrsn} with stream genus major "
                                   f"version={svrsn}.")

        if proto not in Serder.Fields or pvrsn not in Serder.Fields[proto]:
            raise DeserializeError(f"Unsupported message protocol={proto} "
                                   f"version={pvrsn}.")

        if getattr(GenDex, ProGen.get(proto), None) != self.genus:
            raise DeserializeError(f"Incompatible message protocol={proto} "
                                   f"with genus={self.genus}.")

        if gvrsn:
            if gvrsn.major > svrsn.major:
                raise DeserializeError(f"Incompatible message genus major "
                                       f"version={gvrsn} with stream genus "
                                       f"major version={svrsn}.")

            if gvrsn.minor > svrsn.minor:
                raise DeserializeError(f"Incompatible message genus minor "
                                       f"version={gvrsn} with stream genus "
                                       f"minor version={svrsn}.")

            _latest_minor(Counter.Sizes, gvrsn)

    @staticmethod
    def version_from_serder(serder, current):
        """Infer local counter-table context after message-domain bodies."""
        if serder.kind == Kinds.cesr and serder.gvrsn is not None:
            return serder.gvrsn
        if serder.pvrsn.major == Vrsn_1_0.major:
            return Vrsn_1_0
        return current

    @staticmethod
    def primitive_comment(obj, label=None):
        bits = []
        if label:
            bits.append(label)
        bits.append(obj.__class__.__name__)
        if hasattr(obj, "name"):
            bits.append(obj.name)

        if isinstance(obj, Verser):
            versage = obj.versage
            bits.append(f"proto={versage.proto}")
            bits.append(f"vrsn={versage.pvrsn.major}.{versage.pvrsn.minor:02}")
        elif isinstance(obj, Ilker):
            bits.append(f"ilk={obj.ilk}")
        elif isinstance(obj, Traitor):
            bits.append(f"trait={obj.trait}")
        elif isinstance(obj, Dater):
            bits.append(f"dts={obj.dts}")
        elif isinstance(obj, Seqner):
            bits.append(f"sn={obj.sn}")
        elif isinstance(obj, Number):
            bits.append(f"num={obj.num}")
        elif isinstance(obj, Pather):
            bits.append(f"path={obj.path}")
        elif isinstance(obj, Indexer):
            bits.append(f"index={obj.index}")

        return " ".join(bits)
