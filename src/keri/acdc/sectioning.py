"""Durable native section evidence and explicit commitment-based resolution.

Resolution supplies requested evidence to a verifier. It does not authenticate
an issuer, accept a registry, admit a credential, or widen an IPEX disclosure.
The received credential view remains immutable and is always separately read.
"""
import copy
from dataclasses import dataclass, field
import os

from ..core import Diger, SerderACDC
from ..db import Komer, LMDBer, SerderSuber, Suber
from ..kering import ConfigurationError, FailedSchemaValidationError, MissingSchemaError, ValidationError
from . import scheming


SECTION_FIELDS = dict(sch='s', att='a', agg='A', edg='e', rul='r')
CREDENTIAL_ILKS = (None, 'acm', 'act', 'acg')


@dataclass
class RequiredSections:
    """Explicit per-view dependency request persisted beside immutable received bytes.

        fields lists normative credential section labels; sources optionally selects
        one exact section-message SAID when several views share a commitment."""
    fields: list
    sources: dict = field(default_factory=dict)


class SectionBaser(LMDBer):
    """Content-addressed section messages, received views, and dependency escrows."""
    TailDirPath = os.path.join('keri', 'acdc', 'sections')
    AltTailDirPath = os.path.join('.keri', 'acdc', 'sections')

    def reopen(self, **kwa):
        """Open section messages, indexes, exact views, and dependency outcomes.

            Args:
                **kwa: LMDBer reopen options, including test/persistent path settings.

            Returns:
                bool: Whether the existing application environment is open.

            Storage errors propagate. A commitment may index multiple distinct received
            views; no table treats a fuller view as a replacement for an earlier one."""
        super().reopen(**kwa)
        self.messages = SerderSuber(db=self, subkey='msgs.', klas=SerderACDC, verify=True)
        self.parts = Suber(db=self, subkey='parts.')
        # One ACDC commitment can have several legitimately different views.
        self.views = SerderSuber(db=self, subkey='views.', klas=SerderACDC, verify=True)
        self.required = Komer(db=self, subkey='required.', klas=RequiredSections)
        self.pending = Suber(db=self, subkey='pending.')
        self.failures = Suber(db=self, subkey='failures.')
        return self.opened


def _commitment(value, label):
    """Read a section's normative commitment without resolving its contents.

        Args:
            value: Compact SAID or expanded schema/map/aggregate section.
            label (str): Normative field selecting $id, d, or aggregate root.

        Returns:
            str | None: Declared commitment, or None for an unsupported/empty shape."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get('$id' if label == 's' else 'd')
    if label == 'A' and isinstance(value, list) and value:
        return value[0]
    return None


class Sectioner:
    """Concrete native evidence owner; required fields are explicit local requests."""
    def __init__(self, *, db, sections):
        """Bind parser-side evidence processing to caller-owned stores.

            Args:
                db (Baser): Authenticated KEL and conventional schema evidence.
                sections (SectionBaser): Independent section/view/escrow environment.

            Returns:
                None. The caller owns closing both stores; construction reads no view."""
        self.db, self.sections = db, sections

    def processEvent(self, serder, *, nests=(), **kwa):
        """Retain a valid native credential or independent section and retry requests.

            Args:
                serder (SerderACDC): Exact received v2 credential/section message.
                nests (Iterable): Parsed nested independent sections to cache separately.
                **kwa: Parser dispatch metadata unused by this evidence owner.

            Returns:
                str: Credential-view digest or standalone message SAID retained locally.

            Raises:
                ValidationError: Invalid native body, unsupported type, or non-section nest.

            Persistence indexes only expanded evidence. Nested section reception is not
            issuer authentication, wallet admission, or permission to expand a grant."""
        if not isinstance(serder, SerderACDC) or serder.pvrsn.major != 2 or not serder.verify():
            raise ValidationError('valid native ACDC evidence is required')
        if serder.ilk in CREDENTIAL_ILKS:
            result = self.processCredential(serder)
        else:
            label = SECTION_FIELDS.get(serder.ilk)
            if label is None:
                raise ValidationError('not a supported native section message')
            value = serder.sad[label]
            commitment = _commitment(value, label)
            index = (label, commitment, serder.said)
            # A compact section reference has no new revealed evidence to index.
            expanded = bool(value) and not isinstance(value, str) and bool(commitment)
            with self.sections.env.begin(write=True) as txn:
                txn.put(self.sections.messages._tokey(serder.said), self.sections.messages._ser(serder),
                        db=self.sections.messages.sdb, overwrite=False)
                if expanded:
                    txn.put(self.sections.parts._tokey(index), serder.said.encode(),
                            db=self.sections.parts.sdb, overwrite=False)
            result = serder.said
        # Independent sections may also be nested in a credential's foot. They
        # are cached evidence only; no other nested message gains admission.
        for item in nests:
            nested = item if isinstance(item, dict) else vars(item)
            child = nested.get('serder')
            if not isinstance(child, SerderACDC) or child.ilk not in SECTION_FIELDS:
                raise ValidationError('native evidence nests must contain section messages')
            self.processEvent(child, nests=nested.get('nests', ()))
        self.processEscrows()
        return result

    def processCredential(self, serder, *, required=(), sources=None):
        """Retain exact credential bytes and request explicitly selected dependencies.

            Args:
                serder (SerderACDC): Valid native received credential, including partials.
                required (Iterable[str]): Existing normative fields the local caller needs.
                sources (Mapping | None): Optional field-to-section-message SAID choices.

            Returns:
                str: Digest of these exact received bytes, distinguishing equal-SAID views.

            Raises:
                ValidationError: Credential is not a valid supported native body.
                ConfigurationError: Requested fields or explicit source choices are invalid.

            Existing requests merge transactionally, but received bytes never change.
            Missing dependencies remain pending; failed schema resolution is recorded."""
        if (not isinstance(serder, SerderACDC) or serder.pvrsn.major != 2
                or serder.ilk not in CREDENTIAL_ILKS or not serder.verify()):
            raise ValidationError('valid native credential evidence is required')
        fields = list(dict.fromkeys(required))
        if any(label not in ('s', 'a', 'A', 'e', 'r') or label not in serder.sad for label in fields):
            raise ConfigurationError('required sections must name existing normative credential fields')
        view = Diger(ser=serder.raw).qb64
        existing = self.sections.required.get(view)
        selected = dict(sources or {})
        if fields and existing is not None:
            fields = list(dict.fromkeys(existing.fields + fields))
            selected = dict(existing.sources, **selected)
        if any(label not in fields or not isinstance(said, str)
               for label, said in selected.items()):
            raise ConfigurationError('section sources must name requested fields and message SAIDs')
        with self.sections.env.begin(write=True) as txn:
            txn.put(self.sections.views._tokey(view), self.sections.views._ser(serder),
                    db=self.sections.views.sdb, overwrite=False)
            if fields:
                txn.put(self.sections.required._tokey(view),
                        self.sections.required._ser(RequiredSections(fields, selected)),
                        db=self.sections.required.sdb, overwrite=True)
                txn.delete(self.sections.failures._tokey(view), db=self.sections.failures.sdb)
                txn.put(self.sections.pending._tokey(view), view.encode(),
                        db=self.sections.pending.sdb, overwrite=False)
        self.processEscrows()
        return view

    def received(self, view):
        """Read the original received view without merging cached sections.

            Args:
                view (str): Digest returned by processCredential, not credential SAID.

            Returns:
                SerderACDC | None: Exact received credential or None for an unknown view."""
        return self.sections.views.get(view)

    def candidates(self, view, label):
        """List separately received sections matching one compact field commitment.

            Args:
                view (str): Known exact received-view digest.
                label (str): Normative section field whose candidate messages to list.

            Returns:
                list[str]: Matching message SAIDs; empty for already revealed fields.

            Raises:
                ConfigurationError: View or normative section label is unknown.

            Multiple candidates require an explicit local selection rather than choosing
            whichever fuller disclosure arrived most recently."""
        original = self.received(view)
        if original is None or label not in ('s', 'a', 'A', 'e', 'r'):
            raise ConfigurationError('known view and normative section label required')
        commitment = original.sad.get(label)
        if not isinstance(commitment, str):
            return []
        return [said for _, said in self.sections.parts.getTopItemIter((label, commitment, ''))]

    def resolve(self, view, *, required=(), sources=None):
        """Build an explicit local expansion while preserving the credential commitment.

            Args:
                view (str): Known exact received-view digest.
                required (Iterable[str]): Fields explicitly requested for this expansion.
                sources (Mapping | None): Exact message SAIDs resolving ambiguous fields.

            Returns:
                SerderACDC | None: Valid requested expansion, or None while unavailable
                    or ambiguous. No requested fields returns the original exact view.

            Raises:
                ConfigurationError: Requested field or source selection is invalid.
                ValidationError: Unknown view or expansion changes its credential SAID.
                FailedSchemaValidationError: Available expanded evidence violates schema.

            Already revealed partials remain exact. This local evidence result must not
            replace a grant's retained disclosure or its authorized webhook projection."""
        original = self.received(view)
        if original is None:
            raise ValidationError('unknown received credential view')
        fields = list(dict.fromkeys(required))
        if not fields:
            return original
        if any(label not in ('s', 'a', 'A', 'e', 'r') or label not in original.sad for label in fields):
            raise ConfigurationError('required sections must name existing normative credential fields')
        selected = dict(sources or {})
        if any(label not in fields for label in selected):
            raise ConfigurationError('section sources must name requested fields')
        sad = copy.deepcopy(original.sad)
        for label in fields:
            commitment = sad[label]
            if not isinstance(commitment, str):
                continue  # preserve an already revealed partial exactly
            candidates = self.candidates(view, label)
            if label in selected:
                said = selected[label]
                if said not in candidates:
                    return None
            elif len(candidates) == 1:
                said = candidates[0]
            else:
                # Different received disclosures need an explicit local choice.
                return None
            section = self.sections.messages.get(said)
            if section is None or _commitment(section.sad[label], label) != commitment:
                return None
            sad[label] = copy.deepcopy(section.sad[label])
        expanded = SerderACDC(sad=sad, makify=True)
        if expanded.said != original.said:
            raise ValidationError('resolved sections do not preserve credential commitment')
        try:
            scheming.validateSchema(expanded, self.db, sections=self.sections)
        except MissingSchemaError:
            return None
        return expanded

    def processEscrows(self):
        """Retry local dependency requests without aborting unrelated schema failures.

            Returns:
                list[str]: Exact view digests whose requested expansions are now ready.

            Missing/ambiguous dependencies remain pending. Permanent schema failures move
            to the failures table; successful requests leave pending. Unexpected storage
            and malformed-state errors propagate instead of being treated as missing data."""
        ready = []
        for (view,), _ in list(self.sections.pending.getTopItemIter()):
            request = self.sections.required.get(view)
            if request is None:
                continue
            try:
                resolved = self.resolve(view, required=request.fields, sources=request.sources)
            except FailedSchemaValidationError as ex:
                # Distinguish unavailable dependencies from permanently invalid
                # revealed evidence without aborting unrelated pending views.
                self.sections.failures.pin(view, str(ex))
                self.sections.pending.rem(view)
                continue
            if resolved is not None:
                self.sections.pending.rem(view)
                ready.append(view)
        return ready
