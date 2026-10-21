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
    fields: list
    sources: dict = field(default_factory=dict)


class SectionBaser(LMDBer):
    """Content-addressed section messages, received views, and dependency escrows."""
    TailDirPath = os.path.join('keri', 'acdc', 'sections')
    AltTailDirPath = os.path.join('.keri', 'acdc', 'sections')

    def reopen(self, **kwa):
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
        self.db, self.sections = db, sections

    def processEvent(self, serder, *, nests=(), **kwa):
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
        """Retain this exact view; request only explicitly named missing sections."""
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
        """Return only the original received view, regardless of cached sections."""
        return self.sections.views.get(view)

    def candidates(self, view, label):
        """List exact section message SAIDs for a compact received field."""
        original = self.received(view)
        if original is None or label not in ('s', 'a', 'A', 'e', 'r'):
            raise ConfigurationError('known view and normative section label required')
        commitment = original.sad.get(label)
        if not isinstance(commitment, str):
            return []
        return [said for _, said in self.sections.parts.getTopItemIter((label, commitment, ''))]

    def resolve(self, view, *, required=(), sources=None):
        """Return requested, commitment-checked schema evidence, or None if pending.

        This explicit local expansion must never substitute for an IPEX grant's
        actual revealed view or its authorized application projection.
        """
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
