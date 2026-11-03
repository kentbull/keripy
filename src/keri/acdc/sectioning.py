"""Retain independently delivered section bytes without admitting a credential."""

from collections.abc import Mapping

from ..core import Diger, Saider, SerderACDC
from ..kering import Ilks, KeriError, ValidationError


SectionFields = {Ilks.sch: "s", Ilks.att: "a", Ilks.agg: "A", Ilks.edg: "e", Ilks.rul: "r"}


def retainSections(reger, serder, nests=None):
    """Verify a section subtree, then atomically retain its exact message bodies.

    The Reger cache records held material, not issuer authentication, schema
    applicability or credential admission. Distinct disclosure views keep their
    distinct section-message SAIDs even when they share a section commitment.
    Callers select an explicit held view; intake never hydrates an old Grant.
    All nested messages must themselves be sections and verify before any write.

    Parameters:
        reger (Reger): caller-owned credential evidence store.
        serder (SerderACDC): independent section message.
        nests (list | None): parsed nested section substreams.

    Returns:
        tuple[str]: retained section-message SAIDs in traversal order.
    """
    pending = [(serder, nests or [])]
    records = []
    while pending:
        message, children = pending.pop()
        if (not isinstance(message, SerderACDC) or message.pvrsn.major != 2
                or message.ilk not in SectionFields or not message.verify()):
            raise ValidationError("independent section has invalid type or commitments")
        label = SectionFields[message.ilk]
        value = message.sad[label]
        if isinstance(value, Mapping):
            commitment = value.get("$id" if label == "s" else "d")
        elif label == "A" and isinstance(value, list):
            commitment = value[0] if value else None
        else:
            commitment = value if isinstance(value, str) and value else None
        if commitment:
            try:
                if Diger(qb64=commitment).qb64 != commitment:
                    raise ValueError("noncanonical commitment")
            except (ValueError, TypeError, KeriError) as ex:
                raise ValidationError("invalid section commitment") from ex
        records.append((message, label, commitment))
        for child in reversed(children):
            child = child if isinstance(child, dict) else vars(child)
            pending.append((child["serder"], child.get("nests") or []))

    with reger.env.begin(write=True) as txn:
        for message, label, commitment in records:
            key = reger.sections._tokey(message.said)
            existing = txn.get(key, db=reger.sections.sdb)
            if existing is not None and existing != message.raw:
                raise ValidationError("conflicting retained section body")
            txn.put(key, message.raw, db=reger.sections.sdb, overwrite=False)
            if commitment:
                txn.put(reger.sectionIds._tokey((label, commitment)),
                        Saider(qb64=message.said).qb64b,
                        db=reger.sectionIds.sdb, dupdata=False)
    return tuple(message.said for message, _, _ in records)
