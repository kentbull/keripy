# -*- encoding: utf-8 -*-
"""
keri.acdc.registering module

Register database to store registry events. High level abstraction of
RegBaser(lmdb) and WebRegBaser(IndexedDB)

"""

from dataclasses import dataclass

from ..db import Komer
from ..core import Blinder
from ..kering import ConfigurationError, Ilks, ValidationError
from .regbasing import RegBaser
from .webregbasing import WebRegBaser


@dataclass
class RegistryRecord:
    """Persisted local registry data."""

    registryKey: str


def openRegistry(*, web=False, reopen=True, **kwa):
    """Open the backing store used by the V2 ACDC registry service."""
    if web:
        raise ConfigurationError("web registry backend is not yet supported by V2 Regery")
    return RegBaser(reopen=reopen, **kwa)


class RegistryStore:
    """Small convenience wrapper around RegBaser/WebRegBaser."""

    def __init__(self, baser):
        if isinstance(baser, WebRegBaser):
            raise ConfigurationError("web registry backend is not yet supported by V2 Regery")
        self.baser = baser
        self.records = Komer(db=self.baser, subkey='regs.', klas=RegistryRecord)

    @property
    def opened(self):
        return self.baser.opened

    def close(self):
        self.baser.close()

    def event(self, said):
        return self.baser.evts.get(keys=said)

    def putEvent(self, serder):
        return self.baser.evts.pin(keys=serder.said, val=serder)

    def opening(self, said):
        """Return the exact retained public opening bytes for one event SAID."""
        return self.baser.openings.get(keys=said)

    def retainOpening(self, event, opening):
        """Authenticate and retain one event-specific public ``bup`` opening.

        Repeated identical publication is idempotent. A different opening for
        the same event is refused before it can replace durable evidence.
        """
        from .regeventing import vetBlind

        if (event is None or event.ilk != Ilks.bup
                or not isinstance(opening, Blinder)):
            raise ValidationError('public opening requires an ACDC v2 blinded update')
        if not event.verify():
            raise ValidationError('public opening event body does not verify')
        stored = self.event(event.said)
        if stored is None or bytes(stored.raw) != bytes(event.raw):
            raise ValidationError('public opening requires the exact stored event body')
        vetBlind(opening, blid=event.sad['b'])
        old = self.opening(event.said)
        if old is not None and old != opening.qb64:
            raise ValidationError('different public opening is already retained for this event')
        self.baser.openings.pin(keys=event.said, val=opening.qb64)
        return opening

    def anchor(self, said):
        return self.baser.ancs.get(keys=said)

    def putAnchor(self, said, number, diger):
        # Keep the earliest verified sealing event for this TEL event so later
        # re-seals cannot rewrite sibling arbitration order.
        current = self.anchor(said)
        if current is not None and current[0].sn <= number.sn:
            return False
        return self.baser.ancs.pin(keys=said, val=(number, diger))

    def head(self, regk):
        return self.baser.heads.get(keys=regk)

    def headEvent(self, regk):
        saider = self.head(regk)
        return self.event(saider.qb64) if saider is not None else None

    def seqSaider(self, regk, sn):
        return self.baser.tels.get(keys=regk, on=sn)

    def seqEvent(self, regk, sn):
        saider = self.seqSaider(regk, sn)
        return self.event(saider.qb64) if saider is not None else None

    def accept(self, regk, sn, serder):
        """Atomically commit an already authenticated event through RegBaser.

        Args:
            regk (str): Registry whose accepted frontier to advance.
            sn (int): Exact candidate ordinal.
            serder (SerderACDC): Event validated for issuer, anchor, and predecessor.

        Returns:
            bool: True for a new acceptance, False for an identical accepted replay.

        Raises:
            ValidationError: Keys/linkage are inconsistent or a different event already
            occupies the slot. No accepted head changes on refusal."""
        return self.baser.accept(regk, sn, serder)

    def cloneTelIter(self, regk, sn=0):
        """Yield accepted TEL event bodies in sequence from sn inclusive.

        Parameters:
            regk (str): registry SAID (rip.d).
            sn (int): first sequence number to include. Default 0.

        Returns:
            Iterator[bytes]: raw CESR bodies of accepted ``rip``/``bup`` events.
        """
        for _keys, _on, saider in self.baser.tels.getAllItemIter(keys=regk, on=sn):
            serder = self.event(saider.qb64)
            if serder is not None:
                yield bytes(serder.raw)

    def cloneTel(self, regk, sn=0):
        """Concatenate accepted TEL event bodies as a CESR stream from sn.

        Parameters:
            regk (str): registry SAID (rip.d).
            sn (int): first sequence number to include. Default 0.

        Returns:
            bytes: concatenated event bodies. Empty when the registry has no
                accepted events at or after ``sn``.
        """
        stream = bytearray()
        for raw in self.cloneTelIter(regk, sn=sn):
            stream.extend(raw)
        return bytes(stream)

    def escrowMissingAnchor(self, regk, sn, said):
        return self.baser.maes.add(keys=regk, on=sn, val=said)

    def escrowOutOfOrder(self, regk, sn, said):
        return self.baser.ooes.add(keys=regk, on=sn, val=said)

    def clearEscrows(self, regk, sn, said):
        self.baser.maes.rem(keys=regk, on=sn, val=said)
        self.baser.ooes.rem(keys=regk, on=sn, val=said)
