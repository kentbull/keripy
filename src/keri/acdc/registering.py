# -*- encoding: utf-8 -*-
"""
keri.acdc.registering module

Register database to store registry events. High level abstraction of
RegBaser(lmdb) and WebRegBaser(IndexedDB)

"""

from dataclasses import dataclass

from ..core import Blinder, BlindState, BoundState, Number
from ..db import Komer
from ..kering import ConfigurationError, Ilks, KeriError, ValidationError
from .regeventing import vetBlind
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
        return self.baser.accept(regk, sn, serder)

    def _openingEvent(self, said):
        """Require an accepted BUP, not just a body in dependency escrow."""
        event = self.event(said)
        if event is None or event.ilk != Ilks.bup or event.said != said:
            raise ValidationError("opening requires a known accepted BUP")
        accepted = self.seqSaider(event.sad['rd'], Number(numh=event.sad['n']).num)
        if accepted is None or accepted.qb64 != said:
            raise ValidationError("opening event is not in the accepted TEL")
        return event

    def putOpening(self, said, blinder):
        """Explicitly retain one immutable opening of an accepted BUP.

        ``said`` identifies the exact event; ``blinder`` is a Blinder whose
        full primitive encodings must reproduce that event's BLID. Return True
        on first insertion, False on exact replay. No root is needed or stored.
        Credential/Issuee binding and disclosure authorization belong to the
        consuming operation; possession of this material establishes neither.
        """
        if not isinstance(blinder, Blinder):
            raise ValidationError("opening must be a Blinder")
        event = self._openingEvent(said)
        vetBlind(blinder, blid=event.sad['b'])
        inserted = self.baser.openings.put(said, blinder.qb64)
        if not inserted and self.baser.openings.get(said) != blinder.qb64:
            raise ValidationError("held event opening is immutable")
        return inserted

    def opening(self, said):
        """Return a fresh verified Blinder for the exact event, or None.

        Recheck accepted membership and full BLID encodings on every read.
        This does not validate BoundState's credential-specific Issuee reference
        or authorize publishing the opening with public TEL evidence.
        """
        raw = self.baser.openings.get(said)
        if raw is None:
            return None
        event = self._openingEvent(said)
        vetBlind(raw, blid=event.sad['b'])
        for clan in (BlindState, BoundState):
            try:
                candidate = Blinder(clan=clan, qb64=raw, verify=False)
            except (KeriError, ValueError, TypeError):
                continue
            if candidate.qb64 == raw:
                return candidate
        raise ValidationError("invalid held event opening")

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
