# -*- encoding: utf-8 -*-
"""
keri.acdc.regbasing module

Support for RegBaser(LMDBer)

"""

import os

from ..core import Diger, Number, Saider, SerderACDC
from ..db import (LMDBer, B64OnIoSetSuber, CatCesrSuber, CesrOnSuber,
                  CesrSuber, SerderSuber)
from ..db.dbing import onKey
from ..kering import Ilks, ValidationError


class RegBaser(LMDBer):
    """
    RegBaser sets up named sub databases for public ACDC registry TELs.

    Attributes:
        see superclass LMDBer for inherited attributes

        .evts is named subDB instance of SerderSuber (klas=SerderACDC)
            whose values are serialized ACDC registry events.
            subkey 'evts.'
            Key: registry event SAID.
            Value: SerderACDC instance for a rip or bup event.
            Only one value per DB key is allowed.
            Contains both accepted and escrowed event bodies. Membership does
            not indicate acceptance.

        .ancs is named subDB instance of CatCesrSuber
            (klas=(Number, Diger)) for KEL source seal couples.
            subkey 'ancs.'
            Key: registry event SAID.
            Value: Number and Diger of the KEL event that anchors the registry
            event.
            Only one value per DB key is allowed.

        .tels is named subDB instance of CesrOnSuber (klas=Saider) for the
            accepted transaction event log.
            subkey 'tels.'
            onKey (registry SAID + registry event sequence number)
            Value: SAID of the accepted registry event in .evts.
            Only one value per DB key is allowed.
            Membership is the acceptance commit marker.

        .heads is named subDB instance of CesrSuber (klas=Saider) for the
            current accepted registry heads.
            subkey 'heds.'
            Key: registry SAID.
            Value: SAID of the latest accepted registry event.
            Only one value per DB key is allowed.
            This cache is rebuildable from .tels.

        .maes is named subDB instance of B64OnIoSetSuber for registry events
            escrowed because the KEL anchor is missing.
            subkey 'maes.'
            onKey (registry SAID + registry event sequence number)
            Value: registry event SAID.
            More than one value per effective DB key is allowed in insertion
            order without dupsort.

        .ooes is named subDB instance of B64OnIoSetSuber for out-of-order
            registry event escrows.
            subkey 'ooes.'
            onKey (registry SAID + registry event sequence number)
            Value: registry event SAID.
            More than one value per effective DB key is allowed in insertion
            order without dupsort.

        .conflicts is a SerderSuber containing the first independently anchored
            competing event for an accepted slot, keyed by (registry SAID,
            lowercase hexadecimal sequence number). The accepted event remains
            in .tels/.evts; each event's verified KEL reference remains in .ancs.
            One retained competing body per slot supports local conflict
            reporting across restart, not exhaustive duplicity archiving.

    """

    TailDirPath = os.path.join("keri", "acdc", "reg")
    AltTailDirPath = os.path.join(".keri", "acdc", "reg")
    TempPrefix = "keri_acdc_reg_"

    def __init__(self, headDirPath=None, reopen=True, **kwa):
        """
        Setup named sub databases.

        Inherited Parameters:
            name (str): directory path name differentiator for main database
            temp (bool): True means use a temporary directory and clear on close
            headDirPath (str | None): optional head directory path for database
            mode (int): numeric permissions for database directory
            reopen (bool): True means reopen database during initialization

        """
        super(RegBaser, self).__init__(headDirPath=headDirPath,
                                      reopen=reopen, **kwa)

    def reopen(self, **kwa):
        """
        Open database and setup named sub databases.

        Parameters:
            **kwa (dict): keyword arguments passed to LMDBer.reopen

        Returns:
            opened (bool): True when database is opened

        """
        super(RegBaser, self).reopen(**kwa)

        self.evts = SerderSuber(db=self, subkey='evts.', klas=SerderACDC)
        self.ancs = CatCesrSuber(db=self, subkey='ancs.',
                                klas=(Number, Diger))
        self.tels = CesrOnSuber(db=self, subkey='tels.', klas=Saider)
        self.heads = CesrSuber(db=self, subkey='heds.', klas=Saider)
        self.maes = B64OnIoSetSuber(db=self, subkey='maes.')
        self.ooes = B64OnIoSetSuber(db=self, subkey='ooes.')
        self.conflicts = SerderSuber(db=self, subkey='conflicts.', klas=SerderACDC)

        return self.opened

    def recordConflict(self, regk, sn, serder):
        """Retain the first authenticated competing body for an occupied slot.

        Parameters:
            regk (str): registry whose accepted ordinal must remain unchanged.
            sn (int): competing event's sequence number.
            serder (SerderACDC): validated competing event. The caller must
                authenticate its issuer anchor before calling; this method
                requires its verified anchor reference already in .ancs.

        Returns:
            bool: True when the slot's first proof is recorded; False when a
                proof already exists. Additional competitors are not archived.

        Raises:
            ValidationError: no different accepted event, wrong event slot,
                or missing persisted anchor reference.
        """
        accepted = self.tels.get(keys=regk, on=sn)
        if (accepted is None or accepted.qb64 == serder.said
                or Number(numh=serder.sad['n']).num != sn
                or serder.sad.get('rd') != regk
                or self.ancs.get(keys=serder.said) is None):
            raise ValidationError('conflict proof requires a different anchored event at an accepted slot')
        return self.conflicts.put(keys=(regk, f'{sn:x}'), val=serder)

    def accept(self, regk, sn, serder):
        """Commit one already authenticated TEL event in this environment.

        Body, accepted ordinal, and head share one LMDB write transaction.
        The caller owns protocol and anchor authentication; this boundary owns
        accepted-state consistency and never overwrites an occupied ordinal.
        Existing anchor evidence and pending bodies remain usable on failure.

        Returns:
            bool: True for a new acceptance, False for an exact replay.

        Raises:
            ValidationError: inconsistent event keys, conflicting accepted
                state, a missing predecessor, or a mismatched prior.

        Args:
            regk (str): Registry identifier whose frontier to advance.
            sn (int): Exact candidate ordinal, including zero for inception.
            serder (SerderACDC): Event already authenticated by the caller.

        This operation does not authenticate KEL anchors or decide conflict policy;
        its transaction guarantees bodies, accepted ordinals, and head agree on reopen."""
        inception = serder.ilk == Ilks.rip
        if (serder.ilk not in (Ilks.rip, Ilks.bup, Ilks.upd)
                or Number(numh=serder.sad['n']).num != sn
                or (serder.said if inception else serder.sad['rd']) != regk
                or (inception != (sn == 0))):
            raise ValidationError("registry event does not match its accepted slot")

        eventkey = self.evts._tokey(serder.said)
        regkey = self.tels._tokey(regk)
        seqkey = onKey(regkey, sn, sep=self.tels.sep.encode())
        headkey = self.heads._tokey(regk)
        raw = self.evts._ser(serder)
        said = self.tels._ser(Saider(qb64=serder.said))

        with self.env.begin(write=True) as txn:
            existing = txn.get(seqkey, db=self.tels.sdb)
            if existing is not None and existing != said:
                raise ValidationError(f"conflicting registry event at {regk}:{sn}")

            body = txn.get(eventkey, db=self.evts.sdb)
            if body is not None and body != raw:
                raise ValidationError(f"conflicting registry body {serder.said}")

            head = txn.get(headkey, db=self.heads.sdb)
            headsn = -1
            if head is not None:
                headsaid = self.heads._des(head)
                headraw = txn.get(self.evts._tokey(headsaid.qb64), db=self.evts.sdb)
                if headraw is None:
                    raise ValidationError(f"missing registry head body for {regk}")
                headser = self.evts._des(headraw)
                headsn = Number(numh=headser.sad['n']).num
                headseq = onKey(regkey, headsn, sep=self.tels.sep.encode())
                if txn.get(headseq, db=self.tels.sdb) != head:
                    raise ValidationError(f"inconsistent accepted registry head for {regk}")

            if existing is not None:
                if body is None or headsn < sn:
                    raise ValidationError(f"incomplete accepted registry event {regk}:{sn}")
                return False  # replay must never move the head backwards

            if sn != headsn + 1:
                raise ValidationError(f"noncontiguous registry event at {regk}:{sn}")
            if not inception and serder.sad['p'] != headsaid.qb64:
                raise ValidationError(f"mismatched registry prior at {regk}:{sn}")

            txn.put(eventkey, raw, db=self.evts.sdb)
            txn.put(seqkey, said, db=self.tels.sdb)
            txn.put(headkey, self.heads._ser(Saider(qb64=serder.said)),
                    db=self.heads.sdb)
        return True
