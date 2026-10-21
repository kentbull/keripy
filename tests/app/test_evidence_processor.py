"""Borrowed evidence processing must share acceptance without owning lifecycle."""
import pytest
from hio.base import doing

from keri import Vrsn_2_0
from keri.acdc.regbasing import RegBaser
from keri.acdc.regeventing import Rever
from keri.app.evidencing import EvidenceProcessor
from keri.app.habbing import openHby
from keri.core import Kevery
from keri.kering import ConfigurationError


def test_borrowed_evidence_acceptance_and_lifecycle():
    """Real remote KEL intake leaves the caller's stores/runtime ownership intact."""
    with openHby(name='borrowed-source', version=Vrsn_2_0) as source, \
            openHby(name='borrowed-target', version=Vrsn_2_0) as target:
        hab = source.makeHab(name='source')
        reger = RegBaser(name='borrowed-target', temp=True)
        try:
            kvy = Kevery(db=target.db, lax=False, local=False)
            rever = Rever(db=target.db, reger=reger)
            intake = EvidenceProcessor(target, kvy=kvy, rever=rever)
            assert not isinstance(intake, doing.Doer)
            assert intake.rever is rever and intake.kvy is kvy
            result = intake.ingest(hab.replay(gvrsn=Vrsn_2_0))
            assert result == dict(accepted={}, pending={}, rejected={}, heads={})
            assert target.db.kels.getLast(keys=hab.pre, on=0) == hab.kever.serder.said
            assert reger.opened and target.db.opened
            for unsafe in (Kevery(db=target.db, lax=True, local=False),
                           Kevery(db=source.db, lax=False, local=False)):
                with pytest.raises(ConfigurationError, match='strict verifiers'):
                    EvidenceProcessor(target, kvy=unsafe, rever=rever)
        finally:
            reger.close()
