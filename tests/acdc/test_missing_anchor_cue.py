# -*- encoding: utf-8 -*-
"""tests.acdc.test_missing_anchor_cue module

A v2 registry event held for its anchoring KEL event cues the owning loop once.
"""

from keri import Vrsn_2_0
from keri.acdc import Regery, Registrar, acdcmap
from keri.acdc.regeventing import _RegEventer
from keri.app import openHby
from keri.core import Diger, Kevery, Number

from .test_registraring import _anchor, _framed


def _issuedRip(issuerHby, hab, source):
    """Return the issuer's anchored rip and its KEL as separate public frames."""
    registry = Registrar(rgy=source).makeRegistry(name="cued", prefix=hab.pre)
    rip = _anchor(hab, registry, source.store.event(registry.regk))
    return rip, list(issuerHby.db.clonePreIter(pre=hab.pre, gvrsn=Vrsn_2_0))


def test_missing_anchor_cues_once_then_accepts_when_kel_arrives():
    """A rip without its sealing KEL event cues once; replays stay silent."""
    with (openHby(name="cue-issuer", temp=True, version=Vrsn_2_0) as issuerHby,
          openHby(name="cue-receiver", temp=True, version=Vrsn_2_0) as receiverHby):
        hab = issuerHby.makeHab(name="issuer")
        source = Regery(hby=issuerHby, name="cue-issuer", temp=True)
        rgy = Regery(hby=receiverHby, name="cue-receiver", temp=True)
        try:
            rip, kel = _issuedRip(issuerHby, hab, source)
            assert not source.cues  # the issuer anchors its own events itself

            # Held for the anchor: exactly one cue; the issuer is unknown, so fn is 0.
            assert rgy.processEvent(rip) is False
            assert list(rgy.cues) == [dict(kin="anchor", dest=hab.pre, issuer=hab.pre,
                                           regk=rip.said, sn=0, said=rip.said, fn=0, s=None)]
            rgy.cues.clear()

            # Escrow replay and a repeat arrival re-run the hold without a new cue.
            rgy.processEscrows()
            assert rgy.processEvent(rip) is False
            assert not rgy.cues

            # Once the KEL arrives the event is accepted, still without a cue.
            kvy = Kevery(db=receiverHby.db, lax=False, local=False)
            outcomes, refusal = rgy.ingest(b"".join(kel), kvy=kvy)
            assert refusal is None
            assert rgy.store.headEvent(rip.said).said == rip.said
            assert not rgy.cues
        finally:
            source.close()
            rgy.close()


def test_missing_anchor_cue_resumes_after_accepted_issuer_sn():
    """fn is the issuer's accepted sn + 1; a claimed anchor sn becomes s."""
    with (openHby(name="cue-issuer-fn", temp=True, version=Vrsn_2_0) as issuerHby,
          openHby(name="cue-receiver-fn", temp=True, version=Vrsn_2_0) as receiverHby):
        hab = issuerHby.makeHab(name="issuer")
        source = Regery(hby=issuerHby, name="cue-issuer-fn", temp=True)
        rgy = Regery(hby=receiverHby, name="cue-receiver-fn", temp=True)
        try:
            rip, kel = _issuedRip(issuerHby, hab, source)
            kvy = Kevery(db=receiverHby.db, lax=False, local=False)
            outcomes, refusal = rgy.ingest(kel[0], kvy=kvy)  # inception only
            assert refusal is None

            claim = (Number(num=1), Diger(qb64=issuerHby.db.kels.getLast(keys=hab.pre, on=1)))
            assert rgy.processEvent(rip, sscs=[claim]) is False
            [cue] = rgy.cues
            assert (cue["fn"], cue["s"], cue["dest"]) == (1, 1, hab.pre)
        finally:
            source.close()
            rgy.close()


def test_missing_anchor_cue_skipped_when_accepted_kel_reaches_claim():
    """An accepted issuer KEL past the claimed sn means a wrong anchor, not a missing one."""
    with (openHby(name="cue-issuer-skip", temp=True, version=Vrsn_2_0) as issuerHby,
          openHby(name="cue-receiver-skip", temp=True, version=Vrsn_2_0) as receiverHby):
        hab = issuerHby.makeHab(name="issuer")
        source = Regery(hby=issuerHby, name="cue-issuer-skip", temp=True)
        rgy = Regery(hby=receiverHby, name="cue-receiver-skip", temp=True)
        try:
            rip, kel = _issuedRip(issuerHby, hab, source)
            kvy = Kevery(db=receiverHby.db, lax=False, local=False)
            rgy.ingest(b"".join(kel[:1]), kvy=kvy)
            cues = []
            eventer = _RegEventer(db=receiverHby.db, issuer=hab.pre, store=rgy.store,
                                  regk=rip.said, cues=cues)
            assert eventer.escrowMissingAnchor(rip.said, 0, rip.said, anchor=Number(num=0))
            assert cues == []
        finally:
            source.close()
            rgy.close()
