# -*- encoding: utf-8 -*-
"""
tests.cli.common.test_anchorquerying module

The owning loop turns a Regery missing-anchor cue into a signed ``logs`` query.
"""
from types import SimpleNamespace

from keri import Vrsn_2_0
from keri.acdc import Regery, Registrar
from keri.app import openHby
from keri.cli.common import anchorquerying
from keri.cli.common.issuing import IpexV2Issuance
from keri.core import Kevery, Parser

from tests.acdc.test_registraring import _anchor


def test_issuance_loop_sends_signed_logs_query_to_issuer(monkeypatch):
    """IpexV2Issuance.settle sends the issuer a logs query its Kevery answers from fn."""
    with (openHby(name="aq-issuer", temp=True, version=Vrsn_2_0) as issuerHby,
          openHby(name="aq-holder", temp=True, version=Vrsn_2_0) as holderHby):
        issuer = issuerHby.makeHab(name="issuer")
        holder = holderHby.makeHab(name="holder")
        source = Regery(hby=issuerHby, name="aq-issuer", temp=True)
        rgy = Regery(hby=holderHby, name="aq-holder", temp=True)
        try:
            registry = Registrar(rgy=source).makeRegistry(name="queried", prefix=issuer.pre)
            rip = _anchor(issuer, registry, source.store.event(registry.regk))
            kel = list(issuerHby.db.clonePreIter(pre=issuer.pre, gvrsn=Vrsn_2_0))

            # The holder's loop owns the Regery; the rip arrives without its KEL event.
            loop = IpexV2Issuance(SimpleNamespace(), "admit")
            loop.hby, loop.hab, loop.rgy, loop.tock = holderHby, holder, rgy, 0.03125
            sent = []

            def send(owner, raw, dest, *, topic="credential"):
                sent.append((owner, bytes(raw), dest))
                yield owner.tock

            monkeypatch.setattr("keri.cli.common.sending.send", send)
            assert rgy.processEvent(rip) is False
            for _ in loop.settle():
                pass
            assert not rgy.cues

            # One query, addressed to the issuer, from the loop's own habitat.
            [(owner, raw, dest)] = sent
            assert owner is loop and dest == issuer.pre

            # The issuer accepts it as a signed logs query and replays its KEL from fn=0.
            issuerKvy = Kevery(db=issuerHby.db, lax=True, local=False)
            Parser(kvy=issuerKvy, version=Vrsn_2_0).parse(ims=bytearray(holder.replay(gvrsn=Vrsn_2_0)))
            Parser(kvy=issuerKvy, version=Vrsn_2_0).parse(ims=bytearray(raw))
            [cue] = [cue for cue in issuerKvy.cues if cue["kin"] == "replay"]
            assert cue["pre"] == issuer.pre and cue["dest"] == holder.pre
            assert [bytes(msg) for msg in cue["msgs"]] == [bytes(msg) for msg in kel]
        finally:
            source.close()
            rgy.close()


def test_logs_query_carries_fn_and_claimed_anchor_sn():
    """fn and s are hex query modifiers; s is left out without a claim."""
    with openHby(name="aq-query", temp=True, version=Vrsn_2_0) as hby:
        hab = hby.makeHab(name="holder")
        cue = dict(issuer="Eissuer", fn=17, s=None)
        qry = Parser(version=Vrsn_2_0).parseOneBare(
            ims=bytearray(anchorquerying.logsQuery(hab, cue)), processive=False).serder
        assert qry.ked["r"] == "logs"
        assert qry.ked["q"] == dict(i="Eissuer", src="Eissuer", fn="11")
        cue["s"] = 26
        qry = Parser(version=Vrsn_2_0).parseOneBare(
            ims=bytearray(anchorquerying.logsQuery(hab, cue)), processive=False).serder
        assert qry.ked["q"]["s"] == "1a"
