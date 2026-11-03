"""Existing KRAM and reply routing preserve auxiliary evidence until dispatch."""

import pytest

from keri import Kinds, Vrsn_2_0 as V2
from keri.acdc import regcept
from keri.app import openCF, openHby
from keri.core import (Blinder, Diger, Kevery, Kramer, Number, Parser, Revery,
                       SealSource, messagize, query, reply)
from keri.help import helping
from keri.peer.exchanging import serializeParsedSubstream


def config(enabled=True):
    return {"kram": {"enabled": enabled, "denials": [],
                     "caches": {"~": [1000, 5000, 60000, 300000, 5000, 60000, 300000]}}}


def signatures(hab, message, index):
    return [(hab.kever.prefixer, Number(sn=hab.kever.lastEst.s),
             Diger(qb64=hab.kever.lastEst.d), [hab.sign(message.raw)[index]])]


def parsed(raw):
    return Parser(version=V2).parseOneBare(ims=bytearray(raw), processive=False)


@pytest.mark.parametrize("kind", [Kinds.json, Kinds.cbor, Kinds.mgpk, Kinds.cesr])
def test_partial_query_preserves_nested_evidence_order_and_reopen(kind):
    with openHby(name="nested-query", version=V2) as hby, openCF(name="nested-query") as cf:
        sender = hby.makeHab(name="sender", icount=2, isith="2", ncount=2, nsith="2")
        cf.put(config())
        kramer = Kramer(db=hby.db, cf=cf)
        events = [regcept(israid=sender.pre, kind=kind) for _ in range(2)]
        children = [messagize(event, bonds=[SealSource(s="0", d=sender.pre)],
                              nested=True, gvrsn=V2) for event in events]
        message = query(pre=sender.pre, route="/ipex/unblind",
                         query=dict(x=Diger(ser=b"grant").qb64), pvrsn=V2, kind=Kinds.json)
        key = (sender.pre, message.said)
        for nests in ([children[0]], [children[0], children[1]]):
            frame = parsed(messagize(message, tsgs=signatures(sender, message, 0),
                                      nests=nests, gvrsn=V2))
            kwa = vars(frame).copy()
            kwa.pop("serder")
            assert kramer.intake(message, kwa) is None
        # A new Kramer and reopened Baser must recover the first partial's children.
        hby.db.close(clear=False)
        hby.db.reopen(reuse=True)
        kramer = Kramer(db=hby.db, cf=cf)
        frame = parsed(messagize(message, tsgs=signatures(sender, message, 1), gvrsn=V2))
        kwa = vars(frame).copy()
        kwa.pop("serder")
        assert kramer.intake(message, kwa).said == message.said
        assert [serializeParsedSubstream(nest) for nest in kwa.get("nests", [])] == children
        assert hby.db.kramNEST.get(key) == []


def test_expired_partial_query_removes_nested_evidence(fakeHelpingClock):
    with openHby(name="nested-expiry", version=V2) as hby, openCF(name="nested-expiry") as cf:
        sender = hby.makeHab(name="sender", icount=2, isith="2", ncount=2, nsith="2")
        cf.put(config())
        kramer = Kramer(db=hby.db, cf=cf)
        event = regcept(israid=sender.pre)
        child = messagize(event, bonds=[SealSource(s="0", d=sender.pre)], nested=True, gvrsn=V2)
        message = query(pre=sender.pre, route="/ipex/unblind", query={}, pvrsn=V2, kind=Kinds.json)
        frame = parsed(messagize(message, tsgs=signatures(sender, message, 0), nests=[child], gvrsn=V2))
        kwa = vars(frame).copy()
        kwa.pop("serder")
        assert kramer.intake(message, kwa) is None
        key = (sender.pre, message.said)
        assert hby.db.kramNEST.get(key)
        fakeHelpingClock.advance(seconds=302)
        assert kramer._pruneMessages(int(helping.nowUTC().timestamp() * 1000))
        assert hby.db.kramNEST.get(key) == []


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("bound", [False, True])
def test_reply_route_explicitly_receives_openings(enabled, bound):
    with openHby(name="reply-openings", version=V2) as hby, openCF(name="reply-openings") as cf:
        sender = hby.makeHab(name="sender", icount=2, isith="2", ncount=2, nsith="2")
        cf.put(config(enabled))
        rvy = Revery(db=hby.db)
        received = []

        class OpeningRoute:
            def processReply(self, serder, diger, route, cigars=None, tsgs=None, bsqs=None, bsss=None):
                received.append(tuple([[item.qb64 for item in proof] for proof in family]
                                      for family in (bsqs, bsss)))
                rvy.acceptReply(serder, diger, route, sender.pre, cigars=cigars, tsgs=tsgs)

        rvy.rtr.addRoute("/ipex/unblind", OpeningRoute(), blinders=True)
        kvy = Kevery(db=hby.db, rvy=rvy, kramer=Kramer(db=hby.db, cf=cf))
        message = reply(pre=sender.pre, route="/ipex/unblind", data={}, pvrsn=V2, kind=Kinds.json)
        proof = Blinder.blind(acdc=Diger(ser=b"credential").qb64, state="issued", bound=bound)
        for index in (0, 1):
            raw = messagize(message, tsgs=signatures(sender, message, index),
                             bonds=[proof.data] if index == 0 else None, gvrsn=V2)
            Parser(version=V2, kvy=kvy).parse(ims=bytearray(raw), framed=False)
        encoded = [item.qb64 for item in proof.data]
        wanted = ([], [encoded]) if bound else ([encoded], [])
        assert received == ([wanted] if enabled else [wanted, ([], [])])
        assert hby.db.rpys.get((message.said,)) is not None


def test_default_reply_route_keeps_its_existing_signature():
    with openHby(name="ordinary-reply", version=V2) as hby:
        sender = hby.makeHab(name="sender")
        rvy = Revery(db=hby.db)
        received = []

        class OrdinaryRoute:
            def processReply(self, serder, diger, route, cigars=None, tsgs=None):
                received.append(serder.said)

        rvy.rtr.addRoute("/ordinary", OrdinaryRoute())
        message = reply(pre=sender.pre, route="/ordinary", data={}, pvrsn=V2, kind=Kinds.json)
        proof = Blinder.blind(acdc=Diger(ser=b"credential").qb64, state="issued")
        raw = messagize(message, tsgs=signatures(sender, message, 0), bonds=[proof.data], gvrsn=V2)
        Parser(version=V2, rvy=rvy).parse(ims=bytearray(raw), framed=False)
        assert received == [message.said]
