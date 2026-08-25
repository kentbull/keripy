# -*- encoding: utf-8 -*-
"""
KERI
tests.app.forwarding module

"""
import time

from hio.base import doing, tyming

from keri import core, kering
from keri.core import coring, eventing, parsing, serdering

from keri.app import agenting, forwarding, habbing, indirecting, storing

from keri.peer import exchanging


def test_postman(seeder):
    with habbing.openHab(name="test", transferable=True, temp=True) as (hby, hab), \
            habbing.openHby(name="wes", salt=core.Salter(raw=b'wess-the-witness').qb64, temp=True) as wesHby, \
            habbing.openHby(name="repTest", temp=True) as recpHby:

        mbx = storing.Mailboxer(name="wes", temp=True)
        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, mbx=mbx, tcpPort=5634, httpPort=5644)
        wesHab = wesHby.habByName("wes")
        seeder.seedWitEnds(hby.db, witHabs=[wesHab])
        seeder.seedWitEnds(wesHby.db, witHabs=[wesHab])
        seeder.seedWitEnds(recpHby.db, witHabs=[wesHab])

        recpHab = recpHby.makeHab(name="repTest", transferable=True, wits=[wesHab.pre])

        recpIcp = recpHab.makeOwnEvent(sn=0)
        wesKvy = eventing.Kevery(db=wesHab.db, lax=False, local=False)
        parsing.Parser().parse(ims=bytearray(recpIcp), kvy=wesKvy, local=True)
        assert recpHab.pre in wesKvy.kevers

        serder = serdering.SerderKERI(raw=recpIcp)
        rct = wesHab.receipt(serder)

        kvy = eventing.Kevery(db=hab.db)
        parsing.Parser().parseOne(bytearray(recpIcp), kvy=kvy, local=True)
        parsing.Parser().parseOne(bytearray(rct), kvy=kvy, local=True)
        kvy.processEscrows()
        assert recpHab.pre in kvy.kevers

        pman = forwarding.Poster(hby=hby)

        exn, _ = exchanging.exchange(route="/echo", payload=dict(msg="test"), sender=hab.pre)
        atc = hab.endorse(exn, last=False)
        del atc[:exn.size]
        pman.send(src=hab.pre, dest=recpHab.pre, topic="echo", serder=exn, attachment=atc)

        doers = wesDoers + [pman]
        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=doers)
        doist.enter()

        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not tymer.expired:
            doist.recur()
            time.sleep(doist.tock)

        assert doist.limit == limit

        doist.exit()

        msgs = []
        for _, topic, msg in mbx.cloneTopicIter(topic=recpHab.pre + "/echo"):
            msgs.append(msg)

        assert len(msgs) == 1
        serder = serdering.SerderKERI(raw=msgs[0])
        assert serder.ked["t"] == coring.Ilks.exn
        assert serder.ked["r"] == "/echo"
        assert serder.ked["a"] == dict(msg="test")


def test_poster_contains_failed_messenger(monkeypatch):
    with habbing.openHby(name="poster-failure", temp=True) as hby:
        hab = hby.makeHab(name="sender", transferable=True)
        recp = hby.makeHab(name="recipient", transferable=True)
        messenger = agenting.TCPMessenger(
            hab=hab,
            wit=recp.pre,
            url="tcp://127.0.0.1:1",
        )
        messenger.error = kering.ClosedError("connection closed")
        monkeypatch.setattr(agenting, "messengerFrom",
                            lambda hab, pre, urls: messenger)
        monkeypatch.setattr(
            hab,
            "endsFor",
            lambda pre: {
                kering.Roles.controller: {
                    recp.pre: {
                        kering.Schemes.tcp: "tcp://127.0.0.1:1",
                    },
                },
            },
        )

        poster = forwarding.Poster(hby=hby)
        poster.send(hab=hab, dest=recp.pre, topic="test",
                    serder=hab.kever.serder)
        doist = doing.Doist(tock=0.03125, limit=1.0, doers=[poster])
        doist.enter()

        try:
            # terminal failure cleans up the child without reporting delivery
            doist.recur()

            assert not poster.evts
            assert not poster.cues
            assert messenger not in poster.doers
        finally:
            doist.exit()


def test_forward_handler():
    with habbing.openHab(name="test", transferable=True, temp=True) as (hby, hab):
        mbx = storing.Mailboxer()
        forwarder = forwarding.ForwardHandler(hby=hby, mbx=mbx)
        # TODO: implement a real test here
