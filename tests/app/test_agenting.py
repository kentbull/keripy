# -*- encoding: utf-8 -*-
"""
tests.app.agenting module

"""
import time

import pytest

from hio.base import doing, tyming
from hio.core import http

from keri import kering, core
from keri.core import coring, serdering
from keri.core.coring import Seqner
from keri.help import nowIso8601
from keri.app import habbing, indirecting, agenting, directing
from keri.db import basing, dbing
from keri.vdr import eventing, viring


def test_http_messengers_read_state_after_client_service():
    expected = http.clienting.Response(
        version=(1, 1),
        status=204,
        reason=None,
        headers={},
        body=b"",
        data=None,
        request=None,
        errored=False,
        error=None,
    )

    # Test both types of messenger
    for klas in (agenting.HTTPMessenger, agenting.HTTPStreamMessenger):
        kwa = dict(
            hab=None,
            wit="witness",
            url="http://127.0.0.1:1",
        )
        if klas is agenting.HTTPStreamMessenger:
            kwa["msg"] = b"message"

        messenger = klas(**kwa)
        serviced = False

        def service():  # mock just to verify order of call to messenger
            nonlocal serviced
            if not serviced:
                messenger.client.responses.append(expected._asdict())  # mock HTTP success
                serviced = True

        messenger.client.service = service  # Inject mock into service
        doist = doing.Doist(tock=0.03125, limit=1.0, doers=[messenger])
        doist.enter()

        try:
            doist.recur()  # iterate doers normally exactly once

            assert serviced
            if isinstance(messenger, agenting.HTTPStreamMessenger):
                assert messenger.done  # stream messenger is done after one message
                assert messenger.rep == expected  # should be exactly one response
            else:
                assert list(messenger.sent) == [expected]  # should be exactly one response
        finally:
            doist.exit()


@pytest.mark.parametrize("klas", [agenting.TCPMessenger,
                                  agenting.TCPStreamMessenger])
def test_tcp_messenger_retains_terminal_transport_error(klas):
    marker = ConnectionResetError("send failed")

    with habbing.openHab(name="tcp-messenger-terminal", temp=True) as (_, hab):
        messenger = klas(
            hab=hab,
            wit="witness",
            url="tcp://127.0.0.1:1",
            **({"msg": b"message"}
               if klas is agenting.TCPStreamMessenger else {}),
        )
        if klas is agenting.TCPMessenger:
            messenger.msgs.append(bytearray(b"message"))

        receipt = messenger.receiptDo(tymth=lambda: 0.0)
        assert next(receipt) == 0.0
        assert next(receipt) == 0.0
        assert messenger.client.txbs

        messenger.client.error = marker
        messenger.client.cutoff = False
        messenger.client.txCutoff = True

        with pytest.raises(StopIteration):
            next(receipt)

        assert messenger.error is marker
        assert not messenger.cutoff
        assert messenger.txCutoff
        assert not messenger.idle
        messenger.client.close()


@pytest.mark.parametrize("klas", [agenting.TCPMessenger,
                                  agenting.TCPStreamMessenger])
def test_tcp_messenger_allows_drain_after_receive_cutoff(klas):
    with habbing.openHab(name="tcp-messenger-half-close",
                         temp=True) as (_, hab):
        messenger = klas(
            hab=hab,
            wit="witness",
            url="tcp://127.0.0.1:1",
            **({"msg": b"message"}
               if klas is agenting.TCPStreamMessenger else {}),
        )
        if klas is agenting.TCPMessenger:
            messenger.msgs.append(bytearray(b"message"))

        receipt = messenger.receiptDo(tymth=lambda: 0.0)
        assert next(receipt) == 0.0
        assert next(receipt) == 0.0
        messenger.client.cutoff = True

        assert next(receipt) == 0.0
        assert messenger.error is None
        messenger.client.txbs.clear()

        if klas is agenting.TCPStreamMessenger:
            with pytest.raises(StopIteration):
                next(receipt)
        else:
            assert next(receipt) == 0.0

        assert messenger.cutoff
        assert not messenger.txCutoff
        assert messenger.error is None
        assert messenger.idle
        assert messenger.sent.popleft() == bytearray(b"message")
        assert messenger.idle
        messenger.client.close()


@pytest.mark.parametrize(
    ("cutoff", "tx_cutoff", "with_error"),
    [(True, False, False), (False, True, True)],
    ids=("receive-cutoff", "transmit-error"),
)
def test_http_messenger_retains_transport_error_after_client_service(
        cutoff, tx_cutoff, with_error):
    marker = ConnectionResetError("response failed") if with_error else None
    messenger = agenting.HTTPMessenger(
        hab=None,
        wit="witness",
        url="http://127.0.0.1:1",
    )
    response = messenger.responseDo(tymth=lambda: 0.0)
    assert next(response) == 0.0

    messenger.msgs.append(bytearray(b"message"))
    messenger.client.connector.error = marker
    messenger.client.connector.cutoff = cutoff
    messenger.client.connector.txCutoff = tx_cutoff
    assert next(response) is None

    if marker is not None:
        assert messenger.error is marker
    else:
        assert isinstance(messenger.error, kering.ClosedError)
    assert messenger.cutoff is cutoff
    assert messenger.txCutoff is tx_cutoff
    assert not messenger.idle
    response.close()
    messenger.client.close()


def test_http_messenger_completed_response_precedes_later_cutoff():
    expected = http.clienting.Response(
        version=(1, 1),
        status=204,
        reason=None,
        headers={},
        body=b"",
        data=None,
        request=None,
        errored=False,
        error=None,
    )
    marker = ConnectionResetError("closed after response")
    messenger = agenting.HTTPMessenger(
        hab=None,
        wit="witness",
        url="http://127.0.0.1:1",
    )
    messenger.client.responses.append(expected._asdict())
    messenger.client.connector.error = marker
    messenger.client.connector.cutoff = True
    messenger.client.connector.txCutoff = True

    response = messenger.responseDo(tymth=lambda: 0.0)
    assert next(response) == 0.0
    assert next(response) is None
    assert next(response) is None

    assert list(messenger.sent) == [expected]
    assert messenger.error is None
    assert messenger.idle
    messenger.sent.popleft()
    assert messenger.idle
    response.close()
    messenger.client.close()


def test_http_stream_messenger_retains_terminal_transport_error():
    messenger = agenting.HTTPStreamMessenger(
        hab=None,
        wit="witness",
        url="http://127.0.0.1:1",
        msg=b"message",
    )
    marker = ConnectionResetError("response failed")

    def service():
        messenger.client.connector.error = marker
        messenger.client.connector.cutoff = True
        messenger.client.connector.txCutoff = True

    messenger.client.service = service
    doist = doing.Doist(tock=0.03125, limit=1.0, doers=[messenger])
    doist.enter()

    try:
        doist.recur()
        assert messenger.done
        assert messenger.rep is None
        assert messenger.error is marker
        assert not messenger.idle
    finally:
        doist.exit()


def test_witness_inquisitor_contains_failed_messenger(monkeypatch):
    with habbing.openHby(name="inquisitor-failure", temp=True) as hby:
        wit = hby.makeHab(name="offline-witness", transferable=False)
        hab = hby.makeHab(name="controller", transferable=True,
                          wits=[wit.pre])
        messenger = agenting.TCPMessenger(
            hab=hab,
            wit=wit.pre,
            url="tcp://127.0.0.1:1",
        )
        messenger.error = kering.ClosedError("connection closed")
        monkeypatch.setattr(agenting, "messenger",
                            lambda hab, pre: messenger)

        inquisitor = agenting.WitnessInquisitor(hby=hby)
        inquisitor.query(pre=hab.pre, src=hab.pre, wits=[wit.pre])
        doist = doing.Doist(tock=0.03125, limit=1.0,
                            doers=[inquisitor])
        doist.enter()

        try:
            doist.recur()
            assert not inquisitor.msgs
            assert not inquisitor.sent
            assert messenger not in inquisitor.doers
        finally:
            doist.exit()


def test_witness_receiptor_contains_failed_messenger(monkeypatch):
    with habbing.openHby(name="receiptor-failure", temp=True) as hby:
        wit = hby.makeHab(name="offline-witness", transferable=False)
        hab = hby.makeHab(name="controller", transferable=True,
                          wits=[wit.pre])
        messenger = agenting.TCPMessenger(
            hab=hab,
            wit=wit.pre,
            url="tcp://127.0.0.1:1",
        )
        messenger.error = kering.ClosedError("connection closed")
        monkeypatch.setattr(agenting, "messenger",
                            lambda hab, pre, auth=None: messenger)

        receiptor = agenting.WitnessReceiptor(hby=hby)
        receiptor.msgs.append(dict(pre=hab.pre))
        doist = doing.Doist(tock=0.03125, limit=1.0,
                            doers=[receiptor])
        doist.enter()

        try:
            doist.recur()
            doist.recur()
            assert not receiptor.msgs
            assert not receiptor.cues
            assert messenger not in receiptor.doers
        finally:
            doist.exit()


def test_witness_publisher_contains_failed_messenger(monkeypatch):
    with habbing.openHby(name="publisher-failure", temp=True) as hby:
        wit = hby.makeHab(name="offline-witness", transferable=False)
        hab = hby.makeHab(name="controller", transferable=True,
                          wits=[wit.pre])
        messenger = agenting.TCPMessenger(
            hab=hab,
            wit=wit.pre,
            url="tcp://127.0.0.1:1",
        )
        messenger.error = kering.ClosedError("connection closed")
        monkeypatch.setattr(agenting, "messenger",
                            lambda hab, pre: messenger)

        publisher = agenting.WitnessPublisher(hby=hby)
        publisher.msgs.append(dict(pre=hab.pre,
                                   msg=hab.makeOwnInception()))
        doist = doing.Doist(tock=0.03125, limit=1.0,
                            doers=[publisher])
        doist.enter()

        try:
            doist.recur()
            doist.recur()
            assert not publisher.msgs
            assert not publisher.cues
            assert messenger not in publisher.doers
            assert publisher.idle
        finally:
            doist.exit()


def test_receiptor_tocks_are_generator_local():
    with habbing.openHby(name="receiptor-generator-tocks", temp=True) as hby:
        receiptor = agenting.Receiptor(hby=hby)
        seen = []

        def receipt(pre, sn=None, auths=None, tock=0.0):
            seen.append(("receipt", tock))
            yield tock

        def get(pre, sn=None, tock=0.0):
            seen.append(("get", tock))
            yield tock

        receiptor.receipt = receipt
        receiptor.get = get
        receiptor.msgs.append({"pre": "witness"})
        receiptor.gets.append({"pre": "query"})

        witness = receiptor.witDo(tymth=lambda: 0.0, tock=0.011)
        query = receiptor.gitDo(tymth=lambda: 0.0, tock=0.013)

        assert next(witness) == 0.011
        assert next(query) == 0.013
        assert next(witness) == 0.011
        assert next(query) == 0.013
        assert seen == [("receipt", 0.011), ("get", 0.013)]

        witness.close()
        query.close()


def test_witness_receiptor(seeder):
    with habbing.openHby(name="wan", salt=core.Salter(raw=b'wann-the-witness').qb64) as wanHby, \
            habbing.openHby(name="wil", salt=core.Salter(raw=b'will-the-witness').qb64) as wilHby, \
            habbing.openHby(name="wes", salt=core.Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            habbing.openHby(name="pal", salt=core.Salter(raw=b'0123456789abcdef').qb64) as palHby:

        wanDoers = indirecting.setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(alias="wil", hby=wilHby, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)

        wanHab = wanHby.habByName(name="wan")
        wilHab = wilHby.habByName(name="wil")
        wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[wanHab, wilHab, wesHab], protocols=[kering.Schemes.tcp])

        rctDoer = ReceiptDoer(hby=palHby, wanHab=wanHab, wilHab=wilHab, wesHab=wesHab)

        limit = 5.0
        tock = 0.03125
        doers = wanDoers + wilDoers + wesDoers + [rctDoer]
        doist = doing.Doist(limit=limit, tock=tock, doers=doers)
        doist.enter()
        tymer = tyming.Tymer(tymth=doist.tymen(), duration=doist.limit)

        while not (rctDoer.done or tymer.expired):
            doist.recur()
            time.sleep(doist.tock)

        doist.exit()

        assert rctDoer.done is True


class ReceiptDoer(doing.DoDoer):
    """ Test scenario of witness receipts. """

    def __init__(self, hby, wanHab, wilHab, wesHab):
        self.hby = hby
        self.wanHab = wanHab
        self.wilHab = wilHab
        self.wesHab = wesHab

        super(ReceiptDoer, self).__init__(doers=[doing.doify(self.testDo)])

    def testDo(self, tymth, tock=0.0, **kwa):
        """ Execute a series of kli commands for this test scenario """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        palHab = self.hby.makeHab(name="pal", wits=[self.wanHab.pre, self.wilHab.pre], transferable=True)

        witDoer = agenting.WitnessReceiptor(hby=self.hby)
        witDoer.msgs.append(dict(pre=palHab.pre))
        self.extend([witDoer])

        kev = palHab.kever
        ser = kev.serder
        dgkey = dbing.dgKey(ser.preb, ser.saidb)

        while True:
            wilWigs = self.wilHab.db.getWigs(dgkey)
            wanWigs = self.wanHab.db.getWigs(dgkey)
            if len(wilWigs) == 2 and len(wanWigs) == 2:
                break
            yield self.tock

        # Controller should send endpoints between witnesses.  Check for Endpoints for each other:
        keys = (self.wanHab.pre, kering.Schemes.tcp)
        said = self.wilHab.db.lans.get(keys=keys)
        assert said is not None
        keys = (self.wilHab.pre, kering.Schemes.tcp)
        said = self.wanHab.db.lans.get(keys=keys)
        assert said is not None

        palHab.rotate(adds=[self.wesHab.pre])

        witDoer.msgs.append(dict(pre=palHab.pre, sn=1))

        kev = palHab.kever
        ser = kev.serder
        dgkey = dbing.dgKey(ser.preb, ser.saidb)

        while True:
            wilWigs = self.wilHab.db.getWigs(dgkey)
            wanWigs = self.wanHab.db.getWigs(dgkey)
            wesWigs = self.wesHab.db.getWigs(dgkey)
            if len(wilWigs) == 3 and len(wanWigs) == 3 and len(wesWigs) == 3:
                break
            yield self.tock

        self.remove([witDoer])
        return True


def test_witness_sender(seeder):
    with habbing.openHby(name="wan", salt=core.Salter(raw=b'wann-the-witness').qb64) as wanHby, \
            habbing.openHby(name="wil", salt=core.Salter(raw=b'will-the-witness').qb64) as wilHby, \
            habbing.openHby(name="wes", salt=core.Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            habbing.openHby(name="pal", salt=core.Salter(raw=b'0123456789abcdef').qb64) as palHby:

        # looks like bad magic value in seeder is causing this to fail
        pdoer = PublishDoer(wanHby, wilHby, wesHby, palHby, seeder)
        directing.runController(doers=[pdoer], expire=10.0)
        assert pdoer.done is True


class PublishDoer(doing.DoDoer):

    def __init__(self, wanHby, wilHby, wesHby, palHby, seeder):
        wanDoers = indirecting.setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(alias="wil", hby=wilHby, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)
        # Pull the regers out of the Doers so the regers are reused and do not trigger an LMDB error on reuse
        self.regers = dict(
            wan=next(doer.baser for doer in wanDoers if isinstance(doer, basing.BaserDoer)),
            wil=next(doer.baser for doer in wilDoers if isinstance(doer, basing.BaserDoer)),
            wes=next(doer.baser for doer in wesDoers if isinstance(doer, basing.BaserDoer)),
        )

        wanHab = wanHby.habByName(name="wan")
        wilHab = wilHby.habByName(name="wil")
        wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[wanHab, wilHab, wesHab], protocols=[kering.Schemes.tcp])

        self.palHab = palHby.makeHab(name="pal", wits=[wanHab.pre, wilHab.pre, wesHab.pre], transferable=True)

        self.witDoer = agenting.WitnessPublisher(hby=palHby)
        doers = wanDoers + wilDoers + wesDoers + [self.witDoer]
        self.toRemove = list(doers)
        doers.extend([doing.doify(self.testDo)])

        super(PublishDoer, self).__init__(doers=doers)

    def testDo(self, tymth, tock=0.0, **kwa):
        """ Run the test and exit and remove all child doers when done """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        regser = eventing.incept(pre=self.palHab.pre, baks=[], code=coring.MtrDex.Blake3_256)
        serder = eventing.issue(vcdig=regser.pre,
                                regk="EbA1o_bItVC9i6YB3hr2C3I_Gtqvz02vCmavJNoBA3Jg")
        msg = bytearray(serder.raw)
        msg.extend(core.Counter(core.Codens.SealSourceCouples, count=1,
                                gvrsn=kering.Vrsn_1_0).qb64b)
        msg.extend(Seqner(sn=self.palHab.kever.sn).qb64b)
        msg.extend(self.palHab.kever.serder.saidb)

        self.witDoer.msgs.append(dict(pre=self.palHab.pre, msg=msg))

        while not self.witDoer.cues:
            yield self.tock

        cue = self.witDoer.cues.popleft()
        assert cue["pre"] == self.palHab.pre
        assert cue["msg"] == msg
        assert self.witDoer.idle

        for name in ["wes", "wil", "wan"]:
            reger = self.regers[name]
            while True:
                raw = reger.getTvt(dbing.dgKey(serder.preb, serder.saidb))
                if raw:
                    found = serdering.SerderKERI(raw=bytes(raw))
                    if found and serder.pre == found.pre:
                        break
                yield self.tock

        self.remove(self.toRemove)
        return True


def test_witness_inquisitor(mockHelpingNowUTC, seeder):
    with habbing.openHby(name="wan", salt=core.Salter(raw=b'wann-the-witness').qb64) as wanHby, \
            habbing.openHby(name="wil", salt=core.Salter(raw=b'will-the-witness').qb64) as wilHby, \
            habbing.openHby(name="wes", salt=core.Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            habbing.openHby(name="pal", salt=core.Salter(raw=b'0123456789abcdef').qb64) as palHby, \
            habbing.openHby(name="qin", salt=core.Salter(raw=b'abcdef0123456789').qb64) as qinHby:
        wanDoers = indirecting.setupWitness(alias="wan", hby=wanHby, tcpPort=5632, httpPort=5642)
        wilDoers = indirecting.setupWitness(alias="wil", hby=wilHby, tcpPort=5633, httpPort=5643)
        wesDoers = indirecting.setupWitness(alias="wes", hby=wesHby, tcpPort=5634, httpPort=5644)

        wanHab = wanHby.habByName(name="wan")
        wilHab = wilHby.habByName(name="wil")
        wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[wanHab, wilHab, wesHab], protocols=[kering.Schemes.tcp])
        seeder.seedWitEnds(qinHby.db, witHabs=[wanHab, wilHab, wesHab], protocols=[kering.Schemes.tcp])

        palHab = palHby.makeHab(name="pal", wits=[wanHab.pre, wilHab.pre, wesHab.pre], transferable=True)
        qinHab = qinHby.makeHab(name="qin", wits=[wanHab.pre, wilHab.pre, wesHab.pre], transferable=True)

        palWitDoer = agenting.WitnessReceiptor(hby=palHby)
        palWitDoer.msgs.append(dict(pre=palHab.pre))
        qinWitDoer = agenting.WitnessReceiptor(hby=qinHby)
        qinWitDoer.msgs.append(dict(pre=qinHab.pre))

        qinWitq = agenting.WitnessInquisitor(hby=qinHby)
        # query up a few to make sure it still works
        stamp = nowIso8601()  # need same time stamp or not duplicate
        qinWitq.query(src=qinHab.pre, pre=palHab.pre, stamp=stamp, wits=palHab.kever.wits)
        qinWitq.query(src=qinHab.pre, pre=palHab.pre, stamp=stamp, wits=palHab.kever.wits)
        qinWitq.query(src=qinHab.pre, pre=palHab.pre, stamp=stamp, wits=palHab.kever.wits)
        palWitq = agenting.WitnessInquisitor(hby=palHby)
        palWitq.query(src=palHab.pre, pre=qinHab.pre, stamp=stamp, wits=qinHab.kever.wits)

        limit = 5.0
        tock = 0.03125
        doist = doing.Doist(limit=limit, tock=tock)
        doers = wanDoers + wilDoers + wesDoers + [palWitDoer, qinWitDoer]
        doist.do(doers=doers)

        for hab in [palHab, qinHab]:
            kev = hab.kever
            ser = kev.serder
            dgkey = dbing.dgKey(ser.preb, ser.saidb)

            wigs = wanHab.db.getWigs(dgkey)
            assert len(wigs) == 3
            wigs = wilHab.db.getWigs(dgkey)
            assert len(wigs) == 3
            wigs = wesHab.db.getWigs(dgkey)
            assert len(wigs) == 3

        doist = doing.Doist(limit=limit, tock=tock)
        doers = wanDoers + wilDoers + wesDoers + [qinWitq, palWitq]
        doist.do(doers=doers)

        assert palHab.pre in qinHab.kevers
        assert qinHab.pre in palHab.kevers
