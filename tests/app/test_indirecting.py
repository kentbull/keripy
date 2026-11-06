# -*- encoding: utf-8 -*-
"""
tests.app.indirecting module

"""
import json
import subprocess
import time

import falcon
from falcon import testing
import pytest

from hio.core import http, tcp
from hio.base import doing
from hio.help import decking

from keri.kering import Schemes, Vrsn_1_0, Vrsn_2_0, Kinds, Ilks, Roles
from keri.core import SerderKERI, Salter, Kevery, Parser
from keri.db import basing
from keri.app import (MailboxIterable, QryRpyMailboxIterable,
                      QueryEnd, Mailboxer, Receiptor,
                      setupWitness, createHttpServer, openHab, openHby,
                      ReceiptEnd, CESR_CONTENT_TYPE, CESR_DESTINATION_HEADER)
from keri.app.httping import CESR_ATTACHMENT_HEADER



def test_mailbox_iter():
    pre = "EA3mbE6upuYnFlx68GmLYCQd7cCcwG_AtHM6dW_GT068"
    mbx = Mailboxer(temp=True)
    mb = MailboxIterable(mbx=mbx, pre=pre, topics={"/receipt": 0, "/challenge": 1, "/multisig": 0},
                                     retry=1000)

    mbi = iter(mb)

    assert mb.start != 0
    assert mb.end == mb.start

    val = next(mbi)
    assert val == b'retry: 1000\n\n'

    val = next(mbi)
    assert val == b''

    # Store a message for the iter
    msg = dict(i=pre, t="rct")
    mbx.storeMsg(topic=f"{pre}/receipt", msg=json.dumps(msg).encode("utf-8"))
    val = next(mbi)
    assert val == (b'id: 0\nevent: /receipt\nretry: 1000\ndata: {"i": "EA3mbE6upuYnFlx68'
                   b'GmLYCQd7cCcwG_AtHM6dW_GT068", "t": "rct"}\n\n')

    # Store messages for the iter, each next returns all available messages
    mbx.storeMsg(topic=f"{pre}/receipt", msg=json.dumps(msg).encode("utf-8"))
    mbx.storeMsg(topic=f"{pre}/multisig", msg=json.dumps(msg).encode("utf-8"))
    val = next(mbi)
    assert val == (b'id: 1\nevent: /receipt\nretry: 1000\ndata: {"i": "EA3mbE6upuYnFlx68'
                   b'GmLYCQd7cCcwG_AtHM6dW_GT068", "t": "rct"}\n\nid: 0\nevent: /multisi'
                   b'g\nretry: 1000\ndata: {"i": "EA3mbE6upuYnFlx68GmLYCQd7cCcwG_AtHM6d'
                   b'W_GT068", "t": "rct"}\n\n')

    # First stored challenge message will not be found because topics indicates already seen
    mbx.storeMsg(topic=f"{pre}/challenge", msg=json.dumps(msg).encode("utf-8"))
    val = next(mbi)
    assert val == b''

    # Second one will be found
    mbx.storeMsg(topic=f"{pre}/challenge", msg=json.dumps(msg).encode("utf-8"))
    val = next(mbi)
    assert val == (b'id: 1\nevent: /challenge\nretry: 1000\ndata: {"i": "EA3mbE6upuYnFlx'
                   b'68GmLYCQd7cCcwG_AtHM6dW_GT068", "t": "rct"}\n\n')

    # Store a message that does not match any topics
    mbx.storeMsg(topic=f"{pre}/replay", msg=json.dumps(msg).encode("utf-8"))
    val = next(mbi)
    assert val == b''

    mb.TimeoutMBX = 0  # Force the iter to timeout

    with pytest.raises(StopIteration):
        next(mbi)


def test_mailbox_multiple_iter():
    pre = "EA3mbE6upuYnFlx68GmLYCQd7cCcwG_AtHM6dW_GT068"
    msg = dict(words=["abc", "def"])
    mbx = Mailboxer(temp=True)
    mbx.storeMsg(topic=f"{pre}/challenge", msg=json.dumps(msg).encode("utf-8"))

    mb = MailboxIterable(mbx=mbx, pre=pre, topics={"/receipt": 0, "/challenge": 0, "/multisig": 0},
                                     retry=1000)
    mbi = iter(mb)

    assert mb.start != 0
    assert mb.end == mb.start

    # First stored challenge message will not be found because topics indicates already seen
    val = next(mbi)
    assert val == b'retry: 1000\n\n'

    # Second one will be found
    mbx.storeMsg(topic=f"{pre}/challenge", msg=json.dumps(msg).encode("utf-8"))
    val = next(mbi)
    assert val == (b'id: 0\nevent: /challenge\nretry: 1000\ndata: {"words": ["abc", "def'
                   b'"]}\n\nid: 1\nevent: /challenge\nretry: 1000\ndata: {"words": ["a'
                   b'bc", "def"]}\n\n')

    mb.TimeoutMBX = 0  # Force the iter to timeout

    with pytest.raises(StopIteration):
        next(mbi)


def test_qrymailbox_iter():
    with openHab(name="test", transferable=True, temp=True, salt=b'0123456789abcdef', version=Vrsn_1_0, kind=Kinds.json) as (hby, hab):
        assert hab.pre == 'EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3'
        icp = hab.msgOwnInception(framed=True, gvrsn=Vrsn_1_0)
        icpSrdr = SerderKERI(raw=icp)
        qry = hab.query(pre=hab.pre, src=hab.pre, route="/mbx", version=Vrsn_1_0, kind=Kinds.json)
        srdr = SerderKERI(raw=qry)

        cues = decking.Deck()
        mbx = Mailboxer(temp=True)
        mb = QryRpyMailboxIterable(mbx=mbx, cues=cues, said=srdr.said, retry=1000)

        mbi = iter(mb)
        assert mb.iter is None

        #  No cued query response, empty iter
        val = next(mbi)
        assert val == b''
        assert mb.iter is None

        # A cue with the wrong said still returns nothing and recues the cue
        cues.append(dict(kin="stream", serder=icpSrdr))
        val = next(mbi)
        assert val == b''
        assert len(cues) == 1
        assert mb.iter is None
        cues.popleft()

        cues.append(dict(kin="stream", pre=hab.pre, serder=srdr,
                         topics={"/receipt": 0, "/challenge": 1, "/multisig": 0}))
        val = next(mbi)
        assert val == b''
        assert len(cues) == 0
        assert mb.iter is not None

        # And now it behaves just like a standard MailboxIterable
        val = next(mbi)
        assert val == b'retry: 1000\n\n'

        # Store a message for the iter
        msg = dict(i=hab.pre, t="rct")
        mbx.storeMsg(topic=f"{hab.pre}/receipt", msg=json.dumps(msg).encode("utf-8"))
        val = next(mbi)
        assert val == (b'id: 0\nevent: /receipt\nretry: 1000\ndata: '
                       b'{"i": "EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3", '
                       b'"t": "rct"}\n\n')

        mb.iter.TimeoutMBX = 0  # Force the iter to timeout
        with pytest.raises(StopIteration):
            next(mbi)


def test_qrymailbox_iter_v2():
    topics = {"/receipt": 0, "/challenge": 1, "/multisig": 0}

    with openHab(name="test", transferable=True, temp=True, salt=b'0123456789abcdef') as (hby, hab):
        assert hab.pre == 'EChqfw9-5A5qMrZ8_YgOAJm8iKMbTAUvfDVVI6KNGL3M'
        icp = hab.msgOwnInception(framed=True)
        icpSrdr = SerderKERI(raw=icp)
        qry = hab.query(pre=hab.pre, src=hab.pre, route="mbx", query={"topics": topics},
                        kind=Kinds.json)
        srdr = SerderKERI(raw=qry)
        assert srdr.pvrsn == Vrsn_2_0
        assert srdr.gvrsn == Vrsn_2_0
        assert srdr.kind == Kinds.json
        assert srdr.ked["t"] == Ilks.qry
        assert srdr.ked["i"] == hab.pre
        assert srdr.ked["r"] == "mbx"
        assert srdr.ked["q"]["i"] == hab.pre
        assert srdr.ked["q"]["src"] == hab.pre
        assert srdr.ked["q"]["topics"] == topics
        
        cf = {
            "kram": {
                "enabled": True,
                "denials": [],
                "caches": {
                    "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000]
                }
            }
        }

        hby.cf.put(cf)
        kvy = Kevery(db=hby.db, cf=hby.cf, enableKram=True, lax=False, local=False)
        assert kvy.kramer.enabled is True
        Parser().parse(ims=bytearray(qry), kvy=kvy)
        cache = hby.db.kramMSGC.get(keys=(hab.pre, srdr.said))
        assert cache is not None
        assert cache.mdt == srdr.stamp
        assert cache.d == 1000

        cues = decking.Deck()
        mbx = Mailboxer(temp=True)
        mb = QryRpyMailboxIterable(mbx=mbx, cues=cues, said=srdr.said, retry=1000)

        mbi = iter(mb)
        assert mb.iter is None

        #  No cued query response, empty iter
        val = next(mbi)
        assert val == b''
        assert mb.iter is None

        # A cue with the wrong said still returns nothing and recues the cue
        cues.append(dict(kin="stream", serder=icpSrdr))
        val = next(mbi)
        assert val == b''
        assert len(cues) == 1
        assert mb.iter is None
        unrelated = cues.popleft()

        cues.append(dict(kin="stream", pre=hab.pre, serder=srdr, topics=topics))
        otherTopics = {"/receipt": 1}
        otherQry = hab.query(pre=hab.pre, src=hab.pre, route="mbx",
                             query={"topics": otherTopics}, kind=Kinds.json)
        otherSrdr = SerderKERI(raw=otherQry)
        other = QryRpyMailboxIterable(mbx=mbx, cues=cues, said=otherSrdr.said, retry=1000)
        cues.append(dict(kin="stream", pre=hab.pre, serder=otherSrdr, topics=otherTopics))
        cues.append(unrelated)

        # Reverse scheduling must not keep swapping the two query cues.
        assert next(other) == b''
        assert other.iter is not None
        val = next(mbi)
        assert val == b''
        assert list(cues) == [unrelated]
        assert mb.iter is not None

        # And now it behaves just like a standard MailboxIterable
        val = next(mbi)
        assert val == b'retry: 1000\n\n'
        assert next(other) == b'retry: 1000\n\n'

        # Store a message for the iter
        msg = dict(i=hab.pre, t="rct")
        mbx.storeMsg(topic=f"{hab.pre}/receipt", msg=json.dumps(msg).encode("utf-8"))
        val = next(mbi)
        assert val == (b'id: 0\nevent: /receipt\nretry: 1000\ndata: '
                       b'{"i": "EChqfw9-5A5qMrZ8_YgOAJm8iKMbTAUvfDVVI6KNGL3M", '
                       b'"t": "rct"}\n\n')
        assert next(other) == b''
        mbx.storeMsg(topic=f"{hab.pre}/receipt", msg=json.dumps(msg).encode("utf-8"))
        assert next(other) == (b'id: 1\nevent: /receipt\nretry: 1000\ndata: '
                               b'{"i": "EChqfw9-5A5qMrZ8_YgOAJm8iKMbTAUvfDVVI6KNGL3M", '
                               b'"t": "rct"}\n\n')
        assert list(cues) == [unrelated]

        mb.iter.TimeoutMBX = 0  # Force the iter to timeout
        with pytest.raises(StopIteration):
            next(mbi)


def test_wit_query_ends(seeder, witnessPorter):
    with openHby(name="wes", salt=Salter(raw=b'wess-the-witness').qb64) as wesHby, \
            openHby(name="pal", salt=Salter(raw=b'0123456789abcdef').qb64) as palHby:
        witnessPorts, witnessUrls = witnessPorter("wes")
        wesDoers = setupWitness(alias="wes", hby=wesHby,
                                tcpPort=witnessPorts["wes"]["tcp"],
                                httpPort=witnessPorts["wes"]["http"])
        # Pull the reger out of the Doers so the reger is reused and does not trigger an LMDB error on reuse
        wesReger = next(doer.baser for doer in wesDoers if isinstance(doer, basing.BaserDoer))
        witDoer = Receiptor(hby=palHby)

        wesHab = wesHby.habByName(name="wes")
        seeder.seedWitEnds(palHby.db, witHabs=[wesHab],
                           protocols=[Schemes.http], witnessUrls=witnessUrls)

        app = falcon.App()
        query_endpoint = QueryEnd(wesHab, reger=wesReger)
        app.add_route("/query", query_endpoint)

        wesClient = testing.TestClient(app)

        opts = dict(
            wesHab=wesHab,
            palHby=palHby,
            witDoer=witDoer,
            wesClient=wesClient
        )
        testDo = QueryTestDoer(**opts)
        doers = wesDoers + [witDoer, testDo]

        limit = 1.0
        tock = 0.03125
        doist = doing.Doist(tock=tock, limit=limit, doers=doers)
        doist.enter()

        while not testDo.done:
            doist.recur()
            time.sleep(doist.tock)

        assert doist.limit == limit

        doist.exit()


class QueryTestDoer(doing.Doer):
    def __init__(self, **opts):
        self.options = opts
        super(QueryTestDoer, self).__init__(**opts)

    def recur(self, tyme=0.0, deeds=None, **kwa):
        wesHab = self.options["wesHab"]
        palHby = self.options["palHby"]
        witDoer = self.options["witDoer"]
        wesClient = self.options["wesClient"]

        palHab = palHby.makeHab(name="pal", wits=[wesHab.pre], transferable=True)

        assert palHab.pre == "ECF_sIdpuhOhnEw9zV6cq6ZWLKGJbjH052_xiJT7Uh6z"

        witDoer.msgs.append(dict(pre=palHab.pre))
        while not witDoer.cues:
            yield self.tock

        msg = next(wesHab.db.clonePreIter(pre=palHab.pre, version=palHab.kever.serder.pvrsn))


        # Test valid KEL query with 'pre'
        res = wesClient.simulate_get("/query", params={"typ": "kel", "pre": palHab.pre})
        assert res.status_code == 200
        assert res.headers['Content-Type'] == "application/cesr"
        assert bytearray(res.content) == bytearray(msg)

        # Test KEL query without 'pre'
        res = wesClient.simulate_get("/query", params={"typ": "kel"})
        assert res.status_code == 400
        assert res.headers['Content-Type'] == "application/json"
        assert "'pre' query param is required" in res.text

        # Test KEL query with 'sn' parameter
        res = wesClient.simulate_get("/query", params={"typ": "kel", "pre": palHab.pre, "sn": 0})
        assert res.status_code == 200
        assert res.headers['Content-Type'] == "application/cesr"

        # Test KEL query with non-existant 'sn' parameter
        res = wesClient.simulate_get("/query", params={"typ": "kel", "pre": palHab.pre, "sn": 5})
        assert res.status_code == 400
        assert res.headers['Content-Type'] == "application/json"
        assert "non-existant event at seq-num 5" in res.text

        # Test valid TEL query with 'reg'
        res = wesClient.simulate_get("/query", params={"typ": "tel", "reg": "mock_reg"})
        assert res.status_code == 200
        assert res.headers['Content-Type'] == "application/cesr"

        # Test valid TEL query with 'vcid'
        res = wesClient.simulate_get("/query", params={"typ": "tel", "vcid": "mock_vcid"})
        assert res.status_code == 200
        assert res.headers['Content-Type'] == "application/cesr"

        # Test TEL query missing both 'reg' and 'vcid'
        res = wesClient.simulate_get("/query", params={"typ": "tel"})
        assert res.status_code == 400
        assert res.headers['Content-Type'] == "application/json"
        assert "Either 'reg' or 'vcid' query param is required for TEL query" in res.text

        # Test invalid 'typ' parameter
        res = wesClient.simulate_get("/query", params={"typ": "invalid"})
        assert res.status_code == 400
        assert res.headers['Content-Type'] == "application/json"
        assert "unkown query type" in res.text

        return True


def test_createHttpServer(tmp_path):
    """Retain the requested interface, including the actual TLS listening socket."""
    app = falcon.App()
    server = createHttpServer('127.0.0.1', 0, app)
    assert isinstance(server, http.Server)
    assert server.servant.ha[0] == '127.0.0.1'

    # Generate test-only TLS material; no network trust or host keys are needed.
    key, cert = tmp_path / 'key.pem', tmp_path / 'cert.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(key), '-out', str(cert), '-days', '1',
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                   check=True, capture_output=True, timeout=15)
    server = createHttpServer('127.0.0.1', 0, app, keypath=str(key),
                              certpath=str(cert), cafilepath=str(cert))
    try:
        assert isinstance(server.servant, tcp.ServerTls)
        assert server.reopen()
        # The TLS servant owns the socket; passing host only to HTTP is too late.
        assert server.servant.ss.getsockname()[0] == '127.0.0.1'
    finally:
        server.close()


def test_receipt_end_returns_bytes_for_v1_receipt():
    with openHby(name="receipt-wit", version=Vrsn_1_0) as witHby, \
            openHby(name="receipt-cam", version=Vrsn_1_0) as camHby:
        wit = witHby.makeHab(name="wit", transferable=False, version=Vrsn_1_0, kind=Kinds.json)
        cam = camHby.makeHab(name="cam", transferable=True, wits=[wit.pre],
                             toad=1, icount=1, ncount=1,
                             isith="1", nsith="1", version=Vrsn_1_0, kind=Kinds.json)

        serder, _, _ = cam.getOwnEvent(sn=0)
        msg = cam.msgOwnEvent(sn=0, framed=True, gvrsn=Vrsn_2_0)

        ims = bytearray(msg)
        serder = SerderKERI(raw=ims)
        del ims[:serder.size]

        app = falcon.App()
        endpoint = ReceiptEnd(hab=wit, version=Vrsn_1_0)
        app.add_route("/receipts", endpoint)
        client = testing.TestClient(app)

        res = client.simulate_post("/receipts",
                                   body=serder.raw,
                                   headers={
                                       "Content-Type": CESR_CONTENT_TYPE,
                                       "CESR-Genus": "2",
                                       CESR_ATTACHMENT_HEADER: bytes(ims).decode("utf-8"),
                                       CESR_DESTINATION_HEADER: wit.pre,
                                   })

        assert res.status_code == 200
        assert isinstance(res.content, bytes)
        rserder = SerderKERI(raw=res.content)
        assert rserder.pvrsn == Vrsn_1_0
        assert rserder.ked["t"] == Ilks.rct
        assert endpoint.psr.version == Vrsn_1_0
        parsed = Parser(version=Vrsn_1_0).parse(ims=bytearray(res.content), processive=False)
        assert parsed[0].serder.raw == rserder.raw
        assert len(parsed[0].cigars) == 1
        assert parsed[0].cigars[0].verfer.qb64 == wit.pre
        assert parsed[0].cigars[0].verfer.verify(parsed[0].cigars[0].raw, serder.raw)
        fetched = client.simulate_get('/receipts', params=dict(pre=cam.pre, sn=0))
        assert fetched.status_code == 200
        frames = Parser(version=Vrsn_1_0).parse(ims=bytearray(fetched.content), processive=False)
        assert len(frames) == 1 and frames[0].serder.pvrsn == Vrsn_1_0
        camHby.psr.parseOne(ims=bytearray(fetched.content), local=True)
        assert len(camHby.db.wigs.get((cam.pre, serder.said))) == 1


def test_receipt_get_encapsulates_cesr_v2_witness_signatures():
    with openHby(name="get-wit", version=Vrsn_2_0) as whby, \
            openHby(name="get-controller", version=Vrsn_2_0) as chby:
        wit = whby.makeHab(name="wit", transferable=False, version=Vrsn_2_0)
        controller = chby.makeHab(name="controller", wits=[wit.pre], toad=1, version=Vrsn_2_0)
        event, _, _ = controller.getOwnEvent(sn=0)
        endpoint = ReceiptEnd(hab=wit, version=Vrsn_2_0)
        endpoint.psr.parseOne(ims=bytearray(controller.msgOwnInception(gvrsn=Vrsn_2_0)), local=True)
        endpoint.psr.parseOne(ims=bytearray(wit.receipt(event, version=Vrsn_2_0, gvrsn=Vrsn_2_0)), local=True)
        app = falcon.App()
        app.add_route('/receipts', endpoint)
        response = testing.TestClient(app).simulate_get('/receipts', params=dict(pre=controller.pre, sn=0))
        assert response.status_code == 200
        # HTTP success must carry a parseable CESR v2 attachment envelope and verified receipt.
        frames = Parser(version=Vrsn_2_0).parse(ims=bytearray(response.content), processive=False)
        assert len(frames) == 1 and frames[0].serder.said == event.said
        assert len(frames[0].wigers) == 1
        chby.psr.parseOne(ims=bytearray(response.content), local=True)
        assert len(chby.db.wigs.get((controller.pre, event.said))) == 1


def test_mailbox_query_honors_explicit_v1_kwargs():
    with openHby(name="mailbox-query", version=Vrsn_1_0) as hby:
        hab = hby.makeHab(name="cam", version=Vrsn_1_0, kind=Kinds.json)

        msg = hab.query(pre=hab.pre,
                        src=hab.pre,
                        route="mbx",
                        query=dict(topics={"/receipt": 0}),
                        version=Vrsn_1_0, kind=Kinds.json)

        serder = SerderKERI(raw=msg)
        assert serder.pvrsn == Vrsn_1_0
        assert serder.kind == Kinds.json
        assert serder.ked["q"]["topics"] == {"/receipt": 0}


def test_follow_on_events_honor_explicit_v1_kwargs():
    with openHby(name="v1-follow-ons", version=Vrsn_1_0) as hby:
        hab = hby.makeHab(name="cam", version=Vrsn_1_0, kind=Kinds.json)

        rot = hab.rotate(framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        rserder = SerderKERI(raw=rot)
        assert rserder.pvrsn == Vrsn_1_0
        assert rserder.kind == Kinds.json

        ixn = hab.interact(framed=True, version=Vrsn_1_0, kind=Kinds.json, gvrsn=Vrsn_1_0)
        iserder = SerderKERI(raw=ixn)
        assert iserder.pvrsn == Vrsn_1_0
        assert iserder.kind == Kinds.json


def test_end_role_reply_defaults_to_v2_attachments_for_v1_hab():
    """Omitted gvrsn keeps default (``Version``) attachment framing on a v1 reply body."""
    with openHby(name="v1-end-role", version=Vrsn_1_0) as hby:
        hab = hby.makeHab(name="cam", version=Vrsn_1_0, kind=Kinds.json)

        msg = hab.makeEndRole(eid=hab.pre, role=Roles.mailbox)
        serder = SerderKERI(raw=msg)
        assert serder.pvrsn == Vrsn_1_0
        assert serder.kind == Kinds.json
        atc = bytes(msg[serder.size:])
        assert atc.startswith(b"-C")  # default AttachmentGroup framing
        assert not atc.startswith(b"-V")  # not v1 attachment group

        # Local v1-only parser needs explicit v1 attachments.
        msg_v1 = hab.makeEndRole(eid=hab.pre, role=Roles.mailbox, gvrsn=Vrsn_1_0)
        hab.psr.parse(ims=bytearray(msg_v1))
        loaded = hab.loadEndRole(cid=hab.pre, eid=hab.pre, role=Roles.mailbox,
                                 gvrsn=Vrsn_1_0)
        assert loaded



def test_query_end_reuses_injected_reger():
    """QueryEnd must use an injected reger instead of opening a second one,
    preventing LMDB double-open on the same TEL store.  See #1367.
    """
    from keri.app.indirecting import QueryEnd
    from unittest.mock import MagicMock

    mock_hab = MagicMock()
    mock_reger = MagicMock()

    qe = QueryEnd(hab=mock_hab, reger=mock_reger)
    assert qe.reger is mock_reger


if __name__ == "__main__":
    test_mailbox_iter()
    test_qrymailbox_iter()
    test_wit_query_ends()
