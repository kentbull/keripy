"""KRAM forwards the verified reply threshold to ordinary reply acceptance."""
from keri import Vrsn_2_0
from keri.app import openHby, openCF
from keri.core import Diger, Kevery, Kramer, Number, Parser, Revery, reply
from keri.kering import Kinds
from tests.core.test_kraming import KRAM_INTEGRATION_CONFIG


def test_split_reply_signatures_reach_revery_after_partial_cleanup(mockHelpingNowUTC):
    """Separate valid packets release one complete proof, then equal replay drops."""
    with openHby(name='reply-threshold-sender') as sender, \
         openHby(name='reply-threshold-receiver') as receiver, \
         openCF(name='reply-threshold-policy') as cf:
        hab = sender.makeHab(name='author', isith='2', icount=3,
                             version=Vrsn_2_0, kind=Kinds.json)
        Parser(version=Vrsn_2_0, kvy=Kevery(db=receiver.db, lax=False, local=False)).parse(
            ims=bytearray(hab.replay(gvrsn=Vrsn_2_0)))
        cf.put(KRAM_INTEGRATION_CONFIG)
        kramer, rvy = Kramer(db=receiver.db, cf=cf), Revery(db=receiver.db)
        body = reply(pre=hab.pre, route='/test/reply-threshold', data={'value': 'exact'},
                     version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)
        sigers = hab.sign(body.raw, indexed=True)

        def packet(index):
            """Provide exactly one real current-establishment signature per packet."""
            return dict(tsgs=[(hab.kever.prefixer, Number(num=hab.kever.lastEst.s),
                               Diger(qb64=hab.kever.lastEst.d), [sigers[index]])])

        key = (hab.pre, body.said)
        assert kramer.intake(body, packet(0)) is None
        assert [sig.index for sig in receiver.db.kramPMKS.get(key)] == [0]
        assert receiver.db.rpys.get((body.said,)) is None
        # Losing only the process cache must not lose the verified contribution.
        kramer = Kramer(db=receiver.db, cf=cf)
        last = packet(1)
        assert kramer.intake(body, last).said == body.said
        assert [sig.index for sig in last['tsgs'][0][3]] == [0, 1]
        assert receiver.db.kramPMKS.get(key) == []
        assert receiver.db.kramPMKM.get(key) is None
        assert rvy.acceptReply(serder=body, saider=Diger(qb64=body.said),
                               route=body.route, aid=hab.pre, tsgs=last['tsgs'])
        assert receiver.db.rpys.get((body.said,)).raw == body.raw
        assert kramer.intake(body, packet(2)) is None
