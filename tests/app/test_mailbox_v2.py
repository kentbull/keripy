"""MailboxDirector borrows v2 ACDC TEL and reply owners for actual incoming bytes."""
import pytest

from keri import Kinds, Vrsn_2_0
from keri.acdc import Regery, Registrar, messaging
from keri.app import MailboxDirector, openHby
from keri.core import Diger, Revery, SealSource, SerderKERI, messagize
from keri.kering import Roles


@pytest.fixture
def parties():
    with (openHby(name='v2-mail-source', temp=True, version=Vrsn_2_0) as source,
          openHby(name='v2-mail-receiver', temp=True, version=Vrsn_2_0) as receiver):
        sender = source.makeHab(name='issuer', icount=2, isith='2', ncount=2, nsith='2', version=Vrsn_2_0)
        receiver.makeHab(name='holder', icount=2, isith='2', ncount=2, nsith='2', version=Vrsn_2_0)
        registries = [Regery(hby=hby, name=hby.name, temp=True) for hby in (source, receiver)]
        try:
            yield source, receiver, sender, *registries
        finally:
            for rgy in registries:
                rgy.close()


def test_v2_mailbox_parser_and_escrow_accept_anchored_foreign_tel(parties):
    source, receiver, issuer, own, foreign = parties
    registry = Registrar(own).makeRegistry('public', issuer.pre)
    rip = own.store.event(registry.regk)
    first = issuer.interact(data=[dict(i=rip.said, s='0', d=rip.said)],
                            version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
    assert registry.anchorMsg(rip.said)
    bup = messaging.blindate(regid=rip.said, prior=rip.said, blid=Diger(ser=b'public BLID').qb64, sn=1)
    assert registry.processEvent(bup) is False
    second = issuer.interact(data=[dict(i=rip.said, s='1', d=bup.said)],
                             version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
    assert registry.anchorMsg(bup.said)
    mbx = MailboxDirector(hby=receiver, topics=[], rgy=foreign, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
    escrow = mbx.escrowDo(tymth=lambda: 0.0)
    try:
        for wire in (issuer.msgOwnInception(gvrsn=Vrsn_2_0), first):
            mbx.parser.parseOneBare(ims=bytearray(wire))
        anchor = SerderKERI(raw=first)
        mbx.parser.parseOneBare(ims=messagize(rip, bonds=[SealSource(s=anchor.snh, d=anchor.said)], gvrsn=Vrsn_2_0))
        assert foreign.store.seqEvent(rip.said, 0).raw == rip.raw
        anchor = SerderKERI(raw=second)
        mbx.parser.parseOneBare(ims=messagize(bup, bonds=[SealSource(s=anchor.snh, d=anchor.said)], gvrsn=Vrsn_2_0))
        assert foreign.store.headEvent(rip.said).said == rip.said
        mbx.parser.parseOneBare(ims=bytearray(second))
        assert foreign.store.seqEvent(rip.said, 1) is None, 'KEL arrival alone does not retry the TEL owner'
        next(escrow)
        next(escrow)
        assert foreign.store.headEvent(rip.said).raw == bup.raw
        assert foreign.store.anchor(bup.said)[1].qb64 == anchor.said
    finally:
        escrow.close()
        mbx.exit()
    assert foreign.store.opened, 'MailboxDirector borrows v2 ACDC Regery; the caller closes it'


def test_mailbox_routes_real_reply_through_supplied_revery_router(parties):
    _, receiver, issuer, _, _ = parties
    rvy = Revery(db=receiver.db, lax=True, local=False)
    mbx = MailboxDirector(hby=receiver, topics=[], rvy=rvy, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
    try:
        mbx.parser.parseOneBare(ims=bytearray(issuer.msgOwnInception(gvrsn=Vrsn_2_0)))
        reply = issuer.makeEndRole(issuer.pre, role=Roles.controller, pvrsn=Vrsn_2_0, gvrsn=Vrsn_2_0)
        mbx.parser.parseOneBare(ims=bytearray(reply))
        assert receiver.db.ends.get((issuer.pre, Roles.controller, issuer.pre)).allowed
        assert mbx.rtr is rvy.rtr
    finally:
        mbx.exit()
