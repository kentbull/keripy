"""Native registry acceptance waits for genuine remote KEL delegation."""
from keri import Vrsn_2_0
from keri.acdc import Regery, acdcmap, grant, loadHandlers
from keri.acdc.messaging import regcept, update
from keri.acdc.regbasing import RegBaser
from keri.acdc.regeventing import Rever
from keri.app import openHby
from keri.app.registrar.serving import ServiceConfig
from keri.core import Codens, Counter, Diger, Kevery, Kramer, Number, Parser, SealSource, messagize
from keri.peer import Exchanger


class Notices:
    def add(self, attrs):
        """Ignore accepted-notification attributes for this verifier-only test.

        Args:
            attrs (dict): Notification payload deliberately unused by the test.

        Returns:
            None. No notification side effects are needed to observe acceptance."""
        pass


def test_native_delegated_issuer_recovers_after_real_authorization_and_reopen(tmp_path):
    """Retain foreign TEL dependencies across reopen and accept only after real delegator authorization recovers the issuer KEL.

    Parameters:
        tmp_path: Pytest-owned durable registry directory for restart recovery.

    Returns:
        None. Assertions check the stated evidence boundary."""
    with (openHby(name='native-delegator', version=Vrsn_2_0) as sender,
          openHby(name='native-delegation-receiver', version=Vrsn_2_0) as receiver):
        delegator = sender.makeHab(name='delegator')
        issuer = sender.makeHab(name='issuer', delpre=delegator.pre)
        dip = issuer.kever.serder
        holder = receiver.makeHab(name='holder')
        rip = regcept(issuer.pre)
        credential = acdcmap(israid=issuer.pre, regid=rip.said, iseaid=holder.pre,
                             attribute=dict(d='', authority='delegated'))
        issued = update(rip.said, rip.said, credential.said, 'issued')
        for event in (rip, issued):
            issuer.interact(data=[dict(s=event.sad['n'], d=event.said)],
                            version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        foot = Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b
        kvy = Kevery(db=receiver.db, lax=False, local=False,
                     kramer=Kramer(receiver.db, cf=ServiceConfig()))
        parser = Parser(kvy=kvy, version=Vrsn_2_0)
        parser.parse(ims=bytearray(delegator.replay(gvrsn=Vrsn_2_0)))
        parser.parse(ims=bytearray(issuer.replay(gvrsn=Vrsn_2_0)))
        kvy.processEscrows()
        assert receiver.db.kels.getLast(keys=issuer.pre, on=0) is None
        baser = RegBaser(name='delegated-native', headDirPath=str(tmp_path), temp=False)
        rever = Rever(db=receiver.db, reger=baser)
        parser.rgy = rever
        parser.parse(ims=bytearray(rip.raw + foot + issued.raw + foot))
        assert rever.store.head(rip.said) is None
        assert baser.maes.get(keys=rip.said, on=0) == [(rip.said,)]
        assert baser.maes.get(keys=rip.said, on=1) == [(issued.said,)]
        baser.close()
        baser.reopen()
        rgy = Regery(receiver, baser=baser)
        try:
            rever = Rever(db=receiver.db, reger=baser)
            parser.rgy = rever
            rever.processEscrows()
            assert rever.store.head(rip.said) is None
            # Only real delegator approval plus its exact source reference makes
            # the remote dip acceptable. Native TEL acceptance then recovers.
            approval = delegator.interact(data=[dict(i=issuer.pre, s='0', d=dip.said)],
                                          version=Vrsn_2_0, gvrsn=Vrsn_2_0)
            parser.parse(ims=bytearray(approval))
            source = SealSource(s=Number(num=delegator.kever.sn),
                                d=Diger(qb64=delegator.kever.serder.said))
            parser.parse(ims=messagize(dip, sigers=issuer.sign(dip.raw),
                                      bonds=[source], gvrsn=Vrsn_2_0))
            kvy.processEscrows()
            assert receiver.db.kels.getLast(keys=issuer.pre, on=0) == dip.said
            # Prior interaction bodies arrived before authorization and now
            # advance from the ordinary KEL out-of-order escrow.
            assert receiver.kevers[issuer.pre].sn == 2
            rever.processEscrows()
            assert rever.store.headEvent(rip.said).said == issued.said
            assert baser.maes.get(keys=rip.said, on=0) == []
            assert baser.ooes.get(keys=rip.said, on=1) == []
            exc = Exchanger(receiver, handlers=[])
            loadHandlers(receiver, exc, Notices(), rgy=rgy)
            parser.exc = exc
            exn, attachments = grant(issuer, holder.pre, 'authorized delegated issuer',
                                     origin=credential.raw + foot)
            parser.parse(ims=bytearray(exn.raw + attachments))
            assert exc.complete(exn.said)
            assert exc.routes['/ipex/grant'].verifyAccepted(exn.said)
        finally:
            rgy.close()
