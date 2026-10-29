"""Reply dependency recovery preserves existing nontransferable attachments."""
import pytest

from keri import Vrsn_1_0, Vrsn_2_0
from keri.app import openHby
from keri.core import Dater, Parser, Revery, Signer, reply
from keri.kering import Kinds, UnverifiedReplyError, ValidationError


class DependentReply:
    """Require a real reply signature and one explicit application dependency."""

    def __init__(self, rvy, author):
        """Borrow Revery and the expected author; start with evidence unavailable."""
        self.rvy, self.author = rvy, author
        self.ready = False
        self.accepted = []

    def processReply(self, *, serder, diger, route, cigars=None, tsgs=None):
        """Reverify attachments before either escrowing or applying the reply."""
        if not self.rvy.acceptReply(serder=serder, saider=diger, route=route,
                                   aid=self.author, cigars=cigars, tsgs=tsgs):
            raise ValidationError('reply signature is invalid')
        if not self.ready:
            self.rvy.escrowReply(serder=serder, saider=diger, dater=Dater(dts=serder.stamp),
                                 route=route, cigars=cigars)
            raise UnverifiedReplyError('application evidence is not ready')
        self.accepted.append(serder.said)


@pytest.mark.parametrize('version', [Vrsn_1_0, Vrsn_2_0])
@pytest.mark.parametrize('corrupt', [False, True])
def test_cigar_reply_dependency_recovery_reopens_and_reverifies(tmp_path, version, corrupt):
    """Keep a delayed signed reply across reopen; corrupted signatures never apply."""
    with openHby(name='cigar-reply-sender', version=version) as sender, \
         openHby(name='cigar-reply-receiver', temp=False, headDirPath=str(tmp_path), version=version) as receiver:
        hab = sender.makeHab(name='individual', transferable=False, version=version)
        body = reply(pre=hab.pre, route='/test/dependency', data={'value': 'exact'}, version=version, kind=Kinds.json)
        parsed = Parser(version=version).parse(ims=bytearray(hab.endorse(body, gvrsn=version)),
                                              processive=False)[0]
        rvy = Revery(db=receiver.db)
        resource = DependentReply(rvy, hab.pre)
        rvy.rtr.addRoute(body.route, resource)
        with pytest.raises(UnverifiedReplyError):
            rvy.processReply(serder=body, cigars=parsed.cigars)
        assert [said.qb64 for said in receiver.db.rpes.get((body.route,))] == [body.said]
        receiver.db.close()
        receiver.db.reopen()
        rvy = Revery(db=receiver.db)
        resource = DependentReply(rvy, hab.pre)
        rvy.rtr.addRoute(body.route, resource)
        rvy.processEscrowReply()
        assert resource.accepted == []
        assert receiver.db.rpes.get((body.route,))
        if corrupt:
            forged = Signer(transferable=False).sign(body.raw)
            receiver.db.scgs.rem((body.said,))
            receiver.db.scgs.put((body.said,), [(parsed.cigars[0].verfer, forged)])
        resource.ready = True
        rvy.processEscrowReply()
        assert resource.accepted == ([] if corrupt else [body.said])
        assert receiver.db.rpes.get((body.route,)) == []
        if not corrupt:
            assert receiver.db.rpys.get((body.said,)).raw == body.raw
            assert receiver.db.scgs.get((body.said,))[0][1].raw == parsed.cigars[0].raw
