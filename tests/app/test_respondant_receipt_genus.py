"""Respondant receipts preserve authentication across explicit framing versions."""

import pytest
from hio.help import decking

from keri import Vrsn_1_0, Vrsn_2_0
from keri.app import Mailboxer, Poster, Respondant, openHab, openHby
from keri.core import Kevery, Parser
from keri.kering import Roles


@pytest.mark.parametrize('posterVersion,eventVersion,targetVersion,configuredPoster', [
    (Vrsn_1_0, Vrsn_1_0, Vrsn_1_0, False),
    (Vrsn_2_0, Vrsn_2_0, Vrsn_2_0, False),
    (Vrsn_2_0, Vrsn_1_0, Vrsn_2_0, False),
    (Vrsn_2_0, Vrsn_1_0, Vrsn_1_0, True),
], ids=['v1', 'v2', 'native-v2-legacy-event', 'configured-legacy-output'])
def test_respondant_receipt_authenticates(posterVersion, eventVersion,
                                         targetVersion, configuredPoster, monkeypatch):
    """Use a real receipt cue, Poster mailbox and recipient witness-signature verification.

    Input attachment genus comes from the receipt producer. Output framing is
    selected by the existing Poster owner, independently of the event body. A
    native V2 owner does not promise delivery to an unconfigured legacy peer.
    Endpoint selection uses the real local mailbox branch to avoid network I/O.
    """
    with openHab(name='receipt-witness', temp=True, version=posterVersion,
                 transferable=False) as (wby, witness), \
            openHby(name='receipt-owner', temp=True, version=targetVersion) as owner:
        owner.psr.parse(ims=witness.replay(gvrsn=targetVersion))
        hab = owner.makeHab(name='owner', version=eventVersion,
                            wits=[witness.pre], toad=1)
        event = hab.kever.serder
        Parser(kvy=Kevery(db=wby.db, lax=True, local=False), version=eventVersion).parse(
            ims=hab.msgOwnEvent(sn=0, gvrsn=eventVersion), local=True)
        assert wby.kevers[hab.pre].serder.said == event.said
        assert not owner.db.wigs.get((hab.pre, event.said))
        mailbox = Mailboxer(name='respondant-receipt', temp=True)
        try:
            respondent = Respondant(wby, mbx=mailbox,
                cues=decking.Deck([dict(kin='receipt', serder=event)]))
            if configuredPoster:
                respondent.postman = Poster(wby, mbx=mailbox, version=targetVersion)
            monkeypatch.setattr(witness, 'endsFor',
                lambda dest: {Roles.mailbox: {witness.pre: {}}})
            cue = respondent.cueDo(tymth=lambda: 0.0)
            deliver = respondent.postman.deliverDo(tymth=lambda: 0.0)
            try:
                next(cue)
                next(cue)
                assert len(respondent.postman.evts) == 1
                next(deliver)
                next(deliver)
            finally:
                cue.close()
                deliver.close()
            messages = list(mailbox.cloneTopicIter(topic=hab.pre + '/receipt'))
            assert len(messages) == 1
            Parser(kvy=owner.kvy, version=targetVersion).parse(
                ims=bytearray(messages[0][2]), local=False)
            assert {signature.index for signature in owner.db.wigs.get(
                (hab.pre, event.said))} == {0}
        finally:
            mailbox.close(clear=True)
