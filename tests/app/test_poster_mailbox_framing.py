"""Poster carries authenticated group proposals through native mailbox framing."""

from types import SimpleNamespace

import pytest
from hio.base import doing
from hio.core import tcp

from keri import Vrsn_1_0, Vrsn_2_0
from keri.app import (openHab, Mailboxer, ForwardHandler, Poster, MailboxDirector,
                      Multiplexor, multisigInceptExn)
from keri.app import forwarding
from keri.app.agenting import TCPMessenger
from keri.app.grouping import loadHandlers
from keri.core import Parser
from keri.peer import Exchanger
from keri.kering import Roles, Schemes
from tests.app.test_acdc_v2_groups import Notices
from tests.app.test_tcp_stream_delivery import advance, received


def sendViaTcp(hby, sender, recipient, witness, poster, child, attachments, version, proposalVersion):
    """Select a real signed mailbox endpoint and deliver through the queued Poster runtime."""
    server = tcp.Server(ha=('127.0.0.1', 0))
    assert server.reopen()
    server.eha = server.ha
    doist = doing.Doist(tock=0.01)
    try:
        evidence = witness.replay(gvrsn=version)
        evidence.extend(recipient.makeEndRole(eid=witness.pre, role=Roles.mailbox,
                                              version=version, gvrsn=version))
        evidence.extend(witness.makeLocScheme(url=f'tcp://127.0.0.1:{server.ha[1]}',
            scheme=Schemes.tcp, version=version, gvrsn=version))
        hby.psr.parse(ims=evidence)
        poster.send(src=sender.pre, dest=recipient.pre, topic='multisig',
                    serder=child, attachment=attachments, gvrsn=proposalVersion)
        doist.deeds.extend(doist.enter(doers=[tcp.ServerDoer(server=server), poster]))

        def delivered():
            """Observe actual messenger completion and exact server-side socket bytes."""
            transport = next((item for item in poster.doers if isinstance(item, TCPMessenger)), None)
            return (transport is not None and transport.sent and poster.sent(child.said)
                    and received(server) == transport.sent[0])

        advance(doist, delivered)
        return received(server)
    finally:
        doist.exit()
        server.close()


@pytest.mark.parametrize('version, proposalVersion', [(Vrsn_1_0, Vrsn_1_0),
    (Vrsn_2_0, Vrsn_1_0), (Vrsn_2_0, Vrsn_2_0)])
@pytest.mark.parametrize('method', ['forward', 'forwardToWitness', 'sendDirect', 'local', 'tcp'])
def test_poster_proposal_reaches_mailbox_recipient_group_quorum(version, proposalVersion, method, monkeypatch):
    """Verify actual witness intake and recipient replay with both real group signatures.

    Capture only the network leaf except for the real queued TCP cases.
    Existing serializers, witness authentication,
    mailbox storage, MailboxDirector parser and locally approved Multiplexor all
    run normally. Legacy v1 and native v2 proposals keep their exact signed body.
    """
    with openHab(name='mailbox-sender', temp=True, version=version) as (hby, sender), \
            openHab(name='mailbox-recipient', temp=True, version=version) as (rby, recipient), \
            openHab(name='mailbox-witness', temp=True, version=version,
                    transferable=False) as (wby, witness):
        for owner, peer in ((hby, recipient), (rby, sender)):
            Parser(kvy=owner.kvy, version=version).parse(ims=peer.replay(gvrsn=version), local=False)
        mids = [sender.pre, recipient.pre]
        groups = [owner.makeGroupHab(group='group', mhab=member, smids=mids,
            isith='2', nsith='2', version=version) for owner, member in ((hby, sender), (rby, recipient))]
        assert groups[0].pre == groups[1].pre and not groups[1].accepted
        exchanger = Exchanger(rby, handlers=[])
        mux = Multiplexor(rby, Notices(), exc=exchanger)
        loadHandlers(exchanger, mux)
        mailboxDirector = MailboxDirector(rby, topics=['/multisig'], exc=exchanger,
                                          kvy=mux.kvy, rvy=mux.rvy, version=version)
        own, ownAttachments = multisigInceptExn(recipient, mids, mids,
            groups[1].msgOwnInception(allowPartiallySigned=True, gvrsn=version), version=proposalVersion)
        Parser(kvy=mux.kvy, rvy=mux.rvy, exc=exchanger, version=proposalVersion).parse(
            ims=bytearray(own.raw + ownAttachments), local=True)
        child, attachments = multisigInceptExn(sender, mids, mids,
            groups[0].msgOwnInception(allowPartiallySigned=True, gvrsn=version), version=proposalVersion)
        original = Parser(version=proposalVersion).parse(
            ims=bytearray(child.raw + attachments), processive=False)[0]
        captured = SimpleNamespace(msgs=[], idle=True)
        if method != 'tcp':
            monkeypatch.setattr(forwarding, 'messengerFrom', lambda **kwa: captured)
        mailbox = Mailboxer(name='poster-framing', temp=True)
        try:
            poster = Poster(hby, version=version, mbx=mailbox if method == 'local' else None)
            if method != 'tcp':
                monkeypatch.setattr(poster, 'extend', lambda children: None)
            if version == Vrsn_2_0 and proposalVersion == Vrsn_1_0 and method == 'forward':
                with pytest.raises(ValueError, match='Expected one forwarding payload'):
                    list(poster.forward(sender, {witness.pre: {}}, recp=recipient.pre,
                        serder=child, atc=attachments, topic='multisig'))
                assert captured.msgs == []  # ambiguous input is never guessed or sent
            if method == 'sendDirect':
                list(poster.sendDirect(sender, {recipient.pre: {'http': 'http://unused.invalid'}},
                    serder=child, atc=attachments, gvrsn=proposalVersion))
                stream = captured.msgs[0]
            else:
                if method == 'tcp':
                    wire = sendViaTcp(hby, sender, recipient, witness, poster, child,
                                      attachments, version, proposalVersion)
                else:
                    endpoint = sender.pre if method == 'local' else witness.pre
                    operation = poster.forward if method == 'local' else getattr(poster, method)
                    list(operation(sender, {endpoint: {'http': 'http://unused.invalid'}}, recp=recipient.pre,
                        serder=child, atc=attachments, topic='multisig', gvrsn=proposalVersion))
                    wire = captured.msgs[0] if captured.msgs else None
                if method != 'local':
                    witnessExchanger = Exchanger(wby, handlers=[ForwardHandler(wby, mailbox)])
                    Parser(kvy=wby.kvy, rvy=wby.rvy, exc=witnessExchanger, version=version).parse(
                        ims=bytearray(wire), local=False)
                retained = list(mailbox.cloneTopicIter(topic=recipient.pre + '/multisig'))
                assert len(retained) == 1
                stream = retained[0][2]
            if version == Vrsn_1_0:
                assert bytes(stream) == child.raw + attachments
            parsed = Parser(version=version).parse(ims=bytearray(stream), processive=False)
            assert parsed and len(parsed) == 1 and parsed[0].serder.raw == child.raw
            assert [signature.qb64 for signature in parsed[0].tsgs[0][3]] == [
                signature.qb64 for signature in original.tsgs[0][3]]
            mailboxDirector.parser.parse(ims=bytearray(stream), local=False)
            mux.kvy.processEscrows()
            assert rby.db.exns.get((child.said,)).raw == child.raw
            assert groups[1].accepted
            signatures = rby.db.sigs.get((groups[1].pre, groups[1].kever.lastEst.d))
            assert {signature.index for signature in signatures} == {0, 1}
        finally:
            mailbox.close(clear=True)
