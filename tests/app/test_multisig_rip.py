"""Native RIP group proposal integration probes."""

from contextlib import ExitStack, contextmanager
from uuid import uuid4

import pytest

from keri import Kinds, Vrsn_2_0
from keri.acdc import messaging
from keri.acdc.registraring import Regery
from keri.app import Counselor, Multiplexor, Notifier, openHby
from keri.app.grouping import loadHandlers, multisigRipExn
from keri.cli.commands.multisig.join import JoinDoer
from keri.kering import ValidationError
from keri.core import Diger, Number, Parser, SealSource, SerderACDC, SerderKERI, exchange, interact, messagize
from keri.peer import Exchanger
from keri.peer.exchanging import serializeParsedSubstream


@contextmanager
def participant_stores(*, temp=True, base=""):
    with ExitStack() as stack:
        hbys = [stack.enter_context(openHby(name=f'rip-{uuid4().hex}-{i}', temp=temp, base=base,
                                           version=Vrsn_2_0)) for i in range(3)]
        members = [hby.makeHab(name='member', version=Vrsn_2_0, kind=Kinds.json)
                   for hby in hbys]
        for hby in hbys:
            for member in members:
                Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(
                    ims=bytearray(member.msgOwnInception(gvrsn=Vrsn_2_0)), local=True)
        mids = [member.pre for member in members]
        groups = [hby.makeGroupHab(group='issuer', mhab=member, smids=mids,
                                   isith='2', nsith='2', version=Vrsn_2_0, kind=Kinds.json)
                  for hby, member in zip(hbys, members)]
        inception = hbys[0].db.evts.get((groups[0].pre, groups[0].pre))
        inception_stream = messagize(inception, sigers=[hby.db.sigs.get((groups[0].pre, inception.said))[0]
                                                       for hby in hbys[:2]],
                                     gvrsn=Vrsn_2_0)
        for hby, group in zip(hbys, groups):
            Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(
                ims=bytearray(inception_stream), local=True)
            assert group.accepted
        rgys = [Regery(hby=hby, name=hby.name, base=base, temp=temp) for hby in hbys]
        for rgy in rgys:
            stack.callback(rgy.store.close)
        yield hbys, groups, rgys


@pytest.fixture
def participants():
    with participant_stores() as participants:
        yield participants


def proposal(hbys, groups, *, rotate=False):
    rip = messaging.regcept(israid=groups[0].pre)
    seal = dict(i=rip.said, s=rip.sad['n'], d=rip.said)
    if rotate:
        for group in groups:
            update = group.mhab.rotate(version=Vrsn_2_0, gvrsn=Vrsn_2_0)
            for hby in hbys:
                Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(update), local=True)
        anchor = groups[0].rotate(verfers=[group.mhab.kever.verfers[0] for group in groups],
                                  digers=[group.mhab.kever.ndigers[0] for group in groups],
                                  isith='2', nsith='2', data=[seal],
                                  version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
    else:
        anchor = groups[0].interact(data=[seal], version=Vrsn_2_0,
                                    kind=Kinds.json, gvrsn=Vrsn_2_0)
    kel = SerderKERI(raw=anchor)
    tel = messagize(rip, bonds=SealSource(s=kel.snh, d=kel.said), gvrsn=Vrsn_2_0)
    wrapper, attachments = multisigRipExn(groups[0], tel, anchor, usage='membership registry')
    return rip, kel, wrapper, attachments


def processors(hby, rgy):
    notifier = Notifier(hby=hby)
    mux = Multiplexor(hby=hby, notifier=notifier, rgy=rgy)
    exc = Exchanger(hby=hby, handlers=[])
    loadHandlers(exc, mux)
    return notifier, mux, Parser(kvy=hby.kvy, exc=exc, rgy=rgy, version=Vrsn_2_0)


@contextmanager
def restart_join(hby, rgy):
    name, base = hby.name, hby.base
    rgy.close()
    hby.close()
    joined = JoinDoer(name=name, base=base, bran=None, group='issuer', version=Vrsn_2_0)
    try:
        yield joined
    finally:
        joined.notifier.noter.close()
        if joined.rgyV2.store.opened:
            joined.rgyV2.close()
        if joined.rgy.reger.opened:
            joined.rgy.close()
        joined.hby.close()


def test_existing_owners_accept_exact_rip_after_normal_group_threshold(participants):
    hbys, groups, rgys = participants
    rip = messaging.regcept(israid=groups[0].pre)
    anchor = SerderKERI(raw=groups[0].interact(
        data=[dict(i=rip.said, s=rip.sad['n'], d=rip.said)],
        version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0))
    first = messagize(anchor, sigers=groups[0].sign(anchor.raw), gvrsn=Vrsn_2_0)
    second = messagize(anchor, sigers=groups[1].sign(anchor.raw), gvrsn=Vrsn_2_0)
    for hby, group, rgy in zip(hbys, groups, rgys):
        assert rgy.processEvent(rip) is False
        Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(first), local=True)
        rgy.processEscrows()
        assert rgy.store.seqEvent(rip.said, 0) is None
        counselor = Counselor(hby=hby, version=Vrsn_2_0)
        number, diger = Number(num=anchor.sn), Diger(qb64=anchor.said)
        counselor.start(group, group.kever.prefixer, number, diger)
        Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(second), local=True)
        hby.kvy.processEscrows()
        assert group.kever.sn == anchor.sn
        counselor.processEscrows()
        rgy.processEscrows()
        assert counselor.complete(group.kever.prefixer, number, diger)
        assert rgy.store.seqEvent(rip.said, 0).raw == rip.raw
        assert rgy.store.anchor(rip.said)[1].qb64 == anchor.said


def test_authenticated_rip_proposal_reaches_existing_notification_path(participants):
    hbys, groups, _ = participants
    rip = messaging.regcept(israid=groups[0].pre)
    anchor = groups[0].interact(data=[dict(i=rip.said, s=rip.sad['n'], d=rip.said)],
                                version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
    tel = messagize(rip, bonds=SealSource(s=SerderKERI(raw=anchor).snh,
                                          d=SerderKERI(raw=anchor).said), gvrsn=Vrsn_2_0)
    nested = [serializeParsedSubstream(Parser(version=Vrsn_2_0).parseOneBare(
                  ims=bytearray(stream), processive=False)) for stream in (tel, anchor)]
    wrapper = exchange(sender=groups[0].mhab.pre, route='/multisig/rip',
                       attributes=dict(gid=groups[0].pre, tel=rip.said,
                                       anc=SerderKERI(raw=anchor).said),
                       version=Vrsn_2_0, kind=Kinds.json)
    stream = groups[0].mhab.endorse(wrapper, last=False, framed=False,
                                  gvrsn=Vrsn_2_0, nests=nested)
    notifier = Notifier(hby=hbys[1])
    mux = Multiplexor(hby=hbys[1], notifier=notifier)
    exc = Exchanger(hby=hbys[1], handlers=[])
    loadHandlers(exc, mux)
    Parser(kvy=hbys[1].kvy, exc=exc, version=Vrsn_2_0).parse(ims=bytearray(stream))
    assert exc.complete(wrapper.said)
    assert groups[1].kever.sn == 0
    notices = [notice.attrs for _, notice in notifier.noter.notes.getTopItemIter()]
    assert notices == [dict(r='/multisig/rip', d=wrapper.said)]


@pytest.mark.parametrize('rotate', [False, True], ids=['interaction-anchor', 'rotation-anchor'])
@pytest.mark.parametrize('advanced', [False, True], ids=['contributed-member', 'member-advanced'])
@pytest.mark.parametrize('answer', ['n', 'y'], ids=['decline', 'approve'])
def test_real_join_prompts_after_reopen_and_uses_normal_threshold(monkeypatch, answer, advanced, rotate):
    with participant_stores(temp=False, base=f'r06a-{uuid4().hex}') as participants:
        hbys, groups, rgys = participants
        rip, anchor, wrapper, attachments = proposal(hbys, groups, rotate=rotate)
        _, _, proposer = processors(hbys[0], rgys[0])
        proposer.parse(ims=bytearray(wrapper.raw + attachments), local=True)
        if advanced:
            update = groups[1].mhab.rotate(version=Vrsn_2_0, gvrsn=Vrsn_2_0)
            for hby in (hbys[0], hbys[2]):
                Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(update))
        notifier, _, receiver = processors(hbys[1], rgys[1])
        receiver.parse(ims=bytearray(wrapper.raw + attachments))
        attrs = next(notifier.noter.notes.getTopItemIter())[1].attrs
        assert groups[1].kever.sn == 0
        assert rgys[1].store.event(rip.said) is None
        notifier.noter.close()
        with restart_join(hbys[1], rgys[1]) as joined:
            assert joined.notifier.noter.notes.cnt() == 1
            prompted = []
            def respond(prompt):
                prompted.append(prompt)
                return answer
            monkeypatch.setattr('builtins.input', respond)
            approval = joined.rip(attrs)
            if answer == 'n':
                with pytest.raises(StopIteration) as done:
                    next(approval)
                assert done.value.value is False
                assert joined.hby.habs[groups[0].pre].kever.sn == 0
                assert joined.rgyV2.store.event(rip.said) is None
                assert joined.hby.db.sigs.get((groups[0].pre, anchor.said)) == []
                assert not joined.postman.evts
            else:
                next(approval)  # Actual approval; finite member submission remains queued.
                local = joined.hby.habs[groups[0].pre]
                assert local.kever.sn == anchor.sn
                assert joined.rgyV2.store.seqEvent(rip.said, 0).raw == rip.raw
                assert joined.counselor.complete(local.kever.prefixer, Number(num=anchor.sn),
                                                  Diger(qb64=anchor.said))
                submissions = list(joined.postman.evts)
                assert [evt['dest'] for evt in submissions] == [groups[0].mhab.pre,
                                                                groups[2].mhab.pre]
                # Deliver queued bytes to real parsers; this does not fake transport ACKs.
                returned = submissions[0]
                proposer.parse(ims=bytearray(returned['serder'].raw + returned['attachment']))
                hbys[0].kvy.processEscrows()
                rgys[0].processEscrows()
                assert rgys[0].store.seqEvent(rip.said, 0).said == rip.said
                assert groups[0].kever.sn == anchor.sn
                assert groups[2].kever.sn == 0  # No third member signature was required.
                assert not joined.postman.cues  # Parser acceptance is not transport completion.
                approval.close()
            assert len(prompted) == 1 and 'Approve exact RIP anchor' in prompted[0]


@pytest.mark.parametrize('fault', ['sender', 'commitment', 'controller', 'seal', 'extra-child', 'source', 'ordinal'])
def test_rip_refuses_invalid_proposals_before_replay(participants, fault):
    hbys, groups, rgys = participants
    rip, anchor, wrapper, attachments = proposal(hbys, groups)
    parsed = Parser(version=Vrsn_2_0).parseOneBare(
        ims=bytearray(wrapper.raw + attachments), processive=False)
    children = parsed.nests
    payload = dict(wrapper.sad['a'])
    signer = groups[0].mhab
    if fault == 'sender':
        signer = hbys[0].makeHab(name='outsider', version=Vrsn_2_0)
        Parser(kvy=hbys[1].kvy, version=Vrsn_2_0).parse(
            ims=bytearray(signer.msgOwnInception(gvrsn=Vrsn_2_0)))
    elif fault == 'commitment':
        payload['tel'] = Diger(ser=b'other RIP').qb64
    elif fault == 'controller':
        children[0].serder = messaging.regcept(israid=signer.pre)
        payload['tel'] = children[0].serder.said
    elif fault == 'seal':
        children[1].serder = interact(pre=groups[0].pre,
                                      dig=groups[0].kever.serder.said, sn=1,
                                      data=[dict(i=rip.said, s='0', d=Diger(ser=b'other TEL').qb64)],
                                      version=Vrsn_2_0, kind=Kinds.json)
        payload['anc'] = children[1].serder.said
    elif fault == 'ordinal':
        sad = dict(rip.sad, n='1')
        children[0].serder = SerderACDC(sad=sad, makify=True)
        badrip = children[0].serder
        children[1].serder = interact(pre=groups[0].pre,
                                      dig=groups[0].kever.serder.said, sn=1,
                                      data=[dict(i=badrip.said, s='1', d=badrip.said)],
                                      version=Vrsn_2_0, kind=Kinds.json)
        children[0].sscs = [(Number(num=1), Diger(qb64=children[1].serder.said))]
        payload.update(tel=badrip.said, anc=children[1].serder.said)
    elif fault == 'extra-child':
        children.append(children[1])
    elif fault == 'source':
        children[0].sscs = [(Number(num=99), Diger(ser=b'other anchor'))]
    invalid = exchange(sender=signer.pre, route='/multisig/rip', attributes=payload,
                        version=Vrsn_2_0, kind=Kinds.json)
    stream = signer.endorse(invalid, last=False, framed=False, gvrsn=Vrsn_2_0,
                            nests=[serializeParsedSubstream(child) for child in children])
    notifier, _, receiver = processors(hbys[1], rgys[1])
    receiver.parse(ims=bytearray(stream))
    assert not receiver.exc.complete(invalid.said)
    assert notifier.noter.notes.cnt() == 0
    assert groups[1].kever.sn == 0
    assert rgys[1].store.event(rip.said) is None
    assert hbys[1].db.evts.get((groups[0].pre, anchor.said)) is None
    assert hbys[1].db.sigs.get((groups[0].pre, anchor.said)) == []


def test_join_resumes_retained_approval_after_acceptance_without_resigning(monkeypatch):
    with participant_stores(temp=False, base=f'r06a-{uuid4().hex}') as participants:
        hbys, groups, rgys = participants
        rip, anchor, wrapper, attachments = proposal(hbys, groups)
        notifier, _, receiver = processors(hbys[1], rgys[1])
        receiver.parse(ims=bytearray(wrapper.raw + attachments))
        attrs = next(notifier.noter.notes.getTopItemIter())[1].attrs
        notifier.noter.close()
        monkeypatch.setattr('builtins.input', lambda _: 'y')
        with restart_join(hbys[1], rgys[1]) as joined:
            approval = joined.rip(attrs)
            next(approval)
            submitted = joined.postman.evts[0]
            exact = submitted['serder'].raw
            nests = joined.hby.db.enst.get((submitted['serder'].said,))
            sigs = [siger.qb64 for siger in joined.hby.db.sigs.get((groups[0].pre, anchor.said))]
            approval.close()
            joined.notifier.noter.close()
            joined.rgy.close()
            with restart_join(joined.hby, joined.rgyV2) as resumed:
                retry = resumed.rip(attrs)
                next(retry)
                resent = resumed.postman.evts[0]
                assert resent['serder'].raw == exact
                assert resumed.hby.db.enst.get((resent['serder'].said,)) == nests
                assert [siger.qb64 for siger in resumed.hby.db.sigs.get(
                    (groups[0].pre, anchor.said))] == sigs
                assert resumed.rgyV2.store.seqEvent(rip.said, 0).said == rip.said
                retry.close()


def test_join_refuses_group_change_during_prompt_before_signing(monkeypatch):
    with participant_stores(temp=False, base=f'r06a-{uuid4().hex}') as participants:
        hbys, groups, rgys = participants
        rip, anchor, wrapper, attachments = proposal(hbys, groups)
        notifier, _, receiver = processors(hbys[1], rgys[1])
        receiver.parse(ims=bytearray(wrapper.raw + attachments))
        attrs = next(notifier.noter.notes.getTopItemIter())[1].attrs
        notifier.noter.close()
        with restart_join(hbys[1], rgys[1]) as joined:
            local = joined.hby.habs[groups[0].pre]
            def changed_while_deciding(prompt):
                other = interact(pre=local.pre, dig=local.kever.serder.said, sn=1,
                                  data=[], version=Vrsn_2_0, kind=Kinds.json)
                joined.hby.kvy.processEvent(serder=other, local=True,
                                            sigers=[group.sign(other.raw)[0]
                                                    for group in (groups[0], groups[2])])
                return 'y'
            monkeypatch.setattr('builtins.input', changed_while_deciding)
            with pytest.raises(ValidationError, match='group changed'):
                next(joined.rip(attrs))
            assert joined.hby.db.sigs.get((local.pre, anchor.said)) == []
            assert joined.rgyV2.store.event(rip.said) is None
            assert not joined.postman.evts


def test_join_exit_closes_native_owner_before_escrow_doer_starts():
    with participant_stores(temp=False, base=f'r06a-{uuid4().hex}') as participants:
        hbys, _, rgys = participants
        with restart_join(hbys[1], rgys[1]) as joined:
            assert joined.rgyV2.store.opened
            joined.exit()
            assert not joined.rgyV2.store.opened
