"""Native RIP group proposal integration probes."""

from contextlib import ExitStack, contextmanager
from time import monotonic, sleep
from uuid import uuid4

import falcon
import pytest
from hio.base import doing
from hio.core import http

from keri import Kinds, Vrsn_2_0
from keri.acdc import messaging
from keri.acdc.registraring import Regery
from keri.app import Counselor, Multiplexor, Notifier, openHby
from keri.app.grouping import loadHandlers, multisigRipExn
from keri.app.indirecting import ReceiptEnd
from keri.cli.commands.multisig.join import JoinDoer
from keri.cli.commands.vc.registry.incept import NativeRegistryInceptor
from keri.kering import ValidationError
from keri.core import Diger, Number, Parser, Prefixer, SealSource, SerderACDC, SerderKERI, exchange, interact, messagize
from keri.peer import Exchanger
from keri.peer.exchanging import serializeParsedSubstream


@contextmanager
def participant_stores(*, temp=True, base="", est_only=False, wits=()):
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
                                   isith='2', nsith='2', estOnly=est_only, wits=list(wits), toad=len(wits),
                                   version=Vrsn_2_0, kind=Kinds.json)
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
def restart_join(hby, rgy, **options):
    name, base = hby.name, hby.base
    rgy.close()
    hby.close()
    joined = JoinDoer(name=name, base=base, bran=None, group='issuer', version=Vrsn_2_0, **options)
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


def test_group_registry_auth_reaches_elected_witnesser_and_accepts_exact_tel(unused_tcp_port):
    class AuthorizationGate:
        def __init__(self):
            self.expected = None
            self.received = []

        def process_request(self, req, rep):
            if req.method == 'POST':
                header = req.get_header('Authorization')
                self.received.append(header)
                if header != self.expected:
                    raise falcon.HTTPUnauthorized(description='Witness authorization required')

    with openHby(name='auth-witness', version=Vrsn_2_0) as whby:
        witness = whby.makeHab(name='witness', transferable=False, version=Vrsn_2_0)
        endpoint = ReceiptEnd(hab=witness, version=Vrsn_2_0)
        gate = AuthorizationGate()
        app = falcon.App(middleware=[gate])
        app.add_route('/receipts', endpoint)
        server = http.Server(host='127.0.0.1', port=unused_tcp_port, app=app)
        with participant_stores(wits=[witness.pre]) as (hbys, groups, rgys):
            counselors = [Counselor(hby=hby, version=Vrsn_2_0) for hby in hbys[:2]]
            scheduler = doing.Doist(doers=[http.ServerDoer(server=server), endpoint, *counselors], tock=.03125)
            scheduler.enter()
            try:
                server.servant.eha = server.servant.ha
                introduction = witness.replay(gvrsn=Vrsn_2_0) + witness.makeLocScheme(
                    url=f'http://127.0.0.1:{server.servant.ha[1]}', scheme='http', gvrsn=Vrsn_2_0)
                for hby in hbys:
                    hby.psr.parse(ims=bytearray(introduction))

                def witness_event(anchor, tel=None):
                    # The proposer is member 1; the verified lowest signer, member 0, sends receipts.
                    assert groups[0].witnesser(sn=anchor.sn, dig=anchor.said)
                    assert not groups[1].witnesser(sn=anchor.sn, dig=anchor.said)
                    gate.expected = f'code-{anchor.sn}#2026-11-04T00:00:00+00:00'
                    key = (anchor.pre, anchor.sn, anchor.said)
                    borrowed = []
                    for counselor, group in zip(counselors, groups):
                        assert not counselor._witnessAuths
                        counselor.start(group, Prefixer(qb64=anchor.pre), Number(num=anchor.sn),
                                        Diger(qb64=anchor.said), auths={witness.pre: gate.expected})
                        counselor.processEscrows()
                        borrowed.append(counselor._witnessAuths[key])
                    assert counselors[0].witDoer.msgs[0]['auths'] is borrowed[0]
                    assert not counselors[1].witDoer.msgs
                    before = len(gate.received)
                    cutoff = monotonic() + 20
                    while not all(counselor.complete(Prefixer(qb64=anchor.pre), Number(num=anchor.sn),
                                                     Diger(qb64=anchor.said)) for counselor in counselors):
                        assert monotonic() < cutoff, gate.received
                        scheduler.recur()
                        for hby, rgy in zip(hbys, rgys):
                            hby.kvy.processEscrows()
                            rgy.processEscrows()
                        sleep(.002)
                    assert gate.received[before:] == [gate.expected]
                    for counselor, hby, rgy, headers in zip(counselors, hbys, rgys, borrowed):
                        assert not counselor._witnessAuths and not headers
                        assert hby.db.fullyWitnessed(anchor)
                        receipt, = hby.db.wigs.get((anchor.pre, anchor.said))
                        assert receipt.index == 0
                        assert witness.kever.verfers[0].verify(receipt.raw, anchor.raw)
                        if tel is not None:
                            accepted = rgy.store.seqEvent(
                                tel.said if tel.ilk == 'rip' else tel.sad['rd'], Number(numh=tel.sad['n']).num)
                            assert accepted is not None and accepted.raw == tel.raw
                            assert rgy.store.anchor(tel.said)[1].qb64 == anchor.said

                # Bootstrap the witnessed group, then require fresh event-specific headers for RIP and BUP.
                witness_event(groups[0].kever.serder)
                rip = messaging.regcept(israid=groups[0].pre)
                bup = messaging.blindate(regid=rip.said, prior=rip.said,
                                         blid=Diger(ser=b'opaque authorized update').qb64)
                for tel in (rip, bup):
                    regid = rip.said
                    partial = groups[1].interact(data=[dict(i=regid, s=tel.sad['n'], d=tel.said)],
                                                 version=Vrsn_2_0, gvrsn=Vrsn_2_0)
                    anchor = SerderKERI(raw=partial)
                    complete = messagize(anchor, sigers=[group.sign(anchor.raw)[0] for group in groups[:2]],
                                          gvrsn=Vrsn_2_0)
                    for hby, rgy in zip(hbys[:2], rgys[:2]):
                        hby.psr.parse(ims=bytearray(complete), local=True)
                        hby.kvy.processEscrows()
                        assert not rgy.processEvent(tel, sscs=[(Number(num=anchor.sn), Diger(qb64=anchor.said))])
                        assert rgy.store.seqEvent(regid, Number(numh=tel.sad['n']).num) is None
                    witness_event(anchor, tel)
                # Closing an unfinished event also destroys its borrowed header dictionary.
                pending = SerderKERI(raw=groups[1].interact(version=Vrsn_2_0, gvrsn=Vrsn_2_0))
                counselors[1].start(groups[1], groups[1].kever.prefixer, Number(num=pending.sn),
                                     Diger(qb64=pending.said), auths={witness.pre: 'exit-only'})
                abandoned = counselors[1]._witnessAuths[(pending.pre, pending.sn, pending.said)]
            finally:
                scheduler.exit()
            assert all(not counselor._witnessAuths for counselor in counselors)
            assert not abandoned


def test_real_join_supplies_elected_members_exact_witness_authorization():
    with openHby(name='join-auth-witness', version=Vrsn_2_0) as whby:
        witness = whby.makeHab(name='witness', transferable=False, version=Vrsn_2_0)
        with participant_stores(temp=False, base=f'join-auth-{uuid4().hex}', wits=[witness.pre]) as participants:
            hbys, groups, rgys = participants
            # Member 1 proposes; member 0 becomes the elected witnesser only after explicit approval.
            rip, anchor, wrapper, attachments = proposal(
                [hbys[1], hbys[0], hbys[2]], [groups[1], groups[0], groups[2]])
            notifier, _, receiver = processors(hbys[0], rgys[0])
            receiver.parse(ims=bytearray(wrapper.raw + attachments))
            attrs = next(notifier.noter.notes.getTopItemIter())[1].attrs
            notifier.noter.close()
            stamp = '2026-11-04T00:00:00+00:00'
            with restart_join(hbys[0], rgys[0], auto=True, authenticate=True,
                              codes=[f'{witness.pre}:123456'], codeTime=stamp) as joined:
                approval = joined.rip(attrs)
                try:
                    next(approval)
                    group = joined.hby.habByName('issuer')
                    assert group.witnesser(sn=anchor.sn, dig=anchor.said)
                    assert wrapper.pre != group.mhab.pre
                    headers = joined.counselor._witnessAuths[(group.pre, anchor.sn, anchor.said)]
                    assert headers == {witness.pre: f'123456#{stamp}'}
                    assert joined.counselor.witDoer.msgs[0]['auths'] is headers
                    assert joined.rgyV2.store.seqEvent(rip.said, 0) is None
                finally:
                    approval.close()
                    joined.counselor.exit()
                assert not headers


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


@pytest.mark.parametrize('est_only', [False, True], ids=['interaction', 'accepted-establishment-only'])
@pytest.mark.parametrize('answer', ['n', 'y'], ids=['decline', 'approve'])
def test_native_registry_command_proposes_exact_anchor_for_real_join(monkeypatch, est_only, answer):
    with participant_stores(temp=False, base=f'r10group-{uuid4().hex}', est_only=est_only) as participants:
        hbys, groups, rgys = participants
        gid, mids = groups[0].pre, [group.mhab.pre for group in groups]
        if est_only:
            for group in groups:
                wire = group.mhab.rotate(version=Vrsn_2_0, gvrsn=Vrsn_2_0)
                for hby in hbys:
                    Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(wire), local=True)
        name, base = hbys[0].name, hbys[0].base
        rgys[0].close()
        hbys[0].close()
        command = NativeRegistryInceptor(name=name, base=base, bran=None, alias='issuer',
                                           registryName='membership', usage='member credentials')
        operation = command.inceptDo(tymth=lambda: 0.0)
        try:
            next(operation)
            next(operation)  # One contribution cannot satisfy the ordinary 2-of-3 threshold.
            queued = list(command.postman.evts)
            assert [event['dest'] for event in queued] == mids[1:]
            wrapper = queued[0]['serder']
            assert command.exc.complete(wrapper.said), 'own authenticated consent must precede submission'
            children = Parser(version=Vrsn_2_0).parseOneBare(
                ims=bytearray(wrapper.raw + queued[0]['attachment']), processive=False).nests
            rip, anchor = [child.serder for child in children]
            assert anchor.ilk == ('rot' if est_only else 'ixn')
            assert wrapper.sad['a'] == dict(gid=gid, tel=rip.said, anc=anchor.said, usage='member credentials')
            assert dict(i=rip.said, s='0', d=rip.said) in anchor.seals
            assert [(number.num, diger.qb64) for number, diger in children[0].sscs] == [(anchor.sn, anchor.said)]
            assert command.hab.kever.sn == 0
            assert command.rgy.store.seqEvent(rip.said, 0) is None
            assert not command.counselor.complete(command.hab.kever.prefixer, Number(num=1), Diger(qb64=anchor.said))
            notifier, _, receiver = processors(hbys[1], rgys[1])
            receiver.parse(ims=bytearray(wrapper.raw + queued[0]['attachment']))
            attrs = next(notifier.noter.notes.getTopItemIter())[1].attrs
            notifier.noter.close()
            monkeypatch.setattr('builtins.input', lambda _: answer)
            with restart_join(hbys[1], rgys[1]) as joined:
                approval = joined.rip(attrs)
                if answer == 'n':
                    with pytest.raises(StopIteration) as done:
                        next(approval)
                    assert done.value.value is False
                    assert not joined.postman.evts
                    next(operation)
                    assert command.rgy.store.seqEvent(rip.said, 0) is None
                    assert command.hab.kever.sn == 0
                else:
                    next(approval)
                    returned = joined.postman.evts[0]
                    assert returned['dest'] == mids[0]
                    command.mbx.parser.parse(ims=bytearray(returned['serder'].raw + returned['attachment']))
                    command.mux.kvy.processEscrows()
                    command.counselor.processEscrows()
                    with pytest.raises(StopIteration):
                        next(operation)
                    assert command.rgy.store.seqEvent(rip.said, 0).raw == rip.raw
                    assert command.hab.kever.serder.raw == anchor.raw
                    assert command.counselor.complete(command.hab.kever.prefixer, Number(num=1), Diger(qb64=anchor.said))
                    assert groups[2].kever.sn == 0
                    assert len(command.hby.db.sigs.get((gid, anchor.said))) == 2
                    assert list(command.hby.ks.rroots.getTopItemIter()) == []
                    approval.close()
        finally:
            operation.close()
            command.exit()
            assert not command.rgy.store.opened and not command.hby.db.opened
            assert not command.notifier.noter.opened


def test_native_registry_command_prompt_cancellation_precedes_registry_and_kel_mutation(monkeypatch):
    with participant_stores(temp=False, base=f'r10group-{uuid4().hex}') as participants:
        hbys, _, rgys = participants
        name, base = hbys[0].name, hbys[0].base
        rgys[0].close()
        hbys[0].close()
        command = NativeRegistryInceptor(name=name, base=base, bran=None, alias='issuer',
                                           registryName='cancelled')
        operation = command.inceptDo(tymth=lambda: 0.0)
        try:
            def cancel(prompt):
                assert 'description' in prompt
                assert command.hab.kever.sn == 0 and command.rgy.names == {}
                assert list(command.rgy.baser.evts.getTopItemIter()) == []
                raise KeyboardInterrupt
            monkeypatch.setattr('builtins.input', cancel)
            next(operation)
            with pytest.raises(KeyboardInterrupt):
                next(operation)
            assert command.hab.kever.sn == 0 and command.rgy.names == {}
        finally:
            operation.close()
            command.exit()
            assert not command.rgy.store.opened and not command.hby.db.opened
            assert not command.notifier.noter.opened
