"""Exact BUP proposals reuse native TEL and normal group approval owners."""

from uuid import uuid4
import pytest

from keri import Kinds, Vrsn_2_0
from keri.acdc import messaging
from keri.app.grouping import multisigRipExn, multisigBupExn, multisigInteractExn
from keri.kering import ValidationError
from keri.core import Diger, Number, Parser, SealSource, SerderKERI, exchange, interact, messagize
from keri.peer.exchanging import serializeParsedSubstream
from tests.app.test_multisig_rip import participant_stores, processors, restart_join


def accept_rip(hbys, groups, rgys, *, receiver_inception='accepted', seal_update=False):
    rip = messaging.regcept(israid=groups[0].pre)
    alternate = messaging.blindate(regid=rip.said, prior=rip.said,
                                   blid=Diger(ser=b'alternate commitment').qb64) if seal_update else None
    seals = [dict(i=rip.said, s='0', d=rip.said)]
    if alternate is not None:
        seals.append(dict(i=rip.said, s='1', d=alternate.said))
    anchor = SerderKERI(raw=groups[0].interact(
        data=seals, version=Vrsn_2_0,
        gvrsn=Vrsn_2_0, kind=Kinds.json))
    stream = messagize(anchor, sigers=[group.sign(anchor.raw)[0] for group in groups[:2]],
                        gvrsn=Vrsn_2_0)
    for index, (hby, group, rgy) in enumerate(zip(hbys, groups, rgys)):
        if index == 1 and receiver_inception != 'accepted':
            if receiver_inception == 'stored':
                assert rgy.processEvent(rip) is False
            continue
        Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(stream), local=True)
        hby.kvy.processEscrows()
        assert group.kever.serder.said == anchor.said
        assert rgy.processEvent(rip)
        assert rgy.store.seqEvent(rip.said, 0).said == rip.said
    return rip, alternate


def proposal(hbys, groups, rip, *, rotate=False):
    bup = messaging.blindate(regid=rip.said, prior=rip.said,
                             blid=Diger(ser=b'opaque commitment').qb64)
    seal = dict(i=rip.said, s='1', d=bup.said)
    if rotate:
        for group in groups:
            update = group.mhab.rotate(version=Vrsn_2_0, gvrsn=Vrsn_2_0)
            for hby in hbys:
                Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(update), local=True)
        anchor = groups[0].rotate(verfers=[group.mhab.kever.verfers[0] for group in groups],
                                  digers=[group.mhab.kever.ndigers[0] for group in groups],
                                  isith='2', nsith='2', data=[seal],
                                  version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)
    else:
        anchor = groups[0].interact(data=[seal], version=Vrsn_2_0,
                                    gvrsn=Vrsn_2_0, kind=Kinds.json)
    return bup, anchor


def wrap(group, event, anchor, *, route='/multisig/bup', payload=None):
    kel = SerderKERI(raw=anchor)
    tel = messagize(event, bonds=SealSource(s=kel.snh, d=kel.said), gvrsn=Vrsn_2_0)
    children = [Parser(version=Vrsn_2_0).parseOneBare(ims=bytearray(stream), processive=False)
                for stream in (tel, anchor)]
    wrapper = exchange(sender=group.mhab.pre, route=route,
                       attributes=payload or dict(gid=group.pre, tel=event.said, anc=kel.said),
                       version=Vrsn_2_0, kind=Kinds.json)
    stream = group.mhab.endorse(wrapper, last=False, framed=False, gvrsn=Vrsn_2_0,
                                nests=[serializeParsedSubstream(child) for child in children])
    return wrapper, stream


def test_bup_notifies_without_replaying_or_approving():
    with participant_stores() as (hbys, groups, rgys):
        rip, _ = accept_rip(hbys, groups, rgys)
        bup, anchor = proposal(hbys, groups, rip)
        wrapper, stream = wrap(groups[0], bup, anchor)
        notifier, _, receiver = processors(hbys[1], rgys[1])
        receiver.parse(ims=bytearray(stream))
        assert [notice.attrs for _, notice in notifier.noter.notes.getTopItemIter()] == [
            dict(r='/multisig/bup', d=wrapper.said)]
        assert groups[1].kever.sn == 1
        assert rgys[1].store.event(bup.said) is None


def test_distinct_rip_with_same_anchor_does_not_inherit_local_approval():
    with participant_stores() as (hbys, groups, rgys):
        first = messaging.regcept(israid=groups[0].pre)
        other = messaging.regcept(israid=groups[0].pre)
        seals = [dict(i=event.said, s='0', d=event.said) for event in (first, other)]
        remote = groups[0].interact(data=seals, version=Vrsn_2_0,
                                    gvrsn=Vrsn_2_0, kind=Kinds.json)
        local = groups[1].interact(data=seals, version=Vrsn_2_0,
                                   gvrsn=Vrsn_2_0, kind=Kinds.json)
        anchor = SerderKERI(raw=remote)
        assert SerderKERI(raw=local).said == anchor.said
        notifier, mux, receiver = processors(hbys[1], rgys[1])
        own_tel = messagize(first, bonds=SealSource(s=anchor.snh, d=anchor.said), gvrsn=Vrsn_2_0)
        approved, atc = multisigRipExn(groups[1], own_tel, local)
        receiver.parse(ims=bytearray(approved.raw + atc), local=True)
        foreign_tel = messagize(other, bonds=SealSource(s=anchor.snh, d=anchor.said), gvrsn=Vrsn_2_0)
        unapproved, atc = multisigRipExn(groups[0], foreign_tel, remote)
        receiver.parse(ims=bytearray(unapproved.raw + atc))
        mux.kvy.processEscrows()
        rgys[1].processEscrows()
        assert rgys[1].store.event(other.said) is None
        notices = [notice.attrs for _, notice in notifier.noter.notes.getTopItemIter()]
        assert any(note['d'] == unapproved.said for note in notices)


@pytest.mark.parametrize('rotate', [False, True], ids=['interaction', 'rotation'])
@pytest.mark.parametrize('answer', ['n', 'y'], ids=['decline', 'approve'])
def test_real_bup_join_after_reopen_uses_two_of_three(monkeypatch, rotate, answer):
    with participant_stores(temp=False, base=f'r06b-{uuid4().hex}') as (hbys, groups, rgys):
        rip, _ = accept_rip(hbys, groups, rgys)
        bup, anchor = proposal(hbys, groups, rip, rotate=rotate)
        kel = SerderKERI(raw=anchor)
        tel = messagize(bup, bonds=SealSource(s=kel.snh, d=kel.said), gvrsn=Vrsn_2_0)
        wrapper, atc = multisigBupExn(groups[0], tel, anchor, rgy=rgys[0])
        _, _, proposer = processors(hbys[0], rgys[0])
        proposer.parse(ims=bytearray(wrapper.raw + atc), local=True)
        # Advance beyond the contribution to this exact interaction/rotation.
        update = groups[1].mhab.rotate(version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        Parser(kvy=hbys[0].kvy, version=Vrsn_2_0).parse(ims=bytearray(update))
        notifier, _, receiver = processors(hbys[1], rgys[1])
        receiver.parse(ims=bytearray(wrapper.raw + atc))
        attrs = next(notifier.noter.notes.getTopItemIter())[1].attrs
        notifier.noter.close()
        with restart_join(hbys[1], rgys[1]) as joined:
            monkeypatch.setattr('builtins.input', lambda prompt: answer)
            approval = joined.bup(attrs)
            if answer == 'n':
                with pytest.raises(StopIteration) as done:
                    next(approval)
                assert done.value.value is False
                assert joined.hby.db.sigs.get((groups[0].pre, kel.said)) == []
                assert joined.rgyV2.store.event(bup.said) is None
                assert not joined.postman.evts
            else:
                next(approval)
                local = joined.hby.habs[groups[0].pre]
                assert local.kever.serder.raw == kel.raw
                assert joined.counselor.complete(local.kever.prefixer, Number(num=kel.sn),
                                                  Diger(qb64=kel.said))
                assert joined.rgyV2.store.seqEvent(rip.said, 1).raw == bup.raw
                returned = joined.postman.evts[0]
                proposer.parse(ims=bytearray(returned['serder'].raw + returned['attachment']))
                hbys[0].kvy.processEscrows()
                rgys[0].processEscrows()
                assert rgys[0].store.seqEvent(rip.said, 1).said == bup.said
                assert groups[2].kever.sn == 1
                assert not joined.postman.cues  # Parser receipt is not transport completion.
                approval.close()


@pytest.mark.parametrize('fault', ['missing-RIP', 'stored-RIP', 'foreign-RIP', 'prior', 'ordinal',
                                   'sender', 'commitment', 'source', 'seal'])
def test_bup_refuses_before_replay_or_signing(fault):
    with participant_stores() as (hbys, groups, rgys):
        inception = {'missing-RIP': 'missing', 'stored-RIP': 'stored'}.get(fault, 'accepted')
        rip, _ = accept_rip(hbys, groups, rgys, receiver_inception=inception)
        bup, anchor = proposal(hbys, groups, rip)
        if fault == 'foreign-RIP':
            foreign = groups[0].mhab
            rip = messaging.regcept(israid=foreign.pre)
            foreign.interact(data=[dict(i=rip.said, s='0', d=rip.said)], version=Vrsn_2_0)
            Parser(kvy=hbys[1].kvy, version=Vrsn_2_0).parse(
                ims=bytearray(foreign.msgOwnEvent(sn=1, gvrsn=Vrsn_2_0)))
            assert rgys[1].processEvent(rip)
        if fault in ('foreign-RIP', 'prior', 'ordinal', 'seal'):
            bup = messaging.blindate(regid=rip.said,
                                     prior=Diger(ser=b'wrong prior').qb64 if fault == 'prior' else rip.said,
                                     sn=2 if fault == 'ordinal' else 1,
                                     blid=Diger(ser=b'opaque').qb64)
            event = interact(pre=groups[0].pre, dig=groups[0].kever.serder.said,
                              sn=2, data=[dict(i=rip.said, s=bup.sad['n'],
                                         d=Diger(ser=b'wrong seal').qb64 if fault == 'seal' else bup.said)],
                              version=Vrsn_2_0)
            anchor = messagize(event, gvrsn=Vrsn_2_0, sigers=groups[0].sign(event.raw))
        if fault in ('missing-RIP', 'stored-RIP', 'foreign-RIP', 'prior', 'ordinal', 'seal'):
            kel = SerderKERI(raw=anchor)
            tel = messagize(bup, bonds=SealSource(s=kel.snh, d=kel.said), gvrsn=Vrsn_2_0)
            with pytest.raises(ValidationError):
                multisigBupExn(groups[1], tel, anchor, rgy=rgys[1])
        wrapper, stream = wrap(groups[0], bup, anchor)
        parsed = Parser(version=Vrsn_2_0).parseOneBare(ims=bytearray(stream), processive=False)
        payload = dict(wrapper.sad['a'])
        signer = groups[0].mhab
        if fault == 'sender':
            signer = hbys[0].makeHab(name='outsider', version=Vrsn_2_0)
            Parser(kvy=hbys[1].kvy, version=Vrsn_2_0).parse(
                ims=bytearray(signer.msgOwnInception(gvrsn=Vrsn_2_0)))
        elif fault == 'commitment':
            payload['tel'] = Diger(ser=b'wrong child').qb64
        elif fault == 'source':
            parsed.nests[0].sscs = [(Number(num=99), Diger(ser=b'wrong source'))]
        invalid = exchange(sender=signer.pre, route='/multisig/bup', attributes=payload,
                            version=Vrsn_2_0, kind=Kinds.json)
        stream = signer.endorse(invalid, last=False, framed=False, gvrsn=Vrsn_2_0,
                                nests=[serializeParsedSubstream(child) for child in parsed.nests])
        notifier, _, receiver = processors(hbys[1], rgys[1])
        prior = groups[1].kever.serder.said
        receiver.parse(ims=bytearray(stream))
        assert not receiver.exc.complete(invalid.said)
        assert notifier.noter.notes.cnt() == 0
        assert groups[1].kever.serder.said == prior
        assert rgys[1].store.event(bup.said) is None
        assert hbys[1].db.sigs.get((groups[0].pre, SerderKERI(raw=anchor).said)) == []


@pytest.mark.parametrize('kind', ['RIP-BUP', 'BUP-RIP', 'BUP-BUP', 'IXN-BUP', 'invalid-local-auth'])
def test_native_consent_filters_exact_authenticated_operation(kind):
    with participant_stores() as (hbys, groups, rgys):
        rip, _ = accept_rip(hbys, groups, rgys)
        own = (messaging.regcept(israid=groups[0].pre) if kind == 'RIP-BUP' else
               messaging.blindate(regid=rip.said, prior=rip.said,
                                   blid=Diger(ser=b'own opaque commitment').qb64))
        if kind == 'BUP-BUP':
            rip, _ = accept_rip(hbys, groups, rgys)
        incoming = (messaging.regcept(israid=groups[0].pre) if kind == 'BUP-RIP' else
                    messaging.blindate(regid=rip.said, prior=rip.said,
                                        blid=Diger(ser=b'other opaque commitment').qb64))
        if kind == 'invalid-local-auth':
            incoming = own
        events = [incoming] if kind in ('IXN-BUP', 'invalid-local-auth') else [own, incoming]
        seals = [dict(i=event.said if event.ilk == 'rip' else event.sad['rd'],
                      s=event.sad['n'], d=event.said) for event in events]
        remote = groups[0].interact(data=seals, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        local = groups[1].interact(data=seals, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        anchor = SerderKERI(raw=remote)
        notifier, mux, receiver = processors(hbys[1], rgys[1])
        if kind == 'IXN-BUP':
            approved, atc = multisigInteractExn(groups[1], groups[1].smids, local, version=Vrsn_2_0)
        else:
            tel = messagize(own, bonds=SealSource(s=anchor.snh, d=anchor.said), gvrsn=Vrsn_2_0)
            build = multisigRipExn if own.ilk == 'rip' else multisigBupExn
            approved, atc = build(groups[1], tel, local, **(dict(rgy=rgys[1]) if own.ilk == 'bup' else {}))
        receiver.parse(ims=bytearray(approved.raw + atc), local=True)
        if kind == 'invalid-local-auth':
            for keys, _ in list(hbys[1].db.esigs.getTopItemIter(keys=(approved.said,))):
                hbys[1].db.esigs.rem(keys)
        tel = messagize(incoming, bonds=SealSource(s=anchor.snh, d=anchor.said), gvrsn=Vrsn_2_0)
        build = multisigRipExn if incoming.ilk == 'rip' else multisigBupExn
        unapproved, atc = build(groups[0], tel, remote,
                                **(dict(rgy=rgys[0]) if incoming.ilk == 'bup' else {}))
        prior = groups[1].kever.serder.said
        receiver.parse(ims=bytearray(unapproved.raw + atc))
        mux.kvy.processEscrows()
        rgys[1].processEscrows()
        assert groups[1].kever.serder.said == prior
        assert rgys[1].store.event(incoming.said) is None
        assert any(note.attrs['d'] == unapproved.said for _, note in notifier.noter.notes.getTopItemIter())


@pytest.mark.parametrize('later', [False, True], ids=['current-head', 'later-accepted-head'])
def test_bup_join_resumes_accepted_exact_local_contribution(monkeypatch, later):
    with participant_stores(temp=False, base=f'r06b-{uuid4().hex}') as (hbys, groups, rgys):
        rip, _ = accept_rip(hbys, groups, rgys)
        bup, anchor = proposal(hbys, groups, rip)
        wrapper, stream = wrap(groups[0], bup, anchor)
        notifier, _, receiver = processors(hbys[1], rgys[1])
        receiver.parse(ims=bytearray(stream))
        attrs = next(notifier.noter.notes.getTopItemIter())[1].attrs
        notifier.noter.close()
        monkeypatch.setattr('builtins.input', lambda _: 'y')
        with restart_join(hbys[1], rgys[1]) as joined:
            approval = joined.bup(attrs)
            next(approval)
            submitted = joined.postman.evts[0]['serder']
            head = bup
            if later:
                head = messaging.blindate(regid=rip.said, prior=bup.said, sn=2,
                                           blid=Diger(ser=b'later accepted commitment').qb64)
                current = joined.hby.habs[groups[0].pre].kever.serder
                event = interact(pre=groups[0].pre, dig=current.said, sn=current.sn + 1,
                                  data=[dict(i=rip.said, s='2', d=head.said)], version=Vrsn_2_0)
                joined.hby.kvy.processEvent(serder=event, local=True,
                                            sigers=[group.sign(event.raw)[0]
                                                    for group in (groups[0], groups[2])])
                assert joined.rgyV2.processEvent(head)
            sigs = [siger.qb64 for siger in joined.hby.db.sigs.get((groups[0].pre, SerderKERI(raw=anchor).said))]
            approval.close()
            joined.notifier.noter.close()
            joined.rgy.close()
            with restart_join(joined.hby, joined.rgyV2) as resumed:
                retry = resumed.bup(attrs)
                next(retry)
                assert resumed.postman.evts[0]['serder'].raw == submitted.raw
                assert resumed.rgyV2.store.seqEvent(rip.said, 1).said == bup.said
                assert resumed.rgyV2.store.head(rip.said).qb64 == head.said
                assert [siger.qb64 for siger in resumed.hby.db.sigs.get(
                    (groups[0].pre, SerderKERI(raw=anchor).said))] == sigs
                retry.close()


def test_bup_join_rechecks_registry_head_after_prompt(monkeypatch):
    with participant_stores(temp=False, base=f'r06b-{uuid4().hex}') as (hbys, groups, rgys):
        rip, alternate = accept_rip(hbys, groups, rgys, seal_update=True)
        bup, anchor = proposal(hbys, groups, rip)
        wrapper, stream = wrap(groups[0], bup, anchor)
        notifier, _, receiver = processors(hbys[1], rgys[1])
        receiver.parse(ims=bytearray(stream))
        attrs = next(notifier.noter.notes.getTopItemIter())[1].attrs
        notifier.noter.close()
        with restart_join(hbys[1], rgys[1]) as joined:
            prior = joined.hby.habs[groups[0].pre].kever.serder.said
            def received_while_deciding(prompt):
                assert joined.rgyV2.processEvent(alternate)
                return 'y'
            monkeypatch.setattr('builtins.input', received_while_deciding)
            with pytest.raises(ValidationError, match='conflicts'):
                next(joined.bup(attrs))
            assert joined.hby.habs[groups[0].pre].kever.serder.said == prior
            assert joined.hby.db.sigs.get((groups[0].pre, SerderKERI(raw=anchor).said)) == []
            assert joined.rgyV2.store.head(rip.said).qb64 == alternate.said
            assert not joined.postman.evts
