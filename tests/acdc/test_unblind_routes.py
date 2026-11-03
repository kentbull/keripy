"""Three independent parties repair one exact pending presentation by Unblind."""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0 as V2
from keri.acdc import Regery, Registrar, acdcmap, admit, blindate, grant, loadHandlers
from keri.acdc.unblinding import Unblind
from keri.app import openCF, openHby
from keri.core import (Blinder, BlindState, BoundState, Diger, Kevery, Kramer, Labeler, Number, Parser,
                       Salter, SealSource, SerderKERI, Signer, Texter, messagize)
from keri.kering import ValidationError
from keri.peer import Exchanger
from keri.peer.exchanging import loadParsedNestedSubstreams, serializeParsedSubstream


def receive(side, raw):
    ims = bytearray(raw)
    side.psr.parse(ims=ims, framed=False)
    assert not ims


def parsed(raw):
    return Parser(version=V2).parse(ims=bytearray(raw), framed=False, processive=False)[0]


def transfer(issuer, recipients, registry, event):
    kel = issuer.hab.interact(data=[dict(i=registry.regk, s=event.sad['n'], d=event.said)],
                               framed=False, gvrsn=V2)
    assert registry.anchorMsg(event.said)
    anchor = SerderKERI(raw=kel)
    tel = messagize(event, bonds=[SealSource(s=anchor.snh, d=anchor.said)], gvrsn=V2)
    for side in recipients:
        receive(side, kel)
        receive(side, tel)
        assert side.rgy.store.headEvent(registry.regk).said == event.said
    return kel, tel


@contextmanager
def presentation(enabled=False, *, bound=False, known=1):
    """Explicit test capability only; no provisioning protocol is claimed."""
    with ExitStack() as stack:
        sides = []
        for number, name in enumerate(('issuer', 'holder', 'verifier'), 1):
            signer = Signer(raw=bytes([number]) * 32, transferable=False)
            hby = stack.enter_context(openHby(name=f'unblind-{name}', base='test', version=V2,
                salt=Salter(raw=bytes([number]) * 16).qb64,
                seed=signer.qb64, aeid=signer.verfer.qb64))
            hab = hby.makeHab(name=name, icount=2, isith='2', ncount=2, nsith='2')
            rgy = Regery(hby=hby, name=name, temp=True)
            stack.callback(rgy.close)
            exc = Exchanger(hby=hby, handlers=[])
            exc.TimeoutPSE = 300
            loadHandlers(hby=hby, exc=exc, notifier=SimpleNamespace(add=lambda **_: None), rgy=rgy)
            cf = stack.enter_context(openCF(name=f'unblind-{name}', base='test'))
            cf.put(dict(kram=dict(enabled=enabled, denials=[],
                caches={'~': [1000, 5000, 60000, 300000, 5000, 60000, 300000]})))
            route = Unblind(hab, exc, rgy, states=('issued', 'revoked', ''))
            hby.rtr.addRoute(Unblind.Route, route, blinders=True, attachments=True)
            kvy = Kevery(db=hby.db, rvy=hby.rvy, exc=exc, qvy=route,
                         kramer=Kramer(db=hby.db, cf=cf))
            psr = Parser(version=V2, kvy=kvy, exc=exc, rvy=hby.rvy, rgy=rgy)
            sides.append(SimpleNamespace(hby=hby, hab=hab, rgy=rgy, exc=exc,
                                          route=route, kvy=kvy, psr=psr))
        issuer, holder, verifier = sides
        for side in sides:
            for other in sides:
                if side is not other:
                    receive(side, other.hab.msgOwnEvent(sn=0, framed=False, gvrsn=V2))
                    assert side.hby.db.kevers[other.hab.pre].sn == 0
        if bound:
            kel = holder.hab.interact(data=[], framed=False, gvrsn=V2)
            for side in (issuer, verifier):
                receive(side, kel)
        registrar = Registrar(issuer.rgy)
        registry = registrar.makeRegistry('states', issuer.hab.pre)
        transfer(issuer, (holder, verifier), registry, issuer.rgy.store.event(registry.regk))
        root = Salter(raw=b'public-test-root')
        issuer.hab.mgr.putRegistryRoot(issuer.hab.pre, registry.regk, root)
        if not bound:
            holder.hab.mgr.putRegistryRoot(holder.hab.pre, registry.regk, root)
        credential = acdcmap(israid=issuer.hab.pre, iseaid=holder.hab.pre,
                              regid=registry.regk, attribute=dict(d='', role='member'))
        binding = dict(bound=True, bsn=holder.hab.kever.sn,
                       bd=holder.hab.kever.serder.said) if bound else {}
        first, event = registrar.issue(registry, credential, state='issued', salt=root.qb64, **binding)
        transfer(issuer, (holder, verifier), registry, event)
        origin = messagize(credential, bonds=[first.data], gvrsn=V2)
        issued, atc = grant(hab=issuer.hab, recp=holder.hab.pre, message='issue', origin=origin)
        for side in (issuer, holder):
            receive(side, issued.raw + atc)
            assert side.hby.db.exns.get((issued.said,)) is not None
        admission, atc = admit(hab=holder.hab, message='received', grant=issued)
        for side in (issuer, holder):
            receive(side, admission.raw + atc)
            assert side.hby.db.exns.get((admission.said,)) is not None
        proofs, events, later_tel = [first], [event], []
        for state in ('revoked', '', ''):
            proof, event = (registrar.issue(registry, credential, state=state, salt=root.qb64, **binding)
                            if state else registrar.vacate(registry, salt=root.qb64,
                                **(dict(bound=True, bsn=0, bd='') if bound else {})))
            kel, tel = transfer(issuer, (verifier,), registry, event)
            receive(holder, kel)  # Accepted issuer KEL, deliberately stale public TEL.
            if Number(numh=event.sad["n"]).num <= known:
                receive(holder, tel)
            proofs.append(proof)
            events.append(event)
            later_tel.append(tel)
        disclosed = messagize(credential, bonds=[proofs[known - 1].data], gvrsn=V2)
        message, atc = grant(hab=holder.hab, recp=verifier.hab.pre,
                             message='present', origin=disclosed)
        receive(holder, message.raw + atc)
        receive(verifier, message.raw + atc)
        assert holder.hby.db.exns.get((message.said,)) is not None
        assert verifier.hby.db.epse.get((message.said,)) is not None
        assert verifier.hby.db.exns.get((message.said,)) is None
        for side in (holder, verifier):
            xid = side.route.approve(message.said)
        yield SimpleNamespace(issuer=issuer, holder=holder, verifier=verifier,
            registry=registry, credential=credential, grant=message, xid=xid, root=root,
            proofs=proofs, events=events, later_tel=later_tel, issuance=issued)


@pytest.mark.parametrize('enabled', [False, True], ids=['kram-off', 'kram-on'])
def test_unblind_exact_minimum_suffix_repairs_same_grant(enabled):
    with presentation(enabled) as h:
        query = h.verifier.route.start(h.grant.said)
        request = parsed(query)
        assert request.serder.sad['q']['re'] == {h.registry.regk: [event.said for event in h.events[1:]]}
        assert [nest.serder.raw for nest in request.nests] == [event.raw for event in h.events[1:]]
        assert not request.bsqs and not request.bsss
        assert h.holder.rgy.store.headEvent(h.registry.regk).said == h.events[0].said
        receive(h.holder, query)
        assert h.holder.rgy.store.headEvent(h.registry.regk).said == h.events[-1].said
        response = h.holder.route.cues.popleft()
        assert response['dest'] == h.verifier.hab.pre
        reply = parsed(response['msg'])
        assert reply.serder.sad['a']['re'] == {h.registry.regk: [event.said for event in h.events[1:]]}
        assert not reply.nests and len(reply.bsqs) == 3 and not reply.bsss
        assert {data[0].qb64 for data in reply.bsqs} == {proof.said for proof in h.proofs[1:]}
        assert h.proofs[0].qb64b not in response['msg']
        assert h.root.qb64b not in response['msg'] and h.credential.raw not in response['msg']
        receive(h.verifier, response['msg'])
        assert h.verifier.route.finish(h.xid) is True
        assert h.verifier.hby.db.exns.get((h.grant.said,)).raw == h.grant.raw
        assert h.verifier.hby.db.exrs.get((h.grant.said, h.credential.said)).state == 'revoked'
        # Protocol receipt is allowed; applications separately refuse revoked use.
        admission, atc = admit(hab=h.verifier.hab, message='received', grant=h.grant)
        for side in (h.holder, h.verifier):
            receive(side, admission.raw + atc)
        assert h.holder.hby.db.exns.get((admission.said,)) is not None
        with pytest.raises(ValidationError):
            h.verifier.route.finish(h.xid)
        with pytest.raises(ValidationError):
            h.verifier.route.start(h.grant.said)
        receive(h.holder, query)
        assert not h.holder.route.cues


def signed(side, frame, *, indices=None):
    """Real signatures, optionally partial, preserving the supplied attachment view."""
    message = frame.serder
    kever = side.hby.db.kevers[message.pre]
    sigers = side.hab.sign(message.raw)
    if indices is not None:
        sigers = [sigers[index] for index in indices]
    kwa = (dict(lsgs=[(kever.prefixer, sigers)]) if message.ilk == 'qry' else
           dict(tsgs=[(kever.prefixer, Number(sn=kever.lastEst.s), Diger(qb64=kever.lastEst.d), sigers)]))
    result = parsed(messagize(message, gvrsn=V2, **kwa))
    for field in ('nests', 'bsqs', 'bsss', 'sscs', 'ssts', 'essrs'):
        setattr(result, field, deepcopy(getattr(frame, field)))
    return bytes(serializeParsedSubstream(result))


def restart(side):
    previous = side.route
    side.route = side.kvy.qvy = Unblind(side.hab, side.exc, side.rgy,
                                       states=('issued', 'revoked', ''))
    for route in side.hby.rtr.routes:
        if route.resource is previous:
            route.resource = side.route


@pytest.mark.parametrize('enabled', [False, True], ids=['kram-off', 'kram-on'])
def test_rootless_holder_replies_only_with_explicit_held_bound_proofs(enabled):
    with presentation(enabled, bound=True) as h:
        assert h.holder.hab.mgr.getRegistryRoot(h.holder.hab.pre, h.registry.regk) is None
        for event, proof, tel in zip(h.events[1:], h.proofs[1:], h.later_tel):
            receive(h.holder, tel)
            assert h.holder.rgy.store.putOpening(event.said, proof)
        assert h.proofs[1].clan is BoundState
        assert h.proofs[1].bsn == h.holder.hab.kever.sn
        assert h.proofs[1].bd == h.holder.hab.kever.serder.said
        receive(h.holder, h.verifier.route.start(h.grant.said))
        response = h.holder.route.cues.popleft()['msg']
        frame = parsed(response)
        assert frame.serder.sad['a']['re'] == {h.registry.regk: [event.said for event in h.events[1:]]}
        assert not frame.bsqs and not frame.nests and len(frame.bsss) == 3
        assert {Blinder(data=BoundState(*data), verify=False).qb64 for data in frame.bsss} == {
            proof.qb64 for proof in h.proofs[1:]}
        assert h.proofs[0].qb64b not in response and h.root.qb64b not in response
        receive(h.verifier, response)
        assert h.verifier.route.finish(h.xid)
        assert h.verifier.hby.db.exrs.get((h.grant.said, h.credential.said)).state == 'revoked'
        assert h.holder.hab.mgr.getRegistryRoot(h.holder.hab.pre, h.registry.regk) is None


def test_partial_reply_retains_verified_proofs_until_second_signature_without_proofs():
    with presentation(False) as h:
        receive(h.holder, h.verifier.route.start(h.grant.said))
        frame = parsed(h.holder.route.cues.popleft()['msg'])
        receive(h.verifier, signed(h.holder, frame, indices=[0]))
        with pytest.raises(ValidationError):
            h.verifier.route.finish(h.xid)
        frame.bsqs, frame.bsss = [], []
        receive(h.verifier, signed(h.holder, frame, indices=[1]))
        assert h.verifier.route.finish(h.xid)
        assert h.verifier.hby.db.exrs.get((h.grant.said, h.credential.said)).state == 'revoked'


def test_partial_kram_query_retains_nested_public_events():
    with presentation(True) as h:
        frame = parsed(h.verifier.route.start(h.grant.said))
        receive(h.holder, signed(h.verifier, frame, indices=[0]))
        assert not h.holder.route.cues
        assert h.holder.rgy.store.head(h.registry.regk).qb64 == h.events[0].said
        frame.nests = []
        receive(h.holder, signed(h.verifier, frame, indices=[1]))
        assert h.holder.rgy.store.head(h.registry.regk).qb64 == h.events[-1].said
        response = h.holder.route.cues.popleft()['msg']
        assert parsed(response).serder.sad['a']['re'] == {
            h.registry.regk: [event.said for event in h.events[1:]]}
        receive(h.verifier, response)
        assert h.verifier.route.finish(h.xid)


@pytest.mark.parametrize('enabled', [False, True], ids=['kram-off', 'kram-on'])
@pytest.mark.parametrize('fault', ['scope', 'xid', 'sender', 'recipient', 'forged', 'insufficient',
    'duplicate-signature', 'unknown', 'unaccepted', 'swapped', 'trailing', 'source',
    'nested-credential', 'essr-extra', 'source-extra', 'expired', 'abandoned', 'restarted',
    'missing-unrequested-proof', 'huge-ordinal'])
def test_query_refusals_do_not_disclose_or_advance_public_state(enabled, fault, fakeHelpingClock):
    with presentation(enabled) as h:
        frame = parsed(h.verifier.route.start(h.grant.said))
        sad = deepcopy(frame.serder.sad)
        signing, target, indices = h.verifier, h.holder, None
        regid = h.registry.regk
        if fault == 'scope':
            sad['q']['re'][Diger(ser=b'other registry').qb64] = sad['q']['re'].pop(regid)
        elif fault == 'xid':
            sad['q']['x'] = Diger(ser=b'other transaction').qb64
        elif fault == 'sender':
            sad['i'], signing = h.issuer.hab.pre, h.issuer
        elif fault == 'recipient':
            target = h.verifier
        elif fault == 'forged':
            signing = h.issuer
        elif fault == 'insufficient':
            indices = [0]
        elif fault == 'duplicate-signature':
            indices = [0, 0]
        elif fault == 'unknown':
            sad['q']['re'][regid][0] = Diger(ser=b'unknown BUP').qb64
        elif fault == 'huge-ordinal':
            event = blindate(regid=regid, prior=h.events[0].said, sn=2 ** 64,
                              blid=Diger(ser=b'hostile ordinal').qb64)
            frame.nests = [frame.nests[0]]
            frame.nests[0].serder = event
            sad['q']['re'][regid] = [event.said]
        elif fault == 'unaccepted':
            event = blindate(regid=regid, prior=h.events[0].said, sn=2,
                              blid=Diger(ser=b'unaccepted commitment').qb64)
            frame.nests[0].serder = event
            sad['q']['re'][regid][0] = event.said
        elif fault == 'swapped':
            frame.nests[1], frame.nests[2] = frame.nests[2], frame.nests[1]
        elif fault == 'trailing':
            frame.nests.append(deepcopy(frame.nests[-1]))
        elif fault == 'source':
            frame.nests[1].sscs = [(Number(num=999), Diger(ser=b'unaccepted KEL'))]
        elif fault == 'nested-credential':
            frame.nests[-1] = loadParsedNestedSubstreams(h.holder.hby, h.grant.said)[0]
            sad['q']['re'][regid][-1] = h.credential.said
        elif fault == 'essr-extra':
            frame.essrs = [Texter(raw=b'unsupported private payload')]
        elif fault == 'source-extra':
            frame.sscs = [(Number(num=0), Diger(qb64=h.verifier.hab.kever.serder.said))]
        elif fault == 'expired':
            fakeHelpingClock.advance(seconds=301)
            sad['dt'] = fakeHelpingClock.nowIso8601()
        elif fault == 'abandoned':
            h.holder.route.abandon(h.xid)
        elif fault == 'restarted':
            restart(h.holder)
        elif fault == 'missing-unrequested-proof':
            for tel in h.later_tel:
                receive(h.holder, tel)
            sad['q']['re'][regid] = sad['q']['re'][regid][1:]
            frame.nests = frame.nests[1:]
        frame.serder = SerderKERI(sad=sad, makify=True)
        before = h.holder.rgy.store.head(regid).qb64
        receive(target, signed(signing, frame, indices=indices))
        assert not h.holder.route.cues and not h.verifier.route.cues
        assert h.holder.rgy.store.head(regid).qb64 == before
        assert h.verifier.hby.db.exns.get((h.grant.said,)) is None
        with pytest.raises(ValidationError):
            h.verifier.route.finish(h.xid)


@pytest.mark.parametrize('enabled', [False, True], ids=['kram-off', 'kram-on'])
@pytest.mark.parametrize('fault', ['scope', 'xid', 'sender', 'recipient', 'forged', 'insufficient',
    'duplicate-signature', 'unknown', 'wrong-proof', 'excess-proof', 'missing-proof',
    'unnecessary-history', 'nested-credential', 'essr-extra', 'source-extra',
    'expired', 'abandoned', 'restarted'])
def test_reply_refusals_do_not_finish_presentation(enabled, fault, fakeHelpingClock):
    with presentation(enabled) as h:
        receive(h.holder, h.verifier.route.start(h.grant.said))
        frame = parsed(h.holder.route.cues.popleft()['msg'])
        sad = deepcopy(frame.serder.sad)
        signing, target, indices = h.holder, h.verifier, None
        regid = h.registry.regk
        if fault == 'scope':
            sad['a']['re'][Diger(ser=b'other registry').qb64] = sad['a']['re'].pop(regid)
        elif fault == 'xid':
            sad['a']['x'] = Diger(ser=b'other transaction').qb64
        elif fault == 'sender':
            sad['i'], signing = h.issuer.hab.pre, h.issuer
        elif fault == 'recipient':
            target = h.holder
        elif fault == 'forged':
            signing = h.issuer
        elif fault == 'insufficient':
            indices = [0]
        elif fault == 'duplicate-signature':
            indices = [0, 0]
        elif fault == 'unknown':
            sad['a']['re'][regid][0] = Diger(ser=b'unknown event').qb64
        elif fault == 'wrong-proof':
            frame.bsqs[0] = BlindState(*frame.bsqs[0])._replace(ts=Labeler(text='invalid'))
        elif fault == 'excess-proof':
            frame.bsqs.append(h.proofs[0].data)
        elif fault == 'missing-proof':
            frame.bsqs = []
        elif fault == 'unnecessary-history':
            sad['a']['re'][regid] = [event.said for event in h.events]
            frame.bsqs.append(h.proofs[0].data)
        elif fault == 'nested-credential':
            frame.nests = loadParsedNestedSubstreams(h.holder.hby, h.grant.said)
        elif fault == 'essr-extra':
            frame.essrs = [Texter(raw=b'unsupported private payload')]
        elif fault == 'source-extra':
            frame.sscs = [(Number(num=0), Diger(qb64=h.holder.hab.kever.serder.said))]
        elif fault == 'expired':
            fakeHelpingClock.advance(seconds=301)
            sad['dt'] = fakeHelpingClock.nowIso8601()
        elif fault == 'abandoned':
            h.verifier.route.abandon(h.xid)
        elif fault == 'restarted':
            restart(h.verifier)
        frame.serder = SerderKERI(sad=sad, makify=True)
        receive(target, signed(signing, frame, indices=indices))
        assert h.verifier.hby.db.exns.get((h.grant.said,)) is None
        assert h.verifier.hby.db.epse.get((h.grant.said,)).raw == h.grant.raw
        assert h.verifier.hby.db.exrs.get((h.grant.said, h.credential.said)) is None
        with pytest.raises(ValidationError):
            h.verifier.route.finish(h.xid)


@pytest.mark.parametrize('enabled', [False, True], ids=['kram-off', 'kram-on'])
def test_no_held_new_proofs_refuses_reply_without_root(enabled):
    with presentation(enabled, bound=True) as h:
        receive(h.holder, h.verifier.route.start(h.grant.said))
        assert h.holder.rgy.store.head(h.registry.regk).qb64 == h.events[-1].said
        assert h.holder.hab.mgr.getRegistryRoot(h.holder.hab.pre, h.registry.regk) is None
        assert not h.holder.route.cues
        with pytest.raises(ValidationError):
            h.verifier.route.finish(h.xid)


@pytest.mark.parametrize('enabled', [False, True], ids=['kram-off', 'kram-on'])
def test_abandon_discards_cached_unsent_proof_reply(enabled):
    with presentation(enabled) as h:
        query = h.verifier.route.start(h.grant.said)
        receive(h.holder, query)
        assert len(h.holder.route.cues) == 1
        h.holder.route.abandon(h.xid)
        assert not h.holder.route.cues
        receive(h.holder, query)
        assert not h.holder.route.cues
        with pytest.raises(ValidationError):
            h.holder.route.approve(h.grant.said)


@pytest.mark.parametrize('enabled', [False, True], ids=['kram-off', 'kram-on'])
def test_known_nonplaceholder_needs_only_later_placeholder_proofs(enabled):
    with presentation(enabled, known=2) as h:
        query = h.verifier.route.start(h.grant.said)
        assert parsed(query).serder.sad['q']['re'] == {
            h.registry.regk: [event.said for event in h.events[2:]]}
        receive(h.holder, query)
        response = h.holder.route.cues.popleft()['msg']
        frame = parsed(response)
        assert frame.serder.sad['a']['re'] == {h.registry.regk: [event.said for event in h.events[2:]]}
        assert {data[0].qb64 for data in frame.bsqs} == {proof.said for proof in h.proofs[2:]}
        assert not frame.nests and not frame.bsss
        assert all(proof.qb64b not in response for proof in h.proofs[:2])
        receive(h.verifier, response)
        assert h.verifier.route.finish(h.xid)
        assert h.verifier.hby.db.exrs.get((h.grant.said, h.credential.said)).state == 'revoked'


@pytest.mark.parametrize('enabled', [False, True], ids=['kram-off', 'kram-on'])
def test_overbroad_query_discloses_only_minimum_missing_proofs(enabled):
    with presentation(enabled) as h:
        frame = parsed(h.verifier.route.start(h.grant.said))
        first = h.events[0]
        number, diger = h.verifier.rgy.store.anchor(first.said)
        frame.nests.insert(0, parsed(messagize(first, nested=True,
            bonds=[SealSource(s=number.snh, d=diger.qb64)], gvrsn=V2)))
        sad = deepcopy(frame.serder.sad)
        sad['q']['re'][h.registry.regk].insert(0, first.said)
        frame.serder = SerderKERI(sad=sad, makify=True)
        receive(h.holder, signed(h.verifier, frame))
        response = h.holder.route.cues.popleft()['msg']
        assert parsed(response).serder.sad['a']['re'] == {
            h.registry.regk: [event.said for event in h.events[1:]]}
        assert h.proofs[0].qb64b not in response
        receive(h.verifier, response)
        assert h.verifier.route.finish(h.xid)


@pytest.mark.parametrize('enabled', [False, True], ids=['kram-off', 'kram-on'])
def test_authenticated_request_retries_locally_when_exact_held_proofs_arrive(enabled, fakeHelpingClock):
    with presentation(enabled, bound=True) as h:
        request = h.verifier.route.start(h.grant.said)
        deadline = h.holder.hby.db.epsd.get((h.grant.said,)).dts
        receive(h.holder, request)
        assert not h.holder.route.cues
        for event, proof in zip(h.events[1:], h.proofs[1:]):
            assert h.holder.rgy.store.putOpening(event.said, proof)
        response = h.holder.route.respond(h.xid)
        assert h.holder.route.cues.popleft()['msg'] == response
        assert h.holder.route.respond(h.xid) == response
        assert h.holder.hby.db.epsd.get((h.grant.said,)).dts == deadline
        receive(h.verifier, response)
        assert h.verifier.route.finish(h.xid)
        fakeHelpingClock.advance(seconds=301)
        with pytest.raises(ValidationError):
            h.holder.route.respond(h.xid)


@pytest.mark.parametrize('enabled', [False, True], ids=['kram-off', 'kram-on'])
def test_query_for_already_carried_old_proof_returns_empty_not_a_current_verdict(enabled):
    with presentation(enabled) as h:
        frame = parsed(h.verifier.route.start(h.grant.said))
        first = h.events[0]
        number, diger = h.verifier.rgy.store.anchor(first.said)
        frame.nests = [parsed(messagize(first, nested=True,
            bonds=[SealSource(s=number.snh, d=diger.qb64)], gvrsn=V2))]
        sad = deepcopy(frame.serder.sad)
        sad['q']['re'] = {h.registry.regk: [first.said]}
        frame.serder = SerderKERI(sad=sad, makify=True)
        receive(h.holder, signed(h.verifier, frame))
        response = h.holder.route.cues.popleft()['msg']
        reply = parsed(response)
        assert reply.serder.sad['a']['re'] == {}
        assert not reply.bsqs and not reply.bsss and not reply.nests
        assert h.root.qb64b not in response and h.credential.raw not in response
        receive(h.verifier, response)
        with pytest.raises(ValidationError):
            h.verifier.route.finish(h.xid)
        assert h.verifier.hby.db.epse.get((h.grant.said,)) is not None
