"""Three independent parties repair one exact pending presentation by Unblind."""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0 as V2
from keri.acdc import Regery, Registrar, acdcmap, admit, agree, blindate, chaining, grant, loadHandlers, offer
from keri.acdc.salting import RegistrySalt
from keri.acdc.unblinding import Unblind
from keri.app import openCF, openHby
from keri.core import (Blinder, BlindState, BoundState, Diger, Kevery, Kramer, Labeler, Number, Parser,
                       Salter, SealSource, SerderKERI, Signer, Texter, messagize)
from keri.kering import MissingOpeningError, ValidationError
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
def actors(names, *, enabled=False, headDirPath=None):
    """Bootstrap independent encrypted two-key actors through real KEL intake."""
    with ExitStack() as stack:
        sides = []
        for number, name in enumerate(names, 1):
            signer = Signer(raw=bytes([number]) * 32, transferable=False)
            hby = stack.enter_context(openHby(name=f'unblind-{name}', base='test', version=V2,
                temp=headDirPath is None, headDirPath=headDirPath,
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
        for side in sides:
            for other in sides:
                if side is not other:
                    receive(side, other.hab.msgOwnEvent(sn=0, framed=False, gvrsn=V2))
                    assert side.hby.db.kevers[other.hab.pre].sn == 0
        yield sides


@contextmanager
def presentation(enabled=False, *, bound=False, known=1, accepted=False, headDirPath=None):
    """Explicit test capability only; no provisioning protocol is claimed."""
    with actors(('issuer', 'holder', 'verifier'), enabled=enabled,
                headDirPath=headDirPath) as sides:
        issuer, holder, verifier = sides
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
        proofs, events, later_tel, later_kel = [first], [event], [], []
        if accepted:
            # Negotiate and accept at BUP1 before the issuer authors newer heads.
            offered, atc = offer(holder.hab, 'offer presentation', origin=credential,
                recp=verifier.hab.pre, modifiers={'dp': [[[credential.schema['$id'], '/', []]]]})
            for side in (holder, verifier):
                receive(side, offered.raw + atc)
                assert side.exc.complete(offered.said)
            agreed, atc = agree(verifier.hab, 'agree to presentation', offered)
            for side in (holder, verifier):
                receive(side, agreed.raw + atc)
                assert side.exc.complete(agreed.said)
            message, atc = grant(holder.hab, verifier.hab.pre, 'present',
                                 origin=origin, agree=agreed)
            for side in (holder, verifier):
                receive(side, message.raw + atc)
                assert side.exc.complete(message.said)
        for state in ('revoked', '', ''):
            proof, event = (registrar.issue(registry, credential, state=state, salt=root.qb64, **binding)
                            if state else registrar.vacate(registry, salt=root.qb64,
                                **(dict(bound=True, bsn=0, bd='') if bound else {})))
            kel, tel = transfer(issuer, () if accepted else (verifier,), registry, event)
            receive(holder, kel)  # Accepted issuer KEL, deliberately stale public TEL.
            if Number(numh=event.sad["n"]).num <= known:
                receive(holder, tel)
            proofs.append(proof)
            events.append(event)
            later_tel.append(tel)
            later_kel.append(kel)
        if accepted:
            for kel, tel in zip(later_kel, later_tel):
                receive(verifier, kel + tel)
        else:
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


def test_separate_discloser_root_copy_repairs_exact_grant_without_changing_admitted_proofs():
    with actors(('issuer', 'holder', 'discloser', 'verifier'), enabled=True) as sides:
        issuer, holder, discloser, verifier = sides
        assert verifier.kvy.kramer.enabled

        # Issue BUP1 with a root held only by the issuer; every recipient verifies public TEL.
        registrar = Registrar(issuer.rgy)
        registry = registrar.makeRegistry('states', issuer.hab.pre)
        transfer(issuer, sides[1:], registry, issuer.rgy.store.event(registry.regk))
        root = Salter(raw=b'public-test-root')
        issuer.hab.mgr.putRegistryRoot(issuer.hab.pre, registry.regk, root)
        credential = acdcmap(israid=issuer.hab.pre, iseaid=holder.hab.pre,
                              regid=registry.regk, attribute=dict(d='', role='member'))
        first, event1 = registrar.issue(registry, credential, state='issued', salt=root.qb64)
        transfer(issuer, sides[1:], registry, event1)
        for side in sides[1:]:
            assert side.hab.mgr.getRegistryRoot(side.hab.pre, registry.regk) is None

        # Two actual Grant/Admit hops retain the BUP1 proof under each exact admitted Grant.
        origin = messagize(credential, bonds=[first.data], gvrsn=V2)
        issued, atc = grant(issuer.hab, holder.hab.pre, 'issue', origin=origin)
        for side in (issuer, holder):
            receive(side, issued.raw + atc)
            assert side.exc.complete(issued.said)
        admitted, atc = admit(holder.hab, 'received', issued)
        for side in (issuer, holder):
            receive(side, admitted.raw + atc)
            assert side.exc.complete(admitted.said)
        held = bytes(serializeParsedSubstream(loadParsedNestedSubstreams(holder.hby, issued.said)[0]))
        forwarded, atc = grant(holder.hab, discloser.hab.pre, 'delegate disclosure', origin=held)
        for side in (holder, discloser):
            receive(side, forwarded.raw + atc)
            assert side.exc.complete(forwarded.said)
        admitted, atc = admit(discloser.hab, 'received', forwarded)
        for side in (holder, discloser):
            receive(side, admitted.raw + atc)
            assert side.exc.complete(admitted.said)
        selected = loadParsedNestedSubstreams(discloser.hby, forwarded.said)[0]
        disclosed = bytes(serializeParsedSubstream(selected))
        assert disclosed == held
        snapshots = [(holder, issued.said, held), (discloser, forwarded.said, disclosed)]

        # Native RegistrySalt copies the root to the discloser's encrypted Keeper only.
        sender = RegistrySalt(issuer.hab, issuer.rgy)
        recipient = RegistrySalt(discloser.hab, discloser.rgy)
        discloser.hby.rtr.addRoute(RegistrySalt.Route, recipient, attachments=True)
        opening = Blinder(data=BlindState(*selected.bsqs[0]), verify=False)
        recipient.approve(registry.regk, issuer.hab.pre, event=event1.said, opening=opening)
        root_copy = sender.prepare(registry.regk, discloser.hab.pre, discloser.hab.pre)
        assert root.qb64b not in root_copy
        receive(discloser, root_copy)
        assert discloser.hab.mgr.getRegistryRoot(discloser.hab.pre, registry.regk).qb64 == root.qb64
        cipher = discloser.hab.mgr.ks.rroots.get((discloser.hab.pre, registry.regk))
        assert cipher.qb64 != root.qb64
        for side in (holder, verifier):
            assert side.hab.mgr.getRegistryRoot(side.hab.pre, registry.regk) is None

        # Both parties know BUP2 before preparation; held BUP1 bytes leave the new Grant pending.
        second, event2 = registrar.issue(registry, credential, state='issued', salt=root.qb64)
        transfer(issuer, (discloser, verifier), registry, event2)
        message, atc = grant(discloser.hab, verifier.hab.pre, 'present', origin=disclosed)
        original = parsed(message.raw + atc)
        # Match native authoring: self-authored bytes use the protected Habery owner.
        # Remote delivery still uses each actor's separate KRAM-enabled Kevery.
        local = Parser(version=V2, kvy=discloser.hby.kvy, exc=discloser.exc,
                       rvy=discloser.hby.rvy, rgy=discloser.rgy, local=True)
        local.parse(ims=bytearray(message.raw + atc), framed=False)
        assert not discloser.exc.complete(message.said)
        assert discloser.hby.db.epse.get((message.said,)).raw == message.raw
        deadline = discloser.hby.db.epsd.get((message.said,)).dts
        with pytest.raises(ValidationError):
            discloser.route.approve(message.said)

        # A foreign Habery signs the same body independently; ordinary intake verifies both TSGs.
        endorsement = parsed(issuer.hab.endorse(message, gvrsn=V2))
        assert endorsement.serder.raw == original.serder.raw == message.raw
        original.tsgs.extend(endorsement.tsgs)
        authorized = bytes(serializeParsedSubstream(original))
        local.parse(ims=bytearray(authorized), framed=False)
        assert discloser.hby.db.epsd.get((message.said,)).dts == deadline
        # Register the final outbound frame with its conversation owner before delivery.
        receive(discloser, authorized)
        assert discloser.hby.db.epsd.get((message.said,)).dts == deadline
        receive(verifier, authorized)  # First remote delivery already carries issuer consent.
        assert verifier.hby.db.epse.get((message.said,)).raw == message.raw
        assert verifier.hby.db.exns.get((message.said,)) is None
        for side in (discloser, verifier):
            xid = side.route.approve(message.said)
        assert discloser.rgy.store.headEvent(registry.regk).said == event2.said
        assert discloser.rgy.store.opening(event2.said) is None
        with pytest.raises(ValidationError, match='completed own reply'):
            discloser.route.finish(xid)
        assert not discloser.exc.complete(message.said)

        # Unblind requests and returns BUP2 alone, deriving it without transferring the root.
        query = verifier.route.start(message.said)
        assert parsed(query).serder.sad['q']['re'] == {registry.regk: [event2.said]}
        receive(discloser, query)
        response = discloser.route.cues.popleft()['msg']
        reply = parsed(response)
        assert reply.serder.sad['a']['re'] == {registry.regk: [event2.said]}
        assert not reply.nests and not reply.bsss and len(reply.bsqs) == 1
        assert Blinder(data=BlindState(*reply.bsqs[0]), verify=False).qb64 == second.qb64
        assert root.qb64b not in response and first.qb64b not in response
        # Explicit local completion repairs only this outgoing Grant before its peer can Admit it.
        assert discloser.route.finish(xid) is True
        assert discloser.exc.complete(message.said)
        assert discloser.hby.db.epse.get((message.said,)) is None
        assert discloser.route.finish(xid) is True  # The same frozen reply may be retried.
        assert discloser.hby.db.epsd.get((message.said,)).dts == deadline
        receive(verifier, response)
        assert verifier.route.finish(xid) is True
        body, _, verdict, records = verifier.exc.reverifyGrant(message.said)
        assert body.raw == message.raw and verdict.verdict == chaining.Verdicts.valid
        assert records[credential.said].state == 'issued'
        assert records[credential.said].said == event2.said
        admission, atc = admit(verifier.hab, 'received', message)
        for side in (discloser, verifier):
            receive(side, admission.raw + atc)
            assert side.exc.complete(admission.said), side.hab.name
        for side, said, proof in snapshots:
            assert bytes(serializeParsedSubstream(loadParsedNestedSubstreams(side.hby, said)[0])) == proof
        for side in (holder, verifier):
            assert side.hab.mgr.getRegistryRoot(side.hab.pre, registry.regk) is None


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


def test_accepted_live_grant_retains_unblind_proofs_without_changing_admitted_history(tmp_path):
    with presentation(True, accepted=True, headDirPath=str(tmp_path)) as h:
        db = h.verifier.hby.db
        prior = db.exns.get((h.grant.sad['p'],))
        opener = db.exns.get((prior.sad['p'],))
        assert prior.route == '/ipex/agree' and opener.route == '/ipex/offer'
        assert h.grant.ilk == 'exn' and h.xid == opener.said != h.grant.said
        responseLink = db.erpy.get((prior.said,)).qb64
        assert responseLink == h.grant.said
        cache = db.kramTMSC.get((h.grant.pre, h.xid, h.grant.said))
        observed = db.exrs.get((h.grant.said, h.credential.said))
        assert observed.state == 'issued'
        original = db.enst.get((h.grant.said,))
        historical = h.holder.hby.db.enst.get((h.issuance.said,))
        deadline = db.epsd.get((h.grant.said,)).dts
        assert h.verifier.exc.reverifyGrant(h.grant.said)[2].verdict == chaining.Verdicts.unknown
        with pytest.raises(ValidationError):
            h.holder.route.approve(h.issuance.said)
        receive(h.holder, h.verifier.route.start(h.grant.said))
        response = h.holder.route.cues.popleft()['msg']
        receive(h.verifier, response)
        assert h.verifier.route.complete(h.xid)
        # Even a valid replay cannot enrich the first accepted view.
        frame = parsed(h.holder.hab.endorse(h.grant, gvrsn=V2))
        frame.nests = loadParsedNestedSubstreams(h.holder.hby, h.grant.said)
        frame.nests[0].bsqs = [proof.data for proof in h.proofs]
        receive(h.verifier, signed(h.holder, frame))
        assert db.enst.get((h.grant.said,)) == original
        # Candidate rechecks authenticate new proofs but cannot write them.
        assert h.verifier.exc.reverifyGrant(h.grant.said, nests=frame.nests)[2].verdict == chaining.Verdicts.valid
        with pytest.raises(ValidationError, match='exact retained Grant nodes'):
            h.verifier.exc.reverifyGrant(h.grant.said, nests=[])
        assert db.enst.get((h.grant.said,)) == original
        assert db.exrs.get((h.grant.said, h.credential.said)) == observed
        assert h.verifier.route.finish(h.xid) is True
        body, nests, verdict, records = h.verifier.exc.reverifyGrant(h.grant.said)
        assert verdict.verdict == chaining.Verdicts.valid
        assert records[h.credential.said].state == 'revoked'
        assert body.raw == h.grant.raw and nests[0].serder.raw == h.credential.raw
        assert {data[0].qb64 for data in nests[0].bsqs} == {proof.said for proof in h.proofs}
        assert db.epsd.get((h.grant.said,)).dts == deadline
        assert db.erpy.get((prior.said,)).qb64 == responseLink
        assert db.kramTMSC.get((h.grant.pre, h.xid, h.grant.said)) == cache
        current = db.exrs.get((h.grant.said, h.credential.said))
        assert current.state == 'revoked' and current.said == h.events[-1].said
        retained = db.enst.get((h.grant.said,))
        assert retained != original
        # Ordinary replay cannot strip the explicitly retained proofs.
        frame.nests[0].bsqs = [proof.data for proof in h.proofs[1:]]
        receive(h.verifier, signed(h.holder, frame))
        assert db.enst.get((h.grant.said,)) == retained
        admission, atc = admit(hab=h.verifier.hab, message='received', grant=h.grant)
        receive(h.verifier, admission.raw + atc)
        with pytest.raises(ValidationError):
            h.verifier.route.finish(h.xid)
        with pytest.raises(ValidationError):
            h.verifier.route.start(h.grant.said)
        # Replay cannot enrich an already admitted historical view either.
        frame = parsed(h.issuer.hab.endorse(h.issuance, gvrsn=V2))
        frame.nests = nests
        receive(h.holder, signed(h.issuer, frame))
        assert h.holder.hby.db.enst.get((h.issuance.said,)) == historical
        db.close(clear=False)
        db.reopen(reuse=True)
        restart(h.verifier)
        assert h.verifier.exc.reverifyGrant(h.grant.said)[2].verdict == chaining.Verdicts.valid
        assert db.enst.get((h.grant.said,)) == retained


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


def test_partial_reply_retains_verified_proofs_until_second_signature_without_proofs(fakeHelpingClock):
    with presentation(False) as h:
        receive(h.holder, h.verifier.route.start(h.grant.said))
        frame = parsed(h.holder.route.cues.popleft()['msg'])
        receive(h.verifier, signed(h.holder, frame, indices=[0]))
        assert not h.verifier.route.complete(h.xid)
        with pytest.raises(ValidationError):
            h.verifier.route.finish(h.xid)
        frame.bsqs, frame.bsss = [], []
        receive(h.verifier, signed(h.holder, frame, indices=[1]))
        assert h.verifier.route.complete(h.xid)
        assert h.verifier.route.finish(h.xid)
        assert h.verifier.hby.db.exrs.get((h.grant.said, h.credential.said)).state == 'revoked'
        # Readiness never extends the original operation lifetime.
        fakeHelpingClock.advance(seconds=301)
        with pytest.raises(ValidationError):
            h.verifier.route.complete(h.xid)


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
        # Missing held evidence may arrive later; it is not an invalid proof.
        with pytest.raises(MissingOpeningError):
            h.holder.route.respond(h.xid)
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
