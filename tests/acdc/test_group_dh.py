"""Two independent real groups approve DH without copying ephemeral private keys."""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0 as V2
from keri.acdc import Regery, Registrar, acdcmap, admit, chaining, grant, loadHandlers, regeventing
from keri.acdc.dhking import Dhke
from keri.acdc.salting import RegistryRoot
from keri.acdc.unblinding import Unblind
from keri.app import Notifier, grouping, openCF, openHby
from keri.core import (Blinder, Diger, Kevery, Kramer, Matter, MtrDex, Number, Parser, Salter,
                       SealSource, SerderACDC, SerderKERI, Signer, exchange as exchangeMessage,
                       interact, messagize, rotate)
from keri.kering import ValidationError
from keri.peer import Exchanger
from keri.peer.exchanging import (loadParsedNestedSubstreams, serializeMessage,
                                  serializeParsedSubstream, verify)


def receive(side, wire, *, local=False):
    ims = bytearray(wire)
    side.psr.parse(ims=ims, framed=False, local=local)
    assert not ims


def parsed(wire):
    return Parser(version=V2).parseOne(ims=bytearray(wire), processive=False)


def signed(message, members, *, nests=None, last=False):
    """Compose ordinary signatures; production KRAM/Revery owns their acceptance."""
    hab = members[0].hab
    sigers = [sig for member in members for sig in member.hab.sign(message.raw)]
    kwa = (dict(lsgs=[(hab.kever.prefixer, sigers)]) if last else
           dict(tsgs=[(hab.kever.prefixer, Number(sn=hab.kever.lastEst.s),
                       Diger(qb64=hab.kever.lastEst.d), sigers)]))
    return messagize(message, nests=nests, gvrsn=V2, **kwa)


@contextmanager
def groups(enabled=True, size=2, lead=0, count=1, approve=True):
    with ExitStack() as stack:
        parties, allmembers = [], []
        for role in ('issuer', 'issuee'):
            members = []
            for index in range(size):
                n = len(allmembers) + 1
                signer = Signer(raw=bytes([n]) * 32, transferable=False)
                hby = stack.enter_context(openHby(name=f'dh-{role}-{index}', base='test', version=V2,
                    salt=Salter(raw=bytes([n]) * 16).qb64, seed=signer.qb64, aeid=signer.verfer.qb64))
                member = hby.makeHab(name=f'{role}-{index}')
                rgy = Regery(hby=hby, name=hby.name, temp=True)
                stack.callback(rgy.close)
                cf = stack.enter_context(openCF(name=hby.name, base='test'))
                cf.put(dict(kram=dict(enabled=enabled, denials=[],
                    caches={'~': [1000, 5000, 60000, 300000, 5000, 60000, 300000]})))
                exc = Exchanger(hby=hby, handlers=[])
                exc.TimeoutPSE = 300
                loadHandlers(hby, exc, SimpleNamespace(add=lambda **_: None), rgy=rgy)
                kvy = Kevery(db=hby.db, rvy=hby.rvy, exc=exc, kramer=Kramer(db=hby.db, cf=cf))
                side = SimpleNamespace(hby=hby, member=member, rgy=rgy, exc=exc, kvy=kvy,
                    psr=Parser(version=V2, kvy=kvy, rvy=hby.rvy, exc=exc, rgy=rgy))
                members.append(side)
                allmembers.append(side)
            parties.append(members)
        for side in allmembers:
            for other in allmembers:
                if other is not side:
                    receive(side, other.member.msgOwnEvent(sn=0, framed=False, gvrsn=V2))
        for members in parties:
            mids = [side.member.pre for side in members]
            for side in members:
                side.hab = side.hby.makeGroupHab(group='group', mhab=side.member,
                    smids=mids, isith='2', nsith='2', version=V2)
            for side in allmembers:
                for source in members:
                    receive(side, source.hab.msgOwnInception(allowPartiallySigned=True,
                                                            framed=False, gvrsn=V2), local=True)
                side.kvy.processEscrows()
                assert members[0].hab.pre in side.hby.kevers
        for side in allmembers:
            side.dh = Dhke(side.hab, side.exc)
            side.kvy.qvy = side.dh
            side.hby.rtr.addRoute(Dhke.Route, side.dh)
        issuers, issuees = parties
        registrar = Registrar(issuers[lead].rgy)
        registries = [registrar.makeRegistry(f'fresh-{n}', issuers[lead].hab.pre) for n in range(count)]
        registry = registries[0]

        def anchor(event):
            regid = event.sad.get('rd', event.said)
            registry = next(registry for registry in registries if registry.regk == regid)
            hab = issuers[lead].hab
            kel = interact(pre=hab.pre, dig=hab.kever.serder.said, sn=hab.kever.sn + 1,
                data=[dict(i=registry.regk, s=event.sad['n'], d=event.said)], version=V2)
            sigers = [sig for side in issuers[lead:lead + 2] for sig in side.hab.sign(kel.raw)]
            wire = messagize(kel, sigers=sigers, gvrsn=V2)
            for side in allmembers:
                receive(side, wire, local=True)
                assert side.hby.kevers[hab.pre].serder.said == kel.said
            assert registry.anchorMsg(event.said)
            tel = messagize(event, bonds=[SealSource(s=kel.snh, d=kel.said)], gvrsn=V2)
            for side in allmembers:
                receive(side, tel)
                assert side.rgy.store.headEvent(registry.regk).said == event.said
            return kel

        for reg in registries:
            coordinator = anchor(issuers[lead].rgy.store.event(reg.regk))
        # Issuee has no preceding Apply. Its own accepted group event elects custody.
        ihab = issuees[lead].hab
        own = interact(pre=ihab.pre, dig=ihab.kever.serder.said, sn=1, version=V2)
        wire = messagize(own, sigers=[sig for side in issuees[lead:lead + 2]
                                     for sig in side.hab.sign(own.raw)], gvrsn=V2)
        for side in allmembers:
            receive(side, wire, local=True)
        nodes = [acdcmap(israid=issuers[lead].hab.pre, iseaid=ihab.pre,
                        regid=reg.regk, attribute=dict(d='', role='member')) for reg in registries]
        if count > 1:
            nodes[0] = acdcmap(israid=issuers[lead].hab.pre, iseaid=ihab.pre,
                regid=registry.regk, attribute=dict(d='', role='origin'),
                edge=dict(d='', **{f'child{n}': dict(d='', n=node.said, o='E1E')
                                  for n, node in enumerate(nodes[1:])}))
        credential = nodes[0]
        plan = [[credential.schema['$id'], '/', []]] + [
            [node.schema['$id'], f'/e/child{n}/_/', []] for n, node in enumerate(nodes[1:])]
        message, atc = grant(hab=issuers[lead].hab, recp=ihab.pre, message='group issue',
            origin=credential, artifacts=nodes[1:] or None, modifiers=dict(dp=[plan]))
        nests = [serializeParsedSubstream(nest) for nest in parsed(message.raw + atc).nests]
        wire = signed(message, issuers[lead:lead + 2], nests=nests)
        for members, coord in zip(parties, (coordinator, own)):
            for side in members:
                receive(side, wire)
                assert side.hby.db.epse.get((message.said,)) is not None
                if approve:  # Live DH authority requires accepted KRAM evidence.
                    side.dh.approve(message.said, coordinator=(coord.sn, coord.said),
                                    custodian=members[lead].member.pre)
        yield SimpleNamespace(issuers=issuers, issuees=issuees, members=allmembers,
            lead=lead, registrar=registrar, registry=registry, registries=registries, credential=credential,
            grant=message, xid=message.said, anchor=anchor, coordinators=(coordinator, own))


def root(side, setup):
    return side.hab.mgr.getRegistryRoot(side.hab.pre, setup.registry.regk)


def exchange(setup):
    issuers, issuees = setup.issuers, setup.issuees
    left, right = issuers[setup.lead], issuees[setup.lead]
    query = left.dh.start(setup.grant.said)
    assert left.dh.start(setup.grant.said) == query
    voter = issuers[setup.lead + 1]
    other = voter.dh.contribute(setup.xid, query)
    assert parsed(query).serder.raw == parsed(other).serder.raw
    for side in (left, voter):
        receive(side, query)
        assert side.dh._operations[setup.xid]['query'] is None
        receive(side, other)
    query = left.dh.start(setup.grant.said)
    for side in issuees:
        receive(side, query)
    assert all(root(side, setup) is None for side in setup.members)
    proposal = right.dh.cues.popleft()
    assert proposal['kin'] == 'sign'
    voter = issuees[setup.lead + 1]
    other = voter.dh.contribute(setup.xid, proposal['msg'])
    for side in (right, voter):
        receive(side, proposal['msg'])
        receive(side, proposal['msg'])
        assert root(side, setup) is None
        receive(side, other)
    response = next(cue for cue in right.dh.cues if cue['kin'] == 'reply')['msg']
    for side in (left, issuers[setup.lead + 1]):
        receive(side, response)
    assert left.dh.complete(setup.xid) and right.dh.complete(setup.xid)
    matching = root(left, setup).qb64 == root(right, setup).qb64
    assert matching
    for members in (issuers, issuees):
        for index, side in enumerate(members):
            private_count = len(side.dh._operations[setup.xid]['private'])
            assert private_count == 0
            assert (root(side, setup) is not None) == (index == setup.lead)


def test_two_groups_issue_same_grant_then_explicitly_copy_root(fakeHelpingClock):
    with groups() as h:
        exchange(h)
        issuer, issuee = h.issuers[0], h.issuees[0]
        opening, event = h.registrar.issue(h.registry, h.credential, salt=root(issuer, h).qb64)
        h.anchor(event)
        issuer.dh.finish(h.xid)
        issuee.dh.finish(h.xid)
        # Other members use the real issued opening and original sender proofs,
        # not DH or direct writes to accepted Grant rows.
        for side in (h.issuers[1], h.issuees[1]):
            nests = loadParsedNestedSubstreams(side.hby, h.grant.said)
            nests[0].bsqs.append(opening.data)
            tsgs, cigars = verify(side.hby, h.grant)
            side.exc.processEvent(h.grant, tsgs=tsgs, cigars=cigars, nests=nests)
        for side in h.members:
            assert side.hby.db.exns.get((h.grant.said,)) is not None
        admission, _ = admit(hab=issuee.hab, message='received', grant=h.grant)
        wire = signed(admission, h.issuees)
        for side in h.members:
            receive(side, wire)
            assert side.hby.db.exns.get((admission.said,)) is not None
        recipient = h.issuees[1]
        receiver = RegistryRoot(recipient.hby, recipient.rgy)
        recipient.exc.addHandler(receiver)
        wire = RegistryRoot(issuee.hby, issuee.rgy).prepare(
            issuee.member, recipient.member.pre, issuee.hab.pre, h.registry.regk, event=event.said)
        receive(recipient, wire)
        # Stored pending: nothing is decrypted or retained before explicit approval.
        assert root(recipient, h) is None
        assert not recipient.dh._operations[h.xid]['private']
        (pending,) = receiver.pending()
        assert receiver.receive(pending['said'], event=event.said, opening=opening) is True
        matching = root(recipient, h).qb64 == root(issuee, h).qb64
        assert matching

        # The provisioned nonlead opens a later accepted event without another DH operation.
        held = tuple(recipient.hby.db.enst.get((h.grant.said,)))
        _, later = h.registrar.issue(h.registry, h.credential, salt=root(issuer, h).qb64)
        h.anchor(later)
        derived = Blinder.unblind(later.sad['b'], salt=root(recipient, h).qb64,
            sn=Number(numh=later.sad['n']).num, acdc=h.credential.said, states=('issued',))
        assert derived is not None and derived.said == later.sad['b']
        assert recipient.rgy.store.headEvent(h.registry.regk).said == later.said

        # Bootstrap an independent verifier with only real public KEL/TEL evidence.
        with ExitStack() as stack:
            hby = stack.enter_context(openHby(name='dh-independent-receiver', version=V2))
            hab = hby.makeHab(name='receiver')
            rgy = Regery(hby=hby, name=hby.name, temp=True)
            stack.callback(rgy.close)
            cf = stack.enter_context(openCF(name=hby.name, base='test'))
            cf.put(issuer.kvy.kramer.cf.get())
            notifier = Notifier(hby)
            stack.callback(notifier.noter.close, clear=True)
            exc = Exchanger(hby=hby, handlers=[])
            loadHandlers(hby, exc, notifier, rgy=rgy)
            kvy = Kevery(db=hby.db, rvy=hby.rvy, exc=exc, kramer=Kramer(db=hby.db, cf=cf))
            verifier = SimpleNamespace(hby=hby, hab=hab, rgy=rgy, exc=exc, kvy=kvy,
                psr=Parser(version=V2, kvy=kvy, rvy=hby.rvy, exc=exc, rgy=rgy))
            for side in h.members:
                receive(verifier, b''.join(side.hby.db.clonePreIter(side.member.pre, gvrsn=V2)))
                receive(side, hab.msgOwnEvent(sn=0, framed=False, gvrsn=V2))
            for side in (issuer, recipient):
                receive(verifier, b''.join(side.hby.db.clonePreIter(side.hab.pre, gvrsn=V2)))
            for raw in h.registry.store.cloneTelIter(h.registry.regk):
                event = SerderACDC(raw=raw)
                sn, said = regeventing.vetAnchor(event, db=issuer.hby.db, issuer=issuer.hab.pre)
                receive(verifier, messagize(event, bonds=[SealSource(s=f'{sn:x}', d=said)], gvrsn=V2))
            assert rgy.store.headEvent(h.registry.regk).said == later.said

            presentation, atc = grant(hab=recipient.hab, recp=hab.pre, message='provisioned member',
                origin=messagize(h.credential, bonds=[derived.data], gvrsn=V2))
            # A usable opening does not replace the group's ordinary signature threshold.
            receive(verifier, presentation.raw + atc)
            assert not exc.complete(presentation.said)
            nests = [serializeParsedSubstream(nest) for nest in parsed(presentation.raw + atc).nests]
            full = signed(presentation, [recipient, issuee], nests=nests)
            assert root(recipient, h).qb64b not in full
            receive(verifier, full)
            assert exc.complete(presentation.said)
            _, checked, verdict, observations = exc.reverifyGrant(presentation.said)
            assert verdict.verdict == chaining.Verdicts.valid
            assert checked[0].serder.raw == h.credential.raw
            state = observations[h.credential.said]
            assert (state.said, state.sn, state.state) == (later.said, 2, 'issued')
            signatures, _ = verify(hby, presentation)
            assert {sig.index for pre, _, _, sigers in signatures if pre.qb64 == recipient.hab.pre
                    for sig in sigers} == {0, 1}
            assert not list(hby.ks.rroots.getTopItemIter())

            # A later public update needs exact group-approved openings, not another root transfer.
            for side in [*h.issuees, verifier]:
                if side is not verifier:
                    receive(side, full)
                side.unblind = Unblind(side.hab, side.exc, side.rgy, states=('issued', 'revoked', ''))
                side.kvy.qvy = side.unblind
                side.hby.rtr.addRoute(Unblind.Route, side.unblind, blinders=True, attachments=True)
                side.unblind.approve(presentation.said)
            deadlines = [side.exc.exchangeDeadline(presentation) for side in [*h.issuees, verifier]]
            # Group support cannot reopen the already admitted issuance.
            with pytest.raises(ValidationError, match='unavailable, terminated or expired'):
                issuee.unblind.approve(h.grant.said)
            proof3, event3 = h.registrar.issue(h.registry, h.credential, salt=root(issuer, h).qb64)
            kel3 = h.anchor(event3)
            receive(verifier, b''.join(issuer.hby.db.clonePreIter(issuer.hab.pre, gvrsn=V2)))
            receive(verifier, messagize(event3, bonds=[SealSource(s=kel3.snh, d=kel3.said)], gvrsn=V2))
            query = verifier.unblind.start(presentation.said)
            receive(recipient, query)
            assert not recipient.unblind.cues  # A group never auto-authors independent reply timestamps.
            proposal = recipient.unblind.respond(presentation.said)
            assert recipient.unblind.respond(presentation.said) == proposal
            cue = recipient.unblind.cues.popleft()
            assert cue['kin'] == 'sign' and cue['dest'] == recipient.hab.pre
            frame = parsed(proposal)
            assert frame.serder.sad['a']['re'] == {h.registry.regk: [event3.said]}
            assert [block[0].qb64 for block in frame.bsqs] == [proof3.said]
            assert not frame.bsss and not frame.nests and root(recipient, h).qb64b not in proposal
            with pytest.raises(ValidationError, match='authenticated peer query'):
                issuee.unblind.contribute(presentation.said, proposal)
            receive(issuee, query)

            # The other member independently checks scope/proofs before signing these exact bytes.
            extra = parsed(proposal)
            extra.bsqs.append(derived.data)
            with pytest.raises(ValidationError, match='excess opening'):
                issuee.unblind.contribute(presentation.said, serializeParsedSubstream(extra))
            contribution = issuee.unblind.contribute(presentation.said, proposal)
            assert parsed(contribution).serder.raw == frame.serder.raw
            assert issuee.unblind.contribute(presentation.said, proposal) == contribution
            changed = deepcopy(frame.serder.sad)
            changed['dt'] = '2021-01-01T00:00:01.000000+00:00'
            altered = SerderKERI(sad=changed, makify=True)
            with pytest.raises(ValidationError, match='already frozen'):
                issuee.unblind.contribute(presentation.said, recipient.hab.endorse(altered, gvrsn=V2))

            # The v2 Revery must obtain the other genuine signature; duplicate partials do not finish.
            for side in h.issuees:
                receive(side, proposal)
                receive(side, proposal)
                assert not side.unblind.complete(presentation.said)
                assert not side.unblind.cues
                with pytest.raises(ValidationError, match='completed own reply'):
                    side.unblind.finish(presentation.said)
                receive(side, contribution)
                assert side.unblind.complete(presentation.said)
                assert side.unblind.finish(presentation.said)
                assert side.unblind.finish(presentation.said)
            assert not recipient.unblind.cues  # Provisioned nonlead authored; index zero transmits.
            response = issuee.unblind.cues.popleft()
            assert response['kin'] == 'reply' and response['dest'] == verifier.hab.pre
            assert recipient.unblind.respond(presentation.said) == response['msg']
            receive(verifier, response['msg'])
            assert verifier.unblind.complete(presentation.said)
            assert verifier.unblind.finish(presentation.said)
            _, repaired, verdict, observations = exc.reverifyGrant(presentation.said)
            assert verdict.verdict == chaining.Verdicts.valid
            assert observations[h.credential.said].said == event3.said
            assert repaired[0].serder.raw == h.credential.raw
            assert [side.exc.exchangeDeadline(presentation)
                    for side in [*h.issuees, verifier]] == deadlines
            assert not list(hby.ks.rroots.getTopItemIter())
            assert all(tuple(side.hby.db.enst.get((h.grant.said,))) == held for side in h.issuees)
            # Form a rootless verifier group in independent stores; keep the individual history above.
            individual_view = tuple(verifier.hby.db.enst.get((presentation.said,)))
            verifier.unblind.abandon(presentation.said)
            verifier.hby.rtr.routes[:] = [route for route in verifier.hby.rtr.routes
                                         if route.resource is not verifier.unblind]
            phby = stack.enter_context(openHby(name='dh-requester-peer', version=V2))
            pmember = phby.makeHab(name='requester-peer')
            prgy = Regery(hby=phby, name=phby.name, temp=True)
            stack.callback(prgy.close)
            pexc = Exchanger(hby=phby, handlers=[])
            pexc.TimeoutPSE = 300
            loadHandlers(phby, pexc, SimpleNamespace(add=lambda **_: None), rgy=prgy)
            pkvy = Kevery(db=phby.db, rvy=phby.rvy, exc=pexc, kramer=Kramer(db=phby.db, cf=cf))
            peer = SimpleNamespace(hby=phby, member=pmember, hab=pmember, rgy=prgy, exc=pexc, kvy=pkvy,
                psr=Parser(version=V2, kvy=pkvy, rvy=phby.rvy, exc=pexc, rgy=prgy))
            requesters = [SimpleNamespace(**(vars(verifier) | dict(member=verifier.hab))), peer]
            for side in [*h.members, *requesters]:
                for member in requesters:
                    receive(side, member.member.msgOwnEvent(sn=0, framed=False, gvrsn=V2))
            for side in requesters:
                side.hab = side.hby.makeGroupHab(group='requester-group', mhab=side.member,
                    smids=[member.member.pre for member in requesters], isith='2', nsith='2', version=V2)
            for side in [*h.members, *requesters]:
                for member in requesters:
                    receive(side, member.hab.msgOwnInception(allowPartiallySigned=True, framed=False, gvrsn=V2))
                side.kvy.processEscrows()
                assert requesters[0].hab.pre in side.hby.kevers
            for side in h.members:
                receive(peer, b''.join(side.hby.db.clonePreIter(side.member.pre, gvrsn=V2)))
            for side in (issuer, recipient):
                receive(peer, b''.join(side.hby.db.clonePreIter(side.hab.pre, gvrsn=V2)))
            for raw in h.registry.store.cloneTelIter(h.registry.regk):
                event = SerderACDC(raw=raw)
                sn, said = regeventing.vetAnchor(event, db=issuer.hby.db, issuer=issuer.hab.pre)
                receive(peer, messagize(event, bonds=[SealSource(s=f'{sn:x}', d=said)], gvrsn=V2))
            group_grant, atc = grant(hab=recipient.hab, recp=requesters[0].hab.pre, message='group verifier',
                origin=messagize(h.credential, bonds=[proof3.data], gvrsn=V2))
            wire = signed(group_grant, h.issuees,
                nests=[serializeParsedSubstream(node) for node in parsed(group_grant.raw + atc).nests])
            for side in [*h.issuees, *requesters]:
                receive(side, wire)
                assert side.exc.complete(group_grant.said)
                if side in requesters:
                    side.unblind = Unblind(side.hab, side.exc, side.rgy, states=('issued', 'revoked', ''))
                    side.kvy.qvy = side.unblind
                    side.hby.rtr.addRoute(Unblind.Route, side.unblind, blinders=True, attachments=True)
                if side is not requesters[0]:
                    side.unblind.approve(group_grant.said)
            group_deadlines = [side.exc.exchangeDeadline(group_grant)
                               for side in [*h.issuees, *requesters]]
            proof4, event4 = h.registrar.issue(h.registry, h.credential, salt=root(issuer, h).qb64)
            kel4 = h.anchor(event4)
            for side in requesters:
                receive(side, b''.join(issuer.hby.db.clonePreIter(issuer.hab.pre, gvrsn=V2)))
                receive(side, messagize(event4, bonds=[SealSource(s=kel4.snh, d=kel4.said)], gvrsn=V2))

            # Nonlead authors exactly one query; neither a partial nor its duplicate authorizes disclosure.
            qproposal = requesters[1].unblind.start(group_grant.said)
            assert requesters[1].unblind.start(group_grant.said) == qproposal
            assert requesters[1].unblind.cues.popleft()['kin'] == 'sign'
            qframe = parsed(qproposal)
            assert qframe.serder.sad['q']['re'] == {h.registry.regk: [event4.said]}
            assert [node.serder.raw for node in qframe.nests] == [event4.raw]
            assert not qframe.bsqs and not qframe.bsss
            receive(recipient, qproposal)
            receive(recipient, qproposal)
            with pytest.raises(ValidationError, match='authenticated peer request'):
                recipient.unblind.respond(group_grant.said)
            with pytest.raises(ValidationError, match='no local approval'):
                requesters[0].unblind.contribute(group_grant.said, qproposal)
            requesters[0].unblind.approve(group_grant.said)
            # A separately selected local operation may be abandoned before any proposal leaves.
            abandoned = Unblind(requesters[0].hab, requesters[0].exc, requesters[0].rgy, states=('issued',))
            abandoned.start(group_grant.said)
            assert abandoned.cues
            abandoned.abandon(group_grant.said)
            assert not abandoned.cues
            with pytest.raises(ValidationError):
                abandoned.contribute(group_grant.said, qproposal)
            omitted = parsed(qproposal)
            omitted.nests = []
            with pytest.raises(ValidationError, match='selected accepted public events'):
                requesters[0].unblind.contribute(group_grant.said, serializeParsedSubstream(omitted))
            qcontribution = requesters[0].unblind.contribute(group_grant.said, qproposal)
            assert parsed(qcontribution).serder.raw == qframe.serder.raw
            assert [serializeParsedSubstream(node) for node in parsed(qcontribution).nests] == [
                serializeParsedSubstream(node) for node in qframe.nests]
            assert requesters[0].unblind.contribute(group_grant.said, qproposal) == qcontribution
            changed = deepcopy(qframe.serder.sad)
            changed['dt'] = '2021-01-01T00:00:02.000000+00:00'
            altered = SerderKERI(sad=changed, makify=True)
            with pytest.raises(ValidationError, match='already frozen'):
                requesters[0].unblind.contribute(group_grant.said,
                    requesters[1].hab.endorse(altered, last=False, gvrsn=V2))
            for side in requesters:
                receive(side, qproposal)
                receive(side, qproposal)
                assert not side.unblind.cues and not side.unblind.complete(group_grant.said)
                # KRAM accumulates the query factors into the exact threshold.
                receive(side, qcontribution)
                assert not side.unblind.complete(group_grant.said)  # Query readiness is not reply readiness.
            assert not requesters[1].unblind.cues
            qcue = requesters[0].unblind.cues.popleft()
            assert qcue['kin'] == 'query' and qcue['dest'] == recipient.hab.pre
            assert requesters[1].unblind.start(group_grant.said) == qcue['msg']
            assert parsed(qcue['msg']).serder.raw == qframe.serder.raw
            assert {sig.index for _, sigs in parsed(qcue['msg']).lsgs for sig in sigs} == {0, 1}

            # Both groups authenticate exact aggregates; each rootless requester independently finishes.
            for side in h.issuees:
                receive(side, qcue['msg'])
            rproposal = recipient.unblind.respond(group_grant.said)
            assert recipient.unblind.cues.popleft()['kin'] == 'sign'
            rcontribution = issuee.unblind.contribute(group_grant.said, rproposal)
            for side in h.issuees:
                receive(side, rproposal)
                assert not side.unblind.complete(group_grant.said)
                receive(side, rcontribution)
                assert side.unblind.complete(group_grant.said)
            assert not recipient.unblind.cues
            rcue = issuee.unblind.cues.popleft()
            assert rcue['dest'] == requesters[0].hab.pre
            rframe = parsed(rcue['msg'])
            assert rframe.serder.sad['a']['re'] == {h.registry.regk: [event4.said]}
            assert [block[0].qb64 for block in rframe.bsqs] == [proof4.said]
            for side in requesters:
                receive(side, rcue['msg'])
                assert side.unblind.complete(group_grant.said)
                assert side.unblind.finish(group_grant.said)
                _, repaired, verdict, observations = side.exc.reverifyGrant(group_grant.said)
                assert verdict.verdict == chaining.Verdicts.valid
                assert observations[h.credential.said].said == event4.said
                assert repaired[0].serder.raw == h.credential.raw
                assert not list(side.hby.ks.rroots.getTopItemIter())
            assert [side.exc.exchangeDeadline(group_grant)
                    for side in [*h.issuees, *requesters]] == group_deadlines
            assert tuple(verifier.hby.db.enst.get((presentation.said,))) == individual_view
            assert all(tuple(side.hby.db.enst.get((h.grant.said,))) == held for side in h.issuees)
            fakeHelpingClock.advance(seconds=301)
            for side in requesters:
                with pytest.raises(ValidationError):
                    side.unblind.start(group_grant.said)
                with pytest.raises(ValidationError):
                    side.unblind.contribute(group_grant.said, qproposal)
            with pytest.raises(ValidationError):
                recipient.unblind.respond(presentation.said)
            with pytest.raises(ValidationError):
                issuee.unblind.contribute(presentation.said, proposal)
        assert not recipient.dh._operations[h.xid]['private']
        assert tuple(recipient.hby.db.enst.get((h.grant.said,))) == held


def test_frozen_nonzero_custodian_is_not_reelected_by_later_signatures():
    with groups(size=3, lead=1) as h:
        for members, event in zip((h.issuers, h.issuees), h.coordinators):
            assert members[1].hab.witnesser(sn=event.sn, dig=event.said)
            wire = messagize(event, sigers=members[0].hab.sign(event.raw), gvrsn=V2)
            for side in h.members:
                receive(side, wire, local=True)
            assert not members[1].hab.witnesser(sn=event.sn, dig=event.said)
            with pytest.raises(ValidationError, match='custodian'):
                members[0].dh.start(h.grant.said) if members is h.issuers else members[0].dh._custody(
                    members[0].dh._operations[h.xid], lead=True)
        exchange(h)


@pytest.mark.parametrize('fault', ['nonlead', 'forged', 'changed', 'scope', 'abandoned',
                                   'restart', 'expired', 'coordinator', 'signatures'])
def test_group_contribution_refusals_create_no_private_keys_or_roots(fault, fakeHelpingClock):
    with groups() as h:
        lead, member = h.issuers
        proposal = lead.dh.start(h.grant.said)
        if fault == 'nonlead':
            with pytest.raises(ValidationError, match='custodian'):
                member.dh.start(h.grant.said)
        else:
            if fault == 'forged':
                proposal = member.hab.endorse(parsed(proposal).serder, last=True, gvrsn=V2)
            elif fault in ('changed', 'scope'):
                if fault == 'changed':
                    member.dh.contribute(h.xid, proposal)
                sad = deepcopy(parsed(proposal).serder.sad)
                if fault == 'scope':
                    sad['q']['pk'] = {}
                else:
                    sad['dt'] = '2026-01-01T00:00:00.000000+00:00'
                proposal = lead.hab.endorse(SerderKERI(sad=sad, makify=True), last=True, gvrsn=V2)
            elif fault == 'abandoned':
                member.dh.abandon(h.xid)
            elif fault == 'restart':
                member.dh = Dhke(member.hab, member.exc)
            elif fault == 'expired':
                fakeHelpingClock.advance(seconds=301)
            elif fault == 'coordinator':
                coord = h.coordinators[0]
                member.hby.db.evts.rem((member.hab.pre, coord.said))
            elif fault == 'signatures':
                member.hby.db.sigs.rem((member.hab.pre, h.coordinators[0].said))
            with pytest.raises(ValidationError):
                member.dh.contribute(h.xid, proposal)
        for side in h.members:
            assert root(side, h) is None
        for side in (h.issuers[1], *h.issuees):
            count = sum(len(op['private']) for op in side.dh._operations.values())
            assert count == 0
        lead.dh.abandon(h.xid)
        count = len(lead.dh._operations[h.xid]['private'])
        assert count == 0


def test_member_rotations_keep_frozen_historical_contributions():
    with groups() as h:
        for member in h.members:
            wire = member.member.rotate(framed=False, gvrsn=V2)
            for side in h.members:
                if side is not member:
                    receive(side, wire)
        exchange(h)


def rotate_group(h, members, order):
    """Accept a real group rotation, including the old next-key threshold."""
    for member in members:
        wire = member.member.rotate(framed=False, gvrsn=V2)
        for side in h.members:
            if side is not member:
                receive(side, wire)
    hab = members[0].hab
    prior = [diger.qb64 for diger in hab.kever.ndigers]
    selected = [members[index].member for index in order]
    event = rotate(pre=hab.pre, dig=hab.kever.serder.said, sn=hab.kever.sn + 1,
        keys=[member.kever.verfers[0].qb64 for member in selected], isith='2', nsith='2',
        ndigs=[member.kever.ndigers[0].qb64 for member in selected], version=V2)
    sigers = [member.sign(event.raw, indices=[index], ondices=[
        prior.index(Diger(ser=member.kever.verfers[0].qb64b).qb64)])[0]
        for index, member in enumerate(selected)]
    for side in h.members:
        receive(side, messagize(event, sigers=sigers, gvrsn=V2), local=True)
        assert side.hby.kevers[hab.pre].serder.said == event.said


def test_group_rotation_preserves_authorized_custodian_without_reelection():
    with groups() as h:
        for members in (h.issuers, h.issuees):
            rotate_group(h, members, [1, 0])
        exchange(h)


@pytest.mark.parametrize('role', ['issuers', 'issuees'])
def test_removed_custodian_refuses_without_automatic_replacement(role):
    with groups(size=3) as h:
        lead = h.issuers[0]
        proposal = lead.dh.start(h.grant.said)
        members = getattr(h, role)
        rotate_group(h, members, [1, 2])
        for member in members:
            with pytest.raises(ValidationError, match='no longer authorized'):
                member.dh.complete(h.xid)
        if role == 'issuers':
            with pytest.raises(ValidationError, match='no longer authorized'):
                members[1].dh.contribute(h.xid, proposal)
        else:
            receive(members[1], signed(parsed(proposal).serder, h.issuers[:2], last=True))
            assert not members[1].dh.cues
        assert all(root(side, h) is None for side in h.members)
        lead.dh.abandon(h.xid)


@pytest.mark.parametrize('field', ['q', 'a'])
def test_later_low_order_registry_key_never_partially_retains_group_roots(field):
    with groups(count=2) as h:
        issuer, issuee = h.issuers[0], h.issuees[0]
        partial = issuer.dh.start(h.grant.said)
        message = parsed(partial).serder
        query = signed(message, h.issuers, last=True)
        receive(issuer, query)
        if field == 'a':
            receive(issuee, query)
            message = parsed(issuee.dh.cues.popleft()['msg']).serder
        sad = deepcopy(message.sad)
        sad[field]['pk'][h.registries[-1].regk] = Matter(raw=bytes(32), code=MtrDex.X25519).qb64
        wire = signed(SerderKERI(sad=sad, makify=True), h.issuers if field == 'q' else h.issuees,
                      last=field == 'q')
        receive(issuee if field == 'q' else issuer, wire)
        assert all(side.hab.mgr.getRegistryRoot(side.hab.pre, reg.regk) is None
                   for side in h.members for reg in h.registries)
        for side in (issuer, issuee):
            side.dh.abandon(h.xid)


@pytest.mark.parametrize('fault', ['opposite-event', 'wrong-member', 'changed-coordinator'])
def test_group_approval_requires_own_exact_election(fault):
    with groups() as h:
        side = h.issuers[0]
        event = h.coordinators[1 if fault == 'opposite-event' else 0]
        owner = h.issuers[1 if fault == 'wrong-member' else 0].member.pre
        dh = side.dh if fault == 'changed-coordinator' else Dhke(side.hab, side.exc)
        coordinate = (0, side.hab.pre) if fault == 'changed-coordinator' else (event.sn, event.said)
        with pytest.raises(ValidationError):
            dh.approve(h.grant.said, coordinator=coordinate, custodian=owner)
        assert all(root(member, h) is None for member in h.members)


def test_restarted_lead_cannot_accept_old_threshold_reply():
    with groups() as h:
        issuer, issuee = h.issuers[0], h.issuees[0]
        proposal = issuer.dh.start(h.grant.said)
        query = signed(parsed(proposal).serder, h.issuers, last=True)
        receive(issuer, query)
        receive(issuee, query)
        response = signed(parsed(issuee.dh.cues.popleft()['msg']).serder, h.issuees)
        old = issuer.dh
        issuer.dh = Dhke(issuer.hab, issuer.exc)
        issuer.kvy.qvy = issuer.dh
        for route in issuer.hby.rtr.routes:
            if route.resource is old:
                route.resource = issuer.dh
        receive(issuer, response)
        assert not issuer.dh._operations and root(issuer, h) is None
        old.abandon(h.xid)
        issuee.dh.abandon(h.xid)


def test_ipex_v2_proposals_replay_only_after_local_approval_with_v2_verification():
    # v2 IPEX multisig proposal replay needs no DH; KRAM-off retransmission repairs openings.
    with groups(enabled=False, approve=False) as h, ExitStack() as stack:
        opening, event = h.registrar.issue(h.registry, h.credential, salt=Salter().qb64)
        h.anchor(event)
        message, atc = grant(hab=h.issuers[0].hab, recp=h.issuees[0].hab.pre,
            message='exact group presentation', origin=h.credential)
        missing = [serializeParsedSubstream(nest) for nest in parsed(message.raw + atc).nests]
        retained = parsed(message.raw + atc)
        retained.nests[0].bsqs.append(opening.data)
        complete = [serializeParsedSubstream(nest) for nest in retained.nests]

        def wrapper(side, body, nests=None):
            return grouping.multisigExn(side.hab, side.hab.endorse(
                body, last=False, framed=False, gvrsn=V2, nests=nests))

        def coordinator(side):
            notifier = Notifier(hby=side.hby)
            stack.callback(notifier.noter.close)
            mux = grouping.Multiplexor(hby=side.hby, notifier=notifier,
                                      rgy=side.rgy, replay=side.psr)
            exc = Exchanger(hby=side.hby, handlers=[])
            grouping.loadHandlers(exc=exc, mux=mux)
            return mux, Parser(version=V2, kvy=side.kvy, rvy=side.hby.rvy, exc=exc, rgy=side.rgy)

        # Remote-first approval does not replay even an authentic member's exact child.
        remote, ratc = wrapper(h.issuers[1], message, missing)
        assert remote.pvrsn == V2
        assert remote.ked['a'] == dict(gid=message.pre, exn=message.said)
        local, latc = wrapper(h.issuers[0], message, missing)
        mux, psr = coordinator(h.issuers[0])
        child = parsed(remote.raw + ratc).nests[0]
        replay, mux.replay = mux.replay, None
        with pytest.raises(ValidationError, match='verification parser'):
            mux.validate(remote, nests=[child])
        psr.parse(ims=bytearray(remote.raw + ratc))
        assert h.issuers[0].hby.db.exns.get((remote.said,)) is None
        assert not list(h.issuers[0].hby.db.meids.get((message.said,)))
        mux.replay = Parser(exc=mux.exc, kvy=h.issuers[0].kvy, rvy=h.issuers[0].hby.rvy,
                            rgy=h.issuers[0].rgy, version=V2)
        with pytest.raises(ValidationError, match='verification parser'):
            mux.validate(remote, nests=[child])
        mux.replay = replay
        psr.parse(ims=bytearray(remote.raw + ratc))
        assert h.issuers[0].hby.db.exns.get((message.said,)) is None
        assert h.issuers[0].hby.db.epse.get((message.said,)) is None
        psr.parse(ims=bytearray(local.raw + latc), local=True)
        h.issuers[0].exc.processEscrow()
        assert not h.issuers[0].exc.complete(message.said)  # threshold signatures cannot replace the BUP proof
        remote, ratc = wrapper(h.issuers[1], message, complete)
        psr.parse(ims=bytearray(remote.raw + ratc))
        h.issuers[0].exc.processEscrow()
        assert h.issuers[0].exc.complete(message.said)
        accepted = loadParsedNestedSubstreams(h.issuers[0].hby, message.said)
        assert accepted[0].serder.raw == h.credential.raw
        assert serializeParsedSubstream(accepted[0]) == complete[0]
        assert h.issuers[0].exc.reverifyGrant(message.said)[2].verdict == chaining.Verdicts.valid

        # Every boundary still uses signed wrappers; none may enter proposal indexes.
        bad = exchangeMessage(sender=h.issuers[1].member.pre, route='/multisig/exn',
            attributes=dict(gid=message.pre, exn=h.grant.said), version=V2, gvrsn=V2)
        psr.parse(ims=h.issuers[1].member.endorse(bad, last=False, framed=False, gvrsn=V2,
                                               nests=[serializeParsedSubstream(child)]))
        assert h.issuers[0].hby.db.exns.get((bad.said,)) is None
        foreign = exchangeMessage(sender=h.issuees[0].member.pre, route='/multisig/exn',
            attributes=dict(gid=message.pre, exn=message.said), version=V2, gvrsn=V2)
        psr.parse(ims=h.issuees[0].member.endorse(foreign, last=False, framed=False, gvrsn=V2,
                                                nests=[serializeParsedSubstream(child)]))
        assert h.issuers[0].hby.db.exns.get((foreign.said,)) is None
        with pytest.raises(ValidationError, match='authored by the group'):
            grouping.multisigExn(h.issuees[0].hab,
                h.issuers[0].hab.endorse(message, framed=False, gvrsn=V2, nests=complete))
        for extra in (b'garbage', remote.raw + ratc):
            with pytest.raises((ValidationError, ValueError)):
                grouping.multisigExn(h.issuers[0].hab,
                    h.issuers[0].hab.endorse(message, framed=False, gvrsn=V2, nests=complete) + extra)

        # Transport the verified Grant, then coordinate its exact group Admit at the ordinary threshold.
        for side in h.issuees:
            side.psr.parse(ims=serializeMessage(h.issuers[0].hby, message.said))
            assert side.exc.complete(message.said)
        admission, _ = admit(hab=h.issuees[0].hab, message='accept exact Grant', grant=message)
        mux, psr = coordinator(h.issuees[0])
        for index in (0, 1):
            proposal, atc = wrapper(h.issuees[index], admission)
            assert parsed(proposal.raw + atc).nests[0].serder.raw == admission.raw
            psr.parse(ims=bytearray(proposal.raw + atc), local=index == 0)
            h.issuees[0].exc.processEscrow()
            assert h.issuees[0].exc.complete(admission.said) == (index == 1)
        assert h.issuees[0].hby.db.exns.get((admission.said,)).raw == admission.raw
        assert not list(h.issuees[0].hby.ks.rroots.getTopItemIter())


def test_nonzero_dh_custodian_and_ipex_v2_admit_transmitter_are_independent():
    # v2 IPEX election proof only: installed CLI transport is separately exercised with two members.
    with groups(size=3, lead=1) as h:
        exchange(h)
        issuer, custodian = h.issuers[1], h.issuees[1]
        opening, event = h.registrar.issue(h.registry, h.credential, salt=root(issuer, h).qb64)
        h.anchor(event)
        issuer.dh.finish(h.xid)
        custodian.dh.finish(h.xid)
        # KRAM refuses duplicate Grant delivery; other members verify the real
        # issued opening with the original sender proofs.
        for side in h.members:
            if side not in (issuer, custodian):
                nests = loadParsedNestedSubstreams(side.hby, h.grant.said)
                nests[0].bsqs.append(opening.data)
                tsgs, cigars = verify(side.hby, h.grant)
                side.exc.processEvent(h.grant, tsgs=tsgs, cigars=cigars, nests=nests)
            assert side.exc.complete(h.grant.said)
        admission, _ = admit(custodian.hab, message='one retained body', grant=h.grant)
        # The coordinator had signatures 1+2; this Admit reaches threshold with 0+1.
        wire = signed(admission, h.issuees[:2])
        for side in h.issuees:
            receive(side, wire)
            assert side.exc.complete(admission.said)
        assert [side.exc.lead(side.hab, admission.said) for side in h.issuees] == [True, False, False]
        assert custodian.dh._operations[h.xid]['custodian'] == custodian.member.pre
        assert root(custodian, h) is not None
        assert root(h.issuees[0], h) is None and root(h.issuees[2], h) is None
