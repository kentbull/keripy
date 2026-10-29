"""Complete the asymmetric individual/group registry-salt agreement boundaries."""

from types import SimpleNamespace

import pytest

from keri import Vrsn_2_0
from keri.acdc import Registrar
from keri.acdc.messaging import blindate
from keri.acdc.regeventing import Rever, vetBlind
from keri.app import GroupHab, registry_salts
from keri.app.essring import EssrReplyHandler
from keri.app.registry_salt_replies import PROVISION_ROUTE, RECEIPT_ROUTE
from keri.core import Diger, eventing, messagize
from keri.kering import Kinds
from keri.peer import Exchanger
from tests.app.test_acdc_v2_wallet import anchored
from tests.app.test_registry_salt_group_lifecycle import provision, quorum
from tests.app.test_registry_salt_service import groupServiceNetwork


def approve(case, team, leader, body):
    """Authenticate an exact statement through real group quorum or its individual owner."""
    if body.pre == team.gid:
        quorum(case, team, body)
    else:
        outgoing = leader.service.approveReply(body)
        for node in case.nodes:
            node.service.receive(outgoing.stream)


def acceptUpdate(case, issuer, event):
    """Accept the exact private-state commitment under the actual issuer's KEL threshold."""
    head = issuer.kever
    anchor = eventing.interact(pre=issuer.pre, dig=head.serder.said, sn=head.sn + 1,
        data=[dict(i=case.registry, s=event.sad['n'], d=event.said)], version=Vrsn_2_0, kind=Kinds.json)
    signatures = ([group.sign(anchor.raw)[0] for group in case.groups[:2]]
                  if isinstance(issuer, GroupHab) else issuer.sign(anchor.raw))
    stream = messagize(anchor, sigers=signatures, gvrsn=Vrsn_2_0)
    for service in case.services:
        service.parser.parse(ims=bytearray(stream), local=True)
        Rever(db=service.hby.db, reger=service.rgy.baser).processEvent(event)
        assert service.rgy.store.seqEvent(case.registry, event.sn).said == event.said


@pytest.mark.parametrize('groupedParty,initiator', [
    ('issuer', 'discloser'), ('discloser', 'issuer'), ('discloser', 'discloser')])
def test_mixed_parties_confirm_replicate_and_open_same_history(tmp_path, monkeypatch, groupedParty, initiator):
    """Complete the three missing mixed directions with rootless cosigners and sealed member delivery."""
    with groupServiceNetwork(tmp_path) as case:
        case.nodes = [SimpleNamespace(service=service, person=person, parser=service.parser, active=True)
                      for service, person in zip(case.services, case.habs)]
        team = SimpleNamespace(gid=case.groups[0].pre, nodes=case.nodes[:3])
        single = case.habs[3]
        for node in case.nodes:
            exc = node.parser.exc
            if exc is None:
                exc = Exchanger(node.service.hby, handlers=[])
                node.service.exc = node.parser.exc = exc
            exc.addHandler(EssrReplyHandler(node.service.hby, node.person, node.parser,
                                            (PROVISION_ROUTE, RECEIPT_ROUTE)))
        parties = {groupedParty: case.groups[0],
                   'discloser' if groupedParty == 'issuer' else 'issuer': single}
        leaders = {party: case.nodes[0] if isinstance(hab, GroupHab) else case.nodes[3]
                   for party, hab in parties.items()}
        issuer, discloser = parties['issuer'], parties['discloser']
        if groupedParty == 'discloser':
            registry = Registrar(rgy=case.rgys[3]).makeRegistry('single-issuer', single.pre)
            case.rip = case.rgys[3].store.event(registry.regk)
            anchored(single, registry, case.rip)
            for service in case.services[:3]:
                service.parser.parse(ims=single.replay(gvrsn=Vrsn_2_0), local=False)
                Rever(db=service.hby.db, reger=service.rgy.baser).processEvent(case.rip)
                assert service.rgy.store.seqEvent(case.rip.said, 0).said == case.rip.said
        case.registry = case.rip.said
        first = leaders[initiator]
        other = leaders['discloser' if initiator == 'issuer' else 'issuer']
        init = first.service.prepareInit(issuer=issuer.pre, discloser=discloser.pre,
            party=parties[initiator].pre, representative=first.person.pre)
        approve(case, team, first, init)
        bind = other.service.prepareBind(init.said, case.registry, other.person.pre)
        approve(case, team, other, bind)
        source = leaders['issuer']
        confirm = source.service.prepareConfirm(init.said, bind.said)
        approve(case, team, source, confirm)
        assert all(node.service.custody.db.custody.get((case.registry,)) is None for node in team.nodes[1:])
        monkeypatch.setattr(registry_salts, 'generateKeypair',
                            lambda: pytest.fail('existing agreement must not restart DH'))
        origin = source.service.state.origin(case.registry)
        assert (origin.init, origin.bind, origin.confirm, origin.discloser) == (
            init.said, bind.said, confirm.said, discloser.pre)
        credential = Diger(ser=b'mixed-party private credential').qb64
        opening = source.service.custody.derive(case.registry, 1, credential, 'issued')
        historical = blindate(case.registry, case.rip.said, opening.said, sn=1)
        acceptUpdate(case, issuer, historical)
        for target in team.nodes[1:]:
            provision(case, source, SimpleNamespace(gid=issuer.pre), target, team)
        for node in case.nodes:
            assert node.service.state.origin(case.registry) == origin
            old = node.service.custody.derive(case.registry, 1, credential, 'issued')
            assert old.qb64 == opening.qb64
            assert vetBlind(old, blid=historical.sad['b']) == (credential, 'issued')
        future = source.service.custody.derive(case.registry, 2, credential, 'revoked')
        update = blindate(case.registry, historical.said, future.said, sn=2)
        acceptUpdate(case, issuer, update)
        for node in case.nodes:
            current = node.service.custody.derive(case.registry, 2, credential, 'revoked')
            assert current.qb64 == future.qb64
            assert vetBlind(current, blid=update.sad['b']) == (credential, 'revoked')
            assert node.service.state.origin(case.registry) == origin
