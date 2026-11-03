"""Group coordination follows contributed keys, not each member's latest key."""

import pytest

from keri import Vrsn_2_0, Kinds
from keri.app import Counselor, openHby
from keri.core import Diger, MtrDex, Number, SerderKERI, Siger, Signer, exchange
from keri.core import eventing
from keri.peer import Exchanger


def member_signature(member, event, index, ondex=None):
    return member.sign(ser=event.raw, indexed=True, indices=[index], ondices=[ondex])[0]


def accept_group_rotation(hby, group, members, order=None):
    order = list(range(len(members))) if order is None else order
    verfers = [members[index].kever.verfers[0] for index in order]
    digers = [members[index].kever.ndigers[0] for index in order]
    prior_digers = [diger.qb64 for diger in group.kever.ndigers]
    local = members.index(group.mhab)
    other = next(index for index in order if index != local)
    own_index, other_index = order.index(local), order.index(other)
    own_prior = prior_digers.index(Diger(ser=verfers[own_index].qb64b).qb64)
    other_prior = prior_digers.index(Diger(ser=verfers[other_index].qb64b).qb64)
    msg = group.rotate(verfers=verfers, digers=digers, isith='2', nsith='2',
                       version=Vrsn_2_0, kind=Kinds.json, framed=True, gvrsn=Vrsn_2_0)
    event = SerderKERI(raw=msg)
    hby.kvy.processEvent(serder=event, local=True,
                         sigers=[member_signature(members[local], event, own_index, own_prior),
                                 member_signature(members[other], event, other_index, other_prior)])
    assert group.accepted and group.kever.serder.said == event.said
    return event


@pytest.fixture(params=[0, 1], ids=['lowest-zero', 'lowest-one'])
def contributed_group(request):
    with openHby(name='historical-contribution', temp=True, version=Vrsn_2_0) as hby:
        members = [hby.makeHab(name=f'member-{index}', version=Vrsn_2_0, kind=Kinds.json)
                   for index in range(3)]
        witness = hby.makeHab(name='witness', transferable=False,
                              version=Vrsn_2_0, kind=Kinds.json)
        local = request.param
        group = hby.makeGroupHab(group='group', mhab=members[local],
                                  smids=[member.pre for member in members],
                                  isith='2', nsith='2', wits=[witness.pre], toad=1,
                                  version=Vrsn_2_0, kind=Kinds.json)
        inception = hby.db.evts.get((group.pre, group.pre))
        assert inception is not None
        hby.kvy.processEvent(serder=inception, local=True,
                             sigers=[member_signature(members[index], inception, index, index)
                                     for index in (local, local + 1)])
        assert group.accepted
        for member in members:
            member.rotate(version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
        # Choose the local member and a higher index as the actual rotation signers.
        verfers = [member.kever.verfers[0] for member in members]
        digers = [member.kever.ndigers[0] for member in members]
        rotation = SerderKERI(raw=group.rotate(
            verfers=verfers, digers=digers, isith='2', nsith='2',
            version=Vrsn_2_0, kind=Kinds.json, framed=True, gvrsn=Vrsn_2_0))
        hby.kvy.processEvent(serder=rotation, local=True,
                             sigers=[member_signature(members[index], rotation, index, index)
                                     for index in (local, local + 1)])
        assert group.kever.sn == 1 and group.witnesser()
        yield hby, group, members, local


def test_group_witnesser_uses_historical_contribution(contributed_group):
    _, group, members, local = contributed_group
    members[local].rotate(version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
    signature = group.sign(ser=b'group payload')[0]
    assert signature.index == local
    assert group.kever.verfers[local].verify(signature.raw, b'group payload')
    assert group.witnesser() is True
    assert group.witnesser(sn=0, dig=group.kever.serder.said) is False
    assert group.witnesser(sn=1, dig=Diger(ser=b'wrong event digest').qb64) is False


def test_group_witnesser_resolves_establishment_for_interaction(contributed_group):
    hby, group, members, local = contributed_group
    event = SerderKERI(raw=group.interact(data=[], version=Vrsn_2_0, kind=Kinds.json,
                                         framed=True, gvrsn=Vrsn_2_0))
    hby.kvy.processEvent(serder=event, local=True,
                         sigers=[member_signature(members[index], event, index)
                                 for index in (local, local + 1)])
    members[local].rotate(version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
    assert group.kever.sn == 2
    assert group.witnesser() is True


@pytest.mark.parametrize('stage', ['signed', 'witness'])
def test_counselor_keeps_historical_elected_member(contributed_group, stage):
    hby, group, members, local = contributed_group
    members[local].rotate(version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
    counselor = Counselor(hby=hby, version=Vrsn_2_0, kind=Kinds.json)
    number, diger = Number(num=group.kever.sn), Diger(qb64=group.kever.serder.said)
    if stage == 'signed':
        counselor.start(ghab=group, prefixer=group.kever.prefixer, number=number, diger=diger)
        counselor.processPartialSignedEscrow()
        assert list(counselor.witDoer.msgs) == [dict(pre=group.pre, sn=number.sn)]
    else:
        hby.db.gpwe.add(keys=(group.pre,), val=(number, diger))
        counselor.processPartialWitnessEscrow()
        assert list(counselor.witDoer.gets) == []
        assert not counselor.complete(group.kever.prefixer, number, diger)


@pytest.mark.parametrize('stage', ['signed', 'witness'])
def test_counselor_election_uses_escrow_event_after_later_rotation(contributed_group, stage):
    hby, group, members, local = contributed_group
    number, diger = Number(num=group.kever.sn), Diger(qb64=group.kever.serder.said)
    for member in members:
        member.rotate(version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
    accept_group_rotation(hby, group, members,
                          order=[(local + 1) % 3, local, (local + 2) % 3])
    assert group.kever.sn == 2
    assert group.witnesser() is False  # Another member leads the newer event.
    counselor = Counselor(hby=hby, version=Vrsn_2_0, kind=Kinds.json)
    if stage == 'signed':
        counselor.start(ghab=group, prefixer=group.kever.prefixer, number=number, diger=diger)
        counselor.processPartialSignedEscrow()
        assert list(counselor.witDoer.msgs) == [dict(pre=group.pre, sn=number.sn)]
    else:
        hby.db.gpwe.add(keys=(group.pre,), val=(number, diger))
        counselor.processPartialWitnessEscrow()
        assert list(counselor.witDoer.gets) == []


class LeadHandler:
    resource = '/test/historical-lead'

    def verify(self, serder, **kwa):
        return True

    def verifyEvidence(self, serder, *, tsgs, cigars, sourceSeals, invalid):
        return tsgs, cigars, sourceSeals

    def handle(self, serder, **kwa):
        pass


def accepted_exchange(hby, group, members, local, extra=False):
    event = exchange(sender=group.pre, route=LeadHandler.resource,
                     attributes={}, version=Vrsn_2_0, kind=Kinds.json)
    sigers = [member_signature(members[index], event, index) for index in (local, local + 1)]
    groups = [(group.kever.prefixer, Number(sn=group.kever.lastEst.s),
               Diger(qb64=group.kever.lastEst.d), sigers)]
    if extra:
        endorser = hby.makeHab(name='extra', code=MtrDex.Ed25519,
                               version=Vrsn_2_0, kind=Kinds.json)
        assert endorser.pre < group.pre  # Its verified TSG sorts before the sender's.
        groups.append((endorser.kever.prefixer, Number(sn=0),
                       Diger(qb64=endorser.kever.serder.said),
                       endorser.sign(ser=event.raw)))
    exc = Exchanger(hby=hby, handlers=[LeadHandler()])
    assert exc.processEvent(event, tsgs=groups) is True
    return exc, event


def test_exchange_lead_uses_historical_member_contribution(contributed_group):
    hby, group, members, local = contributed_group
    exc, event = accepted_exchange(hby, group, members, local)
    members[local].rotate(version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
    assert exc.lead(group, event.said) is True


def test_exchange_lead_uses_sender_authentication_not_first_endorser(contributed_group):
    hby, group, members, local = contributed_group
    exc, event = accepted_exchange(hby, group, members, local, extra=True)
    assert exc.lead(group, event.said) is True


def test_exchange_lead_uses_signature_establishment_after_group_rotation(contributed_group):
    hby, group, members, local = contributed_group
    exc, event = accepted_exchange(hby, group, members, local)
    for member in members:
        member.rotate(version=Vrsn_2_0, kind=Kinds.json, gvrsn=Vrsn_2_0)
    accept_group_rotation(hby, group, members, order=[local, (local + 1) % 3, (local + 2) % 3])
    assert group.kever.sn == 2
    assert exc.lead(group, event.said) is True


def test_exchange_lead_counts_only_verified_signature_indices(contributed_group):
    hby, group, members, local = contributed_group
    exc, event = accepted_exchange(hby, group, members, local)
    # A stored invalid lower-index signature must not change the elected signer.
    forged = Siger(raw=member_signature(members[local + 1], event, local + 1).raw, index=0)
    hby.db.esigs.add((event.said, group.pre, f'{group.kever.lastEst.s:032x}',
                     group.kever.lastEst.d), forged)
    assert exc.lead(group, event.said) is True


def test_exchange_lead_cannot_use_another_sender_for_this_group(contributed_group):
    hby, group, _, _ = contributed_group
    other = hby.makeHab(name='other-sender', version=Vrsn_2_0, kind=Kinds.json)
    event = exchange(sender=other.pre, route=LeadHandler.resource, attributes={},
                     version=Vrsn_2_0, kind=Kinds.json)
    exc = Exchanger(hby=hby, handlers=[LeadHandler()])
    assert exc.processEvent(event, tsgs=[(other.kever.prefixer, Number(num=0),
                                         Diger(qb64=other.kever.serder.said),
                                         other.sign(ser=event.raw))]) is True
    assert exc.lead(group, event.said) is False


@pytest.fixture(params=[0, 1], ids=['elected-member', 'other-member'])
def external_group(request):
    with openHby(name='external-contribution', temp=True, version=Vrsn_2_0) as hby:
        signers = [Signer(raw=bytes([index + 1]) * 32) for index in range(2)]
        next_signers = [Signer(raw=bytes([index + 3]) * 32) for index in range(2)]
        members = []
        for index, signer in enumerate(signers):
            inception = eventing.incept(keys=[signer.verfer.qb64], isith='1', nsith='1',
                                        ndigs=[Diger(ser=next_signers[index].verfer.qb64b).qb64],
                                        code=MtrDex.Blake3_256, version=Vrsn_2_0)
            members.append(hby.makeSignifyHab(
                name=f'external-{index}', serder=inception,
                sigers=[signer.sign(ser=inception.raw, index=0)]))
        inception = eventing.incept(keys=[signer.verfer.qb64 for signer in signers],
                                    isith='1', nsith='1', code=MtrDex.Blake3_256,
                                    ndigs=[Diger(ser=signer.verfer.qb64b).qb64
                                           for signer in next_signers], version=Vrsn_2_0)
        group = hby.makeSignifyGroupHab(
            name='external-group', mhab=members[request.param],
            smids=[member.pre for member in members],
            serder=inception, sigers=[signers[0].sign(ser=inception.raw, index=0)])
        local = members[request.param]
        rotation = eventing.rotate(pre=local.pre, dig=local.kever.serder.said,
                                   keys=[next_signers[request.param].verfer.qb64], sn=1,
                                   isith='1', nsith='0', ndigs=[], version=Vrsn_2_0)
        local.rotate(serder=rotation,
                     sigers=[next_signers[request.param].sign(ser=rotation.raw, index=0)])
        assert group.accepted and local.kever.sn == 1
        yield hby, group, signers, request.param == 0


def test_external_group_witnesser_uses_contribution(external_group):
    _, group, _, elected = external_group
    assert group.witnesser() is elected


def test_external_group_exchange_lead_is_not_automatically_personal(external_group):
    hby, group, signers, elected = external_group
    event = exchange(sender=group.pre, route=LeadHandler.resource, attributes={},
                     version=Vrsn_2_0, kind=Kinds.json)
    exc = Exchanger(hby=hby, handlers=[LeadHandler()])
    assert exc.processEvent(event, tsgs=[(group.kever.prefixer, Number(num=0),
                                         Diger(qb64=group.kever.serder.said),
                                         [signers[0].sign(ser=event.raw, index=0)])]) is True
    assert exc.lead(group, event.said) is elected
