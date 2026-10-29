"""Fresh and retired local group members verify genuine remote quorum evidence."""
from contextlib import ExitStack, contextmanager
from types import SimpleNamespace

import pytest

from keri import Vrsn_1_0, Vrsn_2_0
from keri.app import openHby
from keri.kering import Kinds
from keri.core import Parser, SerderKERI, eventing, messagize


@contextmanager
def members(version, mode='native'):
    """Create four independent one-key members and an actual two-of-three group."""
    with ExitStack() as stack:
        hbys = [stack.enter_context(openHby(name=f'group-local-{n}', temp=True, version=version))
                for n in range(4)]
        people = [hby.makeHab(name='member', version=version) for hby in hbys]
        for hby in hbys:
            for person in people:
                if person.pre not in hby.prefixes:
                    Parser(kvy=hby.kvy, version=version).parse(
                        ims=bytearray(person.replay(gvrsn=version)), local=False)
        mids = [person.pre for person in people[:3]]
        groups = [hby.makeGroupHab(group='group', mhab=person, smids=mids,
                    isith='2', nsith='2', version=version)
                  for hby, person in zip(hbys[:2], people[:2])]
        icp = SerderKERI(raw=groups[0].msgOwnInception(allowPartiallySigned=True, gvrsn=version))
        if mode.startswith('join'):
            signed = [group.sign(icp.raw, verfers=icp.verfers)[0] for group in groups]
            Parser(kvy=hbys[2].kvy, version=version).parse(
                ims=bytearray(messagize(icp, sigers=signed, gvrsn=version)), local=False)
            join = hbys[2].joinSignifyGroupHab if mode == 'join-signify' else hbys[2].joinGroupHab
            third = join(icp.pre, **({'name': 'group'} if mode == 'join-signify' else {'group': 'group'}),
                         mhab=people[2], smids=mids)
        elif mode == 'signify':
            signature = people[2].sign(icp.raw, indices=[2], ondices=[None])
            third = hbys[2].makeSignifyGroupHab(name='group', mhab=people[2], smids=mids,
                                               serder=icp, sigers=signature)
        else:
            third = hbys[2].makeGroupHab(group='group', mhab=people[2], smids=mids,
                                        isith='2', nsith='2', version=version)
        groups.append(third)
        assert all(group.pre in group.db.groups for group in groups)
        # Accept two independently signed foreign contributions on each member.
        for index, hby in enumerate(hbys[:3]):
            signatures = [people[n].sign(icp.raw, indices=[n], ondices=[None])[0]
                          for n in range(3) if n != index]
            Parser(kvy=hby.kvy, version=version).parse(
                ims=bytearray(messagize(icp, sigers=signatures, gvrsn=version)), local=False)
            assert hby.kevers[icp.pre].serder.said == icp.said
        yield SimpleNamespace(hbys=hbys, people=people, groups=groups, icp=icp)


@pytest.mark.parametrize('version', [Vrsn_1_0, Vrsn_2_0])
@pytest.mark.parametrize('mode', ['native', 'signify', 'join-native', 'join-signify'])
def test_fresh_group_accepts_other_members_threshold(version, mode):
    """Group classification is correct before reload; local keys cannot be injected remotely."""
    with members(version, mode) as case:
        target = case.hbys[2]
        group = case.groups[2]
        assert group.kever.locallyMembered() and not group.kever.locallyOwned()
        first = eventing.interact(pre=group.pre, dig=case.icp.said, sn=1, version=version, kind=Kinds.json)
        signatures = [peer.sign(first.raw)[0] for peer in case.groups[:2]]
        parser = Parser(kvy=target.kvy, version=version)
        parser.parse(ims=bytearray(messagize(first, sigers=signatures, gvrsn=version)), local=False)
        assert group.kever.serder.said == first.said
        assert not list(target.db.misfits.getTopItemIter(keys=group.pre))

        hostile = eventing.interact(pre=group.pre, dig=first.said, sn=2, version=version, kind=Kinds.json)
        # A single other member cannot meet threshold. Adding a remotely
        # supplied signature from this local member must still not count.
        for signatures in ([case.groups[0].sign(hostile.raw)[0]],
                           [case.groups[0].sign(hostile.raw)[0],
                            case.people[2].sign(hostile.raw, indices=[2], ondices=[None])[0]]):
            parser.parse(ims=bytearray(messagize(hostile, sigers=signatures, gvrsn=version)), local=False)
            assert group.kever.serder.said == first.said


@pytest.mark.parametrize('version', [Vrsn_1_0, Vrsn_2_0])
def test_retired_member_accepts_replacement_without_local_signature(version):
    """The retired key contributes no index; both current and prior thresholds remain required."""
    with members(version) as case:
        for index in (1, 2):
            stream = case.people[index].rotate(version=version, gvrsn=version)
            for other, hby in enumerate(case.hbys[:3]):
                if other != index:
                    Parser(kvy=hby.kvy, version=version).parse(ims=bytearray(stream), local=False)
        target, group = case.hbys[0], case.groups[0]
        new = case.people[1:]
        rotation = eventing.rotate(pre=group.pre, dig=case.icp.said, sn=1,
            keys=[person.kever.verfers[0].qb64 for person in new],
            ndigs=[person.kever.ndigers[0].qb64 for person in new],
            isith='2', nsith='2', version=version, kind=Kinds.json)
        assert group.kever.locallyContributedIndices(rotation.verfers) == []
        parser = Parser(kvy=target.kvy, version=version)
        old = case.groups[1].sign(rotation.raw, verfers=rotation.verfers, rotated=True)[0]
        newcomer = case.people[3].sign(rotation.raw, indices=[2], ondices=[None])[0]
        # Two current keys, but only one exposes a prior commitment.
        parser.parse(ims=bytearray(messagize(rotation, sigers=[old, newcomer], gvrsn=version)), local=False)
        assert group.kever.serder.said == case.icp.said
        second = case.groups[2].sign(rotation.raw, verfers=rotation.verfers, rotated=True)[0]
        parser.parse(ims=bytearray(messagize(rotation, sigers=[old, second], gvrsn=version)), local=False)
        assert group.kever.serder.said == rotation.said
        assert group.kever.locallyContributedIndices(rotation.verfers) == []
        with pytest.raises(ValueError, match='not a participant'):
            group.sign(rotation.raw, verfers=rotation.verfers)


@pytest.mark.parametrize('version', [Vrsn_1_0, Vrsn_2_0])
def test_personal_rotation_preserves_protection_of_historical_group_key(version):
    """A remote old local-key signature cannot count while the group still uses it."""
    with members(version) as case:
        group, target = case.groups[2], case.hbys[2]
        local = case.people[2]
        old = local.kever.verfers[0]
        local.rotate(version=version, gvrsn=version)
        assert local.kever.verfers[0].qb64 != old.qb64
        assert group.kever.locallyContributedIndices(group.kever.verfers) == [2]
        update = eventing.interact(pre=group.pre, dig=case.icp.said, sn=1,
                                   version=version, kind=Kinds.json)
        foreign = case.groups[0].sign(update.raw)[0]
        historical = local.sign(update.raw, verfers=[old], indices=[2], ondices=[None])[0]
        parser = Parser(kvy=target.kvy, version=version)
        parser.parse(ims=bytearray(messagize(update, sigers=[foreign, historical], gvrsn=version)), local=False)
        assert group.kever.sn == 0
        second = case.groups[1].sign(update.raw)[0]
        parser.parse(ims=bytearray(messagize(update, sigers=[foreign, second], gvrsn=version)), local=False)
        assert group.kever.serder.said == update.said
