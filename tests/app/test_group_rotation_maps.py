"""Local group authors retain proposed maps without treating them as accepted membership."""

import pytest

from keri import Vrsn_1_0, Vrsn_2_0
from keri.cli.commands.multisig.rotate import GroupMultisigRotate
from keri.core import SerderKERI, eventing
from keri.kering import Kinds, ValidationError
from tests.app.test_group_persistence import openPersistentHabery


@pytest.mark.parametrize('version', [Vrsn_1_0, Vrsn_2_0])
@pytest.mark.parametrize('author', ['hab', 'cli'])
def test_local_author_membership_replacement_survives_reopen(tmp_path, version, author):
    """Author a real dual-index 2-of-3 replacement and reload its exact signing/rotation maps."""
    with openPersistentHabery(tmp_path) as hby:
        people = [hby.makeHab(name=f'member-{index}', version=version) for index in range(4)]
        original = [person.pre for person in people[:3]]
        group = hby.makeGroupHab(group='group', mhab=people[0], smids=original,
                                isith='2', nsith='2', version=version)
        inception = SerderKERI(raw=group.msgOwnInception(
            allowPartiallySigned=True, gvrsn=version))
        hby.kvy.processEvent(serder=inception, sigers=[
            people[index].sign(inception.raw, indices=[index])[0] for index in (0, 1)])
        for person in people[:2]:
            person.rotate(version=version, gvrsn=version)
        proposed = [people[1].pre, people[0].pre, people[3].pre]
        # Distinct next-member order proves rmids is not reconstructed from smids.
        rotating = [people[3].pre, people[0].pre, people[1].pre]
        verfers = [hby.kevers[aid].verfers[0] for aid in proposed]
        digers = [hby.kevers[aid].ndigers[0] for aid in rotating]
        rotation = eventing.rotate(pre=group.pre, dig=group.kever.serder.said,
            sn=1, keys=[key.qb64 for key in verfers], ndigs=[key.qb64 for key in digers],
            isith='2', nsith='2', kind=Kinds.json, version=version)
        with pytest.raises(ValidationError, match='unable to satisfy prior next'):
            group.rotate(smids=proposed, rmids=rotating,
                verfers=[people[3].kever.verfers[0]], digers=digers,
                isith='1', nsith='2', version=version, gvrsn=version)
        assert group.smids == original and group.rmids == original
        assert hby.db.habs.get((group.pre,)).smids == original
        if author == 'hab':
            message = group.rotate(smids=proposed, rmids=rotating, verfers=verfers,
                digers=digers, isith='2', nsith='2', version=version, gvrsn=version)
            assert SerderKERI(raw=message).raw == rotation.raw
        else:
            command = GroupMultisigRotate(hby, 'group', smids=proposed, rmids=rotating,
                                           isith='2', nsith='2', version=version)
            work = command.rotateDo(tymth=lambda: 0.0)
            try:
                next(work)
                next(work)  # actual CLI authors its partial rotation and waits for quorum
            finally:
                work.close()
                command.mux.notifier.noter.close(clear=True)
            assert hby.db.evts.get((group.pre, rotation.said)).raw == rotation.raw
        assert group.kever.lastEst.s == 0
        assert group.smids == proposed and group.rmids == rotating
        record = hby.db.habs.get((group.pre,))
        assert record.smids == proposed and record.rmids == rotating
        # Both retained members change signing index relative to the prior next-key list.
        first = hby.db.sigs.get((group.pre, rotation.said))[0]
        second = people[1].sign(rotation.raw, indices=[0], ondices=[1])[0]
        assert (first.index, first.ondex) == (1, 0)
        assert (second.index, second.ondex) == (0, 1)
        hby.kvy.processEvent(serder=rotation, sigers=[first, second])
        assert group.kever.lastEst.d == rotation.said
        pre = group.pre
    with openPersistentHabery(tmp_path) as reopened:
        loaded = reopened.habByName('group')
        assert loaded.pre == pre and loaded.kever.lastEst.d == rotation.said
        assert loaded.smids == proposed and loaded.rmids == rotating
        assert loaded.mhab.pre == people[0].pre


@pytest.mark.parametrize('version', [Vrsn_1_0, Vrsn_2_0])
@pytest.mark.parametrize('supplied', [False, True])
def test_none_member_maps_preserve_existing_lists(tmp_path, version, supplied):
    """Both authoring and supplied-event paths preserve member maps when passed None."""
    with openPersistentHabery(tmp_path) as hby:
        member = hby.makeHab(name='member', version=version)
        members = [member.pre]
        group = hby.makeGroupHab(group='group', mhab=member, smids=members,
                                isith='1', nsith='1', DnD=True, version=version)
        member.rotate(version=version, gvrsn=version)
        rotation = eventing.rotate(pre=group.pre, dig=group.kever.serder.said, sn=1,
            keys=[member.kever.verfers[0].qb64], ndigs=[member.kever.ndigers[0].qb64],
            isith='1', nsith='1', kind=Kinds.json, version=version)
        if supplied:
            group.rotate(serder=rotation, smids=None, rmids=None, gvrsn=version)
        else:
            group.rotate(verfers=member.kever.verfers, digers=member.kever.ndigers,
                         smids=None, rmids=None, version=version, gvrsn=version)
        assert group.kever.lastEst.d == rotation.said
        assert group.smids == members and group.rmids == members
        record = hby.db.habs.get((group.pre,))
        assert record.smids == members and record.rmids == members
