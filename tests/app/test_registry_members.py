"""Real accepted group/member history bounds local registry-salt recipients."""

from dataclasses import asdict, replace

import pytest

from keri import Vrsn_2_0
from keri.app.registry_members import acceptedRoster, currentRecipientKey
from keri.core import MtrDex, Parser, eventing
from keri.core.signing import Encrypter
from keri.kering import ValidationError
from tests.app.test_acdc_v2_groups import groupMembers


@pytest.fixture
def peers():
    """Yield three independent peers of a real accepted 2-of-3 group."""
    with groupMembers('registry-roster') as result:
        yield result[:2]


def memberAids(groups):
    """Return the fixture's explicit trusted local member order."""
    return [group.mhab.pre for group in groups]


def rotateMembers(hbys, groups):
    """Accept each member's independent rotation in every peer's local KEL."""
    messages = [group.mhab.rotate(version=Vrsn_2_0, gvrsn=Vrsn_2_0) for group in groups]
    for hby in hbys:
        for message in messages:
            Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(message), local=True)


def groupRotation(hby, group, smids):
    """Build a group rotation using supplied trusted member order and new keys."""
    return eventing.rotate(pre=group.pre, sn=group.kever.sn + 1,
        dig=group.kever.serder.said, isith='2', nsith='2',
        keys=[hby.kevers[aid].verfers[0].qb64 for aid in smids],
        ndigs=[hby.kevers[aid].ndigers[0].qb64 for aid in smids], version=Vrsn_2_0)


def test_complete_roster_and_plain_snapshot(peers):
    """All three accepted members are retained independently of the two-signature quorum."""
    hbys, groups = peers
    smids = memberAids(groups)
    quorum = [hby.makeGroupHab(group='quorum-only', mhab=group.mhab,
        smids=smids, isith='2', nsith='2', DnD=True, version=Vrsn_2_0)
        for hby, group in zip(hbys[:2], groups[:2])]
    for group in quorum:
        message = group.msgOwnInception(allowPartiallySigned=True, gvrsn=Vrsn_2_0)
        Parser(kvy=hbys[0].kvy, version=Vrsn_2_0).parse(ims=bytearray(message), local=True)
    hbys[0].kvy.processEscrows()
    assert quorum[0].accepted
    signatures = hbys[0].db.sigs.get(keys=(quorum[0].pre, quorum[0].kever.lastEst.d))
    assert {signature.index for signature in signatures} == {0, 1}
    roster = acceptedRoster(hbys[0], quorum[0].pre, smids)
    assert roster.sn == 0 and roster.digest == quorum[0].kever.lastEst.d
    assert [member.aid for member in roster.members] == smids
    assert [member.index for member in roster.members] == [0, 1, 2]
    assert all(member.sn == 0 for member in roster.members)
    assert asdict(roster)['members'][2]['aid'] == smids[2]
    event, key = currentRecipientKey(hbys[0], roster, roster.members[2])
    assert event.pre == smids[2] and key.code == 'C'


@pytest.mark.parametrize('case', ['order', 'duplicate', 'count', 'key'])
def test_reject_invalid_trusted_mapping(peers, case):
    """Explicit trust cannot override order, uniqueness, count or key evidence."""
    hbys, groups = peers
    smids = memberAids(groups)
    if case == 'order':
        smids.reverse()
    elif case == 'duplicate':
        smids[1] = smids[0]
    elif case == 'count':
        smids.pop()
    else:
        smids[1] = hbys[0].makeHab(name='outsider').pre
    with pytest.raises(ValidationError):
        acceptedRoster(hbys[0], groups[0].pre, smids)


@pytest.mark.parametrize('target', ['group-event', 'member-event', 'member-canonical'])
def test_missing_accepted_history_fails_closed(peers, target):
    """Cached key state cannot replace a missing event or canonical KEL entry."""
    hbys, groups = peers
    hby, group = hbys[0], groups[0]
    aid = group.pre if target == 'group-event' else groups[1].mhab.pre
    last = hby.kevers[aid].lastEst
    if target == 'member-canonical':
        assert hby.db.kels.rem(keys=aid, on=last.s)
    else:
        assert hby.db.evts.rem(keys=(aid, last.d))
    with pytest.raises(ValidationError):
        acceptedRoster(hby, group.pre, memberAids(groups))


def test_historical_contribution_and_current_encryption_target(peers):
    """Member rotation preserves old roster evidence and selects the new accepted key."""
    hbys, groups = peers
    hby, group = hbys[0], groups[0]
    roster = acceptedRoster(hby, group.pre, memberAids(groups))
    oldEvent, oldKey = currentRecipientKey(hby, roster, roster.members[1])
    rotateMembers(hbys, groups)
    assert acceptedRoster(hby, group.pre, memberAids(groups)) == roster
    event, key = currentRecipientKey(hby, roster, roster.members[1])
    assert event.sn == 1 and event.said != oldEvent.said
    assert key.raw != oldKey.raw
    assert key.qb64 == Encrypter(verkey=groups[1].mhab.kever.verfers[0].qb64).qb64
    assert roster.members[1].sn == 0


def test_pending_group_rotation_is_not_accepted_membership(peers):
    """GroupHab's proposed smids cannot replace the accepted order before quorum."""
    hbys, groups = peers
    hby, group = hbys[0], groups[0]
    smids = memberAids(groups)
    roster = acceptedRoster(hby, group.pre, smids)
    rotateMembers(hbys, groups)
    proposed = list(reversed(smids))
    rotation = groupRotation(hby, group, proposed)
    group.rotate(smids=proposed, rmids=proposed, serder=rotation, gvrsn=Vrsn_2_0)
    assert hby.db.signingMembers(group.pre) == proposed
    assert group.kever.lastEst.s == 0
    assert acceptedRoster(hby, group.pre, smids) == roster
    with pytest.raises(ValidationError):
        acceptedRoster(hby, group.pre, hby.db.signingMembers(group.pre))


def test_accepted_group_rotation_invalidates_snapshot(peers):
    """New accepted group establishment makes its previous recipient roster stale."""
    hbys, groups = peers
    smids = memberAids(groups)
    roster = acceptedRoster(hbys[0], groups[0].pre, smids)
    rotateMembers(hbys, groups)
    rotation = groupRotation(hbys[0], groups[0], smids)
    messages = [group.rotate(smids=smids, rmids=smids, serder=rotation, gvrsn=Vrsn_2_0)
                for group in groups[:2]]
    for message in messages:
        Parser(kvy=hbys[0].kvy, version=Vrsn_2_0).parse(ims=bytearray(message), local=True)
    hbys[0].kvy.processEscrows()
    assert groups[0].kever.lastEst.s == 1
    with pytest.raises(ValidationError, match='stale or inconsistent'):
        currentRecipientKey(hbys[0], roster, roster.members[0])


def test_exact_member_snapshot_required(peers):
    """A matching AID alone cannot authorize an altered member coordinate or index."""
    hbys, groups = peers
    roster = acceptedRoster(hbys[0], groups[0].pre, memberAids(groups))
    for member in (replace(roster.members[0], index=2), replace(roster.members[0], sn=9)):
        with pytest.raises(ValidationError, match='exact roster member'):
            currentRecipientKey(hbys[0], roster, member)
    forged = replace(roster, digest=groups[0].mhab.kever.serder.said)
    with pytest.raises(ValidationError, match='stale or inconsistent'):
        currentRecipientKey(hbys[0], forged, forged.members[0])


def test_rotation_only_candidate_does_not_expand_roster(peers):
    """Rotation-only habitat metadata does not add a current signing recipient."""
    hbys, groups = peers
    hby, group = hbys[0], groups[0]
    extra = hby.makeHab(name='rotation-only')
    record = hby.db.habs.get(keys=group.pre)
    record.rmids.append(extra.pre)
    hby.db.habs.pin(keys=group.pre, val=record)
    roster = acceptedRoster(hby, group.pre, memberAids(groups))
    assert len(roster.members) == 3 and extra.pre not in [member.aid for member in roster.members]


def test_duplicate_group_keys_are_ambiguous(peers):
    """An accepted group with duplicate key slots cannot define this roster."""
    hbys, groups = peers
    smids = memberAids(groups)
    duplicated = [smids[0], smids[0], smids[1]]
    ambiguous = [hby.makeGroupHab(group='duplicate-keys', mhab=group.mhab,
        smids=duplicated, isith='2', nsith='2', version=Vrsn_2_0)
        for hby, group in zip(hbys[:2], groups[:2])]
    for group in ambiguous:
        message = group.msgOwnInception(allowPartiallySigned=True, gvrsn=Vrsn_2_0)
        Parser(kvy=hbys[0].kvy, version=Vrsn_2_0).parse(ims=bytearray(message), local=True)
    hbys[0].kvy.processEscrows()
    assert ambiguous[0].accepted
    with pytest.raises(ValidationError, match='unique group key'):
        acceptedRoster(hbys[0], ambiguous[0].pre, smids)


@pytest.mark.parametrize('mode', ['multiple', 'unsupported'])
def test_current_recipient_requires_single_key_and_present_event(peers, mode):
    """A valid old contribution cannot substitute for unusable current key state."""
    hbys, groups = peers
    hby, group = hbys[0], groups[0]
    roster = acceptedRoster(hby, group.pre, memberAids(groups))
    member = groups[1].mhab
    # First commit the new next key configuration, then accept it as current.
    options = dict(ncount=2) if mode == 'multiple' else dict(ncode=MtrDex.ECDSA_256r1_Seed)
    for _ in range(2):
        message = member.rotate(**options, version=Vrsn_2_0, gvrsn=Vrsn_2_0)
        Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(message), local=True)
    assert (len(hby.kevers[member.pre].verfers) == 2 if mode == 'multiple'
            else hby.kevers[member.pre].verfers[0].code == MtrDex.ECDSA_256r1)
    assert acceptedRoster(hby, group.pre, memberAids(groups)) == roster
    with pytest.raises(ValidationError, match='single accepted Ed25519 key'):
        currentRecipientKey(hby, roster, roster.members[1])
    current = hby.kevers[member.pre].lastEst
    assert hby.db.evts.rem(keys=(member.pre, current.d))
    with pytest.raises(ValidationError, match='missing or inconsistent'):
        currentRecipientKey(hby, roster, roster.members[1])


def test_group_change_during_resolution_fails_closed(peers, monkeypatch):
    """A real accepted group rotation during lookup invalidates its partial result."""
    hbys, groups = peers
    hby, group = hbys[0], groups[0]
    smids = memberAids(groups)
    rotateMembers(hbys, groups)
    rotation = groupRotation(hby, group, smids)
    group.rotate(smids=smids, rmids=smids, serder=rotation, gvrsn=Vrsn_2_0)
    second = groups[1].rotate(smids=smids, rmids=smids, serder=rotation, gvrsn=Vrsn_2_0)
    assert group.kever.lastEst.s == 0
    kever = hby.kevers[smids[0]]
    original = kever.fetchLatestContribTo

    def acceptDuringLookup(verfers):
        """Finish the prepared real quorum after reading the first old contribution."""
        found = original(verfers=verfers)
        Parser(kvy=hby.kvy, version=Vrsn_2_0).parse(ims=bytearray(second), local=True)
        hby.kvy.processEscrows()
        assert group.kever.lastEst.s == 1
        return found

    monkeypatch.setattr(kever, 'fetchLatestContribTo', acceptDuringLookup)
    with pytest.raises(ValidationError, match='changed during resolution'):
        acceptedRoster(hby, group.pre, smids)
