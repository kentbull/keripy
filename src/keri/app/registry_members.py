"""Accepted local roster snapshots for experimental registry-salt custody.

The accepted KEL establishment event fixes the group's ordered signing keys.
KERI's group convention associates each key with a member's historical first
key (GroupHab.sign and Kever.fetchLatestContribTo). It does not uniquely prove
the member AID: the ordered AID mapping here MUST come from trusted local
configuration, never arbitrary remote claims. HabitatRecord.smids may describe
a pending rotation, so db.signingMembers is not an accepted-roster authority.

These passive helpers create no stores or membership protocol. Callers persist
the plain dataclass snapshot and retain responsibility for its local provenance.
Rotation-only members are outside this signing-key roster. Quorum signers do
not limit it: every mapped accepted signing key is included.
"""

from dataclasses import dataclass

from ..core.coring import MtrDex
from ..core.signing import Encrypter
from ..kering import ValidationError


@dataclass(frozen=True)
class Member:
    """Local AID mapping at group index, bound to an accepted member event."""

    aid: str
    index: int
    sn: int
    digest: str


@dataclass(frozen=True)
class AcceptedRoster:
    """Immutable accepted group coordinate and ordered local member snapshots."""

    group: str
    sn: int
    digest: str
    members: tuple[Member, ...]


def _event(hby, aid, sn, digest):
    """Return an exact canonical accepted establishment event or fail closed."""
    if not isinstance(digest, str) or hby.db.kels.getLast(keys=aid, on=sn) != digest:
        raise ValidationError('registry roster event is not canonical accepted history')
    event = hby.db.evts.get(keys=(aid, digest))
    if (event is None or not event.estive or event.pre != aid
            or event.sn != sn or event.said != digest):
        raise ValidationError('registry roster establishment history is missing or inconsistent')
    return event


def _latest(hby, aid):
    """Resolve a known AID's current accepted establishment coordinate and body."""
    kever = hby.kevers.get(aid)
    if kever is None:
        raise ValidationError('registry roster requires known accepted key state')
    return _event(hby, aid, kever.lastEst.s, kever.lastEst.d)


def acceptedRoster(hby, group, smids):
    """Resolve accepted signing membership from an explicitly trusted local map.

    Parameters:
        hby: caller-owned Habery holding verified KEL state and event history.
        group (str): accepted group AID.
        smids (list | tuple): trusted local ordered signing-member AIDs, one
            per accepted group key. Never pass untrusted remote AID claims.
    Returns:
        AcceptedRoster: group establishment coordinate and historical member
        contributions, suitable for plain dataclasses.asdict serialization.
    Raises:
        ValidationError: mapping is duplicate, ambiguous, inconsistent, missing
        accepted history, or the group establishment changes during resolution.

    Successful resolution validates the supplied map against keys; it does not
    prove a unique protocol-level AID identity for any contributed public key.
    """
    event = _latest(hby, group)
    if (not isinstance(smids, (list, tuple)) or not smids
            or any(not isinstance(aid, str) for aid in smids)
            or len(set(smids)) != len(smids)):
        raise ValidationError('registry roster requires unique ordered member AIDs')
    keys = event.verfers
    if len(smids) != len(keys) or len({key.qb64 for key in keys}) != len(keys):
        raise ValidationError('registry roster requires one unique member per unique group key')
    members = []
    for index, (aid, key) in enumerate(zip(smids, keys)):
        kever = hby.kevers.get(aid)
        if kever is None or (found := kever.fetchLatestContribTo(verfers=[key])) is None:
            raise ValidationError('registry roster member contribution is unavailable')
        sn, offset, contributed = found
        digest = hby.db.kels.getLast(keys=aid, on=sn)
        memberEvent = _event(hby, aid, sn, digest)
        if (offset != 0 or len(memberEvent.verfers) != 1
                or contributed.qb64 != key.qb64 or memberEvent.verfers[0].qb64 != key.qb64):
            raise ValidationError('registry roster member does not match its ordered group key')
        members.append(Member(aid=aid, index=index, sn=sn, digest=digest))
    current = _latest(hby, group)
    if (current.sn, current.said) != (event.sn, event.said):
        raise ValidationError('registry roster group establishment changed during resolution')
    return AcceptedRoster(group=group, sn=event.sn, digest=event.said, members=tuple(members))


def currentRecipientKey(hby, roster, member):
    """Return the current accepted member event and its X25519 Encrypter.

    Parameters:
        hby: caller-owned Habery holding verified KEL state and event history.
        roster (AcceptedRoster): trusted locally persisted accepted snapshot.
        member (Member): exact member record present in that snapshot.
    Returns:
        tuple: canonical current member establishment SerderKERI and Encrypter,
        retaining the key's coordinates for the caller's provisioning reply.
    Raises:
        ValidationError: snapshot is stale or inconsistent, member is absent,
        accepted evidence is missing, or current key is not one Ed25519 key
        convertible by the existing Encrypter primitive.

    An independent member rotation may update the encryption target while its
    historical contribution to the unchanged group roster remains accepted.
    """
    if not isinstance(roster, AcceptedRoster) or not isinstance(member, Member):
        raise ValidationError('registry recipient requires an accepted roster and member')
    if member not in roster.members:
        raise ValidationError('registry recipient is not an exact roster member')
    resolved = acceptedRoster(hby, roster.group, tuple(item.aid for item in roster.members))
    if resolved != roster:
        raise ValidationError('registry recipient roster is stale or inconsistent')
    event = _latest(hby, member.aid)
    if len(event.verfers) != 1 or event.verfers[0].code not in (MtrDex.Ed25519, MtrDex.Ed25519N):
        raise ValidationError('registry recipient requires a single accepted Ed25519 key')
    try:
        encrypter = Encrypter(verkey=event.verfers[0].qb64)
    except ValueError:
        raise ValidationError('registry recipient key cannot be converted for encryption') from None
    current = _latest(hby, member.aid)
    groupEvent = _latest(hby, roster.group)
    if ((current.sn, current.said) != (event.sn, event.said)
            or (groupEvent.sn, groupEvent.said) != (roster.sn, roster.digest)):
        raise ValidationError('registry recipient accepted establishment changed during resolution')
    return event, encrypter
