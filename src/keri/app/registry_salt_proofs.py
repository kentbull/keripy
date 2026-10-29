"""Historical signature evidence for exact retained registry-salt replies.

This verifies historical authority, not live request freshness, current roster
entitlement or prior existence of a backdated signature. A signed timestamp
does not prove a reply existed before key compromise. Fresh provisioning by an
authorized current member must attest the retained assignment separately.
No new KEL anchor or timing policy is imposed by this experimental profile.
"""

from ..core import Prefixer
from ..kering import KeriError, MissingEntryError, MissingSignatureError, ValidationError
from ..peer.exchanging import verifyAttachments
from .replying import parseReply


def verifyArchivedReply(hby, parser, stream, expectedRoute, expectedAid):
    """Return the original reply after verifying its historical signing threshold.

    Parameters: hby owns accepted historical KEL evidence; parser is borrowed
        for parse-only extraction; stream is the exact retained signed reply;
        expectedRoute and expectedAid identify its required route and logical
        author, rather than a representative signing on that author's behalf.
    Returns: the original parsed SerderKERI, with its bytes and SAID preserved.
    Raises: MissingEntryError with public establishment coordinates when KEL
        evidence is absent; MissingSignatureError when an explicit historical
        threshold is not satisfied; ValidationError for another author, route,
        malformed frame or a noncanonical establishment reference.
    No reply dispatch, acceptance, escrow, operational cue or KRAM write occurs.
    """
    try:
        prefixer = Prefixer(qb64=expectedAid)
        if (prefixer.qb64 != expectedAid or not isinstance(expectedRoute, str) or
                not expectedRoute.startswith('/')):
            raise ValueError
    except (KeriError, ValueError, TypeError):
        raise ValidationError('Invalid archived reply authority or route') from None
    parsed = parseReply(parser, stream, {expectedRoute})
    serder = parsed.serder
    if serder.pre != expectedAid:
        raise ValidationError('Archived reply has another logical author')

    groups = {}
    if prefixer.transferable:
        if parsed.cigars or not parsed.tsgs:
            raise ValidationError('Archived transferable reply requires explicit establishment signatures')
        for signer, number, diger, sigers in parsed.tsgs:
            if signer.qb64 != expectedAid:
                raise ValidationError('Archived reply signatures have another logical author')
            coordinate = (signer.qb64, number.sn, diger.qb64)
            if coordinate not in groups:
                groups[coordinate] = (signer, number, diger, [])
            groups[coordinate][3].extend(sigers)
        for aid, sn, dig in groups:
            accepted = hby.db.kels.getLast(keys=aid, on=sn)
            if accepted is None or hby.db.evts.get(keys=(aid, accepted)) is None:
                raise MissingEntryError(
                    f'Missing archived reply key event pre={aid} sn={sn:x} dig={dig}')
            if accepted != dig:
                raise ValidationError('Archived reply names a noncanonical key event')
    elif parsed.tsgs or any(cigar.verfer.qb64 != expectedAid for cigar in parsed.cigars):
        raise ValidationError('Archived nontransferable reply requires its own nontransferable signatures')

    tsgs, cigars, _, invalid, missing = verifyAttachments(
        hby, serder, tsgs=list(groups.values()), cigars=parsed.cigars)
    if missing:
        # Preserve coordinates supplied by the sender for the caller's existing
        # key-event query workflow, without creating a scheduler or live escrow.
        coords = ', '.join(f'pre={aid} sn={sn:x} dig={dig}' for aid, sn, dig in groups)
        raise MissingEntryError(f'Missing archived reply key evidence {coords}')
    if invalid or not (tsgs or cigars):
        coords = ', '.join(f'pre={aid} sn={sn:x} dig={dig}' for aid, sn, dig in groups)
        raise MissingSignatureError(f'Archived reply historical threshold not satisfied {coords}')
    return serder
