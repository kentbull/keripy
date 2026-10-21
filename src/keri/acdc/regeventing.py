# -*- encoding: utf-8 -*-
"""
keri.acdc.regeventing module

Registry (TEL) event support

Shared TEL support for ACDC v2 state registries made of 'rip' (inception),
'bup' (blinded update), and 'upd' (public update) events.

This module now holds three closely related concerns:

1. Verifier-side evidence vetting through vet() and the vet* helpers. Given a
   supplied registry event chain, the issuer's KEL evidence, and optionally a
   disclosed blinded-state block, these functions determine the registry's
   verified state. They fetch nothing and conclude only from the evidence
   handed to them; KEL verification remains the caller's job.
2. Shared TEL validation and anchor helpers reused across verifier and issuer
   flows so registry-event rules live in one place.
3. The shared event engine used by registraring.py and Rever to validate,
   escrow, replay, and accept locally authored or foreign TEL events against
   accepted controller KEL evidence.
"""

from collections.abc import Mapping
from collections import namedtuple
import re
from datetime import datetime

from .. import help
from ..kering import (Ilks, ValidationError, ConfigurationError,
                      InvalidValueError,
                      MissingAnchorError, MisdigestError, MissequenceError,
                      MisregistryError, MisanchorError, RootSealError,
                      MisbindingError, DuplicitousRegistryError,
                      UnverifiedBlindError)
from ..core import Blinder, BlindState, BoundState, Diger, Number, SerderACDC
from . import messaging, scheming

logger = help.ogler.getLogger()


RegStateRecord = namedtuple("RegStateRecord",
                            "regid issuer said sn ilk acdc state stamp "
                            "binding anchors")
"""Verified state of a registry (TEL) as determined by vet().

Fields:
    regid (str): qb64 registry SAID (the rip event's said)
    issuer (str): qb64 AID of the registry's issuer (the rip's i field)
    said (str): qb64 SAID of the head (latest verified) registry event
    sn (int): sequence number of the head event
    ilk (str): message type of the head event (rip or bup)
    acdc (str|None): qb64 SAID of the disclosed transaction target; None when
        the registry has no disclosed non-vacuous update
    state (str|None): disclosed transaction state string; None when unavailable
    stamp (str): the head event's ISO datetime from vet(), or the latest
        non-vacuous binding event's datetime from vetBinds()
    binding (str|None): how the presented ACDC binds to the registry:
        'mutual' when td == acdc.d and acdc.rd == rip.d both hold, 'oneway'
        when the ACDC carries no rd, 'presentation' when the target is a grant
        SAID, and None when no target binding was requested
    anchors (tuple): one (sn, said) couple per verified chain event, the
        issuer KEL event in which that TEL event's anchoring seal was found
"""

# Shared TEL records
_RegEventRecord = namedtuple("_RegEventRecord",
                             "serder said ilk regk sn prior issuer")
"""Normalized TEL event facts reused across issuer and verifier flows.

Fields:
    serder (SerderACDC): parsed registry event serder
    said (str): qb64 SAID of the event
    ilk (str): registry event type, currently ``rip`` or ``bup``
    regk (str): qb64 registry identifier for the event's TEL
    sn (int): sequence number of the event
    prior (str|None): prior-event SAID for updates, else None for inception
    issuer (str|None): qb64 issuer AID carried by the event when present
"""


# Shared TEL validation kernel
def _coerce(evt):
    """Coerce evt to SerderACDC.  Accepts a SerderACDC instance or raw
    serialized bytes/str (one event's serialization).

    Returns:
        serder (SerderACDC): the coerced event
    """
    if isinstance(evt, SerderACDC):
        return evt
    if isinstance(evt, str):
        evt = evt.encode()
    if isinstance(evt, (bytes, bytearray, memoryview)):
        return SerderACDC(raw=bytes(evt))
    raise InvalidValueError(f"Invalid registry event material type "
                            f"{type(evt)}: expected SerderACDC or raw bytes.")


def _normalizeEventRecord(evt):
    """Normalize one TEL event into a parsed record

    Parameters:
        evt (SerderACDC | bytes | str): registry event material to normalize.

    Returns:
        _RegEventRecord: normalized TEL event facts shared across the issuer
            and verifier flows.

    Raises:
        InvalidValueError: if ``evt`` cannot be coerced into a
            ``SerderACDC``.
        ValidationError: if the event's ``ilk`` is not one of the supported
            v2 registry event types.
    """
    
    # Parse once so every later step reads the same regk/sn/prior/issuer
    serder = _coerce(evt)
    ilk = serder.ilk

    # The v2 ACDC TEL only supports registry inception and blind updates
    if ilk not in (Ilks.rip, Ilks.bup, Ilks.upd):
        raise ValidationError(f"Unsupported registry event type {ilk} for "
                              f"event {serder.said}.")
    sn = serder.sad['n']
    if not isinstance(sn, str) or not re.fullmatch(r"0|[1-9a-f][0-9a-f]*", sn):
        raise MissequenceError("native registry ordinal must be canonical hexadecimal")
    stamp = serder.sad['dt']
    if not isinstance(stamp, str) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}[+-][0-9]{2}:[0-9]{2}", stamp):
        raise ValidationError("native registry timestamp requires microseconds and numeric offset")
    try:
        datetime.fromisoformat(stamp)
    except ValueError as ex:
        raise ValidationError("invalid native registry timestamp") from ex
    return _RegEventRecord(serder=serder,
                           said=serder.said,
                           ilk=ilk,
                           # For a rip the registry id is the event's own SAID;
                           # for a bup it is carried in rd.
                           regk=serder.said if ilk == Ilks.rip else serder.sad['rd'],
                           sn=Number(numh=serder.sad['n']).num,
                           prior=None if ilk == Ilks.rip else serder.sad['p'],
                           issuer=serder.sad.get('i'))


def _validateRip(evt, *, issuer=None):
    """Validate one registry inception event against shared TEL rules.

    Parameters:
        evt (SerderACDC | bytes | str): registry inception event to validate.
        issuer (str | None): optional expected issuer AID for the inception.

    Returns:
        _RegEventRecord: normalized facts for the validated inception event.

    Raises:
        ValidationError: if the event is not a ``rip`` or the issuer does not
            match the expected local or presented issuer.
        MissequenceError: if the inception event is not at sequence number
            ``n = 0``.
    """

    # Normalize the event first so regk, sn, and issuer are interpreted consistently
    event = _normalizeEventRecord(evt)

    # Raise if the event is not a rip
    if event.ilk != Ilks.rip:
        raise ValidationError(f"Expected registry inception ilk={Ilks.rip} "
                              f"got ilk={event.ilk} for event "
                              f"{event.said}.")

    # Validate correct sequence number for a rip
    if event.sn != 0:
        raise MissequenceError(f"Registry inception {event.said} has "
                               f"n={event.serder.sad['n']} but inception "
                               f"must be at n=0.")

    # Validate the issuer is the same as the one provided
    if issuer is not None and event.issuer != issuer:
        raise ValidationError(f"Registry inception event {event.said} has "
                              f"invalid issuer {event.issuer}.")
    return event


def _validateUpdate(evt, *, regid, prior=None):
    """Validate one blindable registry update against shared TEL rules.

    Parameters:
        evt (SerderACDC | bytes | str): registry update event to validate.
        regid (str): expected qb64 registry identifier for the update.
        prior (str | None): optional expected prior-event SAID when the caller
            already knows the accepted predecessor.

    Returns:
        _RegEventRecord: normalized facts for the validated update event.

    Raises:
        ValidationError: if the event is not a ``bup``.
        MisregistryError: if the update names a different registry.
        MissequenceError: if the update is not at sequence number ``n >= 1``.
        MisdigestError: if the update's ``p`` field does not match the
            provided predecessor.
    """

    # Normalize first so regid, sn, and prior are interpreted consistently.
    event = _normalizeEventRecord(evt)

    # Only blindable updates belong in this path
    if event.ilk not in (Ilks.bup, Ilks.upd):
        raise ValidationError(f"Expected registry update ilk={Ilks.bup} got "
                              f"ilk={event.ilk} for event {event.said}.")

    # Validate the registry id matches the one provided
    if event.regk != regid:
        raise MisregistryError(f"Registry update {event.said} has "
                               f"rd={event.regk} which is not the "
                               f"presented registry inception's said "
                               f"{regid}.")

    # sn 0 is reserved for the rip, so updates start at one.
    if event.sn < 1:
        raise MissequenceError(f"Registry update {event.said} has "
                               f"n={event.serder.sad['n']} but updates must "
                               f"be at n >= 1.")

    # When a caller already knows the prior, require the chain link to
    # match before any deeper processing happens.
    if prior is not None and event.prior != prior:
        raise MisdigestError(f"Registry event {event.said} at n={event.sn} "
                             f"has p={event.prior} which is not the prior "
                             f"event's said {prior}.")
    return event


# Shared KEL anchor primitives
def _kever(db, pre):
    """Return the Kever for pre from db's read-through kevers cache, or None
    when the KEL is not available."""
    try:
        return db.kevers[pre]
    except KeyError:
        return None


def _kelEvent(db, pre, claim):
    """Resolve a claimed anchoring key event of pre's KEL by sequence number
    (int) or SAID (str).  Returns the event serder or None when absent."""
    if isinstance(claim, int):
        dig = db.kels.getLast(keys=pre, on=claim)
        if dig is None:
            return None
        return db.evts.get(keys=(pre, dig))
    event = db.evts.get(keys=(pre, claim))
    if event is None or db.kels.getLast(keys=pre, on=event.sn) != event.said:
        return None
    return event


def sealDigests(serder):
    """Extract the candidate seal digests from a key event's seal data list.

    A seal may be as simple as the sealed event's SAID (a bare digest
    string), or a mapping bearing a 'd' field, with or without an 's'
    sequence-number hint.  The hint is never load-bearing: matching is by
    digest only, so a wrong or absent 's' does not disqualify a seal.

    Returns:
        digs (list[str]): qb64 seal digests found in serder's 'a' field
    """
    seals = serder.sad.get('a') or ()
    digs = []
    if isinstance(seals, (list, tuple)):
        for seal in seals:
            if isinstance(seal, str):
                digs.append(seal)
            elif isinstance(seal, Mapping) and 'd' in seal:
                digs.append(seal['d'])
    return digs


def _matchesRegistrySeal(candidate, event):
    """Recognize the approved digest/couple/triple profile, matching all fields."""
    if not isinstance(candidate, Mapping):
        return False
    if set(candidate) not in ({'d'}, {'s', 'd'}, {'i', 's', 'd'}):
        return False
    return (candidate['d'] == event.said
            and ('s' not in candidate or candidate['s'] == event.serder.sad['n'])
            and ('i' not in candidate or candidate['i'] == event.regk))


def _scanKel(db, pre, serder):
    """Find the earliest accepted, fully witnessed matching controller seal."""
    kever = _kever(db, pre)
    if kever is None:
        return None
    event = _normalizeEventRecord(serder)
    for sn in range(kever.sn + 1):
        eserder = _kelEvent(db, pre, sn)
        if eserder is None or not db.fullyWitnessed(eserder):
            continue
        if any(_matchesRegistrySeal(seal, event) for seal in eserder.sad.get('a', ())):
            return (sn, eserder.said)
    return None


def _verifyAnchorCouple(serder, *, db, issuer, number, diger):
    """Verify one explicit local KEL anchor couple against a TEL event seal.

    Parameters:
        serder (SerderACDC): TEL event whose anchor couple to verify.
        db (Baser): local KEL database that stores the controlling habitat's
            verified key events.
        issuer (str): qb64 AID whose KEL must contain the sealing event.
        number (Number | None): claimed sequence number of the sealing KEL
            event.
        diger (Diger | None): claimed digest of the sealing KEL event.

    Returns:
        bool: True when the claimed sealing event exists, is fully witnessed,
            matches ``diger``, and contains the full TEL seal tuple for
            ``serder``. False otherwise.
    """

    # Return False if either is missing
    if number is None or diger is None:
        return False

    # Retrieve dig of KEL event by issuer and sequence number
    dig = db.kels.getLast(keys=issuer, on=number.sn)
    if dig is None:
        return False

    dig = dig.encode("utf-8")
    
    # Retrieve serder from evts
    aserder = db.evts.get(keys=(issuer, dig))
    if aserder is None:
        return False

    # The claimed SAID must match, and the key event must be fully witnessed
    if aserder.said != diger.qb64 or not db.fullyWitnessed(aserder):
        return False

    event = _normalizeEventRecord(serder)
    return any(_matchesRegistrySeal(candidate, event)
               for candidate in aserder.sad.get('a', ()))


def _validateSourceLocators(serder, *, db, issuer, sscs=(), ssts=()):
    """Reject resolvable false source locators on this intake only.

    Native TEL events identify their registry and authorized controller without
    unsigned attachments. Source couples/triples locate evidence; they cannot
    impose a persistent sender-controlled condition on later authentic replay.
    Unavailable KEL evidence therefore follows ordinary anchor discovery/escrow.
    """
    locators = [(issuer, number, diger) for number, diger in sscs]
    locators.extend((prefixer.qb64, number, diger)
                    for prefixer, number, diger in ssts)
    event = _normalizeEventRecord(serder)
    for controller, number, diger in locators:
        if issuer is not None and controller != issuer:
            raise ValidationError('TEL source locator names a different controller')
        if controller is None:
            continue  # an implicit source cannot resolve before registry inception
        if not isinstance(number, Number) or not isinstance(diger, Diger):
            raise ValidationError('TEL source locator requires a number and digest')
        accepted = db.kels.getLast(keys=controller, on=number.num)
        if accepted is None:
            continue
        if accepted != diger.qb64:
            raise ValidationError('TEL source locator conflicts with accepted KEL digest')
        anchor = db.evts.get(keys=(controller, accepted))
        if anchor is not None and not any(
                _matchesRegistrySeal(seal, event) for seal in anchor.sad.get('a', ())):
            raise ValidationError('TEL source locator does not seal this registry event')


# Verifier-side public API
def vetAnchor(serder, *, db, issuer, source=None, told=()):
    """Verify that the registry (TEL) event serder is anchored in the
    issuer's KEL: some key event of the issuer carries a seal whose digest is
    the TEL event's SAID.

    Returns:
        couple (tuple): (sn, said) of the anchoring key event in the
            issuer's KEL

    Parameters:
        serder (SerderACDC): registry event whose anchor to verify
        db (Baser): KEL database the caller has already populated and
            verified.  KEL verification is not performed here.
        issuer (str): qb64 AID of the registry's issuer (the rip's i field).
            The anchoring KEL's controller must be this AID: a seal in any
            other KEL is an endorsement, not a commitment.
        source (int|str|None): optional caller's claim of where the anchor
            lives in the issuer's KEL, by key event sequence number (int) or
            SAID (str).  A claim that resolves to an event whose seal
            digests match no event of the presented TEL (per told) is an
            aggregate (Merkle/SMT root) seal and is refused by name.  A
            claim that does not pan out otherwise falls back to a full scan,
            since a wrong hint is indistinguishable from an anchor not yet
            gathered.
        told (Iterable[str]): SAIDs of all events of the presented TEL, used
            only to discriminate an aggregate seal from a merely mistaken
            source claim.

    Raises:
        MisanchorError: seal found, but only in a KEL whose controller is
            not the issuer (permanent refusal)
        RootSealError: the claimed anchoring event seals digests foreign to
            the whole presented TEL (permanent refusal)
        MissingAnchorError: no seal found anywhere; the anchor may still be
            in flight (retryable)
    """
    if _kever(db, issuer) is None:
        raise MissingAnchorError(f"Issuer KEL for {issuer} not available to "
                                 f"verify the anchor of registry event "
                                 f"{serder.said}.")

    if source is not None:
        eserder = _kelEvent(db, issuer, source)
        if eserder is not None:
            digs = sealDigests(eserder)
            if (_verifyAnchorCouple(serder, db=db, issuer=issuer,
                                    number=Number(num=eserder.sn),
                                    diger=Diger(qb64=eserder.said))):
                return (eserder.sn, eserder.said)
            if digs and not set(digs) & set(told):
                raise RootSealError(f"Claimed anchoring key event "
                                    f"{eserder.said} at sn={eserder.sn} of "
                                    f"issuer {issuer} seals digest(s) "
                                    f"matching no event of the presented "
                                    f"registry {list(told)[:1]}: an "
                                    f"aggregate (Merkle/SMT root) seal "
                                    f"requires an inclusion proof and is "
                                    f"not supported.")
        # a claim that did not pan out is just a bad hint: fall through

    couple = _scanKel(db, issuer, serder)
    if couple is not None:
        return couple

    for pre in list(db.kevers):
        if pre == issuer:
            continue
        if _scanKel(db, pre, serder) is not None:
            raise MisanchorError(f"Seal for registry event {serder.said} "
                                 f"found in the KEL of {pre}, which is not "
                                 f"the registry issuer {issuer}: an "
                                 f"endorsement is not a commitment.")

    raise MissingAnchorError(f"No anchoring seal for registry event "
                             f"{serder.said} in the KEL of issuer {issuer}.")


def vetRip(rip):
    """Validate a registry inception (rip) event's registry-level fields.
    Field presence, order, and SAID are already SerderACDC's own validation.

    Returns:
        serder (SerderACDC): the validated rip event
    """
    return _validateRip(rip).serder


def vetUpdate(bup, rip):
    """Validate a blindable registry update (bup) event's registry-level
    fields against its registry inception.

    Returns:
        serder (SerderACDC): the validated bup event
    """
    return _validateUpdate(bup, regid=vetRip(rip).said).serder


def _blindCandidates(blinder):
    """Decode exactly one blind or bound opening without ignoring trailing bytes."""
    if isinstance(blinder, Blinder):
        return [blinder]
    qb64 = blinder.decode() if hasattr(blinder, "decode") else blinder
    candidates = []
    for clan in (BlindState, BoundState):
        try:
            candidate = Blinder(clan=clan, qb64=qb64)
        except Exception:
            continue
        if candidate.qb64 == qb64:
            candidates.append(candidate)
    if not candidates:
        raise UnverifiedBlindError("undecodable disclosed blind or bound opening")
    return candidates


def vetBlind(blinder, *, blid):
    """Verify a disclosed blinded-state attribute block against the BLID
    anchored by a blindable update (bup) event, by recomputing the BLID over
    the disclosed fields.

    Returns:
        (acdc, state) (tuple[str, str]): the disclosed transaction ACDC said
            and transaction state string; both empty for a placeholder

    Parameters:
        blinder (Blinder|str|bytes): the disclosed block, either a Blinder
            instance or the qb64 concatenation of its CESR field values as a
            discloser attaches it on the wire
        blid (str): qb64 BLID, the b field of the bup event

    Raises:
        UnverifiedBlindError: the disclosure does not reproduce blid, so it
            proves nothing about the registry's state
    """
    candidates = _blindCandidates(blinder)

    for candidate in candidates:
        crew = dict(candidate.crew._asdict())
        crew['d'] = ''
        redone = Blinder(crew=candidate.clan(**crew), makify=True)
        if redone.said == blid:
            return (redone.acdc, redone.state)

    raise UnverifiedBlindError(f"Disclosed blinded-state block does not "
                               f"reproduce the anchored blid={blid}: the "
                               f"disclosure proves nothing.")


def vetBound(blinder, *, acdc, db):
    """Validate a bound opening's exact historical Issuee KEL coordinates.

    Call vetBlind first to authenticate this opening against its TEL BLID.
    ACDC f0bd097d sections 2429-2478 define bn/bd as an Issuee key event,
    not necessarily an establishment event or the receiver's latest event.
    This verifies that reference; it does not infer wall-clock publication time.

    Returns the accepted, fully witnessed Issuee key event for a non-vacuous
    BoundState, or None for a BlindState or a strict all-empty placeholder.
    Missing event/witness evidence is retryable; a conflicting accepted digest,
    missing issuee, or substituted credential is a permanent binding failure.
    """
    blinder = _blindCandidates(blinder)[0]
    if blinder.clan != BoundState:
        return None
    if not blinder.acdc and not blinder.state:
        if blinder.bsn != 0 or blinder.bd:
            raise MisbindingError("bound placeholder requires bn=0 and empty bd")
        return None
    if not blinder.bd:
        raise MisbindingError("non-vacuous bound state requires an Issuee key event")
    if acdc is None:
        raise MisbindingError("bound state requires its disclosed target ACDC")
    credential = _coerce(acdc)
    if blinder.acdc != credential.said:
        raise MisbindingError("bound state does not name the presented ACDC")
    issuee = credential.iseaid
    if not issuee:
        raise MisbindingError("bound state requires the disclosed ACDC Issuee")
    dig = db.kels.getLast(keys=issuee, on=blinder.bsn)
    if dig is None:
        raise MissingAnchorError(f"missing Issuee key event {issuee}:{blinder.bsn}")
    if dig != blinder.bd:
        raise MisanchorError("bound Issuee key event digest conflicts with accepted KEL")
    event = db.evts.get(keys=(issuee, dig))
    if event is None or not db.fullyWitnessed(event):
        raise MissingAnchorError("bound Issuee key event is not fully witnessed")
    return event


BoundStateResult = namedtuple('BoundStateResult', 'valid assurance')


def boundStateAt(transitions, *, issuee, issuer, sn):
    """Interpret a complete, authenticated bound history at an issuance event.

    ``transitions`` contains (state, bound ordinal) pairs in verified TEL order.
    The caller must authenticate every transition and its exact Issuee event;
    a partial history must not be passed as a complete history.

    Published ACDC f0bd097d :2457/:2476 requires the bound event to be current
    at publication. Under that issuer assertion, an update follows its bound
    event and precedes the next Issuee event: issuance authority therefore has
    ``issued.bn < sn <= revoked.bn``. Equal issuance is too early; equal
    revocation is still before revocation. This is an interpretation of the
    normative current-event premise, NOT independent proof of publication time.
    The assurance is explicit because valid signatures cannot prove that an
    issuer did not choose an old bound. Different KEL ordinals are incomparable.
    """
    if not issuee or issuer != issuee:
        return BoundStateResult(None, 'incomparable-kels')
    if type(sn) is not int or sn < 0:
        return BoundStateResult(None, 'incomplete-bound-history')
    prior = -1
    state = None
    for current, bound in transitions:
        if type(bound) is not int or bound < 0 or bound < prior or current not in ('issued', 'revoked'):
            return BoundStateResult(None, 'incomplete-bound-history')
        prior = bound
        if bound < sn:
            state = current
    return BoundStateResult(state == 'issued', 'issuer-current-event')


def issuerRegistry(acdc):
    """Read the disclosed issuer registry, including protected nested rd.

    A top-level registry makes inner registries application/presentation
    declarations. Without it, disclosed a/A blocks may carry the issuer rd.
    No cached disclosure is consulted and no hidden block is expanded.
    """
    serder = _coerce(acdc)
    if regid := serder.sad.get('rd'):
        return regid
    sections = [serder.sad.get('a')]
    aggregate = serder.sad.get('A')
    if isinstance(aggregate, list):
        sections.extend(aggregate[1:])
    registries = {section['rd'] for section in sections
                  if isinstance(section, dict) and section.get('rd')}
    if len(registries) > 1:
        raise MisregistryError('multiple disclosed issuer registries without top-level rd')
    return next(iter(registries), None)


def vetBindings(acdc, *, regid, issuer, td):
    """Verify the bindings between a presented ACDC and its registry evidence.

    The registry evidence must commit to the presented ACDC, the ACDC must
    name the presented registry when ``rd`` is present, and the ACDC's own
    issuer must match the issuer that incepted the presented registry. V2
    ACDCs are not directly signed, so a verifier that skips these bindings
    passes every other obligation while accepting a substituted credential.

    Returns:
        binding (str): 'mutual' when td == acdc.d and acdc.rd == rip.d both
            hold; 'oneway' when the ACDC carries no rd, so only the
            registry->ACDC direction is committed and the caller's policy
            can weigh the weaker basis

    Parameters:
        acdc (SerderACDC|bytes): the presented ACDC
        regid (str): qb64 SAID of the presented registry inception (rip)
        issuer (str): qb64 AID of the issuer that incepted the presented
            registry
        td (str|None): qb64 transaction ACDC said the registry's verified
            head state commits to

    Raises:
        MisbindingError: either equality fails (permanent refusal)
    """
    serder = _coerce(acdc)
    if td != serder.said:
        raise MisbindingError(f"Registry state's transaction ACDC said "
                              f"td={td} does not bind the presented ACDC's "
                              f"said {serder.said}.")
    if serder.sad.get('i') != issuer:
        raise MisbindingError(f"Presented ACDC issuer {serder.sad.get('i')} "
                              f"does not match presented registry issuer "
                              f"{issuer}.")
    rd = issuerRegistry(serder)
    if rd:
        if rd != regid:
            raise MisbindingError(f"Presented ACDC's registry said rd={rd} "
                                  f"does not bind the presented registry "
                                  f"inception's said {regid}.")
        return 'mutual'
    return 'oneway'


def vet(rip, updates=None, *, db, acdc=None, blinder=None, sources=None):
    """Verify a registry (TEL) event chain against the issuer's KEL and
    determine the registry's verified state.  This is the party-side
    verification core: it fetches nothing and concludes only from the
    supplied evidence.

    The registry's state is the state at the highest-n event that
    chain-verifies from the rip and whose anchor verifies in the issuer's
    KEL.  Every presented event must anchor-verify: an event whose anchor is
    missing establishes nothing and the whole determination is retryable
    (MissingAnchorError), since concluding from an anchored prefix could
    silently bless an issuer's half-commitment or hide duplicity still in
    flight.

    Returns:
        record (RegStateRecord): the verified registry state

    Parameters:
        rip (SerderACDC|bytes): registry inception event
        updates (Iterable|None): registry update (bup) events, in any order
        db (Baser): KEL database the caller has already populated; KEL
            verification is the caller's job
        acdc (SerderACDC|bytes|None): optionally, the presented ACDC to
            bind-check against the verified head state
        blinder (Blinder|str|bytes|None): optionally, the disclosed
            blinded-state block for the head bup event.  Without it a bup
            head verifies as a chain but its state stays blinded (state and
            acdc None in the record).  There is no salt parameter: only the
            per-event disclosure is accepted.
        sources (Mapping|None): optional caller's claims of anchor
            locations, mapping TEL event said -> issuer KEL event sn (int)
            or said (str).  See vetAnchor.

    Raises:
        MissequenceError, MisdigestError, MisregistryError,
        MisanchorError, RootSealError, DuplicitousRegistryError,
        MisbindingError, UnverifiedBlindError: permanent, named refusals
        MissingAnchorError: establishes nothing, retryably
    """
    ripper = vetRip(rip)
    issuer = ripper.sad['i']
    updates = [vetUpdate(update, ripper)
               for update in (updates if updates is not None else ())]
    sources = sources if sources is not None else {}
    told = [ripper.said] + [serder.said for serder in updates]

    chain = [ripper]
    anchors = [vetAnchor(ripper, db=db, issuer=issuer,
                         source=sources.get(ripper.said), told=told)]

    remaining = list(updates)
    prior = ripper
    n = 1
    while remaining:
        cands = [serder for serder in remaining
                 if Number(numh=serder.sad['n']).num == n]
        if not cands:
            ns = sorted(Number(numh=serder.sad['n']).num
                        for serder in remaining)
            raise MissequenceError(f"Gapped chain for registry "
                                   f"{ripper.said}: no event at n={n} but "
                                   f"events remain at n={ns}; n = prior + 1 "
                                   f"exactly.")
        for serder in cands:
            if serder.sad['p'] != prior.said:
                raise MisdigestError(f"Registry event {serder.said} at "
                                     f"n={n} has p={serder.sad['p']} which "
                                     f"is not the prior event's said "
                                     f"{prior.said}.")
        unique = list({serder.said: serder for serder in cands}.values())
        couples = {}
        for serder in unique:  # every event must anchor before any concludes
            couples[serder.said] = vetAnchor(serder, db=db, issuer=issuer,
                                             source=sources.get(serder.said),
                                             told=told)
        if len(unique) > 1:
            raise DuplicitousRegistryError(f"Registry duplicity for "
                                           f"{ripper.said}: {len(unique)} "
                                           f"distinct anchored events at "
                                           f"n={n}: "
                                           f"{[s.said for s in unique]}.")
        accepted = unique[0]
        chain.append(accepted)
        anchors.append(couples[accepted.said])
        remaining = [serder for serder in remaining
                     if Number(numh=serder.sad['n']).num != n]
        prior = accepted
        n += 1

    head = chain[-1]
    acdcsaid = state = None
    if head.ilk == Ilks.upd:
        acdcsaid = head.sad['td'] or None
        state = head.sad['ts'] or None
    elif head.ilk == Ilks.bup and blinder is not None:
        disclosed, toldState = vetBlind(blinder=blinder, blid=head.sad['b'])
        vetBound(blinder, acdc=acdc, db=db)
        acdcsaid = disclosed or None
        state = toldState or None

    binding = None
    if acdc is not None:
        serder = _coerce(acdc)
        if head.ilk == Ilks.bup and blinder is None:
            raise UnverifiedBlindError(f"Registry {ripper.said} head at "
                                       f"n={head.sad['n']} is blinded and "
                                       f"no state was disclosed: nothing "
                                       f"binds ACDC {serder.said} to it.")
        binding = vetBindings(acdc=serder, regid=ripper.said,
                              issuer=issuer, td=acdcsaid)

    return RegStateRecord(regid=ripper.said, issuer=issuer, said=head.said,
                          sn=Number(numh=head.sad['n']).num, ilk=head.ilk,
                          acdc=acdcsaid, state=state, stamp=head.sad['dt'],
                          binding=binding, anchors=tuple(anchors))


def vetBinds(rip, updates=None, *, db, blinders, target, controller=None,
             acdc=None, sources=None, cutoff=None, at=None, requireSource=False):
    """Verify a TEL and a disclosed non-vacuous target binding.

    Every blinded update from the verified head back through the latest
    non-vacuous update must have exactly one matching disclosure, and that
    non-vacuous update must bind ``target``. ``at`` selects an exact TEL event
    as the historical head; every event through it still needs a verified KEL
    anchor. Omitting it checks the supplied current head. Controller timestamps
    and request receipt timestamps do not establish KEL ordering.

    Parameters:
        rip (SerderACDC | bytes): Registry inception event.
        updates (Iterable | None): Registry update events.
        db (Baser): Preloaded verifier KEL database.
        blinders (Iterable[Blinder]): Node-local disclosed state blocks.
        target (str): Expected transaction SAID.
        controller (str | None): Required registry-controlling AID.
        acdc (SerderACDC | bytes | None): ACDC for issuer-registry bindings.
        sources (Mapping | None): Optional TEL-event anchor locations.
        cutoff: Obsolete timestamp cutoff; rejected because it proves no
            historical ordering. Select an exact authenticated event instead.
        at (str | None): SAID of the historical TEL head to verify.
        requireSource (bool): True requires an explicit source claim for the
            selected non-vacuous binding event.

    Returns:
        RegStateRecord: Verified TEL state resolved to the selected non-vacuous
            binding.  ``binding`` is ``presentation`` when ``acdc`` is omitted.
    """
    # Normalize the registry inception into a TEL serder.
    rip = _coerce(rip)

    # Normalize every supplied registry update before filtering.
    updates = updates if updates is not None else ()
    updates = [_coerce(update) for update in updates]

    sources = sources if sources is not None else {}

    if cutoff is not None:
        raise ValidationError('datetime cutoff cannot establish anchored history; select at=TEL SAID')
    if at is not None:
        chain = [rip, *updates]
        positions = [index for index, event in enumerate(chain) if event.said == at]
        if len(positions) != 1:
            raise MissingAnchorError(f'historical TEL head {at} is unavailable or ambiguous')
        ordinal = Number(numh=chain[positions[0]].sad['n']).num
        updates = [event for event in updates if Number(numh=event.sad['n']).num <= ordinal]

    # Verify the selected contiguous TEL prefix and all KEL anchors.
    record = vet(rip=rip, updates=updates, db=db, sources=sources)

    blinders = list(blinders)

    # Check that the registry's controlling AID matches
    if controller is not None and record.issuer != controller:
        raise MisbindingError(f"Registry controller {record.issuer} does not match "
                              f"required controller {controller}.")

    # Search backward from the latest update in the verified prefix.
    newestFirst = sorted(
        updates,
        key=lambda update: Number(numh=update.sad['n']).num,
        reverse=True,
    )

    # Inspect each update until the latest non-vacuous state is found.
    for update in newestFirst:

        if update.ilk == Ilks.upd:
            td, state = update.sad['td'], update.sad['ts']
        else:
            matches = [blinder for blinder in blinders
                       if blinder.said == update.sad['b']]
            if len(matches) != 1:
                raise UnverifiedBlindError(
                    f"Registry update {update.said} requires exactly one disclosure "
                    f"for blid={update.sad['b']}.")
            td, state = vetBlind(blinder=matches[0], blid=update.sad['b'])
            vetBound(matches[0], acdc=acdc, db=db)

        # Skip vacuous updates while retaining their chain validation.
        if not td and not state:
            continue

        # Require the latest non-vacuous update to bind the expected target.
        if td != target:
            raise MisbindingError(f"Registry state's transaction said td={td} "
                                  f"does not bind expected target {target}.")

        # Presentation timing requires the Grant to carry this bup's KEL source.
        if requireSource and update.said not in sources:
            raise MisanchorError(
                f"Registry binding event {update.said} has no attached KEL source.")

        # Apply ACDC binding rules only for issuer registries.
        binding = (vetBindings(acdc=acdc, regid=record.regid,
                               issuer=record.issuer, td=td)
                   if acdc is not None else 'presentation')

        # Return state from the selected non-vacuous binding event.
        return record._replace(acdc=td, state=state, stamp=update.sad['dt'],
                               binding=binding)

    # No disclosed non-vacuous update authenticated the requested target.
    raise MisbindingError(f"Registry {record.regid} has no disclosed non-vacuous "
                          f"state binding target {target}.")


# Issuer-side local TEL engine
class _RegEventer:
    """Private issuer-side TEL event engine for one local registry.

    It owns the local TEL workflow that ``Registry`` delegates to:
    shared TEL validation, local KEL anchor discovery and verification,
    acceptance into the ordered registry log, and replay of missing-anchor
    and out-of-order escrows.
    """

    def __init__(self, hab=None, store=None, regk=None, regd=None, *, db=None, issuer=None):
        """Create one local TEL event engine bound to a habitat and store.

        Parameters:
            hab (Hab): controlling habitat whose KEL anchors registry events.
            store (RegistryStore): storage adapter for TEL events, accepted
                ordering, anchors, and escrows.
            regk (str | None): bound registry identifier when reopening or
                attaching to an existing local registry state.
            regd (str | None): accepted head-event SAID when already known.
        """
        # The engine needs the controlling habitat for local KEL inspection,
        # the registry store for persistence, and the current accepted TEL tip
        self.hab = hab
        self.db = hab.db if hab is not None else db
        self.issuer = hab.pre if hab is not None else issuer
        if self.db is None or self.issuer is None or store is None:
            raise ConfigurationError("registry processing requires KEL database, issuer and store")
        self.store = store
        self.regk = regk
        self.regd = regd
    
    
    @property
    def head(self):
        """Return the accepted head SAID for the bound local registry.

        Returns:
            Saider | None: current accepted head SAID, or None when the
                registry has not yet committed any event.
        """
        return self.store.head(self.regk) if self.regk is not None else None

    @property
    def sn(self):
        """Return the accepted head sequence number for the bound registry.

        Returns:
            int: accepted head sequence number, or ``-1`` when no TEL event
                has been committed yet.
        """
        head = self.store.headEvent(self.regk) if self.regk is not None else None
        return _normalizeEventRecord(head).sn if head is not None else -1

    @property
    def regser(self):
        """Return the accepted registry inception event when available.

        Returns:
            SerderACDC | None: committed ``rip`` event, or None when the
                registry inception has not yet been accepted.
        """
        return self.store.seqEvent(self.regk, 0) if self.regk is not None else None

    # Public TEL event API
    def processEvent(self, serder, *, sscs=(), ssts=()):
        """Store one TEL event and commit it when anchor and order allow.

        Parameters:
            serder (SerderACDC): candidate local registry event to process.

        Returns:
            bool: True when the event commits immediately or replays
                idempotently as already accepted. False when the event is
                staged in missing-anchor or out-of-order escrow.

        Raises:
            ValidationError: if the event fails shared TEL validation or
                conflicts with accepted local registry state.
        """
        # First apply shared TEL rules plus local store consistency checks.
        event, existing, prior = self._validateEvent(serder)
        _validateSourceLocators(event.serder, db=self.db, issuer=self.issuer,
                                sscs=sscs, ssts=ssts)

        # The first accepted or staged rip binds this engine instance to the
        # registry key it will manage from then on.
        if self.regk is None and event.ilk == Ilks.rip:
            self.regk = event.regk
            self.regd = event.said

        # Idempotent replay of an already accepted event is a success.
        if existing is not None:
            self.regk = event.regk
            self.regd = self.store.head(event.regk).qb64
            self.store.clearEscrows(event.regk, event.sn, event.said)
            return True

        # Persist the body before any escrow decision so later replay can load
        # the full event again.
        self.store.putEvent(event.serder)

        # Try a single local KEL discovery pass before deciding whether the
        # event must wait in missing-anchor escrow.
        self._discoverAnchor(event)
        if self.store.anchor(event.said) is None:
            self.store.escrowMissingAnchor(event.regk, event.sn, event.said)
            return False

        # Once an anchor exists, remove any stale maes entry for this event.
        self.store.baser.maes.rem(keys=event.regk, on=event.sn, val=event.said)

        # A rip only depends on its own verified anchor.
        if event.ilk == Ilks.rip:
            self._commit(event)
            self._processQueued()
            return True

        # Updates with a verified anchor but no accepted predecessor move to
        # out-of-order escrow until the chain gap is filled.
        if prior is None:
            self.store.escrowOutOfOrder(event.regk, event.sn, event.said)
            return False

        # Anchored and properly ordered updates can commit immediately.
        self._commit(event)
        self._processQueued()
        return True

    def anchorMsg(self, said, number=None, diger=None):
        """Validate and record the local KEL anchor for one stored TEL event.

        Parameters:
            said (str): SAID of the stored TEL event to anchor.
            number (Number | None): optional sequence number of the sealing
                KEL event. Must be supplied together with ``diger``.
            diger (Diger | None): optional digest of the sealing KEL event.
                Must be supplied together with ``number``.

        Returns:
            bool: True when anchoring lets the event commit immediately or it
                was already accepted, False when the event remains queued
                behind a missing predecessor.

        Raises:
            ValidationError: if the stored TEL event is unknown, if only one of
                ``number`` or ``diger`` is supplied, or if the explicit or
                discovered local anchor does not verify.
        """
        # Explicit anchoring always starts from the already stored TEL body.
        serder = self.store.event(said)
        if serder is None:
            raise ValidationError(f"unknown registry event {said}")

        # Reuse the normal validation gate so bad stored bodies do not leave
        # anchors behind.
        event, _, _ = self._validateEvent(serder)
        if (number is None) != (diger is None):
            raise ValidationError("anchorMsg requires both number and diger or neither")

        if number is None or diger is None:
            # With no explicit couple, fall back to the same local KEL discovery
            # path used by normal event ingestion and escrow replay.
            self._discoverAnchor(event)
        elif not _verifyAnchorCouple(event.serder,
                                     db=self.db,
                                     issuer=self.issuer,
                                     number=number,
                                     diger=diger):
            raise ValidationError(f"invalid anchor for registry event {said}")
        else:
            # Store the verified explicit couple so the normal state machine can
            # continue from the exact same persisted anchor representation.
            self.store.putAnchor(said, number, diger)

        if self.store.anchor(said) is None:
            raise ValidationError(f"invalid anchor for registry event {said}")

        # Hand back to the main event path so commit vs ooes behavior stays
        # centralized in one place.
        return self.processEvent(event.serder)

    def processEscrows(self):
        """Retry missing-anchor and out-of-order escrows for this registry.

        Parameters:
            None

        Returns:
            None
        """
        if self.regk is None:
            return
        # A crash may occur after acceptance but before escrow cleanup.
        # Occupied ordinals are final, including their discarded siblings.
        for escrow in (self.store.baser.maes, self.store.baser.ooes):
            for _, sn, said in list(escrow.getTopItemIter(keys=self.regk)):
                if self.store.seqSaider(self.regk, sn) is not None:
                    self.store.clearEscrows(self.regk, sn, said)
        self._processMissingAnchors()
        self._processQueued()

    def blind(self, acdc, state, **kwa):
        """Create and stage one blindable registry state update event.

        Parameters:
            acdc (SerderACDC): transaction-state ACDC that must already belong
                to this registry and be issued by this habitat.
            state (str): logical state value committed by the new blinded TEL
                update.
            **kwa: keyword arguments forwarded to ``Blinder.blind`` and
                ``messaging.blindate``. Blinder-construction keys are removed
                before the TEL event body is created.

        Returns:
            tuple: ``(blinder, serder)`` where ``blinder`` is the derived
                ``Blinder`` and ``serder`` is the staged ``bup`` event.

        Raises:
            ConfigurationError: if the registry has no accepted anchored
                frontier yet, if ``acdc`` is invalid, if it does not belong to
                this registry or issuer, or if a caller-supplied ``blinder``
                override is provided.
            MissingSchemaError: if the ACDC's external schema is unavailable.
            FailedSchemaValidationError: if the ACDC violates its schema.
        """
        # The issuer-side blind path only accepts a full, self-verifying ACDC.
        if not isinstance(acdc, SerderACDC):
            raise ConfigurationError("acdc must be a SerderACDC")
        if not acdc.verify():
            raise ConfigurationError(f"acdc {acdc.said} is invalid")

        # The ACDC must already declare this registry as its governing TEL.
        regid = getattr(acdc, "regid", None)
        if regid is None:
            regid = acdc.sad.get("rd")
        if regid != self.regk:
            raise ConfigurationError(f"acdc {acdc.said} does not belong to registry {self.regk}")

        # The current habitat must also be the ACDC's issuer.
        issuer = getattr(acdc, "israid", None)
        if issuer is None:
            issuer = acdc.sad.get("i")
        if issuer != self.issuer:
            raise ConfigurationError(f"acdc {acdc.said} has issuer {issuer} not {self.issuer}")

        # Reject malformed credentials before deriving or staging an issuance event.
        scheming.validateSchema(acdc=acdc, db=self.db)

        return self._blind(target=acdc.said, state=state, **kwa)

    def present(self, grant, state="presented", **kwa):
        """Create a blinded update that binds this registry to a grant SAID."""
        # Accept either a Grant serder or its qb64 SAID.
        target = grant.said if hasattr(grant, "said") else grant
        # Require a syntactically valid self-addressing target.
        try:
            Diger(qb64=target)
        except Exception as ex:
            raise ConfigurationError("presentation target must be a valid grant SAID") from ex
        # Reuse the shared blinded-update workflow.
        return self._blind(target=target, state=state, **kwa)

    def vacate(self, **kwa):
        """Create a vacuous blinded update that preserves the prior binding."""
        # Empty target and state mark an intentionally vacuous update.
        return self._blind(target="", state="", **kwa)

    def _blind(self, target, state, **kwa):
        """Create the next staged blinded update for a validated target SAID."""
        # Build from the staged frontier so callers may pipeline local updates.
        tip = self._effectiveFrontier()
        # Updates require an accepted or staged predecessor.
        if tip is None:
            raise ConfigurationError("registry must be anchored before updates")
        # Always derive the blinder from validated inputs internally.
        if "blinder" in kwa:
            raise ConfigurationError("caller-supplied blinder overrides are not supported")

        # Separate blinder options from TEL event options.
        blindkwa = {}
        # Move each supported blinder-only option out of the event arguments.
        for key in ("raw", "salt", "tier", "bound", "bsn", "bd"):
            if key in kwa:
                # These options belong to blinder construction, not the TEL
                # event body, so peel them off before calling blindate().
                blindkwa[key] = kwa.pop(key)

        # Normalize the frontier before deriving the next sequence number.
        tipEvent = _normalizeEventRecord(tip)
        # Advance exactly one TEL sequence number.
        sn = tipEvent.sn + 1
        # Derive the blinder from the next TEL sequence number so the bup and
        # blinded state commit to the same step in the chain.
        blinder = Blinder.blind(sn=sn, acdc=target, state=state, **blindkwa)
        # Create the bup that commits to the derived BLID.
        serder = messaging.blindate(regid=self.regk,
                                    prior=tipEvent.said,
                                    blid=blinder.said,
                                    sn=sn,
                                    **kwa)
        # Stage or accept the new event through normal TEL processing.
        self.processEvent(serder)
        # Return both the disclosure proof and its committed event.
        return blinder, serder

    # Shared local validation and acceptance helpers
    def _validateEvent(self, serder):
        """Validate one TEL event against shared TEL rules and local state.

        Parameters:
            serder (SerderACDC): candidate TEL event to validate for local
                issuer-side processing.

        Returns:
            tuple: ``(event, existing, prior)`` where ``event`` is the
                normalized ``_RegEventRecord``, ``existing`` is the already
                accepted event at the same slot when present, and ``prior`` is
                the accepted predecessor event for updates when already known.

        Raises:
            ValidationError: if the event does not belong to this registry, if
                the first local event is not a ``rip``, if the issuer is
                invalid, or if a different event already occupies the accepted
                ``(regk, sn)`` slot.
            MisregistryError, MissequenceError, MisdigestError: if shared TEL
                validation fails for registry id, sequence number, or prior
                linkage.
        """

        # Before a registry is bound, first event must be a rip
        if self.regk is None:
            if serder.ilk != Ilks.rip:
                raise ValidationError("registry must start with an inception event")

            # Validate the rip against the local habitat's AID
            event = _validateRip(serder, issuer=self.issuer)
        else:
            # Once bound, reuse the shared TEL validators against the already
            # known registry id and local habitat issuer.
            event = _validateRip(serder, issuer=self.issuer) if serder.ilk == Ilks.rip \
                else _validateUpdate(serder, regid=self.regk)

        # Validate that the event belongs to the same registry
        if self.regk is not None and event.regk != self.regk:
            raise ValidationError(f"registry event {event.said} does not belong "
                                  f"to {self.regk}")

        # Validate that the event's sequence number is not already accepted with a different SAID
        existing = self.store.seqEvent(event.regk, event.sn)
        if existing is not None and existing.said != event.said:
            raise ValidationError(f"conflicting registry event at "
                                  f"{event.regk}:{event.sn}")

        prior = None
        if event.ilk != Ilks.rip:
            # If the predecessor is already accepted locally, make the update's
            # p field prove it before we stage or replay anything.
            prior = self.store.seqEvent(event.regk, event.sn - 1)

            if prior is not None:
                _validateUpdate(event.serder, regid=event.regk, prior=prior.said)

        return event, existing, prior

    def _commit(self, event):
        """Accept one verified TEL event into the ordered local registry log.

        Parameters:
            event (_RegEventRecord): normalized TEL event already verified for
                registry membership, anchor presence, and ordering.

        Returns:
            SerderACDC: committed TEL event serder.
        """

        # Persist the winner into the ordered TEL and then clear all escrow
        # entries for that exact slot because the slot is now decided.
        self.store.accept(event.regk, event.sn, event.serder)
        for escrowdb in (self.store.baser.maes, self.store.baser.ooes):
            for (said,) in escrowdb.get(keys=event.regk, on=event.sn):
                escrowdb.rem(keys=event.regk, on=event.sn, val=said)

        # Update the registry key and digest
        self.regk = event.regk
        self.regd = event.said

        return event.serder

    def _discoverAnchor(self, event):
        """Find and persist the first verified local KEL seal for one TEL event.

        Parameters:
            event (_RegEventRecord): normalized TEL event whose local KEL
                anchor to discover.

        Returns:
            bool: True when an anchor is already stored or a newly discovered
                local KEL seal verifies and is persisted. False when no usable
                local sealing event is visible yet.
        """
        
        anchor = self.store.anchor(event.said)
        if anchor is not None:
            if _verifyAnchorCouple(event.serder, db=self.db, issuer=self.issuer,
                                   number=anchor[0], diger=anchor[1]):
                return True
            self.store.baser.ancs.rem(keys=event.said)

        couple = _scanKel(self.db, self.issuer, event.serder)
        if couple is None:
            return False
        self.store.putAnchor(event.said, Number(num=couple[0]), Diger(qb64=couple[1]))
        return True

    # Escrow replay helpers
    def _anchorWinnerKey(self, said):
        """Return the deterministic sibling winner key for one staged event.

        Parameters:
            said (str): SAID of the staged TEL event being ordered.

        Returns:
            tuple: sibling arbitration key ordered by earliest verified anchor,
                then diger, then event SAID.
        """
        anchor = self.store.anchor(said)
        if anchor is None:
            return float("inf"), "", said
        number, diger = anchor
        return number.sn, diger.qb64, said

    def _replayCandidate(self, said, sn):
        """Load and revalidate one escrowed TEL event for replay.

        Parameters:
            said (str): SAID of the escrowed TEL event.
            sn (int): escrow slot sequence number used to clear stale entries.

        Returns:
            tuple | None: ``(event, prior)`` for a replayable staged TEL event,
                or None when the escrow entry is unrecoverable and has been
                pruned.
        """
        serder = self.store.event(said)
        if serder is None:
            # A dangling escrow entry with no body cannot recover.
            self.store.clearEscrows(self.regk, sn, said)
            return None

        try:
            # Re-validate on replay so malformed staged data is pruned instead
            # of being retried forever.
            event, existing, prior = self._validateEvent(serder)
        except ValidationError:
            self.store.clearEscrows(self.regk, sn, said)
            return None

        if existing is not None and existing.said != said:
            # A different sibling has already claimed the accepted slot.
            self.store.clearEscrows(self.regk, sn, said)
            return None

        return event, prior

    def _processMissingAnchors(self):
        """Retry missing-anchor escrows using newly visible local KEL seals.

        Parameters:
            None

        Returns:
            None
        """
        if self.regk is None:
            return

        # Re-group by TEL sequence number so sibling candidates compete as a
        # set instead of in database iteration order.
        escrowed = {}
        for _, sn, said in self.store.baser.maes.getTopItemIter(keys=self.regk):
            escrowed.setdefault(sn, []).append(said)

        for sn in sorted(escrowed):
            candidates = []
            for said in escrowed[sn]:
                replay = self._replayCandidate(said, sn)
                if replay is None:
                    continue

                event, _ = replay
                # Replay is what lets a now-visible KEL seal move an event from
                # "missing anchor" toward acceptance.
                self._discoverAnchor(event)
                candidates.append(event.serder)

            # Order competing siblings by their earliest verified anchor so the
            # same event wins regardless of raw database iteration order.
            for serder in sorted(candidates, key=lambda serder: self._anchorWinnerKey(serder.said)):
                try:
                    # Re-enter the normal state machine so the candidate either
                    # commits, moves to ooes, or remains staged in maes.
                    self.processEvent(serder)
                except ValidationError:
                    self.store.clearEscrows(self.regk, sn, serder.said)

    def _processQueued(self):
        """Advance out-of-order escrows whose predecessors now exist locally.

        Parameters:
            None

        Returns:
            None
        """
        if self.regk is None:
            return

        while True:
            # Only the next sequence number after the accepted head can advance.
            sn = self.sn + 1
            queued = list(dict.fromkeys(
                said for escrow in (self.store.baser.maes, self.store.baser.ooes)
                for (said,) in escrow.get(keys=self.regk, on=sn)))
            if not queued:
                return

            # Discover every candidate before sorting: updates that arrived
            # before inception have no cached anchor yet.
            for said in queued:
                replay = self._replayCandidate(said, sn)
                if replay is not None:
                    self._discoverAnchor(replay[0])

            advanced = False
            # Use the same sibling winner policy here as missing-anchor replay
            # so queued and missing-anchor escrows resolve races identically.
            for said in sorted(queued, key=self._anchorWinnerKey):
                replay = self._replayCandidate(said, sn)
                if replay is None:
                    continue

                event, prior = replay
                # An update may precede inception, so its controller was
                # unknown at first intake. Discover its anchor on replay too.
                self._discoverAnchor(event)
                if self.store.anchor(said) is None:
                    self.store.escrowMissingAnchor(event.regk, event.sn, said)
                    self.store.baser.ooes.rem(keys=event.regk, on=event.sn, val=said)
                    continue

                # If the immediate predecessor still is not accepted, the event
                # remains queued for a later pass.
                if prior is None:
                    continue

                # Commit one event per pass, then loop so the next sequence slot
                # sees the updated accepted head.
                self._commit(event)
                advanced = True
                break

            if not advanced:
                return

    # Issuance helper
    def _effectiveFrontier(self):
        """Return the effective TEL frontier, including one staged successor chain.

        Returns:
            SerderACDC | None: accepted head event extended by a single
                unambiguous staged successor chain, or None when no accepted
                head exists yet.

        Raises:
            ConfigurationError: if multiple staged successors compete for the
                same next TEL sequence number.
        """
        
        # Start from the accepted TEL head and then walk forward through any
        # single unambiguous staged successor chain.
        tip = self.store.headEvent(self.regk) if self.regk is not None else None
        while tip is not None:
            tipEvent = _normalizeEventRecord(tip)
            sn = tipEvent.sn + 1
            saids = []
            seen = set()
            for escrowdb in (self.store.baser.maes, self.store.baser.ooes):
                for (said,) in escrowdb.get(keys=self.regk, on=sn):
                    # The same event may be observed across escrows during
                    # replay-heavy flows, so de-duplicate by SAID.
                    if said not in seen:
                        seen.add(said)
                        saids.append(said)

            matches = []
            for said in saids:
                staged = self.store.event(said)
                if staged is None:
                    continue
                stagedEvent = _normalizeEventRecord(staged)
                # Only events that point at the current frontier are eligible
                # to extend it for pipelined issuance.
                if stagedEvent.prior == tipEvent.said:
                    matches.append(stagedEvent)

            if not matches:
                break
            # Multiple staged successors at one slot mean the local staged TEL
            # has forked, so issuance fails closed instead of guessing.
            if len(matches) > 1:
                raise ConfigurationError(f"registry {self.regk} has conflicting staged successors at sn {sn}")
            tip = matches[0].serder

        return tip


class Rever:
    """Accept foreign native registries through the local registry event engine.

    Only accepted, fully witnessed controller KEL evidence can release an
    event from escrow. No local habitat, alias, or controller private key is
    required. Pending bodies and dependencies live in the ordinary RegBaser.
    """

    def __init__(self, *, db, reger):
        from .registering import RegistryStore
        self.db = db
        self.reger = reger
        self.store = RegistryStore(reger)

    def processEvent(self, serder, *, sscs=(), ssts=(), **kwa):
        """Return acceptance, or False after durably escrowing dependencies."""
        event = _normalizeEventRecord(serder)
        if event.ilk == Ilks.rip:
            _validateRip(event.serder)
            rip = event.serder
        else:
            _validateUpdate(event.serder, regid=event.regk)
            rip = self.store.event(event.regk)
            if rip is None:
                _validateSourceLocators(event.serder, db=self.db, issuer=None,
                                        sscs=sscs, ssts=ssts)
                self.store.putEvent(event.serder)
                self.store.escrowOutOfOrder(event.regk, event.sn, event.said)
                return False
            _validateRip(rip)

        engine = _RegEventer(db=self.db, issuer=rip.sad['i'],
                            store=self.store, regk=event.regk)
        return engine.processEvent(event.serder, sscs=sscs, ssts=ssts)

    def processEscrows(self):
        """Recover foreign work from durable escrow rows, including on reopen."""
        regks = set()
        for escrow in (self.reger.maes, self.reger.ooes):
            for keys, _, _ in escrow.getTopItemIter():
                regks.add(keys[0])
        for regk in sorted(regks):
            rip = self.store.event(regk)
            if rip is None:
                continue
            try:
                _validateRip(rip)
                engine = _RegEventer(db=self.db, issuer=rip.sad['i'],
                                    store=self.store, regk=regk)
                engine.processEscrows()
            except ValidationError as ex:
                logger.info("Invalid registry inception in escrow %s: %s", regk, ex)
