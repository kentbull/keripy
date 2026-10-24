"""Compose event-specific ACDC v2 registry proofs from explicit capabilities.

Extracted from ExchangeDoer.registryOrigin at a6539208. The application supplies
retained openings and, only when selected, a derivation callable. This module
has no CLI, wallet database, secret storage, or network lifecycle dependency.
"""
from keri import Vrsn_2_0
from keri.acdc.regeventing import (issuerRegistry, requireSupportedEvent,
                                   vetBlind, vetBound)
from keri.core import Counter, Codens, Number, SealEvent, messagize
from keri.kering import ConfigurationError, ValidationError


def registryProof(hby, rgy, credential, regid, *, retained=(), derive=None):
    """Return unchanged credential bytes with proofs for its accepted TEL state.

    Args:
        hby: Verified supporting KEL owner, used for bound-opening validation.
        rgy: Accepted registry store owner.
        credential: Exact retained disclosure; no cached attributes are expanded.
        regid: Selected issuer registry, including an external registry reference.
        retained: Event-specific Blinders already possessed by the presenter.
        derive: Optional callable(update, target, state) returning a Blinder using
            explicitly provisioned custody. None is ordinary held-material use.

    Returns:
        bytes: Credential and verified opening/source attachments. Public updates
            receive an empty attachment group, not an invented blinding factor.

    Raises:
        ConfigurationError: Missing history/opening, wrong target or no binding.
        KeriError: Core blind/bound validation fails. Derivation failures propagate
            only when the operation explicitly uses that capability.

    Walk from the accepted head through vacuous updates to the credential binding.
    Supplied proof matching is exact by BLID; neither timestamps nor salt possession
    can manufacture accepted history or reveal missing credential attributes.
    """
    head = rgy.store.headEvent(regid)
    if head is None:
        raise ConfigurationError('registry evidence has not been acquired')
    for ordinal in range(Number(numh=head.sad['n']).num + 1):
        event = rgy.store.seqEvent(regid, ordinal)
        if event is None:
            raise ConfigurationError('accepted registry history is incomplete')
        requireSupportedEvent(event)
    retained = list(retained)
    bonds, binding = [], None
    for ordinal in range(Number(numh=head.sad['n']).num, 0, -1):
        update = rgy.store.seqEvent(regid, ordinal)
        if update is None:
            raise ConfigurationError('accepted registry history is incomplete')
        found = next((proof for proof in retained if proof.said == update.sad['b']), None)
        if found is None and derive is not None:
            for target, state in ((credential.said, 'issued'), (credential.said, 'revoked'), ('', '')):
                proof = derive(update, target, state)
                if proof.said == update.sad['b']:
                    found = proof
                    break
        if found is None:
            raise ConfigurationError('current registry opening unavailable; supply --opening or provision custody and use --derive')
        target, _ = vetBlind(found, blid=update.sad['b'])
        if target and target != credential.said:
            raise ConfigurationError('registry opening binds a different credential')
        vetBound(found, acdc=credential, db=hby.db)
        bonds.append(found.data)
        if found.acdc:
            binding = update
            break
    if binding is None:
        raise ConfigurationError('registry has no disclosed non-vacuous credential binding')
    if issuerRegistry(credential) is None:
        bonds.append(SealEvent(i=regid, s=binding.sad['n'], d=binding.said))
    return (messagize(credential, bonds=bonds, gvrsn=Vrsn_2_0) if bonds else
            credential.raw + Counter(Codens.AttachmentGroup, count=0, version=Vrsn_2_0).qb64b)


def boundEvent(hby, acdc, said):
    """Resolve an exact accepted, fully witnessed issuee KEL event.

    Args:
        hby: Owner of verified KEL evidence; no wallet or secret store is needed.
        acdc: Credential defining the issuee whose event is selected.
        said: Explicit event digest, never an implicit substitution of current head.

    Returns:
        dict: Bound-opening derivation options with exact sequence and digest.

    Raises:
        ValidationError: Missing, unaccepted or insufficiently witnessed event.

    Extracted unchanged from Wallet.boundEvent at aef3013d. Historical selection
    is valid for reproducing an existing opening; authoring a new bound update
    separately requires the known current issuee event.
    """
    issuee = acdc.iseaid
    event = hby.db.evts.get((issuee, said)) if issuee else None
    if (event is None or hby.db.kels.getLast(keys=issuee, on=event.sn) != said
            or not hby.db.fullyWitnessed(event)):
        raise ValidationError('bound reference requires an accepted witnessed issuee KEL event')
    return dict(bound=True, bsn=event.sn, bd=event.said)
