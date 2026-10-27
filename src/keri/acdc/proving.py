"""Exact presented disclosures and accepted KEL/TEL evidence shared by callers.

These operations borrow the caller's Habery and Regery. They open no stores,
fetch no evidence, and make no application graph-policy judgment.
"""
from dataclasses import dataclass

from ..core import BlindState, Blinder, BoundState, Number, Prefixer
from ..kering import (ConfigurationError, Ilks, MisbindingError, MissingAnchorError,
                      MissingChainError, MissingSenderKeyStateError, UnverifiedBlindError)
from ..peer.exchanging import verifyAttachments


@dataclass(frozen=True)
class PresentedEvidence:
    """Borrow exact node attachments and accepted histories from one evidence owner.

    ``hby`` supplies verified KEL state; optional ``rgy`` supplies accepted TEL
    history. The caller retains lifecycle ownership of both stores.
    """
    hby: object
    rgy: object = None

    def verifySourceAnchor(self, serder, aid, number, diger):
        """Verify one source reference against the anchorer's accepted KEL."""
        prefixer = Prefixer(qb64=aid)
        _, _, seals, invalid, missing = verifyAttachments(
            hby=self.hby,
            serder=serder,
            sourceSeals=[(prefixer, number, diger)],
        )
        if missing:
            raise MissingSenderKeyStateError(
                f"missing KEL event at sn={number.sn} for {aid}")

        return not invalid and bool(seals)


    def graphRegistry(self, serder, nest):
        """Resolve a disclosed registry declaration or explicit one-way source.

        Args:
            serder (SerderACDC): Exact disclosed node, never a fuller cached view.
            nest: Parsed node-local source triples used for one-way bindings.

        Returns:
            str | None: Declared registry, otherwise a unique non-KEL source identifier.
            Ambiguous or absent source references do not select a registry.

        Raises:
            MisregistryError: Disclosed protected sections disagree on the issuer registry."""
        from .regeventing import issuerRegistry
        regk = issuerRegistry(serder)
        if regk:
            return regk
        parsed = nest if isinstance(nest, dict) else nest.__dict__
        references = {prefixer.qb64 for prefixer, _, _ in parsed.get('ssts', [])
                      if prefixer.qb64 != serder.israid and prefixer.qb64 not in self.hby.kevers}
        return next(iter(references)) if len(references) == 1 else None


    @staticmethod
    def blindProofs(nest):
        """Rebuild all parsed node-local blind disclosures as Blinders."""
        # Read sequenced blind disclosures from the parsed node.
        bsqs = nest.get("bsqs", []) if isinstance(nest, dict) else nest.bsqs

        # Read bound blind disclosures from the parsed node.
        bsss = nest.get("bsss", []) if isinstance(nest, dict) else nest.bsss

        # Rebuild each sequenced disclosure as a BlindState proof.
        proofs = []
        for proof in bsqs:
            stream = b''.join(item.qb64b for item in proof)
            proofs.append(Blinder(clan=BlindState, qb64=stream))

        # Rebuild each bound disclosure as a BoundState proof.
        for proof in bsss:
            stream = b''.join(item.qb64b for item in proof)
            proofs.append(Blinder(clan=BoundState, qb64=stream))

        # Return every proof attached to this one ACDC node.
        return proofs


    def registryEvidence(self, regk, *, proofs=None, target=None, acdc=None):
        """Load accepted history, optionally selecting its unique retained-proof prefix.

        Only None selects current/full history. Every retained opening binding
        target must identify one accepted BUP; the highest selects the prefix.
        Vacuous openings can authenticate its interior but do not select a head.
        Other-target presentation proofs and generic node source locators do not
        select issuer history. Historical selection requires the exact disclosed
        ACDC matching target, including for bound-coordinate checks. The caller
        still authenticates the selected prefix.
        """
        # Registry verification requires an injected local Regery.
        if self.rgy is None:
            return None

        # Load the registry inception and current accepted head.
        rip = self.rgy.store.seqEvent(regk, 0)
        head = self.rgy.store.headEvent(regk)

        # Missing either of them mean the local TEL chain is incomplete.
        if rip is None or head is None:
            raise MissingChainError(f"missing local TEL evidence for registry {regk}")

        # Rebuild the contiguous accepted update chain in sequence order.
        updates = []
        for sn in range(1, Number(numh=head.sad["n"]).num + 1):

            # Load the accepted event at this sequence number.
            update = self.rgy.store.seqEvent(regk, sn)

            # A sequence gap must be retrieved before retrying.
            if update is None:
                raise MissingChainError(f"missing local TEL update {sn} for registry {regk}")

            # Preserve this contiguous update for TEL verification.
            updates.append(update)

        if proofs is not None:
            from .regeventing import vetBlind, vetBound
            proofs = list(proofs)
            if not proofs:
                raise UnverifiedBlindError('historical registry proof is empty')
            if acdc is None or target != acdc.said:
                raise ConfigurationError('historical registry selection requires its target ACDC')
            # Invalid/duplicate evidence wins over a missing target dependency,
            # regardless of the sender's attachment ordering.
            for proof in proofs:
                vetBlind(proof, blid=proof.said)
            if len({proof.said for proof in proofs}) != len(proofs):
                raise UnverifiedBlindError('duplicate historical registry opening')
            missingBound = None
            for proof in proofs:
                if proof.acdc not in (target, ''):
                    continue
                try:
                    vetBound(proof, acdc=acdc, db=self.hby.db)
                except MissingAnchorError as error:
                    missingBound = error
            selected = []
            missing = False
            for proof in proofs:
                if proof.acdc != target:
                    continue
                matches = [event for event in updates
                           if event.ilk == Ilks.bup and event.sad['b'] == proof.said]
                if len(matches) > 1:
                    raise UnverifiedBlindError('ambiguous historical TEL event for retained BLID')
                if matches:
                    selected.append(matches[0])
                else:
                    missing = True
            if missingBound is not None:
                raise MissingChainError('retained registry proof is missing bound KEL evidence') from missingBound
            if missing:
                raise MissingChainError(f'missing accepted TEL event for retained registry {regk} proof')
            if not selected:
                raise MisbindingError('historical registry proof has no target-binding opening')
            ordinal = max(Number(numh=event.sad['n']).num for event in selected)
            updates = [event for event in updates if Number(numh=event.sad['n']).num <= ordinal]

        # Return the complete local chain.
        return rip, updates
