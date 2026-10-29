"""Explicit ACDC v2 credential inventory over ordinary LMDB application records.

Private derivation custody is an optional registry_custody collaborator. Ordinary
issued/admitted inventory and retained disclosure retrieval never load its salt.

Protocol acceptance remains in KERIpy's registry and IPEX processors. Admissions
are views of ordinary authenticated Grant/Admit pairs, not a separate ledger.
The exns/erpy records are owned by the existing Exchanger.logEvent path.
The original issued/admitted reference model was adapted from KERI Foundation Locksmith
3a5ad9ebcf98b4ec03baf1bbb91d928d49c168e4 (Apache-2.0 LICENSE; its package metadata
incorrectly declares MIT). No Locksmith runtime or GUI dependency is used.
"""
from dataclasses import dataclass, field
from base64 import b64encode, b64decode

from keri.acdc import regeventing
from keri.acdc.ipexing import AcdcV2IpexVerification
from keri.core import Blinder, BoundState, Number, SerderACDC
from keri.db import dbing, koming
from keri.kering import ConfigurationError, ValidationError
from keri.peer import exchanging
from .credential_disclosing import boundEvent


@dataclass
class IssuedCredential:
    """Durable issued-history reference plus exact original credential bytes.

        credential/registry/controller/update bind accepted issuance. raw is base64
        under encoding='base64'; bound retains original issuee KEL coordinates for
        explicitly supplied bound openings, never a salt or current-standing claim."""
    credential: str
    registry: str
    controller: str
    update: str
    raw: str
    encoding: str
    bound: dict = field(default_factory=dict)


@dataclass
class DerivedUpdate:
    """Non-secret coordinates needed to reproduce one derived registry opening."""
    credential: str
    state: str
    bound: dict = field(default_factory=dict)


@dataclass
class AdmittedCredential:
    """Explicit local consent to one exact grant/admit disclosure pair.

        credential and holder identify its origin/recipient; grant and admit retain
        exchange provenance. admitted is the signed Admit timestamp, not a local
        observation or issuer-publication time."""
    credential: str
    grant: str
    admit: str
    holder: str
    admitted: str


class WalletBaser(dbing.LMDBer):
    """Remaining issuer records; signed admission state stays in Habery."""
    TailDirPath = 'keri/wallet'
    AltTailDirPath = '.keri/wallet'

    def reopen(self, **kwa):
        """Open credential inventory without private salt storage.

            Args:
                **kwa: Ordinary LMDBer path/reopen settings.

            Returns:
                bool: Whether the application environment is open.

            Issued credential bytes and derivation coordinates remain here.
            Admissions are read from ordinary signed IPEX exchanges; private
            registry salts belong to the existing Keeper."""
        super().reopen(**kwa)
        self.issued = koming.Komer(db=self, subkey='issued.', klas=IssuedCredential)
        self.derivations = koming.Komer(db=self, subkey='derived-updates.', klas=DerivedUpdate)
        return self.opened


class Wallet:
    """Issued records and authenticated retained IPEX disclosure retrieval.

    Optional RegistryCustody is an explicit collaborator for callers that derive
    openings. Inventory itself never invokes it or reads encrypted salt records.
    """
    def __init__(self, hby, rgy, *, exc=None, db=None, verification=None, custody=None):
        """Compose local inventory and ACDC v2 IPEX verification without loading secrets.

        Args:
            hby (Habery): Authenticated local identity and retained exchange owner.
            rgy (Regery): ACDC v2 registry evidence owner.
            exc (Exchanger | None): Router used to check retained completion.
            db (WalletBaser | None): Existing credential inventory store, or create one.
            verification (AcdcV2IpexVerification | None): Explicit context returned by
                app.ipexing.loadHandlers for ACDC v2. None uses ordinary default policy;
                configured applications must pass their actual shared context.
            custody (RegistryCustody | None): Explicit optional private capability.
                None is normal for ordinary holders and public-only issuers.

        Returns:
            None
        """
        self.hby, self.rgy, self.exc = hby, rgy, exc
        self.custody = custody
        self.verification = (verification if verification is not None
                             else AcdcV2IpexVerification(hby, rgy))
        self.db = db if db is not None else WalletBaser(
            name=hby.name, base=hby.base, temp=hby.temp)

    def boundEvent(self, acdc, said):
        """Resolve a selected accepted, witnessed issuee KEL event for derivation.

            Args:
                acdc (SerderACDC): Credential defining the issuee whose KEL is referenced.
                said (str): Exact selected issuee event digest, not today's implicit head.

            Returns:
                dict: Explicit bound=True, sequence number, and digest for opening creation.

            Raises:
                ValidationError: Event is missing, unaccepted, or not fully witnessed.

            This public evidence lookup loads no custody and does not derive an opening."""
        return boundEvent(self.hby, acdc, said)

    def retainPublicOpening(self, event, blinder):
        """Retain one explicitly public event opening without creating custody.

        The opening is authenticated against the exact ``bup`` commitment before
        storage. Repeated identical publication is idempotent; a rival opening for
        the same TEL event is refused. This table contains per-event public proof,
        never a reusable derivation salt.
        """
        if event is None or event.ilk != 'bup' or not isinstance(blinder, Blinder):
            raise ValidationError('public opening requires an ACDC v2 blinded update')
        regeventing.vetBlind(blinder, blid=event.sad['b'])
        old = self.rgy.store.opening(event.said)
        if old is not None and old != blinder.qb64:
            raise ValidationError('different public opening is already retained for this event')
        # Authoring retains the opening before the event enters normal TEL
        # processing. This row alone never establishes event acceptance.
        self.rgy.store.baser.openings.pin((event.said,), blinder.qb64)
        return blinder

    def publicOpening(self, event):
        """Return the authenticated retained public opening for ``event``, if any."""
        if event is None or event.ilk != 'bup':
            return None
        qb64 = self.rgy.store.opening(event.said)
        if qb64 is None:
            return None
        candidates = regeventing._blindCandidates(qb64)
        if len(candidates) != 1:
            raise ValidationError('retained public opening is ambiguous')
        blinder = candidates[0]
        regeventing.vetBlind(blinder, blid=event.sad['b'])
        return blinder

    def retainDerivedUpdate(self, event, blinder):
        """Retain non-secret coordinates for exact future derivation of ``event``."""
        if event is None or event.ilk != 'bup' or not isinstance(blinder, Blinder):
            raise ValidationError('derived update requires an ACDC v2 blinded update')
        regeventing.vetBlind(blinder, blid=event.sad['b'])
        bound = (dict(bn=blinder.bsn, bd=blinder.bd) if blinder.bsn is not None else {})
        record = DerivedUpdate(blinder.acdc, blinder.state, bound)
        old = self.db.derivations.get((event.said,))
        if old is not None and old != record:
            raise ValidationError('different derivation coordinates are already retained for this event')
        self.db.derivations.pin((event.said,), record)
        return record

    def recordIssued(self, acdc, update, *, blinder=None):
        """Record verified issuance, or return an identical historical record.

        Args:
            acdc (SerderACDC): Exact issued credential view retained as bytes.
            update (str): Accepted issuance event SAID in its registry.
            blinder (Blinder | None): Explicit opening required for fresh blinded
                issuance. Derived and supplied openings use the same core verifier.

        Returns:
            IssuedCredential: Newly verified issuance or identical retained history.
                A history retry without an opening makes no current-standing claim.

        Raises:
            ConfigurationError: Fresh blinded recording lacks an explicit opening.
            ValidationError: Ownership, accepted event, proof, or retained bytes differ.
            KeriError: Core registry/KEL/opening authentication fails.

        This inventory boundary never derives an opening or loads private custody.
        """
        event = self.rgy.store.event(update)
        regid = regeventing.issuerRegistry(acdc)
        if regid is None and event is not None:
            regid = event.sad.get('rd')  # explicitly supplied one-way issuance
        rip = self.rgy.store.seqEvent(regid, 0) if regid else None
        if rip is None or event is None or self.hby.habByPre(rip.sad['i']) is None:
            raise ValidationError('local accepted issuance evidence is required')
        sn = Number(numh=event.sad['n']).num
        accepted = self.rgy.store.seqEvent(regid, sn)
        if accepted is None or accepted.said != update:
            raise ValidationError('issuance update is still pending')
        old = self.db.issued.get((acdc.said,))
        if blinder is not None and (event.ilk != 'bup' or not isinstance(blinder, Blinder)):
            raise ValidationError('explicit issuance opening requires an ACDC v2 blinded update')
        if old is not None and blinder is None:
            # Exact retained history can be inspected after custody loss/rotation.
            # This is not a fresh proof or current-standing assertion.
            expected = IssuedCredential(acdc.said, regid, rip.sad['i'], update,
                b64encode(acdc.raw).decode('ascii'), 'base64', old.bound)
            if old != expected or event.ilk not in ('upd', 'bup'):
                raise ValidationError('different issuance is already retained for this credential')
            return old
        if event.ilk == 'bup' and blinder is None:
            raise ConfigurationError('fresh blinded issuance requires an explicit event opening')
        proof = blinder if event.ilk == 'bup' else None
        updates = [self.rgy.store.seqEvent(regid, ordinal) for ordinal in range(1, sn + 1)]
        verified = regeventing.vet(rip, updates, db=self.hby.db, acdc=acdc, blinder=proof)
        if verified.state != 'issued':
            raise ValidationError('referenced update is not an issued state')
        record = IssuedCredential(acdc.said, regid, rip.sad['i'], update,
                                  b64encode(acdc.raw).decode('ascii'), 'base64',
                                  dict(bn=proof.data.bn.num, bd=proof.data.bd.qb64)
                                  if proof is not None and proof.clan == BoundState else {})
        if old is not None and old != record:
            raise ValidationError('different issuance is already retained for this credential')
        self.db.issued.put((acdc.said,), record)
        return record

    def issuedCredential(self, credential):
        """Reconstruct the exact originally issued credential bytes.

            Args:
                credential (str): Issued credential SAID indexing a durable inventory row.

            Returns:
                SerderACDC: Original view, including its binary serialization kind.

            Raises:
                ValidationError: Row/encoding is unsupported or bytes do not match its SAID.
                ValueError: Corrupt stored base64 cannot be decoded.

            Retrieval is historical and never infers present registry standing."""
        record = self.db.issued.get((credential,))
        if record is None or record.encoding != 'base64':
            raise ValidationError('issued credential with a supported encoding is required')
        raw = b64decode(record.raw, validate=True)
        acdc = SerderACDC(raw=raw)
        if acdc.raw != raw or acdc.said != credential:
            raise ValidationError('issued credential bytes do not match their retained identifier')
        return acdc

    def _verification(self):
        """Return the concrete ACDC v2 IPEX context for fresh semantic acceptance.

        Returns:
            AcdcV2IpexVerification: Configured proof-and-policy validation context.

        Raises:
            ConfigurationError: Context is arbitrary or belongs to another owner.
        """
        context = self.verification
        if (type(context) is not AcdcV2IpexVerification or context.hby is not self.hby
                or context.rgy is not self.rgy):
            raise ConfigurationError('configured concrete ACDC v2 IPEX verification is required')
        return context

    def _admission(self, grant, admit, *, historical):
        """Read one authenticated local Grant/Admit pair from exchange storage.

        Args:
            grant (str): Retained Grant identifier.
            admit (str): Retained Admit identifier.
            historical (bool): Select retained TEL prefixes for inspection.

        Returns:
            AdmittedCredential: A view of signed consent, never a new stored row.

        Raises:
            ValidationError: Signature, recipient, response linkage or credential
                proof is invalid. Evidence dependency errors propagate.

        A signed local Admit is the consent artifact. Neither receipt of a Grant
        nor a notification supplies consent. This view asserts no graph-policy
        decision; fresh use must separately evaluate the configured policy.
        """
        gexn, aexn = self.hby.db.exns.get((grant,)), self.hby.db.exns.get((admit,))
        for said, exn, route in ((grant, gexn, '/ipex/grant'), (admit, aexn, '/ipex/admit')):
            if (exn is None or exn.said != said or exn.route != route or exn.pvrsn.major != 2):
                raise ValidationError('accepted ACDC v2 IPEX evidence is required')
        holder = gexn.sad.get('ri')
        response = self.hby.db.erpy.get((grant,))
        if (self.hby.habByPre(holder) is None or aexn.pre != holder or aexn.sad.get('p') != grant
                or aexn.sad.get('ri') != gexn.pre or response is None or response.qb64 != admit):
            raise ValidationError('admit must be the local intended holder response to this grant')
        origins = gexn.sad['a'].get('o')
        if not isinstance(origins, list) or len(origins) != 1:
            raise ValidationError('admission requires one disclosed origin credential')
        verification = self._verification()
        for route, message in (('/ipex/grant', gexn), ('/ipex/admit', aexn)):
            if not verification.verifyAccepted(message.said, route, historical=historical):
                raise ValidationError('ACDC v2 IPEX semantic acceptance is required before admission')
        return AdmittedCredential(origins[0], grant, admit, holder, aexn.sad['dt'])

    def recordAdmission(self, grant, admit, *, consent=False):
        """Validate fresh admission without a second application consent ledger.

        Args:
            grant (str): Retained Grant identifier.
            admit (str): Holder-signed response identifier.
            consent (bool): Explicit local approval for this fresh validation.

        Returns:
            AdmittedCredential: View of the already signed and retained pair.

        Raises:
            ValidationError: Consent, authentication or current graph policy fails.

        The existing Exchanger owns persistence. Repeating this operation creates
        no record, index, journal or delivery authorization. Current policy is
        checked every time; use heldCredential for historical inspection.
        """
        if consent is not True:
            raise ValidationError('explicit consent is required before admission')
        record = self._admission(grant, admit, historical=False)
        if self._verification().evaluateGrant(grant) is not True:
            raise ValidationError('ACDC v2 graph semantic acceptance is required before admission')
        return record

    def heldCredential(self, grant):
        """Read one admitted grant's exact retained proof without merging later views.

            Args:
                grant (str): Grant SAID with existing explicit local consent.

            Returns:
                dict: Exact credential, serialized origin proof, other original artifacts,
                    retained grant, and admit SAID. No cached fuller section is substituted.

            Raises:
                ValidationError: Consent, authenticated exchange evidence, or origin is absent.
                ConfigurationError: Concrete protocol verification context is unavailable.

            Current graph policy and private custody are unnecessary for historical proof
            retrieval; onward acceptance still invokes the receiving semantic verifier."""
        response = self.hby.db.erpy.get((grant,))
        if response is None:
            raise ValidationError('this grant has no signed local admission')
        record = self._admission(grant, response.qb64, historical=True)
        exn = self.hby.db.exns.get((grant,))
        nests = exchanging.loadParsedNestedSubstreams(self.hby, grant)
        for nest in nests:
            if nest.serder.said == record.credential:
                return {'credential': nest.serder,
                        'proof': exchanging.serializeParsedSubstream(nest),
                        'artifacts': [exchanging.serializeParsedSubstream(other) for other in nests
                                      if other.serder.said != record.credential],
                        'grant': exn, 'admit': record.admit}
        raise ValidationError('admitted grant origin evidence is missing')

    def inventory(self):
        """List issued records and authenticated local IPEX admissions.

        Returns:
            dict: Issued records and held Grant/Admit views. The latter come from
                ordinary exchange storage, not an application consent index.

        Listing is historical inspection, not current standing or graph-policy
        acceptance. Invalid or unrelated responses are not held credentials.
        """
        held = []
        for (grant,), response in self.hby.db.erpy.getTopItemIter():
            exn = self.hby.db.exns.get((response.qb64,))
            if (exn is None or exn.route != '/ipex/admit' or exn.pvrsn.major != 2
                    or self.hby.habByPre(exn.pre) is None):
                continue
            try:
                held.append(self._admission(grant, response.qb64, historical=True))
            except ValidationError:
                continue
        return {'issued': [record for _, record in self.db.issued.getTopItemIter()],
                'held': held}

    def admissions(self, credential):
        """Return authenticated local Grant/Admit views for a credential SAID.

        Args:
            credential (str): Credential commitment, possibly disclosed in several views.

        Returns:
            list[AdmittedCredential]: Separate signed consents; no views are merged.
        """
        return [record for record in self.inventory()['held'] if record.credential == credential]

    def close(self):
        """Close this wallet's application environment after dependent work stops.

            Returns:
                None. Habery/Regery remain caller-owned. RegistryCustody uses
                the independently owned Keeper; no secret is exported."""
        self.db.close()
