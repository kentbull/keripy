"""Native credential operations over existing Reger and Habery protocol records.

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
from base64 import b64encode

from keri.acdc import regeventing
from keri.acdc.ipexing import AcdcV2IpexVerification
from keri.core import Blinder, BoundState, Number, SerderACDC, Prefixer, Diger, Saider
from keri.kering import ConfigurationError, ValidationError
from keri.vdr.eventing import Reger
from .credential_disclosing import boundEvent


@dataclass
class IssuedCredential:
    """Read-only view of Reger credential bytes and source coordinates.

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


class Wallet:
    """Issued records and authenticated retained IPEX disclosure retrieval.

    Optional RegistryCustody is an explicit collaborator for callers that derive
    openings. Inventory itself never invokes it or reads encrypted salt records.
    """
    def __init__(self, hby, rgy, *, exc=None, reger=None, verification=None, custody=None):
        """Compose local inventory and ACDC v2 IPEX verification without loading secrets.

        Args:
            hby (Habery): Authenticated local identity and retained exchange owner.
            rgy (Regery): ACDC v2 registry evidence owner.
            exc (Exchanger | None): Router used to check retained completion.
            reger (Reger | None): Borrow an existing credential owner, or open one
                that this facade closes. Native and legacy bytes use its normal tables.
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
        self.reger = reger if reger is not None else Reger(
            name=hby.name, base=hby.base, temp=hby.db.temp, headDirPath=hby.db.headDirPath)
        self.ownsReger = reger is None

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

        Reuse the existing Reger credential/source/issuer tables. This boundary
        never derives an opening or loads private custody; the returned record
        is a view, not a second serialized issuance archive.
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
        old = self.issuedRecord(acdc.said)
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
        stored = self.reger.creds.get((acdc.said,))
        if stored is not None and stored.raw != acdc.raw:
            raise ValidationError('different credential bytes already occupy the Reger identifier')
        if proof is not None:
            self.reger.retainPrivateOpening(event, proof)
        # Reuse Reger.logCred's credential/source representation and its normal
        # issuer index. One native LMDB transaction exposes the complete record;
        # no application rollback, retry journal or duplicate byte archive exists.
        source = (Prefixer(qb64=regid), Number(num=sn), Diger(qb64=update))
        with self.reger.env.begin(write=True) as txn:
            txn.put(self.reger.creds._tokey((acdc.said,)), self.reger.creds._ser(acdc),
                    db=self.reger.creds.sdb, overwrite=False)
            txn.put(self.reger.cancs._tokey((acdc.said,)), self.reger.cancs._ser(source),
                    db=self.reger.cancs.sdb, overwrite=False)
            txn.put(self.reger.issus._tokey((acdc.israid,)), self.reger.issus._ser(Saider(qb64=acdc.said)),
                    db=self.reger.issus.sdb, dupdata=False)
        return record

    def issuedRecord(self, credential):
        """Read a native issuance view from existing Reger credential/source tables.

        Args:
            credential (str): Exact credential identifier.

        Returns:
            IssuedCredential | None: Local native issuance view, or None when no
                native source exists. Legacy credentials remain untouched.

        Raises:
            ValidationError: Retained source coordinates disagree with accepted TEL.

        Raw bytes are serialized for the existing CLI view only; there is no
        base64 credential row. Bound coordinates are read from the exact
        retained CESR proof rather than a separate derivation metadata record.
        """
        acdc = self.reger.creds.get((credential,))
        source = self.reger.cancs.get((credential,))
        if (acdc is None or acdc.pvrsn.major != 2 or source is None
                or self.hby.habByPre(acdc.israid) is None):
            return None
        prefixer, number, diger = source
        event = self.rgy.store.seqEvent(prefixer.qb64, number.num)
        if event is None or event.said != diger.qb64:
            raise ValidationError('issued source is not an accepted registry event')
        proof = self.reger.privateOpening(event)
        bound = dict(bn=proof.bsn, bd=proof.bd) if proof is not None and proof.bsn is not None else {}
        return IssuedCredential(acdc.said, prefixer.qb64, acdc.israid, diger.qb64,
                                b64encode(acdc.raw).decode('ascii'), 'base64', bound)

    def issuedRecords(self):
        """Return local native issuances selected by Reger's existing issuer index.

        Returns:
            list[IssuedCredential]: Views of locally controlled native credentials.
                Legacy and foreign credentials are not treated as local issuances.
        """
        records = []
        for (issuer,), said in self.reger.issus.getTopItemIter():
            if self.hby.habByPre(issuer) is None:
                continue
            record = self.issuedRecord(said.qb64)
            if record is not None:
                records.append(record)
        return records

    def issuedCredential(self, credential):
        """Return exact native credential bytes retained by the existing Reger.

        Args:
            credential (str): Locally issued credential identifier.

        Returns:
            SerderACDC: Original serialization, including CBOR or MessagePack.

        Raises:
            ValidationError: The local native issuance source is missing or invalid.

        Retrieval is historical and makes no current-standing claim.
        """
        if self.issuedRecord(credential) is None:
            raise ValidationError('issued credential with a supported encoding is required')
        return self.reger.creds.get((credential,))

    def inventory(self):
        """Combine issued Reger records and historical signed IPEX admission views.

        Returns:
            dict: Issued records and held views, without a second consent index
                or a claim about current credential standing.
        """
        return {'issued': self.issuedRecords(),
                'held': self.verification.admissions()}

    def close(self):
        """Close this wallet's application environment after dependent work stops.

            Returns:
                None. Habery/Regery and a borrowed Reger remain caller-owned.
                An internally opened Reger closes here. RegistryCustody uses
                the independently owned Keeper; no secret is exported."""
        if self.ownsReger:
            self.reger.close()
