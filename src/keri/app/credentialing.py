"""Explicit native credential inventory over ordinary LMDB application records.

Private derivation custody is an optional registry_custody collaborator. Ordinary
issued/admitted inventory and retained disclosure retrieval never load its salt.

Protocol acceptance remains in KERIpy's registry and IPEX processors. The small
issued/admitted reference model is adapted from KERI Foundation Locksmith
3a5ad9ebcf98b4ec03baf1bbb91d928d49c168e4 (Apache-2.0 LICENSE; its package metadata
incorrectly declares MIT). No Locksmith runtime or GUI dependency is used.
"""
from dataclasses import dataclass, field
from base64 import b64encode, b64decode

from keri.acdc import regeventing
from keri.acdc.ipexing import NativeVerification
from keri.core import Blinder, BoundState, Number, SerderACDC
from keri.db import dbing, koming, subing
from keri.help import helping
from keri.kering import ConfigurationError, ValidationError
from keri.peer import exchanging
from .registry_custody import EncryptedCustody


@dataclass
class IssuedCredential:
    credential: str
    registry: str
    controller: str
    update: str
    raw: str
    encoding: str
    bound: dict = field(default_factory=dict)


@dataclass
class AdmittedCredential:
    credential: str
    grant: str
    admit: str
    holder: str
    admitted: str


class WalletBaser(dbing.LMDBer):
    """Application records; no secret or consent state belongs in public RegBaser."""
    TailDirPath = 'keri/wallet'
    AltTailDirPath = '.keri/wallet'

    def reopen(self, **kwa):
        super().reopen(**kwa)
        self.custody = koming.Komer(db=self, subkey='custody.', klas=EncryptedCustody)
        self.issued = koming.Komer(db=self, subkey='issued.', klas=IssuedCredential)
        self.admitted = koming.Komer(db=self, subkey='admitted.', klas=AdmittedCredential)
        # The index is rebuildable from admitted records, but is committed with them.
        self.credentials = subing.Suber(db=self, subkey='credential-grants.')
        return self.opened


class Wallet:
    """Local issued/admitted references and immutable retained disclosure retrieval.

    Optional RegistryCustody is an explicit collaborator for callers that derive
    openings. Inventory itself never invokes it or reads encrypted salt records.
    """
    def __init__(self, hby, rgy, *, exc=None, db=None, verification=None, custody=None):
        """Compose local inventory and native verification without loading secrets.

        Args:
            hby (Habery): Authenticated local identity and retained exchange owner.
            rgy (Regery): Native registry evidence owner.
            exc (Exchanger | None): Router used to check retained completion.
            db (WalletBaser | None): Existing inventory/custody store, or create one.
            verification (NativeVerification | None): Explicit context returned by
                native/app IPEX loadHandlers. None uses ordinary default policy;
                configured applications must pass their actual shared context.
            custody (RegistryCustody | None): Explicit optional private capability.
                None is normal for ordinary holders and public-only issuers.

        Returns:
            None
        """
        self.hby, self.rgy, self.exc = hby, rgy, exc
        self.custody = custody
        self.verification = (verification if verification is not None
                             else NativeVerification(hby, rgy))
        self.db = db if db is not None else WalletBaser(
            name=hby.name, base=hby.base, temp=hby.temp)

    def boundEvent(self, acdc, said):
        """Resolve an explicitly selected accepted issuee event for bound derivation."""
        issuee = acdc.iseaid
        event = self.hby.db.evts.get((issuee, said)) if issuee else None
        if (event is None or self.hby.db.kels.getLast(keys=issuee, on=event.sn) != said
                or not self.hby.db.fullyWitnessed(event)):
            raise ValidationError('bound reference requires an accepted witnessed issuee KEL event')
        return dict(bound=True, bsn=event.sn, bd=event.said)

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
            raise ValidationError('explicit issuance opening requires a native blinded update')
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
        """Reconstruct exact issued bytes, including native binary serializations."""
        record = self.db.issued.get((credential,))
        if record is None or record.encoding != 'base64':
            raise ValidationError('issued credential with a supported encoding is required')
        raw = b64decode(record.raw, validate=True)
        acdc = SerderACDC(raw=raw)
        if acdc.raw != raw or acdc.said != credential:
            raise ValidationError('issued credential bytes do not match their retained identifier')
        return acdc

    def _accepted(self, said, route):
        if self.exc is None or self.exc.hby is not self.hby or route not in self.exc.routes:
            raise ConfigurationError('the wallet requires its actual IPEX Exchanger')
        exn = self.hby.db.exns.get((said,))
        if (exn is None or exn.said != said or exn.route != route
                or exn.pvrsn.major != 2 or not self.exc.complete(said)):
            raise ValidationError('accepted native IPEX evidence is required')
        exchanging.verify(self.hby, exn)
        return exn

    def _verification(self):
        """Return the concrete native context for fresh semantic acceptance.

        Returns:
            NativeVerification: Configured proof-and-policy validation context.

        Raises:
            ConfigurationError: Context is arbitrary or belongs to another owner.
        """
        context = self.verification
        if (type(context) is not NativeVerification or context.hby is not self.hby
                or context.rgy is not self.rgy):
            raise ConfigurationError('configured concrete native IPEX verification is required')
        return context

    def recordAdmission(self, grant, admit, *, consent=False):
        """Record explicit local consent to an actual accepted grant/admit pair.

        Generic EXN storage is insufficient. New wallet admissions use the core's
        idempotent retained-IPEX validation as well as authenticated messages and
        actual response linkage. An existing consent record remains history;
        reading it does not promise current credential standing.

        Args:
            grant (str): Retained grant SAID with exactly one disclosed origin.
            admit (str): Retained response SAID signed by its local holder.
            consent (bool): Explicit True is required for local retention.

        Returns:
            AdmittedCredential: Existing identical consent or newly persisted row.

        Raises:
            ValidationError: Consent, evidence, response linkage, or current native
                semantic acceptance is invalid.
            ConfigurationError: Exchange or concrete verification owner is absent.
        """
        if consent is not True:
            raise ValidationError('explicit consent is required before wallet admission')
        gexn, aexn = self._accepted(grant, '/ipex/grant'), self._accepted(admit, '/ipex/admit')
        holder = gexn.sad.get('ri')
        response = self.hby.db.erpy.get((grant,))
        if (self.hby.habByPre(holder) is None or aexn.pre != holder or aexn.sad.get('p') != grant
                or aexn.sad.get('ri') != gexn.pre or response is None or response.qb64 != admit):
            raise ValidationError('admit must be the local intended holder response to this grant')
        origins = gexn.sad['a'].get('o')
        if not isinstance(origins, list) or len(origins) != 1:
            raise ValidationError('wallet admission requires one disclosed origin credential')
        nested = exchanging.loadParsedNestedSubstreams(self.hby, grant)
        if not any(isinstance(item.serder, SerderACDC) and item.serder.said == origins[0] for item in nested):
            raise ValidationError('accepted grant origin evidence is missing')
        old = self.db.admitted.get((grant,))
        if old is not None:
            if old.admit != admit or old.credential != origins[0] or old.holder != holder:
                raise ValidationError('conflicting wallet admission for this grant')
            return old
        verification = self._verification()
        for route, message in (('/ipex/grant', gexn), ('/ipex/admit', aexn)):
            if not verification.verifyAccepted(message.said, route):
                raise ValidationError('native IPEX semantic acceptance is required before wallet admission')
        record = AdmittedCredential(origins[0], grant, admit, holder, helping.nowIso8601())
        # Only this application environment participates in the transaction.
        with self.db.env.begin(write=True) as txn:
            txn.put(self.db.admitted._tokey((grant,)), self.db.admitted._ser(record),
                    db=self.db.admitted.sdb, overwrite=False)
            txn.put(self.db.credentials._tokey((record.credential, grant)), self.db.credentials._ser(grant),
                    db=self.db.credentials.sdb, overwrite=False)
        return self.db.admitted.get((grant,))

    def heldCredential(self, grant):
        """Load this admitted disclosure's retained proof without merging later views."""
        record = self.db.admitted.get((grant,))
        if record is None:
            raise ValidationError('this grant has not been admitted to the wallet')
        exn = self._accepted(grant, '/ipex/grant')
        self._accepted(record.admit, '/ipex/admit')
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
        """Return durable references; never infer consent from received notifications."""
        return {'issued': [record for _, record in self.db.issued.getTopItemIter()],
                'held': [record for _, record in self.db.admitted.getTopItemIter()]}

    def admissions(self, credential):
        result = []
        for _, grant in self.db.credentials.getTopItemIter((credential, '')):
            record = self.db.admitted.get((grant,))
            if record is None:
                raise ValidationError('wallet credential index references a missing admission')
            result.append(record)
        return result

    def close(self):
        self.db.close()
