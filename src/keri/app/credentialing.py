"""Private native wallet custody and explicit inventory over ordinary LMDB records.

Protocol acceptance remains in KERIpy's registry and IPEX processors. The small
issued/admitted reference model is adapted from KERI Foundation Locksmith
3a5ad9ebcf98b4ec03baf1bbb91d928d49c168e4 (Apache-2.0 LICENSE; its package metadata
incorrectly declares MIT). No Locksmith runtime or GUI dependency is used.
"""
from dataclasses import asdict, dataclass, field
from base64 import b64encode, b64decode
import json
import os
from pathlib import Path
import stat

from keri.acdc import regeventing
from keri.acdc.ipexing import NativeVerification
from keri.core import Blinder, BoundState, Number, Prefixer, Salter, SerderACDC
from keri.db import dbing, koming, subing
from keri.help import helping
from keri.kering import AuthError, ConfigurationError, ValidationError
from keri.peer import exchanging


@dataclass
class CustodyInfo:
    registry: str
    controller: str
    discloser: str
    algorithm: str = 'keripy.Blinder.makeUUID'
    version: int = 1
    path: str = 'Number.snh'
    tier: str = 'low'
    kdf: str = 'argon2id13'
    nonce: str = 'Salt_256'


@dataclass
class _Custody:
    info: dict
    salt: str = field(repr=False)


@dataclass
class EncryptedCustody:
    aeid: str
    cipher: str


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
    """Privileged local application owner; public presentation code receives proofs only.

Custody always requires an authenticated encrypted Keeper. Manager AEID changes
do not migrate these application records: old custody fails closed until an
explicit operator rewrap/import. This module never changes Manager or AEID.
"""
    def __init__(self, hby, rgy, *, exc=None, db=None, verification=None):
        """Compose local inventory, custody storage, and native verification.

        Args:
            hby (Habery): Authenticated local identity and retained exchange owner.
            rgy (Regery): Native registry evidence owner.
            exc (Exchanger | None): Router used to check retained completion.
            db (WalletBaser | None): Existing inventory/custody store, or create one.
            verification (NativeVerification | None): Explicit context returned by
                native/app IPEX loadHandlers. None uses ordinary default policy;
                configured applications must pass their actual shared context.

        Returns:
            None
        """
        self.hby, self.rgy, self.exc = hby, rgy, exc
        self.verification = (verification if verification is not None
                             else NativeVerification(hby, rgy))
        self.db = db if db is not None else WalletBaser(
            name=hby.name, base=hby.base, temp=hby.temp)

    def _manager(self):
        mgr = self.hby.mgr
        if not mgr.aeid or mgr.encrypter is None or mgr.decrypter is None:
            raise AuthError('private credential custody requires an authenticated encrypted Keeper')
        return mgr

    def _binding(self, regid, controller, discloser, *, importing=False, rewrap=False):
        try:
            Prefixer(qb64=controller)
            Prefixer(qb64=discloser)
        except Exception:
            raise ValidationError('invalid custody controller or discloser') from None
        rip = self.rgy.store.seqEvent(regid, 0)
        if rip is None or rip.sad['i'] != controller:
            raise ValidationError('custody must match the accepted registry controller')
        actor = discloser if importing else controller
        local = self.hby.habByPre(actor)
        if rewrap:
            local = local or self.hby.habByPre(controller)
        if local is None:
            raise ValidationError('custody operation requires the intended local identifier')
        if discloser not in self.hby.kevers:
            raise ValidationError('designated discloser key state is unknown')

    def _load(self, regid):
        mgr = self._manager()
        record = self.db.custody.get((regid,))
        if record is None:
            raise ConfigurationError('registry custody is not provisioned')
        if record.aeid != mgr.aeid:
            raise AuthError('custody encryption AEID changed; explicit operator rewrap is required')
        try:
            payload = json.loads(mgr.decrypter.decrypt(qb64=record.cipher, bare=True))
            secret = _Custody(**payload)
            info = CustodyInfo(**secret.info)
            if info.registry != regid or info != CustodyInfo(info.registry, info.controller, info.discloser):
                raise ValueError('unsupported derivation parameters')
            Salter(qb64=secret.salt)
        except Exception:
            raise AuthError('unable to authenticate private registry custody') from None
        return secret

    def _retain(self, secret, *, rewrap=False):
        mgr = self._manager()
        regid = secret.info['registry']
        previous = self.db.custody.get((regid,))
        if previous is not None and previous.aeid == mgr.aeid:
            if self._load(regid) != secret:
                raise ValidationError('different registry custody is already retained')
            return CustodyInfo(**secret.info)
        if previous is not None and not rewrap:
            raise AuthError('custody encryption AEID changed; explicit operator rewrap is required')
        if previous is None and rewrap:
            raise ValidationError('rewrap requires an existing custody record under a prior AEID')
        cipher = mgr.encrypter.encrypt(ser=json.dumps(asdict(secret), separators=(',', ':')).encode())
        if rewrap:
            # Guard the exact old row in the same application-store transaction.
            # This does not decrypt old custody or claim a cross-store transaction.
            with self.db.env.begin(write=True) as txn:
                key = self.db.custody._tokey((regid,))
                if txn.get(key, db=self.db.custody.sdb) != self.db.custody._ser(previous):
                    raise ValidationError('custody changed during explicit operator rewrap')
                txn.put(key, self.db.custody._ser(EncryptedCustody(mgr.aeid, cipher.qb64)),
                        db=self.db.custody.sdb)
            return CustodyInfo(**secret.info)
        if not self.db.custody.put((regid,), EncryptedCustody(mgr.aeid, cipher.qb64)):
            if self._load(regid) != secret:
                raise ValidationError('different registry custody was concurrently retained')
        return CustodyInfo(**secret.info)

    def createCustody(self, regid, discloser):
        """Generate once for an accepted locally controlled registry; return no secret."""
        self._manager()
        rip = self.rgy.store.seqEvent(regid, 0)
        if rip is None:
            raise ValidationError('accepted registry inception is required before custody')
        controller = rip.sad['i']
        self._binding(regid, controller, discloser)
        if self.db.custody.get((regid,)) is not None:
            current = self._load(regid)
            if current.info != asdict(CustodyInfo(regid, controller, discloser)):
                raise ValidationError('registry custody has different designated bindings')
            return CustodyInfo(**current.info)
        return self._retain(_Custody(asdict(CustodyInfo(regid, controller, discloser)), Salter().qb64))

    def derive(self, regid, ordinal, credential, state, *, bound=False, bsn=0, bd=''):
        """Derive one event opening; never return the long-lived salt."""
        if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 1:
            raise ValidationError('update ordinal must be a positive integer')
        secret = self._load(regid)
        info = CustodyInfo(**secret.info)
        if not (self.hby.habByPre(info.controller) or self.hby.habByPre(info.discloser)):
            raise AuthError('this wallet is not a designated custody participant')
        return Blinder.blind(salt=secret.salt, sn=ordinal, tier=info.tier,
                             acdc=credential, state=state, bound=bound, bsn=bsn, bd=bd)

    def exportCustody(self, regid, path):
        """Create an owner-only plaintext operator handoff file, never overwrite it.

        The operator transfers it over an authenticated private channel. This is
        a protected local artifact, not an IPEX payload or a new wire protocol.
        """
        secret = self._load(regid)
        path = Path(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(json.dumps(asdict(secret), separators=(',', ':')).encode())
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return path

    def importCustody(self, path, *, regid, controller, discloser, rewrap=False):
        """Import a protected artifact; only explicit rewrap can replace old-AEID custody.

        Rewrap trusts the authenticated operator handoff, retains its original
        salt/profile, and encrypts it under the currently authenticated Keeper.
        A normal import never overwrites different custody.
        """
        if not isinstance(rewrap, bool):
            raise ValidationError('explicit rewrap must be a boolean')
        self._manager()
        self._binding(regid, controller, discloser, importing=True, rewrap=rewrap)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1):
                raise ValidationError('custody file must be a regular owner-only mode0600 file')
            raw = stream.read(16385)
        if len(raw) > 16384:
            raise ValidationError('custody file exceeds the supported size')
        try:
            secret = _Custody(**json.loads(raw))
            if secret.info != asdict(CustodyInfo(regid, controller, discloser)):
                raise ValueError('unexpected custody bindings or derivation parameters')
            Salter(qb64=secret.salt)
        except Exception:
            raise ValidationError('custody file does not match the expected bindings and derivation profile') from None
        return self._retain(secret, rewrap=rewrap)

    def boundEvent(self, acdc, said):
        """Resolve an explicitly selected accepted issuee event for bound derivation."""
        issuee = acdc.iseaid
        event = self.hby.db.evts.get((issuee, said)) if issuee else None
        if (event is None or self.hby.db.kels.getLast(keys=issuee, on=event.sn) != said
                or not self.hby.db.fullyWitnessed(event)):
            raise ValidationError('bound reference requires an accepted witnessed issuee KEL event')
        return dict(bound=True, bsn=event.sn, bd=event.said)

    def recordIssued(self, acdc, update, *, blinder=None):
        """Retain native issuance only after its referenced issuance event is accepted."""
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
        parameters = (dict(bound=True, bsn=old.bound['bn'], bd=old.bound['bd'])
                      if old is not None and old.update == update and old.bound else {})
        proof = (blinder if blinder is not None else self.derive(
            regid, sn, acdc.said, 'issued', **parameters)) if event.ilk == 'bup' else None
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
