"""Optional encrypted per-registry derivation custody over existing wallet records.

The encrypted records and methods were moved from credentialing.Wallet at
KERIpy ea3d8281 without changing the custody. database layout; their introducing
local commit was d30395c1acbf609d9099f9ce34288d1d4c89233f. This extraction and
explicit no-regeneration guard are local application changes.
Manager.updateAeid migrates Keeper secrets only. These application records remain
under their old AEID and fail closed until an explicit plaintext re-import under
an authenticated current Keeper. There is no automatic migration or salt export.
"""
from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import stat

from keri.core import Blinder, Number, Prefixer, Salter
from keri.kering import AuthError, ConfigurationError, ValidationError


@dataclass
class CustodyInfo:
    """Public registry/controller/discloser bindings and fixed derivation profile."""
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
    """Private encrypted payload; salt is excluded from diagnostic representation."""
    info: dict
    salt: str = field(repr=False)


@dataclass
class EncryptedCustody:
    """Existing custody. row: Keeper encryption identity plus authenticated cipher."""
    aeid: str
    cipher: str


class RegistryCustody:
    """Explicit private capability; no inventory operation constructs or reads it.

    The caller owns and closes the existing WalletBaser. A separate owner does
    not imply a separate LMDB environment or atomicity with Keeper rotations.
    """
    def __init__(self, hby, rgy, *, db):
        """Bind optional derivation to authenticated identity and existing storage.

        Args:
            hby (Habery): Keeper authentication and local participant identities.
            rgy (Regery): Accepted registry evidence defining controller bindings.
            db (WalletBaser): Existing encrypted custody table; caller closes it.

        Returns:
            None. Construction does not inspect, decrypt, or create a custody row.
        """
        self.hby, self.rgy, self.db = hby, rgy, db

    def _manager(self):
        """Require an authenticated encrypted Keeper for a secret-bearing operation.

            Returns:
                Manager: Existing Keeper manager with matching encryption/decryption keys.

            Raises:
                AuthError: Keeper encryption or its authenticated decrypter is absent.

            The check never enables encryption, rotates AEID, or recreates registry salt."""
        mgr = self.hby.mgr
        if not mgr.aeid or mgr.encrypter is None or mgr.decrypter is None:
            raise AuthError('private credential custody requires an authenticated encrypted Keeper')
        return mgr

    def _binding(self, regid, controller, discloser, *, importing=False, rewrap=False):
        """Check explicit custody identities against accepted registry evidence.

        Args:
            regid (str): Accepted registry inception SAID.
            controller (str): Expected registry controller AID.
            discloser (str): Explicit designated recipient AID, with known KEL.
            importing (bool): Require the local recipient rather than controller.
            rewrap (bool): Permit local controller to re-import its protected copy.

        Returns:
            None. Local checks are guardrails, not signed delegation or transfer
            authentication; the provisioning operator supplies those assurances.

        Raises:
            ValidationError: Identifier, registry, or local-role binding is invalid.
        """
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
        """Authenticate and decrypt one registry's existing private payload.

        Args:
            regid (str): Exact registry key to load.

        Returns:
            _Custody: Validated fixed-profile private payload, for internal use.

        Raises:
            ConfigurationError: No registry capability was explicitly provisioned.
            AuthError: Keeper authentication, AEID binding, cipher, or profile fails.
        """
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
        """Encrypt one supplied payload in the existing application environment.

        Args:
            secret (_Custody): Validated bindings, fixed profile, and private salt.
            rewrap (bool): Explicit plaintext re-import replacing an old-AEID row.

        Returns:
            CustodyInfo: Public metadata only; the salt remains encrypted at rest.

        Raises:
            AuthError: Keeper is unavailable or replacement was not authorized.
            ValidationError: Different custody exists or guarded replacement races.

        Re-import never decrypts the old ciphertext and is not key migration.
        Only this application environment participates in the row transaction.
        """
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
        """Explicitly provision derivation for an accepted controlled registry.

        Args:
            regid (str): Accepted locally controlled registry inception SAID.
            discloser (str): Explicit designated discloser with known key state.

        Returns:
            CustodyInfo: Existing identical or newly provisioned public bindings.

        Raises:
            AuthError: Keeper is unencrypted, unauthenticated, or uses another AEID.
            ValidationError: Registry or participant bindings are invalid.
            ConfigurationError: Accepted blinded history exists without custody;
                restore an explicit protected handoff instead of recreating salt.
        """
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
        # Missing private state after blinded publication is recovery, never a
        # request to invent a replacement salt. A public-only prefix may still
        # opt into blinded authoring later; registry type is not permanent.
        head = self.rgy.store.headEvent(regid)
        if head is not None and any(
                (event := self.rgy.store.seqEvent(regid, ordinal)) is not None
                and event.ilk == 'bup'
                for ordinal in range(1, Number(numh=head.sad['n']).num + 1)):
            raise ConfigurationError('blinded registry history requires explicit custody import; salt cannot be recreated')
        return self._retain(_Custody(asdict(CustodyInfo(regid, controller, discloser)), Salter().qb64))

    def derive(self, regid, ordinal, credential, state, *, bound=False, bsn=0, bd=''):
        """Derive one candidate event opening without releasing the registry salt.

        Args:
            regid (str): Explicitly provisioned registry capability.
            ordinal (int): Positive TEL update ordinal.
            credential (str): Target credential SAID, or empty for vacuous state.
            state (str): Claimed state; this method does not establish acceptance.
            bound (bool): Select issuee-bound opening form.
            bsn (int): Exact issuee KEL ordinal for a bound opening.
            bd (str): Exact issuee KEL digest for a bound opening.

        Returns:
            Blinder: Event-specific candidate supplied to the common verifier.

        Raises:
            ConfigurationError: Registry capability was never provisioned.
            AuthError: Secret is unavailable, corrupt, old-AEID, or not locally held.
            ValidationError: Ordinal or opening fields are invalid.

        Salt possession never establishes TEL/KEL standing or issuer authority.
        The consumer must verify this opening against its exact accepted event.
        """
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
        Mode 0600 does not authenticate a sender, encrypt transit, or protect
        against other processes running as the same user.

        Args:
            regid (str): Provisioned registry capability to export.
            path (str | Path): New output path; existing files/symlinks are refused.

        Returns:
            Path: Owner-only plaintext file containing bindings, profile, and salt.

        Raises:
            AuthError: Existing custody cannot be authenticated/decrypted.
            ConfigurationError: Capability is not provisioned.
            OSError: Safe exclusive creation, write, or durability operation fails.
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
        A normal import never overwrites different custody. The operator must
        authenticate the source and arrange private transfer; file permissions
        and local binding checks are not a signed role delegation.

        Args:
            path (str | Path): Owner-only regular plaintext handoff file.
            regid (str): Expected accepted registry inception SAID.
            controller (str): Expected accepted registry controller AID.
            discloser (str): Explicit intended recipient AID.
            rewrap (bool): Explicit re-import under the current Keeper AEID.

        Returns:
            CustodyInfo: Public metadata for the retained encrypted capability.

        Raises:
            AuthError: Keeper/AEID authentication or replacement authorization fails.
            ValidationError: File, profile, identity, registry, or local-role check fails.
            OSError: Protected file opening/reading fails, including symlinks.
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
