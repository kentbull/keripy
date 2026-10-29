"""Optional encrypted per-registry derivation custody over existing wallet records.

The encrypted records and methods were moved from credentialing.Wallet at
KERIpy ea3d8281 without changing the custody. database layout; their introducing
local commit was d30395c1acbf609d9099f9ce34288d1d4c89233f. This extraction and
explicit no-regeneration guard are local application changes.
Manager.updateAeid migrates Keeper secrets only. These application records remain
under their old AEID and require the original Keeper. There is no automatic
migration or plaintext salt export/import.

Supplied-root preparation and qualified sealed-box handoff are local application
additions using the existing Encrypter and Keeper Manager. The domain caller
owns sender authentication and recipient authorization; custody owns encrypted
root retention and never generates a replacement for a supplied root.

"""
from dataclasses import asdict, dataclass, field
import json

from keri.core import (Blinder, Cipher, Encrypter, MtrDex, Number,
                       Prefixer, Salter, Verfer)
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
    cipher: str = field(repr=False)


@dataclass(frozen=True)
class PreparedCustody:
    """Encrypted root row and exact previous-row snapshot for one wallet transaction.

    Both serialized rows contain ciphertext, never a plaintext root. Excluding
    them from repr also keeps ciphertext out of ordinary diagnostic output.
    """
    registry: str
    expected: bytes | None = field(repr=False)
    encrypted: bytes = field(repr=False)


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

    def _binding(self, regid, controller, discloser):
        """Check explicit custody identities against accepted registry evidence.

        Args:
            regid (str): Accepted registry inception SAID.
            controller (str): Expected registry controller AID.
            discloser (str): Explicit designated recipient AID, with known KEL.

        Returns:
            None. This guards local issuer creation only. Incoming encrypted
            copies are authenticated separately by the ordinary reply handler.

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
        local = self.hby.habByPre(controller)
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
        self._manager()
        record = self.db.custody.get((regid,))
        if record is None:
            raise ConfigurationError('registry custody is not provisioned')
        return self._decode(regid, record)

    def _decode(self, regid, record):
        """Authenticate an encrypted fixed-profile row under the current Keeper.

        Parameters: regid is the expected registry; record is EncryptedCustody.
        Returns: the private payload. Raises: AuthError without disclosing data.
        """
        mgr = self._manager()
        if record.aeid != mgr.aeid:
            raise AuthError('custody encryption AEID changed; original Keeper is required')
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

    def prepareRoot(self, info, root):
        """Prepare an encrypted supplied root without writing or generating one.

        Args:
            info (CustodyInfo): Original registry/controller/discloser metadata
                and this application's fixed derivation profile.
            root (Salter): Explicitly supplied Salt_128 root.

        Returns:
            PreparedCustody: Ciphertext and a previous-row snapshot. The caller
                commits it in its existing LMDB transaction using retainPrepared.

        Raises:
            AuthError: Keeper authentication or existing AEID binding fails.
            ValidationError: Accepted registry, metadata, profile, root type,
                or immutable existing root differs.

        The domain caller must first authenticate replies and authorize the
        recipient. These structural checks
        establish neither network authority nor entitlement from a local discloser.
        Original discloser metadata must stay unchanged for later recipients.
        """
        self._manager()
        if (not isinstance(info, CustodyInfo)
                or info != CustodyInfo(info.registry, info.controller, info.discloser)):
            raise ValidationError('registry root requires the fixed custody profile')
        try:
            for aid in (info.controller, info.discloser):
                if Prefixer(qb64=aid).qb64 != aid:
                    raise ValueError
        except Exception:
            raise ValidationError('registry root has invalid original party metadata') from None
        rip = self.rgy.store.seqEvent(info.registry, 0)
        if rip is None or rip.ilk != 'rip' or rip.sad['i'] != info.controller:
            raise ValidationError('registry root must match the accepted registry controller')
        if not isinstance(root, Salter) or root.code != MtrDex.Salt_128 or len(root.raw) != 16:
            raise ValidationError('registry root must be one Salt_128 Salter')
        return self._prepare(_Custody(asdict(info), root.qb64))

    def _prepare(self, secret):
        """Encrypt validated private data before entering the wallet transaction.

        Args:
            secret (_Custody): Original fixed-profile metadata and supplied root.

        Returns:
            PreparedCustody: New ciphertext or the identical existing row, with
                its exact serialized previous value for guarded retention.
        """
        mgr = self._manager()
        regid = secret.info['registry']
        previous = self.db.custody.get((regid,))
        expected = self.db.custody._ser(previous) if previous is not None else None
        if previous is not None and previous.aeid == mgr.aeid:
            if self._load(regid) != secret:
                raise ValidationError('different registry custody is already retained')
            return PreparedCustody(regid, expected, expected)
        if previous is not None:
            raise AuthError('custody encryption AEID changed; original Keeper is required')
        cipher = mgr.encrypter.encrypt(ser=json.dumps(asdict(secret), separators=(',', ':')).encode())
        encrypted = self.db.custody._ser(EncryptedCustody(mgr.aeid, cipher.qb64))
        return PreparedCustody(regid, expected, encrypted)

    def retainPrepared(self, prepared, txn):
        """CAS-retain a prepared row inside a caller-owned wallet write transaction.

        Args:
            prepared (PreparedCustody): Encrypted output of prepareRoot, prepared
                before the caller opened its transaction.
            txn (lmdb.Transaction): Active write transaction in this WalletBaser.

        Returns:
            bool: True when ciphertext changes, False for an identical retained row.

        Raises:
            AuthError: Keeper identity changed after preparation.
            ValidationError: The previous row changed concurrently.

        This method never opens a transaction, decrypts, or emits a receipt. The
        application commits the encrypted root in its existing transaction, then
        produces any notification or retention receipt after that commit succeeds.
        """
        mgr = self._manager()
        if (not isinstance(prepared, PreparedCustody)
                or self.db.custody._des(prepared.encrypted).aeid != mgr.aeid):
            raise AuthError('prepared custody does not match the authenticated Keeper')
        key = self.db.custody._tokey((prepared.registry,))
        if txn.get(key, db=self.db.custody.sdb) != prepared.expected:
            raise ValidationError('custody changed during prepared retention')
        if prepared.expected == prepared.encrypted:
            return False
        txn.put(key, prepared.encrypted, db=self.db.custody.sdb)
        return True

    def _retain(self, secret):
        """Encrypt and retain a generated salt in one existing store transaction.

        Args:
            secret (_Custody): Validated registry metadata and secret salt.

        Returns:
            CustodyInfo: Public bindings after the transaction commits.
        """
        prepared = self._prepare(secret)
        with self.db.env.begin(write=True) as txn:
            self.retainPrepared(prepared, txn)
        return CustodyInfo(**secret.info)

    def sealRoot(self, regid, encrypter):
        """Seal an existing root to an externally authenticated recipient key.

        Args:
            regid (str): Exact retained registry root.
            encrypter (Encrypter): Accepted recipient X25519 encryption key,
                selected and authorized by the domain caller.

        Returns:
            Cipher: Qualified X25519_Cipher_Salt, suitable for a signed provision
                body. The plaintext root never leaves this operation.

        Raises:
            AuthError: Keeper/custody authentication fails.
            ValidationError: Recipient encryption primitive is unsupported.

        Sealed-box encryption supplies confidentiality, not sender authority. The
        domain binds this cipher to the recipient and encryption key.
        """
        if not isinstance(encrypter, Encrypter) or encrypter.code != MtrDex.X25519:
            raise ValidationError('registry root requires an accepted X25519 recipient key')
        secret = self._load(regid)
        return encrypter.encrypt(prim=Salter(qb64=secret.salt))

    def openRoot(self, cipher, verfer):
        """Open a qualified root cipher with one exact locally retained signing key.

        Args:
            cipher (Cipher | str): Complete X25519_Cipher_Salt primitive.
            verfer (Verfer): Exact local accepted Ed25519 key selected externally;
                its retained private key remains inside the authenticated Keeper.

        Returns:
            Salter: Decrypted Salt_128 root for commitment verification before
                prepareRoot. Callers must never log its raw or qualified values.

        Raises:
            AuthError: Keeper, retained private key, ciphertext, or root fails.
            ValidationError: Cipher or recipient primitive is unsupported.

        The domain verifies authority, recipient membership and historical key
        coordinates before calling, and checks the root commitment before retaining.
        Successful decryption alone grants no disclosure or signing authority.
        """
        mgr = self._manager()
        try:
            sealed = cipher if isinstance(cipher, Cipher) else Cipher(qb64=cipher)
            if (sealed.code != MtrDex.X25519_Cipher_Salt
                    or (isinstance(cipher, str) and sealed.qb64 != cipher)
                    or not isinstance(verfer, Verfer)
                    or verfer.code not in (MtrDex.Ed25519, MtrDex.Ed25519N)):
                raise ValueError
        except Exception:
            raise ValidationError('registry root cipher or recipient key is unsupported') from None
        try:
            raw = mgr.decrypt(qb64=sealed.raw, verfers=[verfer])
            root = Salter(qb64b=raw)
            if root.code != MtrDex.Salt_128 or root.qb64b != raw:
                raise ValueError
        except Exception:
            raise AuthError('unable to open encrypted registry root') from None
        return root

    def sealMembers(self, group, root):
        """Encrypt one supplied salt for the existing group's signing members.

        group is a local accepted GroupHab; root is the issuer-generated Salter.
        Return member AID to CESR cipher values for its signed rip/bup proposal.
        No private candidate record or network operation is created here.
        """
        from .habbing import GroupHab
        if (not isinstance(group, GroupHab) or self.hby.habByPre(group.pre) is not group
                or not group.accepted or root.code != MtrDex.Salt_128):
            raise ValidationError('salt copies require a local group and Salt_128 root')
        copies = {}
        for member in group.smids:
            kever = self.hby.kevers.get(member)
            if kever is None or len(kever.verfers) != 1:
                raise ValidationError('salt copy requires a known individual member key')
            copies[member] = Encrypter(verkey=kever.verfers[0].qb64).encrypt(prim=root).qb64
        return copies

    def retainMemberCopy(self, registry, group, copies):
        """Retain this member's copy after its registry proposal has been accepted.

        The caller authenticates the enclosing EXN and explicitly approves its
        event. copies is that exact proposal's encrypted map. Normal accepted
        registry checks precede persistence; decryption alone grants no authority.
        Return the local custody bindings. No replay task or acknowledgement is
        scheduled, and an existing different salt is never replaced.
        """
        from .grouping import validateRegistrySalts
        validateRegistrySalts(copies, group.smids)
        if not copies or group.mhab.pre not in copies:
            raise ValidationError('registry proposal has no salt copy for this member')
        root = self.openRoot(copies[group.mhab.pre], group.mhab.kever.verfers[0])
        info = CustodyInfo(registry, group.pre, group.pre)
        prepared = self.prepareRoot(info, root)
        with self.db.env.begin(write=True) as txn:
            self.retainPrepared(prepared, txn)
        return info

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
                receive the existing salt through encrypted sharing instead of recreating it.
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
        # Missing private state after undisclosed blinded publication is
        # recovery, never a request to invent a replacement salt. A bup with a
        # retained verified public opening did not assert use of this custody
        # salt, so that public-only prefix may still opt into derived authoring.
        head = self.rgy.store.headEvent(regid)
        if head is not None:
            from keri.acdc import regeventing
            for ordinal in range(1, Number(numh=head.sad['n']).num + 1):
                event = self.rgy.store.seqEvent(regid, ordinal)
                if event is None or event.ilk != 'bup':
                    continue
                qb64 = self.db.openings.get((event.said,))
                candidates = regeventing._blindCandidates(qb64) if qb64 else []
                if len(candidates) != 1:
                    raise ConfigurationError(
                        'blinded registry history requires explicit custody import; salt cannot be recreated')
                regeventing.vetBlind(candidates[0], blid=event.sad['b'])
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
        # Authenticated encrypted possession is the derivation capability. The
        # provisioning domain authorizes later parties; original transcript
        # metadata stays immutable and cannot stand in for current entitlement.
        return Blinder.blind(salt=secret.salt, sn=ordinal, tier=info.tier,
                             acdc=credential, state=state, bound=bound, bsn=bsn, bd=bd)
