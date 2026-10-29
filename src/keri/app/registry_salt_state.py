"""Durable local state for the experimental registry-salt reply lifecycle.

This passive owner borrows RegistryCustody's existing WalletBaser. It schedules
nothing, emits no cues, and accepts no network authority by itself. The caller
verifies signed replies, accepted registry history, current membership, and root
commitment before retention, and sends receipts only after the transaction commits.
Original transcript assignments and locally trusted rosters are immutable.
"""
from base64 import b64decode, b64encode
from dataclasses import asdict, dataclass, field
import json
import math

import pysodium

from .. import Vrsn_2_0
from ..core import Diger, Matter, MtrDex, Prefixer, SerderKERI
from ..kering import AuthError, ConfigurationError, Ilks, Kinds, ValidationError
from .group_members import AcceptedRoster, Member, acceptedRoster
from .registry_custody import EncryptedCustody
from .registry_salt_replies import INIT_ROUTE, BIND_ROUTE, SUITE, PROFILE, PURPOSE


@dataclass(frozen=True)
class PendingDH:
    """Exact recoverable local negotiation; private values never appear in repr."""
    init: str
    representative: str
    body: bytes = field(repr=False)
    private: str = field(repr=False)


@dataclass(frozen=True)
class SaltOrigin:
    """Immutable initial transcript and root commitment, never local entitlement."""
    registry: str
    issuer: str
    discloser: str
    init: str
    bind: str
    confirm: str
    commitment: str
    suite: str = SUITE
    profile: str = PROFILE
    purpose: str = PURPOSE


@dataclass(frozen=True)
class SaltDelivery:
    """One initial assignment/member/admission operation and its delivery progress.

    retryAt is local Unix scheduling time, never a signed protocol timestamp.
    Readiness checks do not increment attempts; the sender records actual sends.
    """
    registry: str
    party: str
    member: str
    admission: str
    assignment: str
    state: str = 'pending'
    provision: str = ''
    receipt: str = ''
    attempts: int = 0
    retryAt: float = 0.0

    @property
    def key(self):
        """Return the immutable operation identity used by the wallet table."""
        return self.registry, self.party, self.member, self.admission


@dataclass(frozen=True)
class SaltRoster:
    """Plain accepted-roster snapshot; nested members remain ordinary mappings."""
    snapshot: dict


def _qualified(value, klas, code=None):
    """Check public coordinate encoding without exposing private input in errors."""
    try:
        material = klas(qb64=value)
        if (not isinstance(value, str) or material.qb64 != value
                or (code is not None and material.code != code)):
            raise ValueError
    except Exception:
        raise ValidationError('registry-salt state contains invalid public coordinates') from None


class RegistrySaltState:
    """Own feature transactions in the caller's wallet; custody owns encryption."""

    def __init__(self, custody):
        """Borrow explicit RegistryCustody and its already-open wallet environment."""
        self.custody = custody
        self.db = custody.db

    def _pending(self, init, representative, body, private):
        """Check exact local reply context and the private/public X25519 pairing."""
        try:
            _qualified(init, Diger)
            _qualified(representative, Prefixer)
            if not isinstance(body, bytes):
                raise ValueError
            reply = SerderKERI(raw=body)
            key = private if isinstance(private, Matter) else Matter(qb64=private)
            if (reply.raw != body or not reply.verify() or reply.ilk != Ilks.rpy
                    or reply.pvrsn != Vrsn_2_0 or reply.gvrsn != Vrsn_2_0
                    or reply.kind != Kinds.json
                    or reply.route not in (INIT_ROUTE, BIND_ROUTE)
                    or key.code != MtrDex.X25519_Private
                    or (not isinstance(private, Matter) and key.qb64 != private)):
                raise ValueError
            attrs = reply.sad['a']
            if (attrs['rep'] != representative
                    or (attrs['suite'], attrs['profile'], attrs['purpose']) != (SUITE, PROFILE, PURPOSE)
                    or (reply.said if reply.route == INIT_ROUTE else attrs['init']) != init):
                raise ValueError
            public = Matter(qb64=attrs['key'])
            if (public.code != MtrDex.X25519 or public.qb64 != attrs['key']
                    or public.raw != pysodium.crypto_scalarmult_base(key.raw)):
                raise ValueError
            return PendingDH(init, representative, body, key.qb64)
        except Exception:
            raise ValidationError('pending registry-salt reply or private key is inconsistent') from None

    def _pendingRecord(self, init, representative):
        """Read an encrypted wrapper without exposing corrupt serialization errors."""
        try:
            return self.db.saltPending.get((init, representative))
        except (ValueError, TypeError, AttributeError, KeyError):
            raise AuthError('unable to authenticate pending registry-salt state') from None

    def _openPending(self, init, representative, record):
        """Authenticate one encrypted row without reading a second row snapshot."""
        mgr = self.custody._manager()
        if record.aeid != mgr.aeid:
            raise AuthError('pending registry-salt AEID changed; original state is required')
        try:
            payload = json.loads(mgr.decrypter.decrypt(qb64=record.cipher, bare=True))
            if set(payload) != {'init', 'representative', 'body', 'private'}:
                raise ValueError
            if payload['init'] != init or payload['representative'] != representative:
                raise ValueError
            body = b64decode(payload['body'], validate=True)
            return self._pending(init, representative, body, payload['private'])
        except Exception:
            raise AuthError('unable to authenticate pending registry-salt state') from None

    def retainPending(self, init, representative, body, private):
        """Encrypt an exact local init/bind attempt and refuse replacement keys.

        Args: init and representative are qualified identities; body is the exact
            local reply body bytes; private is its X25519_Private Matter or qb64.
        Returns: PendingDH containing the same exact body and key on every retry.
        Raises: AuthError for unavailable Keeper/old AEID; ValidationError for
            nonlocal representatives, changed attempts, or private/public mismatch.

        Known local possession is a storage guard, not group reply approval.
        The caller supplies domain-authorized reply bodies; this method sends none.
        """
        mgr = self.custody._manager()
        if self.custody.hby.habByPre(representative) is None:
            raise ValidationError('pending registry-salt representative must be locally known')
        pending = self._pending(init, representative, body, private)
        previous = self._pendingRecord(init, representative)
        if previous is not None:
            if self._openPending(init, representative, previous) != pending:
                raise ValidationError('different pending registry-salt attempt is already retained')
            return pending
        payload = asdict(pending)
        payload['body'] = b64encode(body).decode('ascii')
        cipher = mgr.encrypter.encrypt(ser=json.dumps(payload, separators=(',', ':')).encode())
        record = EncryptedCustody(mgr.aeid, cipher.qb64)
        with self.db.env.begin(write=True) as txn:
            key = self.db.saltPending._tokey((init, representative))
            if txn.get(key, db=self.db.saltPending.sdb) is not None:
                raise ValidationError('pending registry-salt attempt changed during retention')
            txn.put(key, self.db.saltPending._ser(record), db=self.db.saltPending.sdb)
        return pending

    def openPending(self, init, representative):
        """Return authenticated exact private attempt state after restart.

        Args: init and representative identify one retained local attempt.
        Returns: PendingDH with private fields excluded from repr.
        Raises: ConfigurationError if absent; AuthError for corrupted/old-AEID
            state or unavailable Keeper. This method never generates a new key.
        """
        self.custody._manager()
        record = self._pendingRecord(init, representative)
        if record is None:
            raise ConfigurationError('pending registry-salt negotiation is unavailable')
        return self._openPending(init, representative, record)

    def origin(self, registry):
        """Return immutable public origin metadata, or None; decrypt no root."""
        return self.db.saltOrigins.get((registry,))

    def _origin(self, info, origin):
        """Check fixed public storage bindings; signed authority remains external."""
        if (not isinstance(origin, SaltOrigin)
                or (origin.registry, origin.issuer, origin.discloser) !=
                   (info.registry, info.controller, info.discloser)
                or origin.issuer == origin.discloser
                or (origin.suite, origin.profile, origin.purpose) != (SUITE, PROFILE, PURPOSE)):
            raise ValidationError('registry-salt origin differs from the fixed root bindings')
        for aid in (origin.issuer, origin.discloser):
            _qualified(aid, Prefixer)
        for said in (origin.registry, origin.init, origin.bind, origin.confirm):
            _qualified(said, Diger)
        _qualified(origin.commitment, Diger, MtrDex.SHA2_256)

    def retainEstablished(self, info, root, origin, deliveries=(), pendingKey=None):
        """Atomically retain root, immutable origin, jobs, and pending-key deletion.

        Args: info/root are supplied to RegistryCustody.prepareRoot; origin is an
            authenticated SaltOrigin; deliveries are fresh validated SaltDelivery
            rows; pendingKey optionally names (init, local representative) to remove.
        Returns: The immutable public SaltOrigin after commit. No cue or receipt.
        Raises: AuthError for Keeper/private-state failures; ValidationError for
            changed root/origin, conflicting jobs, or a changed pending row.

        The domain verifies reply authority, exact transcript commitment and
        current accepted membership before calling. Encryption and decryption
        happen before this method opens its single wallet write transaction.
        """
        prepared = self.custody.prepareRoot(info, root)
        self._origin(info, origin)
        jobs = tuple(deliveries)
        for job in jobs:
            if (not isinstance(job, SaltDelivery) or job.registry != origin.registry
                    or job.party not in (origin.issuer, origin.discloser)
                    or job.assignment != origin.confirm
                    or (job.state, job.provision, job.receipt, job.attempts, job.retryAt) !=
                       ('pending', '', '', 0, 0.0)):
                raise ValidationError('registry-salt delivery must name the exact initial assignment')
            _qualified(job.party, Prefixer)
            _qualified(job.member, Prefixer)
            _qualified(job.admission, Diger)
        pending = None
        if pendingKey is not None:
            if len(pendingKey) != 2 or pendingKey[0] != origin.init:
                raise ValidationError('registry-salt pending key references another init')
            record = self._pendingRecord(*pendingKey)
            if record is not None:
                saved = self._openPending(*pendingKey, record)
                reply = SerderKERI(raw=saved.body)
                expected = origin.init if reply.route == INIT_ROUTE else origin.bind
                if reply.said != expected:
                    raise ValidationError('registry-salt pending reply differs from the origin')
                pending = self.db.saltPending._ser(record)
            elif self.origin(origin.registry) != origin:
                raise ValidationError('registry-salt establishment lost its pending attempt')
        with self.db.env.begin(write=True) as txn:
            self.custody.retainPrepared(prepared, txn)
            originKey = self.db.saltOrigins._tokey((origin.registry,))
            encoded = self.db.saltOrigins._ser(origin)
            current = txn.get(originKey, db=self.db.saltOrigins.sdb)
            if current is not None and current != encoded:
                raise ValidationError('different registry-salt origin is already retained')
            if current is None:
                txn.put(originKey, encoded, db=self.db.saltOrigins.sdb)
            for job in jobs:
                key = self.db.saltDeliveries._tokey(job.key)
                existing = txn.get(key, db=self.db.saltDeliveries.sdb)
                if existing is None:
                    txn.put(key, self.db.saltDeliveries._ser(job), db=self.db.saltDeliveries.sdb)
                else:
                    prior = self.db.saltDeliveries._des(existing)
                    if prior.key != job.key or prior.assignment != job.assignment:
                        raise ValidationError('different registry-salt delivery is already retained')
                    # An exact establishment retry must preserve delivery progress.
            if pendingKey is not None:
                key = self.db.saltPending._tokey(pendingKey)
                if txn.get(key, db=self.db.saltPending.sdb) != pending:
                    raise ValidationError('registry-salt pending attempt changed during establishment')
                if pending is not None:
                    txn.delete(key, db=self.db.saltPending.sdb)
        return origin

    def delivery(self, registry, party, member, admission):
        """Return one concrete public delivery row, or None; authorize no sender."""
        return self.db.saltDeliveries.get((registry, party, member, admission))

    def deliveryCandidates(self, now, limit=32):
        """Return at most limit due pending jobs for a caller-owned bounded worker.

        now is Unix seconds and limit is a positive integer. Returned public
        records are candidates only: revalidate membership, keys, and authority
        before each attempt. This read neither increments retries nor sends work.
        """
        if (isinstance(now, bool) or not isinstance(now, (int, float))
                or not math.isfinite(now) or now < 0
                or isinstance(limit, bool) or not isinstance(limit, int) or limit < 1):
            raise ValidationError('registry-salt candidate bounds are invalid')
        candidates = []
        for _, job in self.db.saltDeliveries.getTopItemIter():
            if job.state == 'pending' and job.retryAt <= now:
                candidates.append(job)
                if len(candidates) == limit:
                    break
        return candidates

    def retainRoster(self, roster):
        """Persist an exact locally trusted accepted roster, never a pending Habord.

        Args: roster is an AcceptedRoster resolved from trusted local member maps.
        Returns: roster after an immutable snapshot insert or identical retry.
        Raises: ValidationError if accepted state differs or a snapshot conflicts.
        """
        if (not isinstance(roster, AcceptedRoster) or
                acceptedRoster(self.custody.hby, roster.group,
                               tuple(member.aid for member in roster.members)) != roster):
            raise ValidationError('registry-salt roster must match accepted local history')
        record = SaltRoster(asdict(roster))
        encoded = self.db.saltRosters._ser(record)
        with self.db.env.begin(write=True) as txn:
            key = self.db.saltRosters._tokey((roster.group, roster.digest))
            existing = txn.get(key, db=self.db.saltRosters.sdb)
            if existing is not None and existing != encoded:
                raise ValidationError('different accepted registry-salt roster is already retained')
            if existing is None:
                txn.put(key, encoded, db=self.db.saltRosters.sdb)
        return roster

    def roster(self, group, digest=None):
        """Rebuild a plain saved roster; default to the current accepted establishment.

        group and optional digest select immutable local provenance. Returns an
        AcceptedRoster or None. This does not make a historical snapshot current;
        the delivery owner must revalidate it before selecting recipients.
        """
        if digest is None:
            kever = self.custody.hby.kevers.get(group)
            if kever is None:
                return None
            digest = kever.lastEst.d
        record = self.db.saltRosters.get((group, digest))
        if record is None:
            return None
        try:
            data = record.snapshot
            members = tuple(Member(**item) for item in data['members'])
            roster = AcceptedRoster(data['group'], data['sn'], data['digest'], members)
            if roster.group != group or roster.digest != digest:
                raise ValueError
            return roster
        except Exception:
            raise ValidationError('retained registry-salt roster is inconsistent') from None
