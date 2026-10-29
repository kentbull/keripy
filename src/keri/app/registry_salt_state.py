"""Durable local state for the experimental registry-salt reply lifecycle.

This passive owner borrows RegistryCustody's existing WalletBaser. It schedules
nothing, emits no cues, and accepts no network authority by itself. The caller
verifies signed replies, accepted registry history, current membership, and root
commitment before retention, and sends receipts only after the transaction commits.
Original transcript assignments and locally trusted rosters are immutable.
"""
from base64 import b64decode, b64encode
from dataclasses import asdict, dataclass, field, replace
import json
import math

import pysodium

from .. import Vrsn_2_0
from ..core import Diger, Matter, MtrDex, Parser, Prefixer, SerderKERI
from ..kering import AuthError, ConfigurationError, Ilks, Kinds, ValidationError
from .group_members import AcceptedRoster, Member, acceptedRoster
from .registry_custody import CustodyInfo, EncryptedCustody
from .registry_salt_replies import (INIT_ROUTE, BIND_ROUTE, CONFIRM_ROUTE, ASSIGN_ROUTE,
                                    PROVISION_ROUTE, RECEIPT_ROUTE, SUITE, PROFILE, PURPOSE)
from .replying import parseReply


@dataclass(frozen=True)
class PendingDH:
    """Exact recoverable local negotiation; private values never appear in repr."""
    init: str
    representative: str
    body: bytes = field(repr=False)
    private: str = field(repr=False)
    confirmation: bytes | None = field(default=None, repr=False)


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


@dataclass(frozen=True)
class SaltProof:
    """One complete authenticated historical proof, retained across Revery pruning."""
    frame: str = field(repr=False)


@dataclass(frozen=True)
class SaltAssignment:
    """Immutable issuer grant for one additional party under the original root."""
    registry: str
    origin: str
    party: str
    reply: str


@dataclass(frozen=True)
class SaltReceiptIntent:
    """Durable obligation to acknowledge one provision after root retention."""
    provision: str
    registry: str
    party: str
    member: str
    admission: str
    source: str
    body: str = field(repr=False)
    state: str = 'pending'
    reply: str = ''
    attempts: int = 0
    retryAt: float = 0.0

    @property
    def bodyBytes(self):
        """Return the original validated incoming provision body."""
        return b64decode(self.body, validate=True)


@dataclass(frozen=True)
class SaltAttempt:
    """Immutable signed provision/receipt and ultimate-recipient envelope bytes."""
    reply: str
    kind: str
    registry: str
    party: str
    member: str
    admission: str
    provision: str
    target: str
    recipientEst: dict
    signed: str = field(repr=False)
    essr: str = field(repr=False)
    createdAt: float
    expiresAt: float

    @property
    def jobKey(self):
        """Return the concrete member/admission operation identity."""
        return self.registry, self.party, self.member, self.admission

    @property
    def signedBytes(self):
        """Return the exact signed inner reply selected for this attempt."""
        return b64decode(self.signed, validate=True)

    @property
    def essrBytes(self):
        """Return the exact sealed outer frame prepared before launch."""
        return b64decode(self.essr, validate=True)


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
    """Own feature transactions in the caller's wallet; custody owns encryption.

    Progress methods return a new durable snapshot or None on a CAS conflict.
    Only the fixed delivery and receipt operation types are supported; this is
    not an arbitrary message journal. Domain callers own authentication and I/O.
    """

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
            if set(payload) not in ({'init', 'representative', 'body', 'private'},
                                   {'init', 'representative', 'body', 'private', 'confirmation'}):
                raise ValueError
            if payload['init'] != init or payload['representative'] != representative:
                raise ValueError
            body = b64decode(payload['body'], validate=True)
            pending = self._pending(init, representative, body, payload['private'])
            if payload.get('confirmation') is not None:
                confirmation = b64decode(payload['confirmation'], validate=True)
                self._confirmation(pending, confirmation)
                pending = replace(pending, confirmation=confirmation)
            return pending
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
            current = self._openPending(init, representative, previous)
            if replace(current, confirmation=None) != pending:
                raise ValidationError('different pending registry-salt attempt is already retained')
            return current
        payload = asdict(pending)
        payload['body'] = b64encode(body).decode('ascii')
        payload['confirmation'] = None
        cipher = mgr.encrypter.encrypt(ser=json.dumps(payload, separators=(',', ':')).encode())
        record = EncryptedCustody(mgr.aeid, cipher.qb64)
        with self.db.env.begin(write=True) as txn:
            key = self.db.saltPending._tokey((init, representative))
            if txn.get(key, db=self.db.saltPending.sdb) is not None:
                raise ValidationError('pending registry-salt attempt changed during retention')
            txn.put(key, self.db.saltPending._ser(record), db=self.db.saltPending.sdb)
        return pending

    def hasPending(self, init, representative):
        """Check exact attempt existence without treating corruption as absence."""
        return self._pendingRecord(init, representative) is not None

    def _confirmation(self, pending, body):
        """Check a draft's exact local issuer and init binding, without consent."""
        try:
            draft = SerderKERI(raw=body)
            local = SerderKERI(raw=pending.body)
            if (draft.raw != body or not draft.verify() or draft.ilk != Ilks.rpy
                    or draft.route != CONFIRM_ROUTE or draft.pvrsn != Vrsn_2_0
                    or draft.gvrsn != Vrsn_2_0 or draft.kind != Kinds.json
                    or draft.pre != local.pre or draft.sad['a']['init'] != pending.init
                    or (draft.sad['a']['suite'], draft.sad['a']['profile'], draft.sad['a']['purpose'])
                       != (SUITE, PROFILE, PURPOSE)):
                raise ValueError
            _qualified(draft.sad['a']['bind'], Diger)
            _qualified(draft.sad['a']['commitment'], Diger, MtrDex.SHA2_256)
        except Exception:
            raise ValidationError('registry-salt confirmation draft differs from its local attempt') from None

    def retainConfirmationDraft(self, init, representative, body):
        """CAS-append one exact public confirmation to encrypted pending state.

        body is an externally validated unsigned confirmation's exact bytes.
        Returns PendingDH with its append-once confirmation. This is preparation,
        not group approval. A retry preserves the original timestamp and SAID.
        """
        mgr = self.custody._manager()
        previous = self._pendingRecord(init, representative)
        if previous is None:
            raise ConfigurationError('pending registry-salt negotiation is unavailable')
        pending = self._openPending(init, representative, previous)
        self._confirmation(pending, body)
        if pending.confirmation is not None:
            if pending.confirmation != body:
                raise ValidationError('different registry-salt confirmation draft is already retained')
            return pending
        pending = replace(pending, confirmation=body)
        payload = asdict(pending)
        payload['body'] = b64encode(pending.body).decode('ascii')
        payload['confirmation'] = b64encode(body).decode('ascii')
        cipher = mgr.encrypter.encrypt(ser=json.dumps(payload, separators=(',', ':')).encode())
        record = EncryptedCustody(mgr.aeid, cipher.qb64)
        with self.db.env.begin(write=True) as txn:
            key = self.db.saltPending._tokey((init, representative))
            if txn.get(key, db=self.db.saltPending.sdb) != self.db.saltPending._ser(previous):
                raise ValidationError('pending registry-salt attempt changed during confirmation preparation')
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

    def origins(self):
        """Return retained public origins for entitlement-filtered reconciliation."""
        return tuple(origin for _, origin in self.db.saltOrigins.getTopItemIter())

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

    def _proofRecord(self, serder, frame):
        """Check exact framing; caller has already authenticated complete authority."""
        routes = {INIT_ROUTE, BIND_ROUTE, CONFIRM_ROUTE, ASSIGN_ROUTE}
        parsed = parseReply(Parser(version=Vrsn_2_0), frame, routes)
        if parsed.serder.raw != serder.raw:
            raise ValidationError('registry-salt proof differs from its exact body')
        return SaltProof(b64encode(bytes(frame)).decode('ascii'))

    def _putProof(self, txn, serder, record):
        """Preserve the first full SaltProof for serder in the caller wallet transaction."""
        key = self.db.saltProofs._tokey((serder.said,))
        previous = txn.get(key, db=self.db.saltProofs.sdb)
        if previous is None:
            txn.put(key, self.db.saltProofs._ser(record), db=self.db.saltProofs.sdb)
        else:
            saved = self.db.saltProofs._des(previous)
            if SerderKERI(raw=b64decode(saved.frame, validate=True)).raw != serder.raw:
                raise ValidationError('registry-salt proof body changed')
            # Additional valid signature frames preserve the first full proof.

    def retainProof(self, serder, authenticatedFrame):
        """Retain the first complete authenticated init/bind/confirm/assign frame.

        The domain verifies full threshold and historical authority first. This
        archive adds only exact framing/body checks and survives Revery pruning.
        Returns the first archived frame, including on additional-signature retries.
        """
        record = self._proofRecord(serder, authenticatedFrame)
        with self.db.env.begin(write=True) as txn:
            self._putProof(txn, serder, record)
        return self.proof(serder.said)

    def proof(self, said):
        """Return exact historical proof bytes or None, without live dispatch."""
        record = self.db.saltProofs.get((said,))
        return b64decode(record.frame, validate=True) if record is not None else None

    def _assignmentRecord(self, origin, body, frame):
        """Return grant/proof records for one externally authenticated issuer assignment."""
        proof = self._proofRecord(body, frame)
        data = body.sad['a']
        if (body.route != ASSIGN_ROUTE or body.pre != origin.issuer
                or data.get('origin') != origin.confirm or data.get('registry') != origin.registry
                or data.get('party') in (origin.issuer, origin.discloser)
                or (data.get('suite'), data.get('profile'), data.get('purpose')) != (SUITE, PROFILE, PURPOSE)):
            raise ValidationError('registry-salt assignment differs from the immutable origin')
        _qualified(data.get('party'), Prefixer)
        return SaltAssignment(origin.registry, origin.confirm, data['party'], body.said), proof

    def _putAssignment(self, txn, assignment):
        """Insert an immutable per-origin/party grant in the caller transaction."""
        key = self.db.saltAssignments._tokey((assignment.origin, assignment.party))
        encoded = self.db.saltAssignments._ser(assignment)
        prior = txn.get(key, db=self.db.saltAssignments.sdb)
        if prior is not None and prior != encoded:
            raise ValidationError('different registry-salt assignment is already retained')
        if prior is None:
            txn.put(key, encoded, db=self.db.saltAssignments.sdb)

    def assignment(self, registry, party):
        """Return an initial confirmation or immutable issuer-grant SAID, or None."""
        origin = self.origin(registry)
        if origin is not None:
            if party in (origin.issuer, origin.discloser):
                return origin.confirm
            grant = self.db.saltAssignments.get((origin.confirm, party))
            return grant.reply if grant is not None else None
        # A public assignment may arrive before local root possession.
        known = {grant.reply for _, grant in self.db.saltAssignments.getTopItemIter()
                 if grant.registry == registry and grant.party == party}
        if len(known) > 1:
            raise ValidationError('registry-salt assignment origin is ambiguous')
        return next(iter(known), None)

    def _newJobs(self, origin, deliveries, grants=()):
        """Return fresh jobs validated against staged or already retained grants."""
        jobs = tuple(deliveries)
        staged = {grant.party: grant.reply for grant in grants}
        for job in jobs:
            if not isinstance(job, SaltDelivery):
                raise ValidationError('registry-salt delivery row is invalid')
            assignment = (origin.confirm if job.party in (origin.issuer, origin.discloser)
                          else staged.get(job.party) or self.assignment(origin.registry, job.party))
            if (not isinstance(job, SaltDelivery) or job.registry != origin.registry
                    or job.assignment != assignment or assignment is None
                    or (job.state, job.provision, job.receipt, job.attempts, job.retryAt) !=
                       ('pending', '', '', 0, 0.0)):
                raise ValidationError('registry-salt delivery must name an exact entitled assignment')
            _qualified(job.party, Prefixer)
            _qualified(job.member, Prefixer)
            _qualified(job.admission, Diger)
        return jobs

    def _putJobs(self, txn, jobs):
        """Insert concrete jobs in txn while preserving every prior progress field."""
        for job in jobs:
            key = self.db.saltDeliveries._tokey(job.key)
            existing = txn.get(key, db=self.db.saltDeliveries.sdb)
            if existing is None:
                txn.put(key, self.db.saltDeliveries._ser(job), db=self.db.saltDeliveries.sdb)
            else:
                prior = self.db.saltDeliveries._des(existing)
                if prior.key != job.key or prior.assignment != job.assignment:
                    raise ValidationError('different registry-salt delivery is already retained')
                # Reconciliation preserves confirmed, blocked and retry progress.

    def queueDeliveries(self, registry, jobs):
        """Queue validated current members of initial or explicitly assigned parties.

        Caller revalidates membership before each send. This method creates no
        entitlement and requires an existing root/origin; it never regenerates one.
        Returns canonical durable rows, including any existing terminal progress.
        """
        origin = self.origin(registry)
        if origin is None or self.db.custody.get((registry,)) is None:
            raise ConfigurationError('registry-salt delivery requires retained root and origin')
        jobs = self._newJobs(origin, jobs)
        with self.db.env.begin(write=True) as txn:
            self._putJobs(txn, jobs)
        return tuple(self.delivery(*job.key) for job in jobs)

    def retainAssignment(self, origin, assignSerder, authenticatedFrame, jobs=()):
        """Retain a verified issuer grant and queue same-root jobs atomically.

        A public grant without local root may be indexed with no jobs. The domain
        authenticates issuer threshold/history; membership reconciliation cannot
        create grants. Original root/discloser metadata stays unchanged.
        """
        self._origin(CustodyInfo(origin.registry, origin.issuer, origin.discloser), origin)
        current = self.origin(origin.registry)
        if current is not None and current != origin:
            raise ValidationError('registry-salt assignment names a different retained origin')
        grant, proof = self._assignmentRecord(origin, assignSerder, authenticatedFrame)
        if jobs and (current is None or self.db.custody.get((origin.registry,)) is None):
            raise ConfigurationError('registry-salt assignment jobs require retained custody')
        jobs = self._newJobs(origin, jobs, (grant,))
        with self.db.env.begin(write=True) as txn:
            self._putProof(txn, assignSerder, proof)
            self._putAssignment(txn, grant)
            self._putJobs(txn, jobs)
        return grant.reply

    def _receiptIntent(self, origin, intent):
        """Check a fresh acknowledgement obligation against its exact incoming provision."""
        if not isinstance(intent, SaltReceiptIntent):
            raise ValidationError('registry-salt receipt intent is invalid')
        try:
            body = SerderKERI(raw=intent.bodyBytes)
            data = body.sad['a']
            if (body.raw != intent.bodyBytes or body.said != intent.provision or not body.verify()
                    or body.route != PROVISION_ROUTE or body.pre != intent.source
                    or (data['registry'], data['party'], data['target'], data['admission']['d'], data['origin']) !=
                       (origin.registry, intent.party, intent.member, intent.admission, origin.confirm)
                    or intent.registry != origin.registry
                    or (intent.state, intent.reply, intent.attempts, intent.retryAt) != ('pending', '', 0, 0.0)):
                raise ValueError
        except Exception:
            raise ValidationError('registry-salt receipt intent differs from its provision') from None

    def _putReceiptIntent(self, txn, intent):
        """Insert a durable post-commit obligation without resetting an earlier send."""
        key = self.db.saltReceipts._tokey((intent.provision,))
        prior = txn.get(key, db=self.db.saltReceipts.sdb)
        if prior is None:
            txn.put(key, self.db.saltReceipts._ser(intent), db=self.db.saltReceipts.sdb)
        elif replace(self.db.saltReceipts._des(prior), state='pending', reply='', attempts=0, retryAt=0.0) != intent:
            raise ValidationError('different registry-salt receipt intent is already retained')

    def retainEstablished(self, info, root, origin, deliveries=(), pendingKey=None,
                          *, receiptIntent=None, assignments=()):
        """Atomically retain root, immutable origin, jobs, and pending-key deletion.

        Args: info/root are supplied to RegistryCustody.prepareRoot; origin is an
            authenticated SaltOrigin; deliveries are fresh validated SaltDelivery
            rows; pendingKey optionally names (init, local representative) to remove.
            receiptIntent records an obligation to acknowledge an incoming provision;
            assignments contains authenticated (issuer assign body, full frame) pairs.
        Returns: The immutable public SaltOrigin after commit. No cue or receipt.
        Raises: AuthError for Keeper/private-state failures; ValidationError for
            changed root/origin, conflicting jobs, or a changed pending row.

        The domain verifies reply authority, exact transcript commitment and
        current accepted membership before calling. Encryption and decryption
        happen before this method opens its single wallet write transaction.
        """
        prepared = self.custody.prepareRoot(info, root)
        self._origin(info, origin)
        grants = [(body, *self._assignmentRecord(origin, body, frame))
                  for body, frame in assignments]
        jobs = self._newJobs(origin, deliveries, tuple(grant for _, grant, _ in grants))
        if receiptIntent is not None:
            self._receiptIntent(origin, receiptIntent)
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
                if saved.confirmation is not None and SerderKERI(raw=saved.confirmation).said != origin.confirm:
                    raise ValidationError('registry-salt pending confirmation differs from the origin')
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
            for body, grant, proof in grants:
                self._putProof(txn, body, proof)
                self._putAssignment(txn, grant)
            self._putJobs(txn, jobs)
            if receiptIntent is not None:
                self._putReceiptIntent(txn, receiptIntent)
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

    def deliveryCandidates(self, now, limit=32, after=None):
        """Return at most limit due pending jobs for a caller-owned bounded worker.

        now is Unix seconds and limit is a positive integer. Returned public
        records are candidates only: revalidate membership, keys, and authority
        before each attempt. after is a previous job.key; volatile cursors avoid
        starvation without changing unready jobs' persistent retry state. This read neither increments retries nor sends work.
        """
        if (isinstance(now, bool) or not isinstance(now, (int, float))
                or not math.isfinite(now) or now < 0
                or isinstance(limit, bool) or not isinstance(limit, int) or limit < 1):
            raise ValidationError('registry-salt candidate bounds are invalid')
        candidates = []
        for key, job in self.db.saltDeliveries.getTopItemIter():
            if after is not None and tuple(key) <= tuple(after):
                continue
            if job.state == 'pending' and job.retryAt <= now:
                candidates.append(job)
                if len(candidates) == limit:
                    break
        return candidates

    def receipt(self, provisionSaid):
        """Return a durable post-commit receipt obligation, or None."""
        return self.db.saltReceipts.get((provisionSaid,))

    def receiptCandidates(self, now, limit=32, after=None):
        """Return due pending receipt intents without signing or counting attempts.

        after is the previous provision SAID (or one-tuple). Reset a caller-owned
        volatile cursor after an empty tail; readiness waits add no send attempts.
        """
        if not math.isfinite(now) or now < 0 or isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValidationError('registry-salt candidate bounds are invalid')
        result = []
        cursor = (after,) if isinstance(after, str) else tuple(after) if after is not None else None
        for key, intent in self.db.saltReceipts.getTopItemIter():
            if cursor is not None and tuple(key) <= cursor:
                continue
            if intent.state == 'pending' and intent.retryAt <= now:
                result.append(intent)
                if len(result) == limit:
                    break
        return result

    def attempt(self, replySaid):
        """Return one immutable exact provision/receipt attempt, or None."""
        return self.db.saltAttempts.get((replySaid,))

    def currentAttempt(self, jobKey):
        """Return a delivery's current prepared attempt without changing progress."""
        job = self.delivery(*jobKey)
        return self.attempt(job.provision) if job is not None and job.provision else None

    def _attemptRecord(self, expected, body, signed, essr, recipientEst, createdAt, expiresAt):
        """Check static operation/frame bindings; service owns authority and keys."""
        receipt = isinstance(expected, SaltReceiptIntent)
        route = RECEIPT_ROUTE if receipt else PROVISION_ROUTE
        parsed = parseReply(Parser(version=Vrsn_2_0), signed, {route})
        if parsed.serder.raw != body.raw:
            raise ValidationError('registry-salt outbound signed body differs')
        data = body.sad['a']
        origin = self.origin(expected.registry)
        target = expected.source if receipt else expected.member
        provision = expected.provision if receipt else body.said
        if (origin is None or data.get('registry') != expected.registry
                or data.get('party') != expected.party or data.get('origin') != origin.confirm
                or data.get('admission', {}).get('d') != expected.admission
                or (receipt and (data.get('provision') != expected.provision or body.pre != expected.member))
                or (not receipt and data.get('target') != expected.member)
                or not all(isinstance(value, (int, float)) and not isinstance(value, bool)
                           and math.isfinite(value) for value in (createdAt, expiresAt))
                or createdAt < 0 or expiresAt <= createdAt):
            raise ValidationError('registry-salt outbound attempt differs from its operation')
        # One strict parse-only outer frame; never decrypt recipient material here.
        remaining = bytearray(essr)
        generator = Parser(version=Vrsn_2_0).msgParsator(ims=remaining, framed=True, local=False)
        try:
            try:
                next(generator)
            except StopIteration as done:
                outer = done.value
            else:
                raise ValueError
            q = outer.serder.sad['q']
            if (remaining or outer.serder.ilk != Ilks.exn or outer.serder.route != '/essr/req'
                    or outer.serder.pre != body.pre or q.get('src') != body.pre or q.get('dest') != target
                    or set(recipientEst) != {'s', 'd'} or q.get('sn') != recipientEst['s']
                    or q.get('dig') != recipientEst['d']):
                raise ValueError
        except Exception:
            raise ValidationError('registry-salt outbound envelope differs from its recipient') from None
        finally:
            generator.close()
        return SaltAttempt(body.said, 'receipt' if receipt else 'provision',
            expected.registry, expected.party, expected.member, expected.admission,
            provision, target, dict(recipientEst), b64encode(bytes(signed)).decode('ascii'),
            b64encode(bytes(essr)).decode('ascii'), float(createdAt), float(expiresAt))

    def _recordAttempt(self, expected, record):
        """Persist immutable packet bytes and CAS the concrete operation pointer."""
        receipt = isinstance(expected, SaltReceiptIntent)
        table = self.db.saltReceipts if receipt else self.db.saltDeliveries
        key = table._tokey((expected.provision,) if receipt else expected.key)
        pointer = expected.reply if receipt else expected.provision
        updated = expected if pointer == record.reply else replace(expected, retryAt=0.0,
            **({'reply': record.reply} if receipt else {'provision': record.reply}))
        with self.db.env.begin(write=True) as txn:
            current = txn.get(key, db=table.sdb)
            if expected.state != 'pending' or current != table._ser(expected):
                return None
            attemptKey = self.db.saltAttempts._tokey((record.reply,))
            saved = txn.get(attemptKey, db=self.db.saltAttempts.sdb)
            encoded = self.db.saltAttempts._ser(record)
            if saved is not None and self.db.saltAttempts._des(saved) != record:
                raise ValidationError('different registry-salt outbound attempt is already retained')
            if saved is None:
                txn.put(attemptKey, encoded, db=self.db.saltAttempts.sdb)
            txn.put(key, table._ser(updated), db=table.sdb)
        return updated

    def recordAttempt(self, expected, provision, signedReply, essr, recipientEst, createdAt, expiresAt):
        """Persist exact provision/ESSR bytes and CAS its operation before launch.

        expected is a SaltDelivery snapshot. Service validates signing authority
        and accepted keys first. Returns the updated row, or None on a concurrent
        change. New attempts set retryAt=0 without incrementing launch counts.
        """
        if not isinstance(expected, SaltDelivery):
            raise ValidationError('registry-salt delivery snapshot is invalid')
        return self._recordAttempt(expected, self._attemptRecord(expected, provision,
            signedReply, essr, recipientEst, createdAt, expiresAt))

    def recordReceiptAttempt(self, expected, receipt, signedReply, essr, recipientEst, createdAt, expiresAt):
        """Persist an exact post-commit receipt attempt before transport launch."""
        if not isinstance(expected, SaltReceiptIntent):
            raise ValidationError('registry-salt receipt snapshot is invalid')
        return self._recordAttempt(expected, self._attemptRecord(expected, receipt,
            signedReply, essr, recipientEst, createdAt, expiresAt))

    def _progress(self, expected, *, state=None, now=None, deadline=None, delay=None, launch=False):
        """CAS progress for only the two concrete registry-salt operation records."""
        receipt = isinstance(expected, SaltReceiptIntent)
        if not receipt and not isinstance(expected, SaltDelivery):
            raise ValidationError('registry-salt operation snapshot is invalid')
        if state is None:
            if (not isinstance(now, (int, float)) or isinstance(now, bool) or not math.isfinite(now)
                    or now < 0 or (deadline is not None and (not math.isfinite(deadline) or deadline <= now))
                    or (delay is not None and (not math.isfinite(delay) or delay <= 0))):
                raise ValidationError('registry-salt scheduling bounds are invalid')
            retryAt = deadline if deadline is not None else now + delay
            if launch:
                pointer = expected.reply if receipt else expected.provision
                attempt = self.attempt(pointer) if pointer else None
                if attempt is None or now >= attempt.expiresAt:
                    raise ValidationError('registry-salt outbound attempt is missing or expired')
            updated = replace(expected, retryAt=float(retryAt), attempts=expected.attempts + int(launch))
        else:
            updated = replace(expected, state=state)
        table = self.db.saltReceipts if receipt else self.db.saltDeliveries
        key = table._tokey((expected.provision,) if receipt else expected.key)
        with self.db.env.begin(write=True) as txn:
            if expected.state != 'pending' or txn.get(key, db=table.sdb) != table._ser(expected):
                return None
            txn.put(key, table._ser(updated), db=table.sdb)
        return updated

    def markAttempt(self, expected, now, deadline):
        """Record an actual launch and positive durable receipt-wait deadline."""
        return self._progress(expected, now=now, deadline=deadline, launch=True)

    def failAttempt(self, expected, now, delay):
        """Schedule backoff after failure/readiness wait without counting a send."""
        return self._progress(expected, now=now, delay=delay)

    def blockDelivery(self, expected):
        """CAS-stop a removed or unauthorized member's operation."""
        return self._progress(expected, state='blocked')

    def markReceiptAttempt(self, expected, now, deadline):
        """Record a launched receipt and its durable transport-wait deadline."""
        return self._progress(expected, now=now, deadline=deadline, launch=True)

    def failReceiptAttempt(self, expected, now, delay):
        """Back off a failed receipt transport without adding another launch."""
        return self._progress(expected, now=now, delay=delay)

    def markReceiptSent(self, expected):
        """CAS-finish receipt transport; this does not assert remote acceptance."""
        return self._progress(expected, state='sent')

    def confirmDelivery(self, jobKey, provisionSaid, receiptSaid):
        """Confirm an operation from an externally authenticated target receipt.

        Any retained provision attempt for this operation may be acknowledged,
        including a late receipt after a newer packet was prepared. First receipt
        wins. No signature or current-member authority is inferred by this store.
        """
        _qualified(receiptSaid, Diger)
        attempt = self.attempt(provisionSaid)
        if attempt is None or attempt.kind != 'provision' or attempt.jobKey != tuple(jobKey):
            raise ValidationError('registry-salt receipt references no matching retained provision')
        with self.db.env.begin(write=True) as txn:
            key = self.db.saltDeliveries._tokey(jobKey)
            raw = txn.get(key, db=self.db.saltDeliveries.sdb)
            if raw is None:
                return None
            current = self.db.saltDeliveries._des(raw)
            if current.state == 'confirmed':
                return current
            updated = replace(current, state='confirmed', receipt=receiptSaid)
            txn.put(key, self.db.saltDeliveries._ser(updated), db=self.db.saltDeliveries.sdb)
        return updated

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
