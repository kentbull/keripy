# -*- encoding: utf-8 -*-
"""
keri.acdc.registraring module

Registrar service support for managing Registries of ACDC state


"""

from base64 import b64encode
from dataclasses import dataclass, field

from hio.help import ogler

from ..core import Blinder, BoundState, Number, Prefixer, Diger, Saider

from ..kering import ClosedError, ConfigurationError, ValidationError
from . import messaging, regeventing
from .registering import RegistryStore, openRegistry

logger = ogler.getLogger()


class Regery:
    """Local manager for V2 ACDC blindable state registries."""

    def __init__(self, hby, name="test", base="", baser=None, temp=False, web=False):
        """Create a registry manager around one registry storage backend.

        Parameters:
            hby (Habery): local habitat environment that owns the registries.
            name (str): human-facing storage name for the registry backend.
            base (str): optional storage base path qualifier.
            baser (RegBaser | WebRegBaser | None): optional pre-opened registry
                backend. When ``None``, one is created from ``openRegistry``.
            temp (bool): True means use temporary storage semantics.
            web (bool): True means use the web storage backend.

        Returns:
            None
        """
        self.hby = hby
        self.name = name
        self.base = base
        self.temp = temp
        self.baser = baser if baser is not None else openRegistry(name=name,
                                                                  base=base,
                                                                  temp=temp,
                                                                  web=web)
        self.store = RegistryStore(self.baser)
        self.regs = {}
        self.names = {}
        if self.store.opened:
            self.loadRegistries()

    def makeRegistry(self, name, prefix, **kwa):
        """Create, stage, and register a new local V2 registry.

        Parameters:
            name (str): local alias for the registry.
            prefix (str): qb64 AID prefix of the habitat that controls the
                registry.
            **kwa: keyword arguments forwarded to ``messaging.regcept``.

        Returns:
            Registry: newly created managed registry instance.
        """
        if name in self.names:
            raise ConfigurationError(f"registry {name} already exists")

        hab = self.hby.habs.get(prefix)
        if hab is None:
            raise ConfigurationError(f"unknown prefix {prefix} for registry {name}")

        serder = messaging.regcept(israid=hab.pre, **kwa)
        if serder.said in self.regs:
            raise ConfigurationError(f"registry {serder.said} already exists")

        reg = Registry(hab=hab, store=self.store, name=name)
        reg.processEvent(serder)
        self.store.records.pin(keys=name,
                               val=self.store.records.klas(registryKey=reg.regk))
        self.regs[reg.regk] = reg
        self.names[name] = reg
        return reg

    def loadRegistries(self):
        """Load persisted registry aliases into the in-memory manager maps.

        Raises:
            ConfigurationError: if a persisted registry is missing its stored
                inception event, if that event is not a ``rip``, or if the
                controlling habitat named by the stored inception issuer is not
                loaded in this Habery.
        """
        for (name,), record in self.store.records.getTopItemIter():
            rip = self.store.event(record.registryKey)
            if rip is None:
                raise ConfigurationError(f"missing registry inception event {record.registryKey} for registry {name}")
            if rip.ilk != "rip":
                raise ConfigurationError(f"registry {record.registryKey} for {name} has invalid inception type {rip.ilk}")

            prefix = rip.sad["i"]
            hab = self.hby.habs.get(prefix)
            if hab is None:
                raise ConfigurationError(f"unknown prefix {prefix} for registry {name}")

            reg = self.regs.get(record.registryKey)
            if reg is None:
                reg = Registry(hab=hab, store=self.store, name=name, regk=record.registryKey)
                head = self.store.head(reg.regk)
                reg.regd = head.qb64 if head is not None else reg.regk
                self.regs[reg.regk] = reg
            self.names[name] = reg

    def registryByName(self, name):
        """Look up one managed registry by its local alias.

        Parameters:
            name (str): local alias used when the registry was created.

        Returns:
            Registry | None: matching registry instance when present, else None.
        """
        return self.names.get(name)

    def processEscrows(self):
        """Retry queued escrow work for every managed registry.

        Parameters:
            None

        Returns:
            None
        """
        for reg in self.regs.values():
            reg.processEscrows()

    def close(self):
        """Close the underlying registry storage backend.

        Parameters:
            None

        Returns:
            None

        Raises:
            ClosedError: if the registry backend has already been closed.
        """
        if not self.store.opened:
            raise ClosedError("attempt to close unopened registry store")
        self.store.close()


class Registry:
    """Transaction-state registry backed by the ACDC registry stores."""

    def __init__(self, hab, store, name="test", regk=None):
        """Create one local registry state machine bound to a habitat.

        Parameters:
            hab (Hab): controlling habitat for this registry.
            store (RegistryStore): storage adapter for registry events, anchors,
                and escrows.
            name (str): local alias for the registry.
            regk (str | None): registry identifier when reopening or attaching to
                an existing registry state.

        Returns:
            None
        """
        self.hab = hab
        self.store = store
        self.name = name
        # Registry remains the public facade, but the TEL event state machine
        # now lives in the private regeventing engine.
        self._eventer = regeventing._RegEventer(hab=hab,
                                                store=store,
                                                regk=regk)

    @property
    def regk(self):
        """Return the registry identifier bound to the shared event engine."""
        # Surface the engine's current registry binding through the legacy API.
        return self._eventer.regk

    @regk.setter
    def regk(self, regk):
        """Bind regk on the shared engine without independently accepting history."""
        self._eventer.regk = regk

    @property
    def regd(self):
        """Return the shared engine's current registry TEL head digest."""
        # Surface the engine's current accepted TEL head SAID.
        return self._eventer.regd

    @regd.setter
    def regd(self, regd):
        """Set the engine's head reference; event verification remains engine-owned."""
        self._eventer.regd = regd

    @property
    def head(self):
        """Return the SAID of the current accepted head event.

        Returns:
            Saider | None: SAID of the current accepted head event, or None when
                the registry has no accepted head yet.
        """
        return self._eventer.head

    @property
    def sn(self):
        """Return the sequence number of the current accepted head event.

        Returns:
            int: accepted head sequence number, or ``-1`` when the registry has
                not committed any event yet.
        """
        return self._eventer.sn

    @property
    def regser(self):
        """Return the accepted registry inception event when available.

        Returns:
            SerderACDC | None: accepted ``rip`` event, or None when inception has
                not been committed yet.
        """
        return self._eventer.regser

    def processEvent(self, serder):
        """Store one registry event and commit it when anchor and order allow.

        Parameters:
            serder (SerderACDC): candidate registry event to process. Supported
                ilks are ``rip`` and ``bup``.

        Returns:
            bool: True when the event is accepted immediately or was already
                accepted idempotently. False when the event is stored but left
                in escrow because its anchor or prior ordering prerequisites are
                not yet satisfied.

        Raises:
            ValidationError: if the event type is unsupported, belongs to a
                different registry, conflicts with an existing committed event,
                has an invalid inception sequence number, or names an invalid
                prior event.
        """
        # Delegate TEL ingestion to the shared local event engine.
        return self._eventer.processEvent(serder)
              
    def processEscrows(self):
        """Retry missing-anchor and out-of-order escrows for this registry.

        Parameters:
            None

        Returns:
            None
        """
        # Keep the public entrypoint here while the actual replay workflow
        # lives beside the rest of the TEL engine in regeventing.py.
        self._eventer.processEscrows()

    def anchorMsg(self, said, number=None, diger=None):
        """Validate and record the KEL anchor for one stored registry event.

        Parameters:
            said (str): SAID of the stored registry event to anchor.
            number (Number | None): optional sequence number of the sealing KEL
                event. Must be supplied together with ``diger``. When both are
                omitted, the local KEL is searched for a sealing event that
                matches this registry event.
            diger (Diger | None): optional digest of the sealing KEL event.
                Must be supplied together with ``number``. When both are
                omitted, the local KEL is searched for a sealing event that
                matches this registry event.

        Returns:
            bool: True when the validated anchor allows the event to commit
                immediately, False when the event remains queued behind an
                unmet prior-event dependency.

        Raises:
            ValidationError: if the event is unknown, if only one of
                ``number``/``diger`` is supplied, or if the supplied anchor
                does not validate against the controlling habitat's KEL.
        """
        # Preserve the existing public API while delegating anchor handling to
        # the shared local event engine.
        return self._eventer.anchorMsg(said, number=number, diger=diger)

    def make(self, **kwa):
        """Create and stage a registry inception event for this registry.

        Parameters:
            **kwa: keyword arguments forwarded to ``messaging.regcept``.

        Returns:
            SerderACDC: created ``rip`` event staged until a sealing KEL event
                is later validated with ``anchorMsg``.
        """
        serder = messaging.regcept(israid=self.hab.pre, **kwa)
        self.processEvent(serder)
        return serder

    def blind(self, acdc, state, **kwa):
        """Create and stage one blindable registry state update event.

        Parameters:
            acdc (SerderACDC): valid transaction-state ACDC whose registry
                identifier and issuer must match this registry and its
                controlling habitat.
            state (str): logical state represented by the blindable update.
            **kwa: keyword arguments forwarded to ``Blinder.blind`` and
                ``messaging.blindate``. Keys used to build a blinder are removed
                from ``kwa`` before the message event is created. Blinders are
                always derived internally for this update; passing ``blinder``
                explicitly is not supported.

        Returns:
            tuple: ``(blinder, serder)`` where ``blinder`` is the generated
                ``Blinder`` instance and ``serder`` is the created ``bup``
                event staged until a sealing KEL event is later validated with
                ``anchorMsg``.

        Raises:
            ConfigurationError: if the registry has not yet committed an
                accepted inception/head event, if ``acdc`` is not a valid
                ``SerderACDC``, if the ACDC does not belong to this registry or
                controlling habitat, or if an unsupported explicit ``blinder``
                argument is supplied.
            MissingSchemaError: if the ACDC's external schema is unavailable.
            FailedSchemaValidationError: if the ACDC violates its schema.
        """
        # Blind issuance remains a Registry method for callers, but the staged
        # frontier walk and TEL event creation now live in regeventing.py.
        return self._eventer.blind(acdc=acdc, state=state, **kwa)

    def present(self, grant, state="presented", **kwa):
        """Create a blinded registry update binding a grant message SAID."""
        # Delegate event construction to this registry's TEL engine.
        return self._eventer.present(grant=grant, state=state, **kwa)

    def vacate(self, **kwa):
        """Create a vacuous update that leaves the prior registry state in force."""
        # Delegate vacuous event construction to the TEL engine.
        return self._eventer.vacate(**kwa)


@dataclass
class IssuedCredential:
    """Read-only view of Reger credential bytes and source coordinates.

        credential/registry/controller/update bind accepted issuance. raw is base64
        under encoding='base64'; bound retains original issuee KEL coordinates for
        explicitly supplied bound openings, never a salt or current-standing claim.

        The reference view originated in our adaptation of KERI Foundation
        Locksmith 3a5ad9ebcf98b4ec03baf1bbb91d928d49c168e4 (Apache-2.0).
        This view is reconstructed from existing Reger evidence, not persisted.
    """
    credential: str
    registry: str
    controller: str
    update: str
    raw: str
    encoding: str
    bound: dict = field(default_factory=dict)


class Registrar:
    """Small facade for V2 registry inception and blindable state updates."""

    def __init__(self, rgy):
        """Create a caller-facing registry helper around a Regery.

        Parameters:
            rgy (Regery): managed registry environment used to resolve and
                operate on registries.

        Returns:
            None
        """
        self.rgy = rgy

    def recordIssued(self, reger, acdc, update, *, blinder=None):
        """Record verified issuance, or return an identical historical record.

        Args:
            reger (Reger): Caller-owned credential and exact-opening store.
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
        if rip is None or event is None or self.rgy.hby.habByPre(rip.sad['i']) is None:
            raise ValidationError('local accepted issuance evidence is required')
        sn = Number(numh=event.sad['n']).num
        accepted = self.rgy.store.seqEvent(regid, sn)
        if accepted is None or accepted.said != update:
            raise ValidationError('issuance update is still pending')
        old = self.issuedRecord(reger, acdc.said)
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
        verified = regeventing.vet(rip, updates, db=self.rgy.hby.db, acdc=acdc, blinder=proof)
        if verified.state != 'issued':
            raise ValidationError('referenced update is not an issued state')
        record = IssuedCredential(acdc.said, regid, rip.sad['i'], update,
                                  b64encode(acdc.raw).decode('ascii'), 'base64',
                                  dict(bn=proof.data.bn.num, bd=proof.data.bd.qb64)
                                  if proof is not None and proof.clan == BoundState else {})
        if old is not None and old != record:
            raise ValidationError('different issuance is already retained for this credential')
        stored = reger.creds.get((acdc.said,))
        if stored is not None and stored.raw != acdc.raw:
            raise ValidationError('different credential bytes already occupy the Reger identifier')
        if proof is not None:
            reger.retainPrivateOpening(event, proof)
        # Reuse Reger.logCred's credential/source representation and its normal
        # issuer index. One native LMDB transaction exposes the complete record;
        # no application rollback, retry journal or duplicate byte archive exists.
        source = (Prefixer(qb64=regid), Number(num=sn), Diger(qb64=update))
        with reger.env.begin(write=True) as txn:
            txn.put(reger.creds._tokey((acdc.said,)), reger.creds._ser(acdc),
                    db=reger.creds.sdb, overwrite=False)
            txn.put(reger.cancs._tokey((acdc.said,)), reger.cancs._ser(source),
                    db=reger.cancs.sdb, overwrite=False)
            txn.put(reger.issus._tokey((acdc.israid,)), reger.issus._ser(Saider(qb64=acdc.said)),
                    db=reger.issus.sdb, dupdata=False)
        return record

    def issuedRecord(self, reger, credential):
        """Read a native issuance view from existing Reger credential/source tables.

        Args:
            reger (Reger): Caller-owned credential and exact-opening store.
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
        acdc = reger.creds.get((credential,))
        source = reger.cancs.get((credential,))
        if (acdc is None or acdc.pvrsn.major != 2 or source is None
                or self.rgy.hby.habByPre(acdc.israid) is None):
            return None
        prefixer, number, diger = source
        event = self.rgy.store.seqEvent(prefixer.qb64, number.num)
        if event is None or event.said != diger.qb64:
            raise ValidationError('issued source is not an accepted registry event')
        proof = reger.privateOpening(event)
        bound = dict(bn=proof.bsn, bd=proof.bd) if proof is not None and proof.bsn is not None else {}
        return IssuedCredential(acdc.said, prefixer.qb64, acdc.israid, diger.qb64,
                                b64encode(acdc.raw).decode('ascii'), 'base64', bound)

    def issuedRecords(self, reger):
        """Return local native issuances selected by Reger's existing issuer index.

        Args:
            reger (Reger): Caller-owned credential and exact-opening store.

        Returns:
            list[IssuedCredential]: Views of locally controlled native credentials.
                Legacy and foreign credentials are not treated as local issuances.
        """
        records = []
        for (issuer,), said in reger.issus.getTopItemIter():
            if self.rgy.hby.habByPre(issuer) is None:
                continue
            record = self.issuedRecord(reger, said.qb64)
            if record is not None:
                records.append(record)
        return records

    def issuedCredential(self, reger, credential):
        """Return exact native credential bytes retained by the existing Reger.

        Args:
            reger (Reger): Caller-owned credential and exact-opening store.
            credential (str): Locally issued credential identifier.

        Returns:
            SerderACDC: Original serialization, including CBOR or MessagePack.

        Raises:
            ValidationError: The local native issuance source is missing or invalid.

        Retrieval is historical and makes no current-standing claim.
        """
        if self.issuedRecord(reger, credential) is None:
            raise ValidationError('issued credential with a supported encoding is required')
        return reger.creds.get((credential,))

    def _registry(self, registry):
        """Resolve a registry object from an instance, key, or local name.

        Parameters:
            registry (Registry | str): registry instance, registry key, or local
                registry alias.

        Returns:
            Registry: resolved registry instance.

        Raises:
            ConfigurationError: if the supplied registry reference cannot be
                resolved.
        """
        if isinstance(registry, Registry):
            return registry
        if registry in self.rgy.regs:
            return self.rgy.regs[registry]
        reg = self.rgy.registryByName(registry)
        if reg is None:
            raise ConfigurationError(f"unknown registry {registry}")
        return reg

    def makeRegistry(self, name, prefix, **kwa):
        """Create and register a named registry for one local habitat.

        Parameters:
            name (str): local alias for the registry.
            prefix (str): qb64 AID prefix of the controlling habitat.
            **kwa: keyword arguments forwarded to ``Regery.makeRegistry``.

        Returns:
            Registry: newly created managed registry.
        """
        return self.rgy.makeRegistry(name=name, prefix=prefix, **kwa)

    def issue(self, registry, acdc, state="issued", **kwa):
        """Create one blindable registry update through the facade.

        Parameters:
            registry (Registry | str): registry instance, key, or local alias.
            acdc (SerderACDC): transaction-state ACDC whose registry identifier
                and issuer must match the target registry and its controller.
            state (str): target logical state for the update.
            **kwa: keyword arguments forwarded to ``Registry.blind``.

        Returns:
            tuple: ``(blinder, serder)`` where ``blinder`` is the created
                ``Blinder`` and ``serder`` is the created ``bup`` event.

        Raises:
            MissingSchemaError: if the ACDC's external schema is unavailable.
            FailedSchemaValidationError: if the ACDC violates its schema.
        """
        reg = self._registry(registry)
        return reg.blind(acdc=acdc, state=state, **kwa)

    def present(self, registry, grant, state="presented", **kwa):
        """Bind a grant message SAID in an issuee-controlled registry."""
        # Resolve an instance, registry key, or local alias.
        reg = self._registry(registry)
        # Build the presentation update through the resolved registry.
        return reg.present(grant=grant, state=state, **kwa)

    def vacate(self, registry, **kwa):
        """Append a vacuous blinded update through the public facade."""
        # Resolve an instance, registry key, or local alias.
        reg = self._registry(registry)
        # Build the vacuous update through the resolved registry.
        return reg.vacate(**kwa)
