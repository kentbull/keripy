# -*- encoding: utf-8 -*-
"""
keri.acdc.registraring module

Registrar service support for managing Registries of ACDC state


"""

from hio.help import ogler

from ..kering import ClosedError, ConfigurationError, ValidationError
from ..core import Blinder, Diger, SerderACDC
from . import messaging, regeventing, scheming
from .regeventing import _normalizeEventRecord
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

    def _eventer(self, regk, rip=None):
        """Reconstruct a foreign engine from its RIP without creating a local alias."""
        if regk in self.regs:
            return self.regs[regk]._eventer
        rip = rip if rip is not None else self.store.event(regk)
        if rip is None:
            return None
        inception = regeventing._validateRip(rip)
        if inception.regk != regk:
            raise ValidationError("stored registry inception does not match its key")
        return regeventing._RegEventer(db=self.hby.db, issuer=inception.issuer,
                                       store=self.store, regk=regk)

    def processEvent(self, serder, *, sscs=None, ssts=None, **kwa):
        """Receive v2 ACDC RIP/BUP evidence and accept only its authenticated TEL.

        Parameters:
            serder (SerderACDC): incoming v2 ACDC registry event.
            sscs (list | None): issuer-implied KEL source couples.
            ssts (list | None): explicit-controller KEL source triples.
            **kwa: other parser attachments, which do not establish a TEL anchor.

        Returns:
            bool: True when accepted; False while KEL, anchor, or prior evidence
                remains unavailable in the existing dependency escrows.
        """
        event = _normalizeEventRecord(serder)
        if event.ilk == "rip":
            event = regeventing._validateRip(serder)
            rip = serder
        else:
            event = regeventing._validateUpdate(serder, regid=event.regk)
            rip = self.store.event(event.regk)
        eventer = self._eventer(event.regk, rip=rip)
        issuer = eventer.issuer if eventer is not None else None
        regeventing._validateSourceLocators(serder, db=self.hby.db, issuer=issuer,
                                            sscs=sscs or (), ssts=ssts or ())
        if eventer is None:
            self.store.putEvent(serder)
            self.store.escrowOutOfOrder(event.regk, event.sn, event.said)
            return False
        accepted = eventer.processEvent(serder)
        if event.ilk == "rip":
            self._processEventerEscrows(eventer)
        return accepted

    def _processEventerEscrows(self, eventer):
        """Give pre-inception updates ordinary anchor discovery before replay."""
        for _, sn, said in list(self.baser.ooes.getTopItemIter(keys=eventer.regk)):
            if self.store.anchor(said) is None:
                self.store.escrowMissingAnchor(eventer.regk, sn, said)
        eventer.processEscrows()

    def processEscrows(self):
        """Retry local and foreign registry dependencies from existing stored keys.

        Parameters:
            None

        Returns:
            None
        """
        for reg in self.regs.values():
            self._processEventerEscrows(reg._eventer)
        pending = {keys[0] for escrow in (self.baser.maes, self.baser.ooes)
                   for keys, _, _ in escrow.getTopItemIter()}
        for regk in sorted(pending - self.regs.keys()):
            eventer = self._eventer(regk)
            if eventer is not None:
                self._processEventerEscrows(eventer)

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
        self._eventer = regeventing._RegEventer(db=hab.db,
                                               issuer=hab.pre,
                                               store=store,
                                               regk=regk)

    @property
    def regk(self):
        # Surface the engine's current registry binding through the legacy API.
        return self._eventer.regk

    @regk.setter
    def regk(self, regk):
        self._eventer.regk = regk

    @property
    def regd(self):
        # Surface the engine's current accepted TEL head SAID.
        return self._eventer.regd

    @regd.setter
    def regd(self, regd):
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
        # The issuer-side blind path only accepts a full, self-verifying ACDC.
        if not isinstance(acdc, SerderACDC):
            raise ConfigurationError("acdc must be a SerderACDC")
        if not acdc.verify():
            raise ConfigurationError(f"acdc {acdc.said} is invalid")

        # The ACDC must already declare this registry as its governing TEL.
        regid = getattr(acdc, "regid", None)
        if regid is None:
            regid = acdc.sad.get("rd")
        if regid != self.regk:
            raise ConfigurationError(f"acdc {acdc.said} does not belong to registry {self.regk}")

        # The current habitat must also be the ACDC's issuer.
        issuer = getattr(acdc, "israid", None)
        if issuer is None:
            issuer = acdc.sad.get("i")
        if issuer != self.hab.pre:
            raise ConfigurationError(f"acdc {acdc.said} has issuer {issuer} not {self.hab.pre}")

        # Reject malformed credentials before deriving or staging an issuance event.
        scheming.validateSchema(acdc=acdc, db=self.hab.db)

        return self._blind(target=acdc.said, state=state, **kwa)

    def present(self, grant, state="presented", **kwa):
        """Create a blinded registry update binding a grant message SAID."""
        # Accept either a Grant serder or its qb64 SAID.
        target = grant.said if hasattr(grant, "said") else grant
        # Require a syntactically valid self-addressing target.
        try:
            Diger(qb64=target)
        except Exception as ex:
            raise ConfigurationError("presentation target must be a valid grant SAID") from ex
        # Reuse the shared blinded-update workflow.
        return self._blind(target=target, state=state, **kwa)

    def vacate(self, **kwa):
        """Create a vacuous update that leaves the prior registry state in force."""
        # Empty target and state mark an intentionally vacuous update.
        return self._blind(target="", state="", **kwa)


    def _blind(self, target, state, **kwa):
        """Create the next staged blinded update for a validated target SAID."""
        # Build from the staged frontier so callers may pipeline local updates.
        tip = self._effectiveFrontier()
        # Updates require an accepted or staged predecessor.
        if tip is None:
            raise ConfigurationError("registry must be anchored before updates")
        # Always derive the blinder from validated inputs internally.
        if "blinder" in kwa:
            raise ConfigurationError("caller-supplied blinder overrides are not supported")

        # Separate blinder options from TEL event options.
        blindkwa = {}
        # Move each supported blinder-only option out of the event arguments.
        for key in ("raw", "salt", "tier", "bound", "bsn", "bd"):
            if key in kwa:
                # These options belong to blinder construction, not the TEL
                # event body, so peel them off before calling blindate().
                blindkwa[key] = kwa.pop(key)

        # Normalize the frontier before deriving the next sequence number.
        tipEvent = _normalizeEventRecord(tip)
        # Advance exactly one TEL sequence number.
        sn = tipEvent.sn + 1
        # Derive the blinder from the next TEL sequence number so the bup and
        # blinded state commit to the same step in the chain.
        blinder = Blinder.blind(sn=sn, acdc=target, state=state, **blindkwa)
        # Create the bup that commits to the derived BLID.
        serder = messaging.blindate(regid=self.regk,
                                    prior=tipEvent.said,
                                    blid=blinder.said,
                                    sn=sn,
                                    **kwa)
        # Stage or accept the new event through normal TEL processing.
        self.processEvent(serder)
        # Return both the disclosure proof and its committed event.
        return blinder, serder

    def _effectiveFrontier(self):
        """Return the effective TEL frontier, including one staged successor chain.

        Returns:
            SerderACDC | None: accepted head event extended by a single
                unambiguous staged successor chain, or None when no accepted
                head exists yet.

        Raises:
            ConfigurationError: if multiple staged successors compete for the
                same next TEL sequence number.
        """
        # Start from the accepted TEL head and then walk forward through any
        # single unambiguous staged successor chain.
        tip = self.store.headEvent(self.regk) if self.regk is not None else None
        while tip is not None:
            tipEvent = _normalizeEventRecord(tip)
            sn = tipEvent.sn + 1
            saids = []
            seen = set()
            for escrowdb in (self.store.baser.maes, self.store.baser.ooes):
                for (said,) in escrowdb.get(keys=self.regk, on=sn):
                    # The same event may be observed across escrows during
                    # replay-heavy flows, so de-duplicate by SAID.
                    if said not in seen:
                        seen.add(said)
                        saids.append(said)

            matches = []
            for said in saids:
                staged = self.store.event(said)
                if staged is None:
                    continue
                stagedEvent = _normalizeEventRecord(staged)
                # Only events that point at the current frontier are eligible
                # to extend it for pipelined issuance.
                if stagedEvent.prior == tipEvent.said:
                    matches.append(stagedEvent)

            if not matches:
                break
            # Multiple staged successors at one slot mean the local staged TEL
            # has forked, so issuance fails closed instead of guessing.
            if len(matches) > 1:
                raise ConfigurationError(f"registry {self.regk} has conflicting staged successors at sn {sn}")
            tip = matches[0].serder

        return tip


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
