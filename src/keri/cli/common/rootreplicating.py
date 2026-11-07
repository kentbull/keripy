"""Finite kli owner for local-profile ``/registry/root`` ESSR root replication.

``send`` and ``newcomers`` prepare one signed ESSR ``exn`` per (recipient,
registry) through ``salting.RegistryRoot`` and deliver each one to the
recipient's mailbox (topic ``credential``) with the shared finite sender.
``--out`` writes the same bytes to a file instead. ``receive`` is an
optional convenience drain: any kli command or agent that polls the
credential mailbox with the IPEX handlers already retains copies. It ingests
copies from the ``/credential`` mailbox (or ``--message`` files) through the
ordinary Parser, Kevery/KRAM and Exchanger path; the handler retains each
verifiable root automatically and escrows the rest for retry. ``receive``
then adopts stored copies no handler escrowed, drains that escrow once and
reports what is retained or still pending.
"""
import json
import math
from pathlib import Path

from hio.base import doing

from . import sending, setupHby
from .credentialing import recipient
from .presenting import opening
from ... import Kinds, Vrsn_2_0
from ...acdc import Regery, ipexing
from ...acdc.salting import RegistryRoot, RootUnverified
from ...app import GroupHab, Keeper, MailboxDirector, Notifier, SignifyGroupHab, SignifyHab
from ...core import Kevery, Kramer, Parser
from ...kering import ConfigurationError, KeriError, ValidationError
from ...peer import Exchanger


class RootReplication(doing.DoDoer):
    """Own one finite send, newcomers or receive invocation; retain no new ledger."""

    def __init__(self, args, verb):
        self.args, self.verb = args, verb
        super().__init__(doers=[doing.doify(self.run)])

    def check(self):
        if self.tyme >= self.deadline:
            raise TimeoutError('registry root replication did not complete before --timeout')

    def run(self, tymth, tock=0.03125, **kwa):
        self.wind(tymth)
        self.tock = tock
        yield tock
        args = self.args
        if args.version != Vrsn_2_0:
            raise ConfigurationError('registry root replication requires --version 2.0')
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ConfigurationError('--timeout must be finite and positive')
        out = getattr(args, 'out', None)
        if out and Path(out).exists():
            raise ConfigurationError('output already exists')
        keeper = Keeper(name=args.name, base=args.base, reopen=True)
        try:
            if not keeper.gbls.get('aeid'):
                raise ConfigurationError('registry root replication requires an existing encrypted Keeper')
        finally:
            keeper.close()
        self.deadline = self.tyme + args.timeout
        self.hby = setupHby(name=args.name, base=args.base, bran=args.bran, version=Vrsn_2_0)
        self.rgy, background = None, []
        try:
            self.hab = self.hby.habByName(args.alias)
            if (self.hab is None or not self.hab.accepted
                    or isinstance(self.hab, (SignifyHab, SignifyGroupHab))
                    or isinstance(self.hab, GroupHab) and self.hab.mhab is None):
                raise ConfigurationError('registry root replication requires an accepted local signer')
            self.rgy = Regery(hby=self.hby, name=args.name, base=args.base)
            self.notifier = Notifier(self.hby)
            self.root = RegistryRoot(self.hby, self.rgy, self.notifier)
            if self.verb == 'receive':
                yield from self.receive(background)
            else:
                yield from self.send()
        finally:
            self.remove(background)
            if self.rgy is not None:
                self.rgy.close()
            self.hby.close()

    # sending

    def copies(self):
        """Return [(recipient, gid, registry)] selected by this invocation."""
        args, hab = self.args, self.hab
        group = isinstance(hab, GroupHab)
        if self.verb == 'newcomers':
            if not group:
                raise ConfigurationError('newcomers requires a local group alias')
            gid = hab.pre
            recipients = self.root.newcomers(hab, args.rotation)
            registries = args.registry or self.root.held(gid)
            self.elected = self.root.witnesser(hab, args.rotation)
        else:
            gid = recipient(self.hby, args.holder) if args.holder else (hab.pre if group else None)
            if args.recipient:
                recipients = [recipient(self.hby, value) for value in args.recipient]
            elif group and gid == hab.pre:
                recipients = [aid for aid in self.root.members(gid) if aid != hab.mhab.pre]
            else:
                raise ConfigurationError('send requires --recipient unless a group alias sends to its members')
            registries = [args.registry]
        copies = []
        for member in recipients:
            for registry in registries:
                copies.append((member, gid if gid is not None else member, registry))
        return copies

    def send(self):
        args = self.args
        sender = self.hab.mhab if isinstance(self.hab, GroupHab) else self.hab
        self.elected = None
        copies = self.copies()
        prepared = []
        for member, gid, registry in copies:
            self.check()
            wire = self.root.prepare(sender, member, gid, registry,
                                     event=getattr(args, 'event', None), td=getattr(args, 'acdc', None))
            said = Parser(version=Vrsn_2_0).parseOneBare(ims=bytearray(wire), processive=False).serder.said
            prepared.append((dict(registry=registry, sender=sender.pre, recipient=member, gid=gid,
                                  exchange=said), wire))
        if self.verb == 'newcomers':
            print(json.dumps(dict(rotation=args.rotation, gid=self.hab.pre, elected=self.elected,
                                  newcomers=sorted({member for member, _, _ in copies}))), flush=True)
        if args.out:
            with Path(args.out).open('xb') as output:
                for _, wire in prepared:
                    output.write(wire)
        for result, wire in prepared:
            if not args.out:
                yield from sending.send(self, wire, result['recipient'], topic='credential')
            print(json.dumps(dict(result, transmitted=not args.out, output=args.out)), flush=True)

    # receiving

    def retained(self, registry):
        return self.hby.mgr.getRegistryRoot(self.hab.pre, registry) is not None

    def receive(self, background):
        """Ingest copies and let the handler retain them; report what remains."""
        args = self.args
        if args.listen and not args.registry:
            raise ConfigurationError('receive --listen requires --registry')
        if (args.event or args.opening) and not args.said:
            raise ConfigurationError('--event and --opening retry one stored copy; add --said')
        proof = opening(Path(args.opening).read_bytes()) if args.opening else None
        # The IPEX loader reuses this handler for /registry/root; other
        # credential-topic traffic stays retained as ordinary IPEX notes.
        exc = Exchanger(hby=self.hby, handlers=[self.root])
        ipexing.loadHandlers(self.hby, exc, self.notifier, rgy=self.rgy)
        kvy = Kevery(db=self.hby.db, rvy=self.hby.rvy, exc=exc, lax=True, local=False, direct=False,
                     kramer=Kramer(db=self.hby.db, cf=self.hby.cf))
        if args.message:
            psr = Parser(version=Vrsn_2_0, kvy=kvy, rvy=self.hby.rvy, exc=exc, rgy=self.rgy)
            for filename in args.message:
                psr.parse(ims=bytearray(Path(filename).read_bytes()), framed=False)
        elif args.listen:
            mbx = MailboxDirector(hby=self.hby, topics=['/credential'], exc=exc, kvy=kvy,
                                  rvy=self.hby.rvy, rgy=self.rgy,
                                  version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)
            background.append(mbx)
            self.extend([mbx])
            print(json.dumps(dict(registry=args.registry, phase='listening')), flush=True)
            while not self.retained(args.registry):
                self.check()
                yield self.tock
        # Drain: adopt stored copies no handler escrowed, then retry every
        # escrowed copy whose local state may now be present.
        self.root.reconcile()
        self.root.processEscrows()
        if args.said:
            try:
                self.root.receive(args.said, event=args.event, opening=proof)
            except RootUnverified as error:
                raise ConfigurationError(f'{error}; the copy stays pending') from None
        local = self.hab.mhab.pre if isinstance(self.hab, GroupHab) else self.hab.pre
        for item in self.root.pending():
            if item['recipient'] == local and item['gid'] == self.hab.pre:
                print(json.dumps(dict(item, retained=False)), flush=True)
        if args.registry:
            if not self.retained(args.registry):
                raise ConfigurationError('no registry root is retained for this registry')
            print(json.dumps(dict(gid=self.hab.pre, registry=args.registry, retained=True)), flush=True)
