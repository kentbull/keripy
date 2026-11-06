"""Update one existing v2 ACDC issuer registry without replacing its root."""
import argparse
import json
import math
from pathlib import Path

from hio.base import doing

from ....common import Parsery, parseVersion, setupHby
from ....common.registryanchoring import anchor, groupAnchor
from ....common import sending
from ....common.witnessing import witnessAuths
from ..... import Kinds, Vrsn_1_0, Vrsn_2_0
from .....acdc import Regery, Registry, Registrar, ipexing, regeventing
from .....app import GroupHab, Keeper, MailboxDirector, Multiplexor, Notifier, SignifyHab, SignifyGroupHab
from .....app.grouping import loadHandlers as loadGroupingHandlers
from .....core import Blinder, Kevery, Kramer, Number, SealSource, SerderACDC, messagize
from .....kering import ConfigurationError
from .....peer import Exchanger


parser = argparse.ArgumentParser(description='Update the state of one existing v2 ACDC credential',
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: [AcdcV2StateUpdate(args)])
parser.add_argument('--alias', '-a', required=True, help='accepted local issuer alias; group updates require exact member join')
parser.add_argument('--version', type=parseVersion, default=Vrsn_1_0)
parser.add_argument('--credential', required=True, help='exact self-verifying v2 ACDC credential body')
parser.add_argument('--state', required=True, choices=('issued', 'revoked', 'vacuous'))
parser.add_argument('--output', required=True, help='exclusive-create public KEL/TEL evidence file')
parser.add_argument('--timeout', type=float, default=120.0, help='finite whole-operation deadline')
parser.add_argument('--authenticate', '-z', action='store_true')
parser.add_argument('--code', action='append', default=[], help='selected witness AID:code')
parser.add_argument('--code-time', default=None, help='ISO8601 capture time of witness codes')


class AcdcV2StateUpdate(doing.DoDoer):
    """Require existing authority and verified current binding before authoring."""
    def __init__(self, args):
        self.args = args
        super().__init__(doers=[doing.doify(self.run)])

    def check(self):
        if self.tyme >= self.deadline:
            raise TimeoutError('v2 ACDC state update did not complete before --timeout; staged work may remain')

    def selected(self, body):
        """Resolve the exact owned registry and its root without generating one."""
        raw = Path(self.args.credential).read_bytes()
        if (body.raw != raw or body.pvrsn != Vrsn_2_0 or not body.verify()
                or body.ilk not in ('acm', 'act', 'acg') or body.israid != self.hab.pre):
            raise ConfigurationError('credential must exactly match the local issuer and owned v2 ACDC registry')
        rip = self.rgy.store.seqEvent(body.regid, 0)
        if rip is None or rip.said != body.regid or rip.israid != self.hab.pre:
            raise ConfigurationError('v2 ACDC registry inception does not match its local issuer')
        regeventing.vetAnchor(rip, db=self.hby.db, issuer=self.hab.pre)
        registry = self.rgy.regs.get(body.regid)
        if registry is None:
            if not isinstance(self.hab, GroupHab):
                raise ConfigurationError('credential must exactly match the local issuer and owned v2 ACDC registry')
            # Accepted imported group history needs no new persistent local alias.
            registry = Registry(hab=self.hab, store=self.rgy.store, regk=body.regid)
        root = self.hab.mgr.getRegistryRoot(self.hab.pre, registry.regk)
        if root is None:
            raise ConfigurationError('v2 ACDC state update requires the existing issuer-owned registry root')
        head = self.rgy.store.headEvent(registry.regk)
        if head is None or head.ilk != 'bup':
            raise ConfigurationError('v2 ACDC state update requires an accepted existing BUP, not a RIP-only registry')
        regeventing.vetAnchor(head, db=self.hby.db, issuer=self.hab.pre)
        frontier = registry._effectiveFrontier()
        if frontier is None or frontier.said != head.said:
            raise ConfigurationError('v2 ACDC registry has an outstanding staged successor; refusing another update')
        updates = [self.rgy.store.seqEvent(registry.regk, sn)
                   for sn in range(1, Number(numh=head.sad['n']).num + 1)]
        if any(event is None for event in updates):
            raise ConfigurationError('v2 ACDC registry accepted history is incomplete')
        proofs = []
        for event in reversed(updates):
            proof = self.rgy.store.opening(event.said)
            if proof is None:
                proof = Blinder.unblind(event.sad['b'], salt=root.qb64,
                    sn=Number(numh=event.sad['n']).num, acdc=body.said,
                    states=('issued', 'revoked', ''))
            if proof is None:
                raise ConfigurationError('current binding lacks a derivable ordinary or exact held opening')
            proofs.append(proof)
            if proof.acdc or proof.state:
                break
        regeventing.vetBinds(rip, updates, db=self.hby.db, blinders=proofs,
                            target=body.said, controller=self.hab.pre, acdc=body)
        return registry, root, head

    def send(self, raw, dest, *, topic='credential'):
        """Borrow the existing finite sender; this command retains acceptance authority."""
        yield from sending.send(self, raw, dest, topic=topic)

    def public(self, registry):
        """Export only accepted public history and its ordinary anchor sources."""
        raw = bytearray()
        for support in self.hby.db.cloneDelegation(self.hab.kever, gvrsn=Vrsn_2_0):
            raw.extend(support)
        raw.extend(self.hab.replay(gvrsn=Vrsn_2_0))
        for body in self.rgy.store.cloneTelIter(registry):
            event = SerderACDC(raw=body)
            sn, said = regeventing.vetAnchor(event, db=self.hby.db, issuer=self.hab.pre)
            raw.extend(messagize(event, bonds=[SealSource(s=f'{sn:x}', d=said)], gvrsn=Vrsn_2_0))
        return bytes(raw)

    def run(self, tymth, tock=0.03125, **kwa):
        self.wind(tymth)
        self.tock = tock
        yield tock
        args = self.args
        if args.version != Vrsn_2_0:
            raise ConfigurationError('v2 ACDC state update requires --version 2.0')
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ConfigurationError('--timeout must be finite and positive')
        self.deadline = self.tyme + args.timeout
        if Path(args.output).exists():
            raise ConfigurationError('output already exists')
        keeper = Keeper(name=args.name, base=args.base, reopen=True)
        try:
            if not keeper.gbls.get('aeid'):
                raise ConfigurationError('v2 ACDC state update requires an existing encrypted Keeper')
        finally:
            keeper.close()
        self.hby = setupHby(name=args.name, base=args.base, bran=args.bran, version=Vrsn_2_0)
        self.rgy, background, event, notifier = None, [], None, None
        try:
            self.hab = self.hby.habByName(args.alias)
            if (self.hab is None or not self.hab.accepted
                    or isinstance(self.hab, (SignifyHab, SignifyGroupHab))
                    or isinstance(self.hab, GroupHab) and (self.hab.mhab is None
                        or self.hab.mhab.pre not in self.hby.db.signingMembers(pre=self.hab.pre))):
                raise ConfigurationError('v2 ACDC state update requires an accepted local signer')
            group = isinstance(self.hab, GroupHab)
            self.rgy = Regery(self.hby, name=args.name, base=args.base)
            body = SerderACDC(raw=Path(args.credential).read_bytes())
            registry, root, prior = self.selected(body)
            auths = witnessAuths(self.hab.kever.wits, authenticate=args.authenticate,
                                codes=args.code, codeTime=args.code_time)
            self.check()
            # Reserve the requested output before staging a BUP or signing KEL.
            with Path(args.output).open('xb') as output:
                registrar = Registrar(self.rgy)
                _, event = (registrar.vacate(registry, salt=root.qb64) if args.state == 'vacuous'
                            else registrar.issue(registry, body, state=args.state, salt=root.qb64))
                result = dict(regid=registry.regk, priorHead=prior.said, head=event.said,
                    sequence=Number(numh=event.sad['n']).num, state=args.state, output=args.output)
                print(json.dumps(dict(result, accepted=False, phase='staged')), flush=True)
                kwa = {}
                if group:
                    notifier = Notifier(self.hby)
                    exc = Exchanger(hby=self.hby, handlers=[])
                    ipexing.loadHandlers(self.hby, exc, notifier, rgy=self.rgy)
                    kwa = dict(exc=exc, rvy=self.hby.rvy, kvy=Kevery(db=self.hby.db,
                        rvy=self.hby.rvy, exc=exc, lax=True, local=False, direct=False,
                        kramer=Kramer(db=self.hby.db, cf=self.hby.cf)))
                topics = ['/receipt', '/replay', '/delegate'] + (['/multisig'] if group else [])
                mailbox = MailboxDirector(hby=self.hby, topics=topics,
                    rgy=self.rgy, version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json, **kwa)
                if group:
                    self.psr = mailbox.parser
                    mux = Multiplexor(self.hby, notifier, rgy=self.rgy, replay=self.psr)
                    loadGroupingHandlers(exc, mux)
                background.append(mailbox)
                self.extend([mailbox])
                try:
                    if group:
                        yield from groupAnchor(self, registry, event, mux, background, auths=auths)
                    else:
                        yield from anchor(self, registry, event, auths, background)
                except TimeoutError:
                    print(json.dumps(dict(result, accepted=False, phase='incomplete')), flush=True)
                    raise
                output.write(self.public(registry.regk))
            print(json.dumps(dict(result, accepted=True)), flush=True)
        finally:
            self.remove(background)
            if notifier is not None:
                notifier.noter.close()
            if self.rgy is not None:
                self.rgy.close()
            self.hby.close()
