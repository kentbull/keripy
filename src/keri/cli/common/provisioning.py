"""Explicit finite copies of existing registry roots through native RegistrySalt."""
import json
import math
from pathlib import Path
from time import monotonic

from hio.base import doing

from . import setupHby
from .credentialing import recipient
from .presenting import opening
from ... import Kinds, Vrsn_2_0
from ...acdc import Regery
from ...acdc.salting import RegistrySalt
from ...app import GroupHab, Keeper, MailboxDirector, SignifyHab, SignifyGroupHab, StreamPoster
from ...app.agenting import HTTPStreamMessenger
from ...core import Kevery, Kramer, Parser, SerderACDC, SerderKERI
from ...kering import ConfigurationError, KeriError


class _Receipt:
    """Observe only native successful receipt, after decryption and Keeper retention."""
    def __init__(self, owner, check):
        self.owner, self.check, self.said, self.error = owner, check, None, None

    def processReply(self, **kwa):
        try:
            self.check()
            received = self.owner.processReply(**kwa)
        except (KeriError, ValueError, TimeoutError) as error:
            self.error = error
            raise
        if received is True and self.said is None:
            self.said = kwa['serder'].said


class NativeRootCopy(doing.DoDoer):
    """Own one approval, native parser and finite transport; retain no live ledger."""
    def __init__(self, args, role):
        self.args, self.role = args, role
        super().__init__(doers=[doing.doify(self.run)])

    def check(self):
        if monotonic() >= self.deadline:
            raise TimeoutError('registry root copy did not complete before --timeout')

    def public(self, raw):
        """Restrict evidence files to public support; native owners verify acceptance."""
        stream = bytearray(raw)
        parser = Parser(version=Vrsn_2_0)
        if not stream:
            raise ConfigurationError('--evidence requires complete public KEL/TEL frames')
        while stream:
            before = len(stream)
            try:
                frame = parser.parseOneBare(ims=stream, framed=True, processive=False)
            except Exception as error:
                raise ConfigurationError('--evidence requires complete public KEL/TEL frames') from error
            if frame is None or len(stream) >= before:
                raise ConfigurationError('--evidence requires complete public KEL/TEL frames')
            body = frame.serder
            if frame.bsqs or frame.bsss or frame.nests:
                raise ConfigurationError('--evidence must contain only public KEL/TEL support')
            allowed = (isinstance(body, SerderACDC) and body.ilk in ('rip', 'bup')
                       or isinstance(body, SerderKERI) and body.ilk in ('icp', 'rot', 'ixn', 'dip', 'drt', 'rct')
                       or isinstance(body, SerderKERI) and body.ilk == 'rpy'
                       and body.route.startswith(('/loc/scheme', '/end/role')))
            if not allowed:
                raise ConfigurationError('--evidence must contain only public KEL/TEL support')
        self.psr.parse(ims=bytearray(raw), framed=False)

    def send(self, wire, dest):
        """Use the existing StreamPoster and close its finite children on every exit."""
        poster = StreamPoster(hby=self.hby, hab=self.hab, recp=dest, topic='reply',
                              version=Vrsn_2_0, kind=Kinds.json)
        support = [*self.hby.db.cloneDelegation(self.hab.kever, gvrsn=Vrsn_2_0),
                   *self.hby.db.clonePreIter(self.hab.pre, gvrsn=Vrsn_2_0), wire]
        for raw in support:
            stream = bytearray(raw)
            while stream:
                before = bytes(stream)
                frame = Parser(version=Vrsn_2_0).parseOneBare(ims=stream, processive=False)
                consumed = len(before) - len(stream)
                poster.send(frame.serder, attachment=before[frame.serder.size:consumed], gvrsn=Vrsn_2_0)
        children = poster.deliver()
        if not children:
            raise ConfigurationError('no finite recipient transport was available')
        transport = doing.DoDoer(doers=children)
        self.extend([transport])
        try:
            while not transport.done:
                self.check()
                yield self.tock
            for child in children:
                if isinstance(child, HTTPStreamMessenger) and (child.rep is None
                        or not 200 <= child.rep.status < 300):
                    raise ConfigurationError('registry root copy HTTP submission failed')
        finally:
            self.remove([transport])

    def run(self, tymth, tock=0.03125, **kwa):
        self.wind(tymth)
        self.tock = tock
        yield tock
        args = self.args
        if args.version != Vrsn_2_0:
            raise ConfigurationError('registry root provisioning requires --version 2.0')
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ConfigurationError('--timeout must be finite and positive')
        if self.role == 'provision' and Path(args.output).exists():
            raise ConfigurationError('output already exists')
        keeper = Keeper(name=args.name, base=args.base, reopen=True)
        try:
            if not keeper.gbls.get('aeid'):
                raise ConfigurationError('registry root provisioning requires an existing encrypted Keeper')
        finally:
            keeper.close()
        self.deadline = monotonic() + args.timeout
        self.hby = setupHby(name=args.name, base=args.base, bran=args.bran, version=Vrsn_2_0)
        self.rgy, self.owner, sender, background = None, None, None, []
        try:
            self.hab = self.hby.habByName(args.alias)
            if (self.hab is None or not self.hab.accepted
                    or isinstance(self.hab, (GroupHab, SignifyHab, SignifyGroupHab))):
                raise ConfigurationError('registry root provisioning requires an accepted individual local signer')
            self.rgy = Regery(self.hby, name=args.name, base=args.base)
            self.owner = RegistrySalt(self.hab, self.rgy)
            if self.role == 'provision':
                dest = recipient(self.hby, args.recipient)
                wire = self.owner.prepare(args.registry, dest, dest)
                message = Parser(version=Vrsn_2_0).parseOneBare(
                    ims=bytearray(wire), processive=False).serder
                with Path(args.output).open('xb') as output:
                    output.write(wire)
                result = dict(registry=args.registry, recipient=dest, target=dest,
                              reply=message.said, output=args.output)
                if args.deliver:
                    print(json.dumps(dict(result, phase='prepared', transmitted=False)), flush=True)
                    yield from self.send(wire, dest)
                print(json.dumps(dict(result, transmitted=args.deliver)), flush=True)
                return
            kvy = Kevery(db=self.hby.db, rvy=self.hby.rvy, lax=True, local=False,
                         kramer=Kramer(db=self.hby.db, cf=self.hby.cf))
            self.psr = Parser(version=Vrsn_2_0, kvy=kvy, rvy=self.hby.rvy, rgy=self.rgy)
            for filename in args.evidence:
                self.public(Path(filename).read_bytes())
            kvy.processEscrows()
            self.rgy.processEscrows()
            sender = recipient(self.hby, args.sender)
            proof = opening(Path(args.opening).read_bytes())
            self.check()
            self.owner.approve(args.registry, sender, event=args.event, opening=proof)
            receipt = _Receipt(self.owner, self.check)
            self.hby.rtr.addRoute(RegistrySalt.Route, receipt, attachments=True)
            selected = dict(registry=args.registry, sender=sender, recipient=self.hab.pre, event=args.event)
            print(json.dumps(dict(selected, phase='approved', received=False)), flush=True)
            if args.message:
                wire = Path(args.message).read_bytes()
                stream = bytearray(wire)
                frame = Parser(version=Vrsn_2_0).parseOneBare(ims=stream, processive=False)
                if stream or frame.serder.ilk != 'rpy' or frame.serder.route != RegistrySalt.Route:
                    raise ConfigurationError('--message requires exactly one encrypted registry reply')
                self.psr.parse(ims=bytearray(wire), framed=False)
                if receipt.said is None:
                    raise ConfigurationError(str(receipt.error) if receipt.error else
                                             'selected reply was not successfully received')
            else:
                mailbox = MailboxDirector(hby=self.hby, topics=['/reply', '/replay', '/receipt'],
                    kvy=kvy, rvy=self.hby.rvy, rgy=self.rgy,
                    version=Vrsn_2_0, gvrsn=Vrsn_2_0, kind=Kinds.json)
                background.append(mailbox)
                self.extend([mailbox])
                while receipt.said is None:
                    if receipt.error:
                        raise receipt.error
                    self.check()
                    yield tock
            print(json.dumps(dict(selected, reply=receipt.said, received=True)), flush=True)
        finally:
            if self.owner is not None and sender is not None:
                self.owner.abandon(args.registry, sender)
            self.remove(background)
            if self.rgy is not None:
                self.rgy.close()
            self.hby.close()
