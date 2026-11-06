"""Explicit finite copies of existing registry roots through v2 ACDC RegistrySalt."""
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
from ...app import (GroupHab, Keeper, MailboxDirector, SignifyHab, SignifyGroupHab,
                    StreamPoster, multisigRpyExn)
from ...app.habbing import _groupWitnesserSelection
from ...app.agenting import HTTPStreamMessenger
from ...core import Cipher, Kevery, Kramer, MtrDex, Parser, SerderACDC, SerderKERI, messagize
from ...kering import ConfigurationError, KeriError
from ...peer import Exchanger
from ...peer.exchanging import loadParsedNestedSubstreams


class _Proposal:
    """Authenticate the selected custodian's exact ciphertext before local contribution."""
    resource = '/multisig/rpy'

    def __init__(self, command, recipient, target, coordinator):
        self.command, self.recipient, self.target = command, recipient, target
        self.said = None
        self.selection = _groupWitnesserSelection(command.hab, sn=coordinator[0], dig=coordinator[1])
        if self.selection is None:
            raise ConfigurationError('proposal requires an exact accepted threshold-signed coordinator event')

    def verify(self, serder, attachments=None, nests=None):
        command = self.command
        command.check()
        try:
            if attachments or serder.pvrsn != Vrsn_2_0 or len(nests) != 1:
                return False
            child = nests[0]
            child = child if isinstance(child, dict) else vars(child)
            body = child['serder']
            if (body.pvrsn != Vrsn_2_0 or body.ilk != 'rpy' or body.route != RegistrySalt.Route
                    or body.pre != command.hab.pre or not body.verify()
                    or serder.sad['a'] != dict(gid=body.pre, rpy=body.said)
                    or not child.get('tsgs')
                    or any(value for key, value in child.items() if key not in ('serder', 'tsgs'))):
                return False
            current = command.hab.kever.lastEst
            if any(pre.qb64 != body.pre or number.sn != current.s or diger.qb64 != current.d
                   for pre, number, diger, _ in child['tsgs']):
                return False
            establishment, index = self.selection
            proposer = command.hby.kevers.get(serder.pre)
            contribution = proposer.fetchLatestContribTo(verfers=establishment.verfers) if proposer else None
            if (contribution is None or contribution[1] != index
                    or proposer.fetchLatestContribTo(verfers=command.hab.kever.verfers) is None):
                return False
            command.owner._scope(command.args.registry, command.hab.pre, self.recipient, self.target)
            data = body.sad['a']
            if (set(data) != {'registry', 'recipient', 'target', 'cipher'}
                    or data['registry'] != command.args.registry or data['recipient'] != self.recipient
                    or data['target'] != self.target):
                return False
            cipher = Cipher(qb64=data['cipher'])
            return cipher.code == MtrDex.X25519_Cipher_Salt and cipher.qb64 == data['cipher']
        except (KeriError, ValueError, KeyError, TypeError, AttributeError):
            return False

    def handle(self, serder, attachments=None, nests=None):
        # This invocation must actually authenticate the packet; retained rows cannot grant consent.
        self.command.check()
        self.said = serder.said


class _Receipt:
    """Observe only v2 ACDC successful receipt, after decryption and Keeper retention."""
    def __init__(self, owner, check):
        self.owner, self.check, self.said, self.error = owner, check, None, None
        self.waiting = None

    def processReply(self, **kwa):
        try:
            self.check()
            received = self.owner.processReply(**kwa)
        except (KeriError, ValueError, TimeoutError) as error:
            self.error = error
            raise
        if received is True and self.said is None:
            self.said = kwa['serder'].said
        elif (received is None and isinstance(self.owner.hab, GroupHab)
              and self.waiting != kwa['serder'].said):
            self.waiting = kwa['serder'].said
            print(json.dumps(dict(registry=kwa['serder'].sad['a']['registry'],
                reply=kwa['serder'].said, phase='awaiting_signatures', received=False)), flush=True)


class AcdcV2RootCopy(doing.DoDoer):
    """Own one approval, v2 parser and finite transport; retain no live ledger."""
    def __init__(self, args, role):
        self.args, self.role = args, role
        super().__init__(doers=[doing.doify(self.run)])

    def check(self):
        if monotonic() >= self.deadline:
            raise TimeoutError('registry root copy did not complete before --timeout')

    def public(self, raw):
        """Restrict evidence files to public support; v2 ACDC owners verify acceptance."""
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
        sender = self.hab.mhab if isinstance(self.hab, GroupHab) else self.hab
        poster = StreamPoster(hby=self.hby, hab=sender, recp=dest, topic='reply',
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
            self.check()
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
        if self.role == 'provision':
            if args.proposal and args.proposal_output:
                raise ConfigurationError('contributors output v2 replies; use the original custodian proposal for further contributions')
            paths = [args.output] + ([args.proposal_output] if args.proposal_output else [])
            if len({Path(path).resolve() for path in paths}) != len(paths):
                raise ConfigurationError('reply and proposal outputs must be distinct')
            if any(Path(path).exists() for path in paths):
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
                    or isinstance(self.hab, (SignifyHab, SignifyGroupHab))):
                raise ConfigurationError('registry root provisioning requires an accepted local signer')
            self.rgy = Regery(self.hby, name=args.name, base=args.base)
            self.owner = RegistrySalt(self.hab, self.rgy)
            if self.role == 'provision':
                dest = recipient(self.hby, args.recipient)
                target = recipient(self.hby, args.target) if args.target else dest
                group = isinstance(self.hab, GroupHab)
                coordinator = None
                if group:
                    event = self.hby.db.evts.get((self.hab.pre, args.coordinator)) if args.coordinator else None
                    if event is None or not args.target:
                        raise ConfigurationError('group provision requires --coordinator event SAID and explicit --target AID')
                    coordinator = (event.sn, event.said)
                    if not args.proposal and not args.proposal_output:
                        raise ConfigurationError('group ciphertext preparation requires --proposal-output')
                elif args.coordinator or args.proposal or args.proposal_output:
                    raise ConfigurationError('group proposal options require a local group signer')
                if args.proposal:
                    raw = Path(args.proposal).read_bytes()
                    stream = bytearray(raw)
                    frame = Parser(version=Vrsn_2_0).parseOneBare(ims=stream, framed=True, processive=False)
                    if (stream or frame.serder.pvrsn != Vrsn_2_0 or frame.serder.ilk not in ('xip', 'exn')
                            or frame.serder.route != _Proposal.resource):
                        raise ConfigurationError('--proposal requires one exact v2 /multisig/rpy envelope')
                    approval = _Proposal(self, dest, target, coordinator)
                    exc = Exchanger(hby=self.hby, handlers=[approval])
                    Parser(version=Vrsn_2_0, exc=exc).parse(ims=bytearray(raw))
                    if approval.said != frame.serder.said:
                        raise ConfigurationError('proposal did not pass selected custodian and scope authentication')
                    retained = loadParsedNestedSubstreams(self.hby, frame.serder.said)[0]
                    self.check()
                    endorsement = self.hab.endorse(retained.serder, gvrsn=Vrsn_2_0)
                    local = Parser(version=Vrsn_2_0).parseOneBare(ims=endorsement, framed=True, processive=False)
                    wire = messagize(retained.serder, tsgs=[*retained.tsgs, *local.tsgs], gvrsn=Vrsn_2_0)
                else:
                    self.check()
                    wire = self.owner.prepare(args.registry, dest, target, coordinator=coordinator)
                message = Parser(version=Vrsn_2_0).parseOneBare(
                    ims=bytearray(wire), processive=False).serder
                if args.proposal_output:
                    wrapper, atc = multisigRpyExn(self.hab, wire, version=Vrsn_2_0)
                    with Path(args.proposal_output).open('xb') as output:
                        output.write(wrapper.raw + atc)
                self.check()
                with Path(args.output).open('xb') as output:
                    output.write(wire)
                result = dict(registry=args.registry, recipient=dest, target=target,
                              reply=message.said, output=args.output)
                if group:
                    result.update(prepared=not args.proposal, contributed=bool(args.proposal), proposal=args.proposal_output)
                if args.deliver:
                    print(json.dumps(dict(result, phase='contributed' if args.proposal else 'prepared',
                                          transmitted=False)), flush=True)
                    yield from self.send(wire, target)
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
            wires, selectedBody = [], None
            for filename in args.message or []:
                wire = Path(filename).read_bytes()
                stream = bytearray(wire)
                frame = Parser(version=Vrsn_2_0).parseOneBare(ims=stream, framed=True, processive=False)
                if (stream or frame.serder.ilk != 'rpy' or frame.serder.route != RegistrySalt.Route
                        or selectedBody is not None and selectedBody != frame.serder.raw):
                    raise ConfigurationError('--message requires contributions to one exact encrypted registry reply')
                selectedBody = frame.serder.raw
                wires.append(wire)
            self.check()
            self.owner.approve(args.registry, sender, event=args.event, opening=proof)
            receipt = _Receipt(self.owner, self.check)
            self.hby.rtr.addRoute(RegistrySalt.Route, receipt, attachments=True)
            selected = dict(registry=args.registry, sender=sender, recipient=self.hab.pre, event=args.event)
            print(json.dumps(dict(selected, phase='approved', received=False)), flush=True)
            if args.message:
                for wire in wires:
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
