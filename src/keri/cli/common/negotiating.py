"""Finite individual native IPEX negotiation; public intake never implies consent."""
import json
import math
from dataclasses import asdict
from pathlib import Path

from hio.base import doing

from . import parseVersion, setupHby
from ... import Kinds, Vrsn_1_0, Vrsn_2_0
from ...acdc import ipexing
from ...app.agenting import HTTPStreamMessenger
from ...app import GroupHab, SignifyHab, SignifyGroupHab, Notifier, StreamPoster
from ...core import Parser
from ...kering import ConfigurationError
from ...peer import Exchanger
from ...peer.exchanging import serializeMessage, verify


def options(parser):
    """Add opt-in native arguments without requiring them for the released nonce command."""
    parser.add_argument('--version', type=parseVersion, default=Vrsn_1_0)
    parser.add_argument('--alias', '-a')
    parser.add_argument('--message', '-m', default='')
    parser.add_argument('--input', action='append', default=[], help='signed public KEL/IPEX CESR file to receive')
    parser.add_argument('--output', help='create a public CESR file without overwriting')
    parser.add_argument('--deliver', action='store_true', help='submit through existing recipient endpoints/mailboxes')
    parser.add_argument('--timeout', type=float, default=30.0, help='finite transport wait; does not change protocol deadlines')


class NativeNegotiation(doing.DoDoer):
    """Own one explicit apply, offer or agree and its finite transport children.

    Incoming files use ordinary KEL/Exchanger acceptance. The selected command
    alone authorizes the response. No registry, private-operation journal or
    receiver service is opened; required anchored Agree completion is separate.
    """
    def __init__(self, args, verb):
        self.args, self.verb = args, verb
        super().__init__(doers=[doing.doify(self.run)])

    def run(self, tymth, tock=0.03125, **kwa):
        self.wind(tymth)
        yield tock
        args = self.args
        if not args.name or not args.alias:
            raise ConfigurationError('native negotiation requires --name and --alias')
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ConfigurationError('--timeout must be finite and positive')
        if not args.output and not args.deliver:
            raise ConfigurationError('select --output or --deliver')
        if args.output and Path(args.output).exists():
            raise ConfigurationError('output already exists')
        hby = setupHby(name=args.name, base=args.base, bran=args.bran, version=Vrsn_2_0)
        notifier, transport = None, None
        try:
            hab = hby.habByName(args.alias)
            if (hab is None or not hab.accepted
                    or isinstance(hab, (GroupHab, SignifyHab, SignifyGroupHab))):
                raise ConfigurationError('native negotiation requires an accepted individual local signer')
            notifier = Notifier(hby)
            exc = Exchanger(hby=hby, handlers=[])
            ipexing.loadHandlers(hby=hby, exc=exc, notifier=notifier)
            psr = Parser(kvy=hby.kvy, exc=exc, rvy=hby.rvy, version=Vrsn_2_0)
            for filename in args.input:
                self.intake(psr, exc, Path(filename).read_bytes())
            plan = None
            if getattr(args, 'plan', None) is not None:
                value = args.plan
                plan = json.loads(Path(value[1:]).read_text() if value.startswith('@') else value)
            common = dict(hab=hab, message=args.message, kind=Kinds.json, gvrsn=Vrsn_2_0)
            if self.verb == 'apply':
                serder, attachment = ipexing.apply(recp=args.recipient, modifiers=dict(dp=plan), **common)
            elif self.verb == 'offer':
                prior = self.prior(hby, args.prior, '/ipex/apply') if args.prior else None
                modifiers = dict(dp=plan) if plan is not None else None
                serder, attachment = ipexing.offer(origin=args.origin, apply=prior,
                    recp=args.recipient, modifiers=modifiers, **common)
            else:
                prior = self.prior(hby, args.said, '/ipex/offer')
                if prior.sad['a'].get('ax', [False])[0]:
                    raise ConfigurationError('anchored Agree completion is not supported by this signature-negotiation command')
                serder, attachment = ipexing.agree(offer=prior, **common)
            self.intake(psr, exc, serder.raw + attachment, local=True)
            raw = serializeMessage(hby, serder.said)
            if args.output:
                with Path(args.output).open('xb') as output:
                    output.write(bytes(hab.replay(gvrsn=Vrsn_2_0)) + raw)
            if args.deliver:
                poster = StreamPoster(hby=hby, hab=hab, recp=serder.sad['ri'], topic='credential',
                                      version=Vrsn_2_0, kind=Kinds.json)
                poster.send(serder, attachment=raw[serder.size:], gvrsn=Vrsn_2_0)
                children = poster.deliver()
                if not children:
                    raise ConfigurationError('no finite recipient transport was available')
                transport = doing.DoDoer(doers=children)
                self.extend([transport])
                deadline = self.tyme + args.timeout
                while not transport.done:
                    if self.tyme >= deadline:
                        raise TimeoutError('negotiation transport did not complete before --timeout')
                    yield tock
                for child in children:
                    if isinstance(child, HTTPStreamMessenger) and not 200 <= child.rep.status < 300:
                        raise ConfigurationError(f"HTTP submission failed with status {child.rep.status}")
                self.remove([transport])
                transport = None
            print(json.dumps(dict(exchange=serder.said, locally_accepted=True, transmitted=args.deliver,
                                  recipient=serder.sad['ri'])))
        finally:
            if transport is not None:
                self.remove([transport])
            if notifier is not None:
                notifier.noter.close()
            hby.close()

    @staticmethod
    def prior(hby, said, route):
        """Read an accepted, authenticated exact prior; pending intake is insufficient."""
        prior = hby.db.exns.get((said,)) if said else None
        if prior is None or prior.route != route or prior.pvrsn != Vrsn_2_0:
            raise ConfigurationError(f'--prior/--said requires an accepted native {route}')
        verify(hby, prior)
        return prior

    @staticmethod
    def intake(psr, exc, raw, *, local=False):
        """Consume complete signed public streams with ordinary accepted-state owners."""
        stream = bytearray(raw)
        if not stream:
            raise ConfigurationError('empty signed input')
        while stream:
            message = psr.parseOneBare(ims=stream, processive=False, local=local, version=Vrsn_2_0)
            if message.serder.ilk in ('xip', 'exn') and message.serder.route not in (
                    '/ipex/apply', '/ipex/offer', '/ipex/agree'):
                raise ConfigurationError('input exchange is outside native negotiation')
            psr.msgProcess(asdict(message), kvy=psr.kvy, tvy=None, exc=exc, rvy=psr.rvy, vry=None)
            if message.serder.ilk in ('xip', 'exn') and not exc.complete(message.serder.said):
                raise ConfigurationError('input exchange did not pass native IPEX verification')
