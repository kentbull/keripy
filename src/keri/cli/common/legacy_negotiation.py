"""Legacy IPEX negotiation composed from existing v1 protocol constructors.

This fills the former apply/offer/agree CLI stubs. Native disclosure plans and
registry openings stay in the native command path; v1 uses protocoling's schema,
attributes, metadata credential, and prior-message contracts.
"""
import json
import math
from pathlib import Path

from hio.base import doing

from keri import Vrsn_1_0
from keri.app import GroupHab, Notifier, StreamPoster, serialize
from keri.app.keeping import Keeper
from keri.app.notifying import Noter
from keri.cli.common import setupHby, cesr_sending
from keri.core import Kevery, Parser
from keri.kering import ConfigurationError
from keri.peer import exchanging
from keri.vc import protocoling
from keri.vdr import credentialing


class Negotiation(doing.DoDoer):
    """Own one v1 negotiation command, its identity, and bounded delivery work."""

    def __init__(self, args, verb):
        """Retain parsed CLI args and apply/offer/agree verb for scheduled work."""
        self.args, self.verb = args, verb
        super().__init__(doers=[doing.doify(self.run)])

    def prior(self, hby, said, route):
        """Return an accepted v1 message with exact route, or refuse the action."""
        event = hby.db.exns.get((said,))
        if event is None or event.pvrsn != Vrsn_1_0 or event.route != route:
            raise ConfigurationError(f'expected an accepted legacy {route} message')
        return event

    def run(self, tymth, tock=0.03125, **kwa):
        """Authenticate, construct and persist a v1 message, then export/deliver.

        tymth/tock supply cooperative time. Args select an existing individual
        identity and public evidence. Output files are exclusive and include
        sender KEL evidence; direct or mailbox transport completion is distinct
        from remote acceptance. Errors close owned stores and child work.
        """
        self.wind(tymth)
        self.tock = tock
        yield tock
        args = self.args
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ConfigurationError('--timeout must be positive and finite')
        unsupported = ('plan', 'observer', 'registry', 'proposal', 'proposal_output',
                       'from_grant', 'disclose', 'time')
        if any(getattr(args, key, None) for key in unsupported):
            raise ConfigurationError('native disclosure options and explicit timestamps require --v2')
        keeper = Keeper(name=args.name, base=args.base, reopen=True)
        try:
            aeid = keeper.gbls.get('aeid')
            if aeid is None:
                raise ConfigurationError('legacy negotiation requires an existing identity')
        finally:
            keeper.close()
        hby = setupHby(args.name, args.base, args.bran if aeid else None,
                       noPrompt=True, version=Vrsn_1_0)
        rgy = None
        noter = None
        try:
            hab = hby.habByName(args.alias)
            if hab is None or isinstance(hab, GroupHab) or hab.kever.serder.pvrsn != Vrsn_1_0:
                raise ConfigurationError('legacy negotiation requires an individual v1 alias')
            exc = exchanging.Exchanger(hby, handlers=[])
            noter = Noter(name=hby.name, base=hby.base, temp=hby.temp)
            protocoling.loadHandlers(hby, exc, Notifier(hby, noter=noter))
            parser = Parser(kvy=Kevery(db=hby.db, lax=False, local=False), exc=exc,
                            version=Vrsn_1_0)
            if args.input:
                parser.parse(ims=bytearray(Path(args.input).read_bytes()))
                exc.processEscrow()
            recipient = getattr(args, 'recipient', None)
            if self.verb == 'apply':
                if not args.schema:
                    raise ConfigurationError('legacy apply requires --schema')
                text = args.attributes
                attrs = json.loads(Path(text[1:]).read_text() if text.startswith('@') else text)
                if not isinstance(attrs, dict):
                    raise ConfigurationError('legacy application attributes must be a JSON object')
                exn, attachment = protocoling.ipexApplyExn(hab, recipient,
                    args.message, args.schema, attrs, version=Vrsn_1_0)
            elif self.verb == 'offer':
                prior = self.prior(hby, args.prior, '/ipex/apply') if args.prior else None
                if prior is not None and (prior.pre != recipient or prior.sad['a'].get('i') != hab.pre):
                    raise ConfigurationError('application sender/recipient does not match this offer')
                rgy = credentialing.Regery(hby=hby, name=hby.name, base=hby.base)
                creder, prefixer, seqner, saider = rgy.reger.cloneCred(said=args.said)
                if (creder is None or creder.pvrsn != Vrsn_1_0
                        or rgy.reger.saved.get((args.said,)) is None):
                    raise ConfigurationError('offer requires a retained verified v1 credential')
                if prior is not None and prior.sad['a'].get('s') != creder.schema:
                    raise ConfigurationError('credential schema does not match application')
                exn, attachment = protocoling.ipexOfferExn(hab, args.message,
                    serialize(creder, prefixer, seqner, saider), apply=prior, version=Vrsn_1_0)
            else:
                offer = self.prior(hby, args.said, '/ipex/offer')
                if offer.sad['p']:
                    application = self.prior(hby, offer.sad['p'], '/ipex/apply')
                    if application.pre != hab.pre or application.sad['a'].get('i') != offer.pre:
                        raise ConfigurationError('offer is not a response to this local application')
                recipient = offer.pre
                exn, attachment = protocoling.ipexAgreeExn(hab, args.message, offer, version=Vrsn_1_0)
            raw = bytes(exn.raw + attachment)
            # The ordinary Exchanger verifies and persists our authored message.
            parser.parse(ims=bytearray(raw))
            if not exc.complete(exn.said):
                raise ConfigurationError('authored legacy exchange remains unaccepted')
            stream = bytes(hab.replay(gvrsn=Vrsn_1_0)) + raw
            if args.output:
                with Path(args.output).open('xb') as output:
                    output.write(stream)
            if args.endpoint:
                yield from cesr_sending.send(self, args.endpoint, stream, args.timeout)
            elif not args.output:
                poster = StreamPoster(hby=hby, hab=hab, recp=recipient, topic='credential')
                poster.send(serder=exn, attachment=attachment, gvrsn=Vrsn_1_0)
                child = doing.DoDoer(doers=poster.deliver())
                self.extend([child])
                try:
                    deadline = self.tyme + args.timeout
                    while not child.done:
                        if self.tyme >= deadline:
                            raise TimeoutError('legacy negotiation delivery timed out')
                        yield tock
                finally:
                    self.remove([child])
            print(json.dumps(dict(exchange=exn.said, version='1.0', route=exn.route,
                                  recipient=recipient, localAccepted=True)))
        finally:
            if rgy is not None:
                rgy.close()
            if noter is not None:
                noter.close()
            hby.close()
