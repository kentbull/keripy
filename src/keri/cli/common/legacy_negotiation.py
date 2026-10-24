"""Legacy IPEX negotiation composed from existing v1 protocol constructors.

This fills the former apply/offer/agree CLI stubs and provides explicit direct
admission through the existing legacy credential verifier. Native disclosure plans and
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
from keri.core import Kevery, Parser, SerderKERI, SerderACDC
from keri.kering import ConfigurationError
from keri.peer import exchanging
from keri.vc import protocoling
from keri.vdr import credentialing, Verifier


class Negotiation(doing.DoDoer):
    """Own one v1 negotiation command, its identity, and bounded delivery work."""

    def __init__(self, args, verb):
        """Schedule one existing v1 IPEX negotiation operation.

        Args:
            args (Namespace): Existing individual identity and public CLI selections.
            verb (str): apply, offer, agree, or admit from the concrete legacy adapter.

        Returns:
            None. Retains arguments and schedules run; opens no identity or transport yet."""
        self.args, self.verb = args, verb
        super().__init__(doers=[doing.doify(self.run)])

    def prior(self, hby, said, route):
        """Select a retained v1 thread message with the exact expected route.

        Args:
            hby (Habery): Caller-owned environment containing accepted EXN bodies.
            said (str): Exact retained predecessor identifier.
            route (str): Expected legacy IPEX route, including its leading slash.

        Returns:
            SerderKERI: Retained body with matching v1 version and route.

        Raises:
            ConfigurationError: No matching retained body exists.

        This lookup does not rerun the entire negotiation. run checks operation-specific
        sender/recipient/schema relationships and ordinary Exchanger verifies new work."""
        event = hby.db.exns.get((said,))
        if event is None or event.pvrsn != Vrsn_1_0 or event.route != route:
            raise ConfigurationError(f'expected an accepted legacy {route} message')
        return event

    def run(self, tymth, tock=0.03125, **kwa):
        """Authenticate an individual identity, author a v1 message, and export/deliver.

        Args:
            tymth (Callable): HIO injected clock governing bounded delivery.
            tock (float): Cooperative scheduling interval.
            **kwa: Additional scheduler lifecycle metadata, unused here.

        Yields:
            float | None: Initial delay and delegated direct/mailbox transport progress.

        Returns:
            None. Prints the locally accepted exchange/version/recipient after ordinary
            Exchanger validation and any selected export/delivery operation completes.

        Raises:
            ConfigurationError: Invalid timeout/options/identity, missing schema or saved
            v1 credential, mismatched thread roles/schema, or authored EXN stays unaccepted.
            TimeoutError: Credential dependency verification or transport/mailbox delivery
                exceeds the finite command deadline.
            OSError, ValueError: Exclusive output, input-file, or attribute JSON handling fails.

        Owned Habery, optional legacy Regery/Noter, and delivery child work close on every
        exit. Existing unencrypted Keeper mode is preserved. Transport completion remains
        distinct from remote acceptance; native plans/openings require explicit --v2."""
        self.wind(tymth)
        self.tock = tock
        yield tock
        args = self.args
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ConfigurationError('--timeout must be positive and finite')
        unsupported = ('plan', 'observer', 'registry', 'proposal', 'proposal_output',
                       'from_grant', 'disclose')
        if self.verb != 'admit' and args.time:
            raise ConfigurationError('explicit negotiation timestamps require --v2')
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
            verifier = None
            if self.verb == 'admit':
                rgy = credentialing.Regery(hby=hby, name=hby.name, base=hby.base)
                verifier = Verifier(hby=hby, reger=rgy.reger)
            parser = Parser(kvy=Kevery(db=hby.db, lax=False, local=False), exc=exc,
                            tvy=rgy.tvy if rgy else None, vry=verifier,
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
            elif self.verb == 'agree':
                offer = self.prior(hby, args.said, '/ipex/offer')
                if offer.sad['p']:
                    application = self.prior(hby, offer.sad['p'], '/ipex/apply')
                    if application.pre != hab.pre or application.sad['a'].get('i') != offer.pre:
                        raise ConfigurationError('offer is not a response to this local application')
                recipient = offer.pre
                exn, attachment = protocoling.ipexAgreeExn(hab, args.message, offer, version=Vrsn_1_0)
            elif self.verb == 'admit':
                grant = self.prior(hby, args.said, '/ipex/grant')
                if grant.sad['a'].get('i') != hab.pre:
                    raise ConfigurationError('legacy grant is addressed to another recipient')
                exchanging.verify(hby, grant)
                _, pathed = exchanging.cloneMessage(hby, grant.said)
                # Follow legacy AdmitDoer: normal processors verify the embedded
                # anchor, TEL event, and credential before an admission is signed.
                for label in ('anc', 'iss', 'acdc'):
                    klass = SerderACDC if label == 'acdc' else SerderKERI
                    embedded = klass(sad=grant.sad['e'][label])
                    parser.parseOne(ims=bytearray(embedded.raw) + pathed[label])
                credential = grant.sad['e']['acdc']['d']
                deadline = self.tyme + args.timeout
                while rgy.reger.saved.get((credential,)) is None:
                    parser.kvy.processEscrows()
                    rgy.processEscrows()
                    verifier.processEscrows()
                    if self.tyme >= deadline:
                        raise TimeoutError('legacy admission requires verified credential dependencies')
                    yield tock
                recipient = grant.pre
                exn, attachment = protocoling.ipexAdmitExn(hab, args.message, grant,
                    dt=args.time, version=Vrsn_1_0)
            else:
                raise ConfigurationError('unsupported legacy negotiation operation')
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
