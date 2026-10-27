# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands module

"""
import argparse
import json
import math
from pathlib import Path
from ...common import acdc_v2_ipex, cesr_sending

from hio.base import doing

from ...common import Parsery, setupHby

from ....kering import Vrsn_1_0, ConfigurationError
from ....app import (Notifier, StreamPoster, Organizer,
                     GroupHab, Multiplexor, MailboxDirector,
                     serialize, multisigExn)
from ....app.notifying import Noter
from ....app.keeping import Keeper
from ....app.grouping import loadHandlers as loadGroupingHandlers

from ....core import coring, parsing, serdering
from ....peer import exchanging

from ....vc import ipexGrantExn
from ....vc.protocoling import loadHandlers as loadProtocolingHandlers

from ....vdr import credentialing


parser = argparse.ArgumentParser(description='Reply to IPEX agree message or initiate an IPEX exchange with a '
                                             'credential issuance or presentation',
                                parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    required=True)

parser.add_argument("--recipient", "-r", help="alias or qb64 identifier prefix of the self.recp of "
                                              "the credential", required=True)
parser.add_argument("--said", "-s", help="SAID of the credential to grant", required=True)
parser.add_argument("--message", "-m", help="optional human readable message to "
                                            "send to recipient", required=False, default="")
parser.add_argument("--time", help="timestamp for the revocation", required=False, default=None)


acdc_v2_ipex.options(parser, send=True)
parser.add_argument('--from-grant', help='present this admitted grant disclosure')
parser.add_argument('--disclose', action='append', default=[], help='attribute disclosure path rooted at a')
parser.add_argument('--prior', help='accepted apply or agree SAID')
parser.add_argument('--refresh', action='store_true', help='use known current registry evidence for an admitted disclosure')
parser.add_argument('--derive', action='store_true', help='explicitly use provisioned registry custody for missing openings')
parser.add_argument('--opening', action='append', default=[], help='file containing one event-specific CESR Blinder, without a salt')
parser.add_argument('--bound-event', help='explicit accepted issuee KEL event SAID for bound-state derivation')

def handler(args):
    """Select the explicit ACDC v2 presentation owner or existing legacy Grant runtime.

    Args:
        args (Namespace): Parsed identity, credential/recipient, version selection,
        optional ACDC v2 capability controls, and legacy prior/output/delivery options.

    Returns:
        list[Doer]: One ACDC v2 ExchangeDoer when --acdc-v2 is selected, otherwise GrantDoer.

    Raises:
        ConfigurationError: Controls reserved for ACDC v2 are supplied to v1, timeout is not
        finite/positive, or opening the selected existing legacy identity fails."""
    if args.acdc_v2:
        return [acdc_v2_ipex.ExchangeDoer(args, 'grant')]
    acdc_v2_ipex.ObserverPolicy.fromArgs(args, None)
    if any(getattr(args, key, None) for key in ('from_grant', 'disclose', 'refresh', 'derive', 'opening', 'bound_event', 'observer', 'registry', 'proposal', 'proposal_output')):
        raise ConfigurationError('ACDC v2 presentation options require --acdc-v2')
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise ConfigurationError('--timeout must be positive and finite')
    ed = GrantDoer(name=args.name,
                   alias=args.alias,
                   base=args.base,
                   bran=args.bran,
                   said=args.said,
                   recp=args.recipient,
                   message=args.message,
                   timestamp=args.time, options=args)
    return [ed]


class GrantDoer(doing.DoDoer):

    """Own legacy credential Grant composition, child delivery, and opened stores.

    The existing multisig/mailbox path remains available. Explicit direct output
    includes public artifact dependencies and any verified accepted negotiation;
    transport completion does not prove recipient credential acceptance."""
    def __init__(self, name, alias, base, bran, said, recp, message, timestamp, options=None):
        """Open the selected existing v1 identity and compose its legacy Grant owners.

        Args:
            name (str): Existing Keeper/Habery name.
            alias (str): Local v1 habitat or group alias sending the Grant.
            base (str): Store namespace shared by identity, registry, and notification data.
            bran (str | None): Authentication passcode for an already encrypted Keeper.
            said (str): Retained credential SAID to disclose.
            recp (str | None): Recipient AID/contact; None selects the credential Issuee.
            message (str): Human Grant message.
            timestamp (str | None): Optional authored exchange timestamp.
            options (Namespace | None): Accepted prior, public input, exclusive output,
            endpoint, and deadline for the optional direct adapter.

        Returns:
            None. Owns Habery, legacy Regery/Noter, mailbox and scheduled Grant work.

        Raises:
            ConfigurationError: Keeper is absent, alias is unknown, or alias uses v2.
            Identity authentication/storage errors propagate. An existing unencrypted
            Keeper opens without bran so this operation does not migrate its AEID."""
        self.options = options
        self.said = said
        self.recp = recp
        self.message = message
        self.timestamp = timestamp
        keeper = Keeper(name=name, base=base, reopen=True)
        try:
            aeid = keeper.gbls.get('aeid')
            if aeid is None:
                raise ConfigurationError('legacy grant requires an existing identity')
        finally:
            keeper.close()
        self.hby = setupHby(name=name, base=base, bran=bran if aeid else None,
                            version=Vrsn_1_0)
        self.hab = self.hby.habByName(alias)
        if self.hab is None or self.hab.kever.serder.pvrsn != Vrsn_1_0:
            self.hby.close()
            raise ConfigurationError('legacy grant requires a v1 alias; use --acdc-v2 for ACDC v2 workflows')
        self.rgy = credentialing.Regery(hby=self.hby, name=name, base=base)
        self.org = Organizer(hby=self.hby)
        self.noter = Noter(name=self.hby.name, base=self.hby.base, temp=self.hby.temp)
        notifier = Notifier(self.hby, noter=self.noter)
        mux = Multiplexor(self.hby, notifier=notifier)

        self.exc = exchanging.Exchanger(hby=self.hby, handlers=[])
        loadGroupingHandlers(self.exc, mux)
        loadProtocolingHandlers(self.hby, exc=self.exc, notifier=notifier)

        mbx = MailboxDirector(hby=self.hby,
                              topics=["/receipt", "/multisig", "/replay", "/credential"],
                              exc=self.exc, version=Vrsn_1_0)

        self.toRemove = [mbx]
        super(GrantDoer, self).__init__(doers=self.toRemove + [doing.doify(self.grantDo)])

    def grantDo(self, tymth, tock=0.0, **kwa):
        """Create an authenticated legacy Grant and perform selected group/direct delivery.

        Args:
            tymth (Callable): HIO injected clock driving this cooperative operation.
            tock (float): Scheduling delay while waiting for group/mailbox/direct work.
            **kwa: Additional HIO lifecycle metadata, unused here.

        Yields:
            float | None: Initial delay and group/transport progress.

        Returns:
            None. Optional direct output prints locally accepted v1 exchange identifiers;
            the existing default route reports transport progress to the operator.

        Raises:
            ValueError: Retained credential is absent/wrong-version or recipient cannot
            be resolved. ConfigurationError refuses mismatched accepted negotiation.
            TimeoutError: Explicit direct delivery exceeds its selected deadline.
            OSError: Input/output access or exclusive file creation fails.

        Input evidence passes through ordinary Parser/Exchanger first. An accepted prior
        is checked before authoring; directStream includes public dependencies. Existing
        multisig leader selection and mailbox scheduling retain their original contract;
        only the direct transport helper adds its own finite request deadline. exit owns
        final child cancellation and store closure, including failure paths."""
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        if self.options is not None and self.options.input:
            parsing.Parser(version=Vrsn_1_0).parse(
                ims=bytearray(Path(self.options.input).read_bytes()),
                kvy=self.hby.kvy, exc=self.exc)
            self.exc.processEscrow()

        creder, prefixer, seqner, saider = self.rgy.reger.cloneCred(said=self.said)
        if creder is None or creder.pvrsn != Vrsn_1_0:
            raise ValueError(f"invalid credential SAID to grant={self.said}")

        acdc = serialize(creder, prefixer, seqner, saider)

        if self.recp is None:
            # Default the recipient to the issuee, resolved via .iseaid so an
            # aggregate ('acg') credential works here too: its .attrib is None
            # and its issuee lives at .sad["A"][1]["i"]. Same defect as the one
            # sendArtifacts had, one step earlier on the same grant path.
            recp = creder.iseaid
        elif self.recp in self.hby.kevers:
            recp = self.recp
        else:
            recp = self.org.findExact("alias", self.recp)
            if len(recp) == 0:
                raise ValueError(f"no contact found with alias {self.recp!r}")
            if len(recp) > 1:
                raise ValueError(f"multiple contacts match alias {self.recp!r}, use prefix instead")
            recp = recp[0]['id']

        if recp is None:
            raise ValueError("unable to find recipient")

        agree = None
        if self.options is not None and self.options.prior:
            agree = self.acceptedAgreement(self.options.prior, recp, creder)

        iss = self.rgy.reger.cloneTvtAt(creder.said, gvrsn=Vrsn_1_0)

        iserder = serdering.SerderKERI(raw=bytes(iss))
        seqner = coring.Seqner(sn=iserder.sn)

        serder = self.hby.db.fetchLastSealingEventByEventSeal(creder.sad['i'],
                                                              seal=dict(i=iserder.pre, s=seqner.snh, d=iserder.said))
        anc = self.hby.db.cloneEvtMsg(pre=serder.pre, fn=0, dig=serder.said, gvrsn=Vrsn_1_0)

        exn, atc = ipexGrantExn(hab=self.hab, recp=recp, message=self.message, acdc=acdc, iss=iss, anc=anc,
                                dt=self.timestamp, agree=agree, version=Vrsn_1_0)
        msg = bytearray(exn.raw)
        msg.extend(atc)

        parsing.Parser(version=Vrsn_1_0).parseOne(ims=bytes(msg), exc=self.exc)

        sender = self.hab
        if isinstance(self.hab, GroupHab):
            sender = self.hab.mhab
            wexn, watc = multisigExn(self.hab, exn=msg, version=Vrsn_1_0)

            smids = self.hab.db.signingMembers(pre=self.hab.pre)
            smids.remove(self.hab.mhab.pre)

            for part in smids:  # this goes to other participants
                postman = StreamPoster(hby=self.hby, hab=self.hab.mhab, recp=part, topic="multisig", version=Vrsn_1_0)
                postman.send(serder=wexn,
                             attachment=watc, gvrsn=Vrsn_1_0)
                doer = doing.DoDoer(doers=postman.deliver())
                self.extend([doer])

            while not self.exc.complete(said=exn.said):
                yield self.tock

        if self.exc.lead(self.hab, said=exn.said):
            if self.options is not None and (self.options.output or self.options.endpoint):
                raw = self.directStream(creder, exn)
                if self.options.output:
                    with Path(self.options.output).open('xb') as output:
                        output.write(raw)
                if self.options.endpoint:
                    yield from cesr_sending.send(self, self.options.endpoint, raw, self.options.timeout)
                print(json.dumps(dict(exchange=exn.said, version='1.0', recipient=recp,
                                      localAccepted=self.exc.complete(exn.said))))
                self.remove(self.toRemove)
                return
            print(f"Sending message {exn.said} to {recp}")
            postman = StreamPoster(hby=self.hby, hab=sender, recp=recp, topic="credential", version=Vrsn_1_0)

            sources = self.rgy.reger.sources(self.hby.db, creder)
            credentialing.sendArtifacts(self.hby, self.rgy.reger, postman, creder, recp)
            for source, atc in sources:
                credentialing.sendArtifacts(self.hby, self.rgy.reger, postman, source, recp)
                postman.send(serder=source, attachment=atc, gvrsn=source.pvrsn)

            atc = exchanging.serializeMessage(self.hby, exn.said, framed=True)
            del atc[:exn.size]
            # serializeMessage rebuilds this legacy pathed grant with V1 attachments.
            postman.send(serder=exn,
                         attachment=atc, gvrsn=Vrsn_1_0)

            doer = doing.DoDoer(doers=postman.deliver())
            self.extend([doer])

            while not doer.done:
                yield self.tock

            print(f"... grant message sent")
            self.remove([doer])

        self.remove(self.toRemove)


    def acceptedAgreement(self, said, recipient, credential):
        """Verify retained signed negotiation binds the requested legacy Grant exactly.

        Args:
            said (str): Accepted agreement SAID selected as the new Grant predecessor.
            recipient (str): Required agreement signer and original Apply sender.
            credential (SerderACDC): Verified retained credential promised by the issuer Offer.

        Returns:
            SerderKERI: Agreement after its signature and Offer/optional Apply bindings verify.

        Raises:
            ConfigurationError: Missing/wrong-version/route thread evidence, wrong parties,
            substituted offered credential, or original application schema mismatch.
            KeriError: Retained exchange signatures cannot be verified.

        Each selected thread message reuses exchanging.verify; an arbitrary body row or
        route spelling alone cannot authorize a new Grant. No message is authored here."""
        agree = self.hby.db.exns.get((said,))
        if (agree is None or agree.pvrsn != Vrsn_1_0 or agree.route != '/ipex/agree'
                or agree.pre != recipient):
            raise ConfigurationError('legacy grant requires the recipient agreement')
        exchanging.verify(self.hby, agree)
        offer = self.hby.db.exns.get((agree.sad['p'],))
        if (offer is None or offer.pvrsn != Vrsn_1_0 or offer.route != '/ipex/offer'
                or offer.pre != self.hab.pre
                or offer.sad.get('e', {}).get('acdc', {}).get('d') != credential.said):
            raise ConfigurationError('legacy agreement does not bind this credential offer')
        exchanging.verify(self.hby, offer)
        if offer.sad['p']:
            application = self.hby.db.exns.get((offer.sad['p'],))
            if (application is None or application.pvrsn != Vrsn_1_0
                    or application.route != '/ipex/apply' or application.pre != recipient
                    or application.sad['a'].get('i') != self.hab.pre
                    or application.sad['a'].get('s') != credential.schema):
                raise ConfigurationError('legacy agreement changes the original application parties or schema')
            exchanging.verify(self.hby, application)
        return agree

    def directStream(self, credential, exn):
        """Assemble exact accepted Grant bytes with public dependencies for direct intake.

        Args:
            credential (SerderACDC): Retained legacy credential whose source graph is needed.
            exn (SerderKERI): Locally accepted Grant to serialize with its stored attachments.

        Returns:
            bytes: Sender/delegation KELs, registry/credential TELs, source credentials,
            and the final exact Grant stream in the legacy genus.

        This mirrors credentialing.sendArtifacts/sources through existing replay APIs;
        private signing/registry derivation material is never selected. Missing/corrupt
        retained artifacts or replay storage errors propagate rather than supplying
        synthetic acceptance rows. Recipient verification remains a separate boundary."""
        raw = bytearray(self.hab.replay(gvrsn=Vrsn_1_0))
        sources = list(self.rgy.reger.sources(self.hby.db, credential))
        for creder in [source for source, _ in sources] + [credential]:
            for aid in dict.fromkeys(aid for aid in (creder.israid, creder.iseaid) if aid):
                if aid in self.hby.kevers:
                    raw.extend(b''.join(self.hby.db.cloneDelegation(self.hby.kevers[aid], gvrsn=Vrsn_1_0)))
                    raw.extend(b''.join(self.hby.db.clonePreIter(pre=aid, gvrsn=Vrsn_1_0)))
            if creder.regid:
                raw.extend(b''.join(self.rgy.reger.clonePreIter(pre=creder.regid, gvrsn=Vrsn_1_0)))
            raw.extend(b''.join(self.rgy.reger.clonePreIter(pre=creder.said, gvrsn=Vrsn_1_0)))
        for source, attachment in sources:
            raw.extend(source.raw + attachment)
        raw.extend(exchanging.serializeMessage(self.hby, exn.said, framed=True))
        return bytes(raw)


    def exit(self, deeds=None):
        """Cancel owned scheduler children before closing legacy stores.

        Args:
            deeds: Optional HIO child-deed queue passed to DoDoer.exit.

        Returns:
            None. Selective child removal closes only the supplied deeds. Full owner
            exit closes Noter, Regery and Habery after all children unwind, including
            failed delivery; close/storage errors propagate.

        HIO remove() calls this method with a temporary deeds queue. Closing stores
        there would invalidate the still-running Grant immediately after its HTTP
        or TCP client finishes. Only the full lifecycle exit owns those stores."""
        try:
            super().exit(deeds=deeds)
        finally:
            if deeds is None:
                self.noter.close()
                self.rgy.close()
                self.hby.close()
