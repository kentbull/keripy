# -*- encoding: utf-8 -*-
"""
keri.kli.commands module

"""
import argparse

from hio.base import doing
from hio.help import ogler

from ...common import Parsery, setupHby, printIdentifier

from ....app import HaberyDoer, Receiptor, WitnessReceiptor, MailboxDirector
from ....help import helping


logger = ogler.getLogger()

parser = argparse.ArgumentParser(description='Submit current event to witnesses for receipting', 
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--alias', '-a', help='human readable alias for the new identifier prefix', required=True)
parser.add_argument("--config", "-c", help="directory override for configuration data")

# Authentication for keystore
parser.add_argument('--aeid', help='qualified base64 of non-transferable identifier prefix for  authentication '
                                   'and encryption of secrets in keystore', default=None)
parser.add_argument('--force', action="store_true", required=False,
                    help='True means to send witnesses all receipts even if we have a full complement of receipts for '
                         'the current event')
parser.add_argument("--receipt-endpoint", help="Attempt to connect to witness receipt endpoint for witness receipts.",
                    dest="endpoint", action='store_true')
parser.add_argument("--authenticate", '-z', help="Prompt the controller for authentication codes for each witness",
                    action='store_true')


def handler(args):
    """Return the existing identity's witness-receipt submission worker.

    args selects name/base/passcode, alias, force/authentication, and synchronous
    receipt-endpoint mode. Return one lifecycle Doer; this command submits the
    current event and does not create a new identifier. Authentication, witness,
    and transport failures propagate through the scheduled worker."""

    name = args.name
    base = args.base
    bran = args.bran
    alias = args.alias
    force = args.force

    subDoer = SubmitDoer(name=name, base=base, alias=alias, bran=bran, force=force, authenticate=args.authenticate,
                         endpoint=args.endpoint)

    doers = [subDoer]
    return doers


class SubmitDoer(doing.DoDoer):
    """Own receipt acquisition for an existing identifier's current KEL event.

    Endpoint mode uses synchronous receipt work and avoids a mailbox listener.
    The ordinary path retains mailbox processing and queued witness receipt work;
    identifier details are printed only after that selected receipt loop finishes."""

    def __init__(self, name, base, alias, bran, force, endpoint=False, authenticate=False):

        """Open the requested identity and compose its receipt acquisition owners.

        name/base/bran select an existing identity and alias its habitat. force keeps
        the legacy witness retry policy; endpoint chooses synchronous receipt queries;
        authenticate prompts for witness codes during work. Schedule HaberyDoer and,
        only outside endpoint mode, MailboxDirector. Store authentication failures
        propagate here; scheduled children own normal resource teardown."""
        hby = setupHby(name=name, base=base, bran=bran)
        self.hbyDoer = HaberyDoer(habery=hby)  # setup doer
        self.mbx = (None if endpoint else
                    MailboxDirector(hby=hby, topics=['/receipt', "/replay", "/reply"]))
        self.alias = alias
        self.hby = hby
        self.force = force
        self.endpoint = endpoint
        self.authenticate = authenticate

        doers = [self.hbyDoer, doing.doify(self.submitDo)]
        if self.mbx is not None:
            doers.append(self.mbx)

        super(SubmitDoer, self).__init__(doers=doers)

    def submitDo(self, tymth, tock=0.0, **kwa):
        """Yield while the chosen receipt path works, then print identifier details.

        tymth/tock/kwa follow hio scheduling. Resolve the existing alias, optionally
        prompt for per-witness authentication codes, and run synchronous Receiptor or
        the existing queued WitnessReceiptor. Return None after removing receipt and
        identity/mailbox workers. No new identifier, credential, or registry is authored;
        receipt/authentication failures propagate to the enclosing scheduler."""
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        hab = self.hby.habByName(name=self.alias)
        auths = {}
        if self.authenticate:
            for wit in hab.kever.wits:
                code = input(f"Entire code for {wit}: ")
                auths[wit] = f"{code}#{helping.nowIso8601()}"

        if self.endpoint:
            receiptor = Receiptor(hby=self.hby)
            self.extend([receiptor])

            yield from receiptor.receipt(hab.pre, sn=hab.kever.sn, auths=auths)
            self.remove([receiptor])

        else:
            witDoer = WitnessReceiptor(hby=self.hby, force=self.force, auths=auths)
            self.extend([witDoer])

            if hab.kever.wits:
                print("Waiting for witness receipts...")
                witDoer.msgs.append(dict(pre=hab.pre))
                while not witDoer.cues:
                    _ = yield self.tock

            self.remove([witDoer])

        printIdentifier(self.hby, hab.pre)

        toRemove = [self.hbyDoer]
        if self.mbx is not None:
            toRemove.append(self.mbx)
        self.remove(toRemove)

        return
