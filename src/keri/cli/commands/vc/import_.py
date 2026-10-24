# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
from os import getenv

from hio.help import ogler
from hio.base import doing

from ...common import setupHby
from ...common import acdc_v2
from ....kering import ConfigurationError

from ....app import HaberyDoer
from ....core import Parser
from ....vdr import Tevery, Verifier, Regery


logger = ogler.getLogger()

parser = argparse.ArgumentParser(description='Import a legacy CESR credential, or explicitly provision ACDC v2 registry salt custody with --acdc-v2 --custody')
parser.set_defaults(handler=lambda args: imprt(args),
                    transferable=True)
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='21 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=getenv('KLI_KEYSTORE_PASSCODE'))  # passcode => bran
parser.add_argument("--file", help="Legacy CESR credential, or ACDC v2 plaintext per-registry salt file with owner-only permissions received through operator-arranged authenticated private transfer", required=True)
parser.add_argument("--said", "-s", help="SAID of the credential to expect.", required=False, default=None)
acdc_v2.options(parser)
parser.add_argument('--custody', action='store_true', help='import a plaintext per-registry salt file into encrypted local custody (requires --acdc-v2)')
parser.add_argument('--registry', default=None)
parser.add_argument('--controller', default=None)
parser.add_argument('--discloser', default=None)
parser.add_argument('--rewrap', action='store_true', help='explicitly re-import plaintext salt under the current Keeper encryption identity; does not migrate old ciphertext or provide automatic key rotation')


def imprt(args):
    """Select legacy credential import or explicit ACDC v2 plaintext provisioning.

    args supplies the file, identity and exact registry/controller/discloser
    bindings. Reject mode-incompatible options before store or file access.
    Return scheduled import work; ACDC v2 credential intake remains IPEX's job.
    """

    if getattr(args, 'acdc_v2', False):
        if args.said:
            raise ConfigurationError('ACDC v2 import provisions salt custody, not credentials; use IPEX intake for credentials')
        if not args.custody or not all((args.registry, args.controller, args.discloser)):
            raise ConfigurationError('ACDC v2 import requires --custody, --registry, --controller and --discloser')
        return acdc_v2.read(args, 'import')
    if any((args.custody, args.registry, args.controller, args.discloser, args.rewrap)):
        raise ConfigurationError('custody provisioning options require --acdc-v2 --custody')
    ed = ImportDoer(name=args.name,
                    base=args.base,
                    bran=args.bran,
                    file=args.file,
                    said=args.said)
    return [ed]


class ImportDoer(doing.DoDoer):

    def __init__(self, name, base, bran, file, said=None):
        self.file = file
        self.said = said

        self.hby = setupHby(name=name, base=base, bran=bran)
        self.rgy = Regery(hby=self.hby, name=name, base=base)
        self.tvy = Tevery(db=self.hby.db, reger=self.rgy.reger)
        self.vry = Verifier(hby=self.hby, reger=self.rgy.reger)

        doers = [doing.doify(self.importDo), HaberyDoer(self.hby)]

        super(ImportDoer, self).__init__(doers=doers)

    def importDo(self, tymth, tock=0.0, **kwa):
        """ Export credential from store and any related material

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        Returns:
            doifiable Doist compatible generator method

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        with open(self.file, 'rb') as f:
            ims = f.read()

            Parser(kvy=self.hby.kvy, tvy=self.tvy, vry=self.vry, local=False).parse(ims=ims)
            self.tvy.processEscrows()
            self.vry.processEscrows()
            self.hby.kvy.processEscrows()

            if self.said:
                while self.vry.reger.creds.get(keys=self.said) is None:
                    self.tvy.processEscrows()
                    self.vry.processEscrows()
                    self.hby.kvy.processEscrows()
                    yield self.tock

                print("Credential successfully imported.")

        self.exit()
        return True
