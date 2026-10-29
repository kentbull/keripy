# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse
import sys

from hio.base import doing
from hio.help import ogler

from ...common import Parsery, setupHby
from ...common import acdc_v2
from ....kering import ConfigurationError

from ....app import serialize
from ....core import SerderKERI
from ....vdr import Regery


logger = ogler.getLogger()

parser = argparse.ArgumentParser(description='Export credential from store and any related material',
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: export_credentials(args))
parser.add_argument('--alias', '-a', help='human readable alias for the identifier to whom the credential was issued',
                    required=True)
parser.add_argument("--said", "-s", help="SAID of the credential to export.", required=False, default=None)
parser.add_argument("--tels", help="export the transaction event logs for the credential and any chained credentials",
                    action="store_true")
parser.add_argument("--kels", help="export the key event logs for the issuer's of the credentials", action="store_true")
parser.add_argument("--chains", help="export any chained credentials", action="store_true")
parser.add_argument("--full", help="export credential, signatures, tels, kels and full chains", action="store_true")
parser.add_argument("--files", help="export artifacts to individual files keyed off of AIDs or SAIDS, default is "
                                    "stdout", action="store_true")
acdc_v2.options(parser)
parser.add_argument('--derive', action='store_true', help='with --acdc-v2 --full, explicitly derive a missing historical issuance opening from provisioned custody')
parser.add_argument('--opening', help='with --acdc-v2 --full, use one event-specific CESR opening file without loading registry salts')
parser.add_argument('--registry-name', '-r', default=None)
parser.add_argument('--output', default=None, help='ACDC v2 export destination (created exclusively)')


def export_credentials(args):
    """Return ACDC v2 evidence work or the existing legacy export worker.

    args chooses identity, credential, registry, destination, and evidence flags.
    ACDC v2 export requires registry-name and an explicit output path or raises
    ConfigurationError. ACDC v2 read owns store cleanup and exclusive file creation;
    Legacy export behavior remains the default."""
    if getattr(args, 'acdc_v2', False):
        if args.files:
            raise ConfigurationError('ACDC v2 export uses --output, not --files')
        if (args.derive or args.opening) and not args.full:
            raise ConfigurationError('--derive and --opening require --acdc-v2 --full')
        if not args.output or not args.registry_name:
            raise ConfigurationError('ACDC v2 export requires --output and --registry-name')
        return acdc_v2.read(args, 'export')
    if args.derive or args.opening:
        raise ConfigurationError('--derive and --opening require --acdc-v2')
    tels = args.tels
    kels = args.kels
    chains = args.chains if args.chains is not None else {}

    if args.full:
        tels = kels = chains = True

    ed = ExportDoer(name=args.name,
                    alias=args.alias,
                    base=args.base,
                    bran=args.bran,
                    said=args.said,
                    tels=tels,
                    kels=kels,
                    chains=chains,
                    files=args.files)
    return [ed]


class ExportDoer(doing.DoDoer):

    def __init__(self, name, alias, base, bran, said, tels, kels, chains, files):
        self.said = said
        self.tels = tels
        self.kels = kels
        self.chains = chains
        self.files = files

        self.hby = setupHby(name=name, base=base, bran=bran)
        self.hab = self.hby.habByName(alias)
        self.rgy = Regery(hby=self.hby, name=name, base=base)

        doers = [doing.doify(self.exportDo)]

        super(ExportDoer, self).__init__(doers=doers)

    def exportDo(self, tymth, tock=0.0, **kwa):
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

        if self.said is None:
            for (said,), _ in self.rgy.reger.creds.getTopItemIter():
                self.outputCred(said=said)

        else:
            self.outputCred(said=self.said)

    def outputCred(self, said):
        creder, *_ = self.rgy.reger.cloneCred(said=said)

        if self.kels:
            issr = creder.israid
            self.outputKEL(issr)

        if self.tels:
            if creder.regid is not None:
                self.outputTEL(creder.regid)
                self.outputTEL(creder.said)

        if self.chains:
            chains = creder.edge if creder.edge is not None else {}
            saids = []
            for key, source in chains.items():
                if key == 'd':
                    continue

                if not isinstance(source, dict):
                    continue

                saids.append(source['n'])

            for said in saids:
                self.outputCred(said)

        (prefixer, number, diger) = self.rgy.reger.cancs.get(keys=(creder.said,))
        if self.files:
            f = open(f"{creder.diger}-acdc.cesr", 'w')
            f.write(serialize(creder, prefixer, number, diger))
            f.close()
        else:
            sys.stdout.write(serialize(creder, prefixer, number, diger).decode("utf-8"))
            sys.stdout.flush()

    def outputTEL(self, regk):
        f = None
        if self.files:
            f = open(f"{regk}-tel.cesr", "w")

        for msg in self.rgy.reger.clonePreIter(pre=regk):
            if f is not None:
                f.write(msg.decode("utf-8"))
            else:
                serder = SerderKERI(raw=msg)
                atc = msg[serder.size:]
                sys.stdout.write(serder.raw.decode("utf-8"))
                sys.stdout.write(atc.decode("utf-8"))

        if f is not None:
            f.close()

    def outputKEL(self, pre):
        f = None
        if self.files:
            f = open(f"{pre}-kel.cesr", "w")

        for msg in self.hby.db.clonePreIter(pre=pre):
            if f is not None:
                f.write(msg.decode("utf-8"))
            else:
                serder = SerderKERI(raw=msg)
                atc = msg[serder.size:]
                sys.stdout.write(serder.raw.decode("utf-8"))
                sys.stdout.write(atc.decode("utf-8"))

        if f is not None:
            f.close()
