import argparse

from hio.base import doing
from hio.help import ogler

from ....common import Parsery, setupHby, parseVersion

from .....app import MailboxDirector, HaberyDoer, Counselor
from .....core import SerderKERI, SerderACDC
from .....kering import ConfigurationError, Vrsn_1_0, Vrsn_2_0
from .....vdr import Regery
from .....acdc import Regery as NativeRegery


logger = ogler.getLogger()

parser = argparse.ArgumentParser(description='Checks the status of a credential registry', 
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: registryStatus(args))
parser.add_argument('--registry-name', '-r', help='Human readable name for registry, defaults to name of Habitat',
                    default=None, required=True)
parser.add_argument('--version', type=parseVersion, default=Vrsn_1_0,
                    help='Registry protocol version: 1.0 (default) or native 2.0')
parser.add_argument("--verbose", "-V", help="print JSON of all current events", action="store_true")


def registryStatus(args):
    name = args.name
    bran = args.bran
    base = args.base
    verbose = args.verbose
    registryName = args.registry_name

    icpDoer = RegistryStatusor(name=name, base=base, bran=bran, registryName=registryName, verbose=verbose,
                                version=getattr(args, 'version', Vrsn_1_0))

    doers = [icpDoer]
    return doers


class RegistryStatusor(doing.DoDoer):
    """

    """

    def __init__(self, name, base, bran, registryName, verbose, version=Vrsn_1_0):
        """


        """
        self.name = name
        self.registryName = registryName
        self.verbose = verbose
        self.native = version == Vrsn_2_0
        self.hby = setupHby(name=name, base=base, bran=bran, version=version)
        self.rgy = (NativeRegery if self.native else Regery)(hby=self.hby, name=name, base=base)
        self.hbyDoer = HaberyDoer(habery=self.hby)  # setup doer
        if not self.native:
            counselor = Counselor(hby=self.hby)
            mbx = MailboxDirector(hby=self.hby, topics=["/receipt", "/multisig", "/replay"])
        doers = [self.hbyDoer] if self.native else [self.hbyDoer, counselor, mbx]
        self.toRemove = list(doers)

        doers.extend([doing.doify(self.statusDo)])
        super(RegistryStatusor, self).__init__(doers=doers)

    def exit(self, deeds=None):
        try:
            super().exit(deeds=deeds)
        finally:
            if deeds is None:
                if self.native and self.rgy.store.opened:
                    self.rgy.close()
                self.hby.close()

    def statusDo(self, tymth, tock=0.0, **kwa):
        """ Process incoming messages to incept a credential registry

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

        reg = self.rgy.registryByName(self.registryName)
        if self.native:
            if reg is None:
                raise ConfigurationError(f"unknown registry {self.registryName}")
            print(f"Registry:  {reg.regk}\nSeq No.  {reg.sn}")
            print(f"    Controlling Identifier:  {reg.hab.pre}")
            print(f"Head:  {reg.head.qb64 if reg.head else 'pending'}")
            if self.verbose:
                for raw in self.rgy.store.cloneTelIter(reg.regk):
                    print(SerderACDC(raw=raw).pretty())
            self.remove(self.toRemove)
            return
        print(f"Registry:  {reg.regk}")
        print(f"Seq No.  {reg.tever.sn}")
        print(f"    Controlling Identifier:  {reg.hab.pre}")
        print()

        if reg.tever.noBackers:
            print("Backers: Not supported")
        else:
            print("\nBackers:")
            print("Count:\t\t{}".format(len(reg.tever.baks)))
            print("Threshold:\t{}".format(reg.tever.toad))

        if reg.estOnly:
            print("Events:\tEstablishment Only")
        else:
            print("Events:\tInteraction Allowed")

        print()
        if self.verbose:
            cloner = reg.reger.clonePreIter(pre=reg.regk, fn=0)  # create iterator at 0
            for msg in cloner:
                srdr = SerderKERI(raw=msg)
                print(srdr.pretty())
                print()

        self.remove(self.toRemove)

