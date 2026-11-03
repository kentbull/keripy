# -*- encoding: utf-8 -*-
"""
KERI
keri.kli.commands module

"""
import argparse

from hio.base import doing
from hio.help import ogler

from ....common import Parsery, existingHby, parseVersion

from .....kering import ConfigurationError, Vrsn_1_0, Vrsn_2_0
from .....vdr import Regery
from .....acdc import Regery as NativeRegery
from .....core import SerderACDC


logger = ogler.getLogger()

parser = argparse.ArgumentParser(description='List credential registry names and identifiers', 
                                 parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: list_registries(args))
parser.add_argument('--version', type=parseVersion, default=Vrsn_1_0,
                    help='Registry protocol version: 1.0 (default) or native 2.0')
parser.add_argument("--verbose", "-V", help="print JSON of all current events", action="store_true")


def list_registries(args):
    """ Command line list credential registries handler

    """
    kwa = dict(args=args)
    return [doing.doify(registries, **kwa)]


def registries(tymth, tock=0.0, **opts):
    _ = (yield tock)

    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran

    try:
        with existingHby(name=name, base=base, bran=bran) as hby:
            native = getattr(args, 'version', Vrsn_1_0) == Vrsn_2_0
            rgy = (NativeRegery if native else Regery)(hby=hby, name=name, base=base)
            try:
                for registry in rgy.regs.values():
                    summary = f"{registry.name} : {registry.regk} : {registry.hab.pre}"
                    if native:
                        summary += f" : {registry.head.qb64 if registry.head else 'pending'}"
                    print(summary)
                    if native and args.verbose:
                        for raw in rgy.store.cloneTelIter(registry.regk):
                            print(SerderACDC(raw=raw).pretty())
            finally:
                rgy.close()

    except ConfigurationError as e:
        print(f"identifier prefix for {name} does not exist, incept must be run first", )
        return -1
