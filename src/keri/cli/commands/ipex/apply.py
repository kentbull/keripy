# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands module

"""
import argparse

from hio.base import doing
from ...common import Parsery, negotiating
from ....core import Salter
from ....kering import Vrsn_2_0


parser = argparse.ArgumentParser(description='Request a credential from another party by initiating an IPEX exchange',
                                 parents=[Parsery.keystore(required=False)])
parser.set_defaults(handler=lambda args: handler(args))

negotiating.options(parser)
parser.add_argument('--recipient', '-r')
parser.add_argument('--plan', help='single-DAG q.dp JSON or @file')


def handler(args):
    if args.version == Vrsn_2_0:
        return [negotiating.NativeNegotiation(args, 'apply')]
    return [doing.doify(nonce)]


def nonce(tymth, tock=0.0, **kwa):
    """ nonce
    """
    _ = (yield tock)

    print(Salter().qb64)
