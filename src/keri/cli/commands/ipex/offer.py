# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands module

"""
import argparse

from hio.base import doing

from ...common import Parsery, negotiating
from ....core import Salter
from ....kering import Vrsn_2_0


parser = argparse.ArgumentParser(description='Reply to IPEX apply message or initiate an IPEX exchange with an offer'
                                             ' for a credential with certain characteristics',
                                 parents=[Parsery.keystore(required=False)])
parser.set_defaults(handler=lambda args: handler(args))

negotiating.options(parser)
parser.add_argument('--recipient', '-r')
parser.add_argument('--plan', help='single-DAG q.dp JSON or @file')
parser.add_argument('--prior', help='accepted native Apply SAID')
parser.add_argument('--origin', help='optional commitment-only ACDC SAID')


def handler(args):
    if args.version == Vrsn_2_0:
        return [negotiating.NativeNegotiation(args, 'offer')]
    return [doing.doify(nonce)]


def nonce(tymth, tock=0.0, **kwa):
    """ nonce
    """
    _ = (yield tock)

    print(Salter().qb64)
