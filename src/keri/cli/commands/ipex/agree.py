# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands module

"""
import argparse

from hio.base import doing
from ...common import Parsery, negotiating
from ....core import Salter
from ....kering import Vrsn_2_0


parser = argparse.ArgumentParser(description='Reply to IPEX offer message acknowledged willingness to accept offered '
                                             'credential',
                                 parents=[Parsery.keystore(required=False)])
parser.set_defaults(handler=lambda args: handler(args))

negotiating.options(parser)
parser.add_argument('--said', '-s', help='exact accepted v2 IPEX Offer SAID')


def handler(args):
    if args.version == Vrsn_2_0:
        return [negotiating.IpexV2Negotiation(args, 'agree')]
    return [doing.doify(nonce)]


def nonce(tymth, tock=0.0, **kwa):
    """ nonce
    """
    _ = (yield tock)

    print(Salter().qb64)
