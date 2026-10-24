"""Agree to an accepted v1 or ACDC v2 IPEX offer."""
import argparse
from ...common import Parsery, acdc_v2_ipex, legacy_negotiation
from ....kering import ConfigurationError

parser = argparse.ArgumentParser(description='Agree to an accepted v1 or ACDC v2 IPEX offer', parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--alias', '-a', required=True)
parser.add_argument('--message', '-m', default='')
parser.add_argument('--time', default=None)
acdc_v2_ipex.options(parser, send=True)
parser.add_argument('--said', '-s', required=True, help='accepted offer SAID')


def handler(args):
    """Select v1 negotiation by default or the explicit ACDC v2 command path."""
    if not args.acdc_v2:
        return [legacy_negotiation.Negotiation(args, 'agree')]
    return [acdc_v2_ipex.ExchangeDoer(args, 'agree')]
