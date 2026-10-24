"""Agree to an accepted v1 or native v2 IPEX offer."""
import argparse
from ...common import Parsery, native_exchange, legacy_negotiation
from ....kering import ConfigurationError

parser = argparse.ArgumentParser(description='Agree to an accepted v1 or native v2 IPEX offer', parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--alias', '-a', required=True)
parser.add_argument('--message', '-m', default='')
parser.add_argument('--time', default=None)
native_exchange.options(parser, send=True)
parser.add_argument('--said', '-s', required=True, help='accepted offer SAID')


def handler(args):
    """Select v1 negotiation by default or the explicit native v2 command path."""
    if not args.native:
        return [legacy_negotiation.Negotiation(args, 'agree')]
    return [native_exchange.ExchangeDoer(args, 'agree')]
