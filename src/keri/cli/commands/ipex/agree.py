"""Agree to an accepted native IPEX offer."""
import argparse
from ...common import Parsery, native_exchange
from ....kering import ConfigurationError

parser = argparse.ArgumentParser(description='Agree to an accepted native IPEX offer', parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--alias', '-a', required=True)
parser.add_argument('--message', '-m', default='')
parser.add_argument('--time', default=None)
native_exchange.options(parser, send=True)
parser.add_argument('--said', '-s', required=True, help='accepted offer SAID')


def handler(args):
    if not args.native:
        raise ConfigurationError('this command requires --native; legacy negotiation is not implemented')
    return [native_exchange.ExchangeDoer(args, 'agree')]
