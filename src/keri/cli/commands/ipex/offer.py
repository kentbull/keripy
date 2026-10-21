"""Offer native IPEX disclosure."""
import argparse
from ...common import Parsery, native_exchange
from ....kering import ConfigurationError

parser = argparse.ArgumentParser(description='Offer native IPEX disclosure', parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--alias', '-a', required=True)
parser.add_argument('--message', '-m', default='')
parser.add_argument('--time', default=None)
native_exchange.options(parser, send=True)
parser.add_argument('--recipient', '-r', required=True)
parser.add_argument('--plan', help='JSON one-DAG disclosure plan, or @file')
parser.add_argument('--said', '-s', required=True, help='issued credential SAID')
parser.add_argument('--from-grant', help='admitted grant providing the credential')
parser.add_argument('--prior', help='accepted apply SAID')
parser.add_argument('--disclose', action='append', default=[])


def handler(args):
    if not args.native:
        raise ConfigurationError('this command requires --native; legacy negotiation is not implemented')
    return [native_exchange.ExchangeDoer(args, 'offer')]
