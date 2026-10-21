"""Request v1 or native v2 IPEX disclosure."""
import argparse
from ...common import Parsery, native_exchange, legacy_negotiation
from ....kering import ConfigurationError

parser = argparse.ArgumentParser(description='Request v1 or native v2 IPEX disclosure', parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--alias', '-a', required=True)
parser.add_argument('--message', '-m', default='')
parser.add_argument('--time', default=None)
native_exchange.options(parser, send=True)
parser.add_argument('--recipient', '-r', required=True)
parser.add_argument('--plan', help='JSON one-DAG disclosure plan, or @file')

parser.add_argument('--schema', help='v1 credential schema SAID')
parser.add_argument('--attributes', default='{}', help='v1 requested attributes JSON or @file')


def handler(args):
    """Select v1 negotiation by default or the explicit native v2 command path."""
    if not args.native:
        return [legacy_negotiation.Negotiation(args, 'apply')]
    if not args.plan:
        raise ConfigurationError('native apply requires --plan')
    if args.schema or args.attributes != '{}':
        raise ConfigurationError('v1 schema/attributes options cannot be used with --v2')
    return [native_exchange.ExchangeDoer(args, 'apply')]
