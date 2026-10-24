"""Request v1 or ACDC v2 IPEX disclosure."""
import argparse
from ...common import Parsery, acdc_v2_ipex, legacy_negotiation
from ....kering import ConfigurationError

parser = argparse.ArgumentParser(description='Request v1 or ACDC v2 IPEX disclosure', parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--alias', '-a', required=True)
parser.add_argument('--message', '-m', default='')
parser.add_argument('--time', default=None)
acdc_v2_ipex.options(parser, send=True)
parser.add_argument('--recipient', '-r', required=True)
parser.add_argument('--plan', help='JSON one-DAG disclosure plan, or @file')

parser.add_argument('--schema', help='v1 credential schema SAID')
parser.add_argument('--attributes', default='{}', help='v1 requested attributes JSON or @file')


def handler(args):
    """Select v1 negotiation by default or the explicit ACDC v2 command path."""
    if not args.acdc_v2:
        return [legacy_negotiation.Negotiation(args, 'apply')]
    if not args.plan:
        raise ConfigurationError('ACDC v2 apply requires --plan')
    if args.schema or args.attributes != '{}':
        raise ConfigurationError('v1 schema/attributes options cannot be used with --acdc-v2')
    return [acdc_v2_ipex.ExchangeDoer(args, 'apply')]
