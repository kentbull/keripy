"""Receive authenticated ACDC v2 IPEX messages without automatic wallet consent."""
import argparse
from ...common import Parsery, acdc_v2_ipex
from ....kering import ConfigurationError

parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--alias', '-a', required=True)
parser.add_argument('--host', default='127.0.0.1')
parser.add_argument('--port', type=int, default=5648)
acdc_v2_ipex.options(parser)


def handler(args):
    """Return the ACDC v2 intake worker for an explicitly selected v2 receiver.

    args selects existing identity/alias, listen address, evidence inputs, and
    optional observer synchronization. Without --acdc-v2 raise ConfigurationError.
    The returned worker owns its listener lifetime; receiving proof alone grants
    no wallet consent."""
    if not args.acdc_v2:
        raise ConfigurationError('ACDC v2 IPEX receiver requires --acdc-v2')
    return [acdc_v2_ipex.ExchangeDoer(args, 'receive')]
