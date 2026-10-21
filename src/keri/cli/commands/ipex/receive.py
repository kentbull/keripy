"""Receive authenticated native IPEX messages without automatic wallet consent."""
import argparse
from ...common import Parsery, native_exchange
from ....kering import ConfigurationError

parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--alias', '-a', required=True)
parser.add_argument('--host', default='127.0.0.1')
parser.add_argument('--port', type=int, default=5648)
native_exchange.options(parser)


def handler(args):
    """Return the native intake worker for an explicitly selected v2 receiver.

    args selects existing identity/alias, listen address, evidence inputs, and
    optional observer synchronization. Without --v2/--native raise ConfigurationError.
    The returned worker owns its listener lifetime; receiving proof alone grants
    no wallet consent."""
    if not args.native:
        raise ConfigurationError('native IPEX receiver requires --native')
    return [native_exchange.ExchangeDoer(args, 'receive')]
