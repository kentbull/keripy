"""Read exact retained v2 IPEX disclosure and optional current verdict."""
import argparse

from ...common import Parsery, parseVersion, presenting
from ....kering import ConfigurationError, Vrsn_1_0, Vrsn_2_0

parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--version', type=parseVersion, default=Vrsn_1_0)
parser.add_argument('--said', '-s', required=True)
parser.add_argument('--current', action='store_true', help='read current v2 IPEX reverifyGrant result without acquiring evidence')


def handler(args):
    if args.version != Vrsn_2_0:
        raise ConfigurationError('v2 IPEX inspection requires --version 2.0')
    return [presenting.IpexV2Inspection(args)]
