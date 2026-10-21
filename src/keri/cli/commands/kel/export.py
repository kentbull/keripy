"""Export an accepted public KEL and optional authenticated endpoint replies."""
import argparse
from ...common import Parsery, parseVersion, public_evidence

parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.add_argument('--alias', '-a', required=True)
parser.add_argument('--version', type=parseVersion, default=parseVersion('2.0'))
parser.add_argument('--ends', action='store_true')
parser.add_argument('--output', required=True)
parser.set_defaults(handler=lambda args: public_evidence.kel(args, 'export'))
