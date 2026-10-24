"""Query an observer and independently verify its fresh public registry proof."""
import argparse
from ....common import Parsery, public_evidence

parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.add_argument('--alias', '-a', required=True)
parser.add_argument('--endpoint', required=True)
parser.add_argument('--registry', required=True)
parser.add_argument('--output', required=True)
parser.add_argument('--timeout', type=float, default=10.0)
parser.set_defaults(handler=lambda args: [public_evidence.Request(args, 'query')])
