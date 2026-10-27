"""Import signed public KEL evidence through its ordinary parser and escrows."""
import argparse
from ...common import Parsery, parseVersion, public_evidence

parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.add_argument('--version', type=parseVersion, default=parseVersion('2.0'))
parser.add_argument('--file', required=True)
parser.set_defaults(handler=lambda args: public_evidence.kel(args, 'import'))
