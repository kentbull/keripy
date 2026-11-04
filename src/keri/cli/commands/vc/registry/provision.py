"""Prepare an explicitly authorized encrypted copy of an existing registry root."""
import argparse

from ....common import Parsery, parseVersion
from ....common.provisioning import NativeRootCopy
from ..... import Vrsn_1_0


parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: [NativeRootCopy(args, 'provision')])
parser.add_argument('--alias', '-a', required=True)
parser.add_argument('--version', type=parseVersion, default=Vrsn_1_0)
parser.add_argument('--registry', required=True, help='exact accepted native registry SAID')
parser.add_argument('--recipient', required=True, help='known individual recipient AID')
parser.add_argument('--output', required=True, help='exclusive-create signed encrypted reply file')
parser.add_argument('--deliver', action='store_true', help='explicitly submit through recipient endpoints/mailboxes')
parser.add_argument('--timeout', type=float, default=120.0, help='finite whole-operation wait')
