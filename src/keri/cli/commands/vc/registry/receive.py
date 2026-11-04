"""Approve and receive one existing registry root within this finite process."""
import argparse

from ....common import Parsery, parseVersion
from ....common.provisioning import NativeRootCopy
from ..... import Vrsn_1_0


parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: [NativeRootCopy(args, 'receive')])
parser.add_argument('--alias', '-a', required=True)
parser.add_argument('--version', type=parseVersion, default=Vrsn_1_0)
parser.add_argument('--registry', required=True, help='exact accepted native registry SAID')
parser.add_argument('--sender', required=True, help='exact authorized sender AID')
parser.add_argument('--event', required=True, help='exact accepted BUP for this held opening')
parser.add_argument('--opening', required=True, help='one held CESR state opening, never a root')
source = parser.add_mutually_exclusive_group(required=True)
source.add_argument('--message', help='exact signed encrypted reply file')
source.add_argument('--listen', action='store_true', help='listen through the ordinary mailboxes after approval')
parser.add_argument('--evidence', action='append', default=[], help='signed public KEL/TEL support file')
parser.add_argument('--timeout', type=float, default=120.0, help='finite approval/intake lifetime; restart requires fresh approval')
