"""Send every held group root to the members added by one accepted group rotation."""
import argparse

from .....common import Parsery, parseVersion
from .....common.rootreplicating import RootReplication
from ...... import Vrsn_1_0


parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: [RootReplication(args, 'newcomers')])
parser.add_argument('--alias', '-a', required=True, help='local group alias; sends as its local member')
parser.add_argument('--version', type=parseVersion, default=Vrsn_1_0)
parser.add_argument('--rotation', required=True, help='accepted group rotation SAID that added members')
parser.add_argument('--registry', action='append', help='limit to these registry SAIDs (default: every root held for the group)')
parser.add_argument('--acdc', help='ACDC SAID hint overriding the one derived per registry from a held opening or stored Grant')
parser.add_argument('--out', help='exclusive-create file for the signed exns instead of mailbox delivery')
parser.add_argument('--timeout', type=float, default=60.0, help='finite whole-operation wait')
