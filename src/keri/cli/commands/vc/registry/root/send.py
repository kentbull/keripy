"""Send one held registry root to members by ESSR exn through their mailboxes."""
import argparse

from .....common import Parsery, parseVersion
from .....common.rootreplicating import RootReplication
from ...... import Vrsn_1_0


parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: [RootReplication(args, 'send')])
parser.add_argument('--alias', '-a', required=True, help='local group (sends as its member) or individual sender')
parser.add_argument('--version', type=parseVersion, default=Vrsn_1_0)
parser.add_argument('--registry', required=True, help='accepted registry SAID whose root is held locally')
parser.add_argument('--recipient', action='append',
                    help='individual member AID or alias; repeatable. A group alias defaults to its other current members')
parser.add_argument('--holder', help='AID the root is held for (defaults to the group alias, else the recipient)')
parser.add_argument('--event', help='accepted BUP SAID hint (defaults to the registry head)')
parser.add_argument('--acdc', help='ACDC SAID hint for commitment reproduction by a recipient without an opening')
parser.add_argument('--out', help='exclusive-create file for the signed exn instead of mailbox delivery')
parser.add_argument('--timeout', type=float, default=60.0, help='finite whole-operation wait')
