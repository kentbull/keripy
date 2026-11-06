"""Ingest registry root copies; verifiable roots are retained automatically."""
import argparse

from .....common import Parsery, parseVersion
from .....common.rootreplicating import RootReplication
from ...... import Vrsn_1_0


parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: [RootReplication(args, 'receive')])
parser.add_argument('--alias', '-a', required=True, help='local group alias or individual holder')
parser.add_argument('--version', type=parseVersion, default=Vrsn_1_0)
parser.add_argument('--registry', help='require a retained root for this registry SAID; --listen waits for it')
parser.add_argument('--said', help='manually retry this stored exn SAID (with --event/--opening)')
parser.add_argument('--event', help='accepted BUP SAID overriding the sender hint for --said')
parser.add_argument('--opening', help='held CESR state opening file for --said')
source = parser.add_mutually_exclusive_group()
source.add_argument('--listen', action='store_true', help='process the /credential mailbox until --registry is retained')
source.add_argument('--message', action='append', help='fallback: signed exn file; repeatable')
parser.add_argument('--timeout', type=float, default=60.0, help='finite whole-operation wait')
