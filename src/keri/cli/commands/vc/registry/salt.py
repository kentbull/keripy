"""Establish and replicate optional registry roots through authenticated replies."""
import argparse

from ....common import Parsery, registry_salts


parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.add_argument('operation', choices=('export', 'import', 'send', 'approve', 'receive', 'status', 'serve'))
parser.add_argument('--alias', '-a', required=True, help='local logical issuer or discloser alias')
parser.add_argument('--evidence', action='append', default=[], help='public CESR evidence file to verify first')
parser.add_argument('--input', help='signed reply or member-proposal CESR file to receive')
parser.add_argument('--output', help='create a signed encrypted reply file; export includes public KEL/TEL evidence')
parser.add_argument('--proposal-output', help='create an exact member proposal file while awaiting quorum')
parser.add_argument('--proposal', help='retained multisig/rpy proposal SAID to approve')
parser.add_argument('--party', help='logical holder or discloser receiving the encrypted salt')
parser.add_argument('--target', help='current individual member receiving an encrypted salt copy')
parser.add_argument('--registry', help='exact accepted registry inception SAID')
delivery = parser.add_mutually_exclusive_group()
delivery.add_argument('--endpoint', help='HTTP(S) or TCP recipient for the fully authenticated reply')
delivery.add_argument('--deliver', action='store_true',
                      help="send through the addressed member's existing endpoint or witness mailbox")
parser.add_argument('--host', default='127.0.0.1')
parser.add_argument('--port', type=int, default=5649, help='HTTP intake port for serve')
parser.add_argument('--timeout', type=float, default=30.0, help='bounded quorum or transport wait in seconds')
parser.set_defaults(handler=registry_salts.command)
