"""Establish and replicate optional registry roots through authenticated replies."""
import argparse

from ....common import Parsery, registry_salts


parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.add_argument('operation', choices=('init', 'bind', 'confirm', 'assign',
                                        'approve', 'resume', 'import', 'archive', 'export', 'status', 'serve'))
parser.add_argument('--alias', '-a', required=True, help='local logical issuer or discloser alias')
parser.add_argument('--rosters', help='trusted local JSON map of logical AIDs to ordered member AIDs')
parser.add_argument('--evidence', action='append', default=[], help='public CESR evidence file to verify first')
parser.add_argument('--input', help='signed reply or member-proposal CESR file to receive')
parser.add_argument('--output', help='create an exact authenticated public reply file')
parser.add_argument('--proposal-output', help='create an exact member proposal file while awaiting quorum')
parser.add_argument('--proposal', help='retained multisig/rpy proposal SAID to approve')
parser.add_argument('--issuer', help='logical issuer AID for initial agreement')
parser.add_argument('--discloser', help='initial entitled holder or separate discloser AID')
parser.add_argument('--init', help='exact accepted initial reply SAID')
parser.add_argument('--bind', help='exact accepted binding reply SAID')
parser.add_argument('--origin', help='exact original issuer confirmation SAID')
parser.add_argument('--party', help='additional logical party explicitly entitled by the issuer')
parser.add_argument('--registry', help='exact accepted registry inception SAID')
parser.add_argument('--said', help='authenticated reply SAID to export')
parser.add_argument('--endpoint', help='HTTP(S) or TCP recipient for the fully authenticated reply')
parser.add_argument('--host', default='127.0.0.1')
parser.add_argument('--port', type=int, default=5649, help='HTTP intake port for serve')
parser.add_argument('--timeout', type=float, default=30.0, help='bounded quorum or transport wait in seconds')
parser.set_defaults(handler=registry_salts.command)
