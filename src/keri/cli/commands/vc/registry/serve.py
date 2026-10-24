"""Serve authenticated legacy registry replay/TSNs from an existing issuer store."""
import argparse
from ....common import Parsery, parseVersion, legacy_evidence

parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.add_argument('--alias', '-a', required=True)
parser.add_argument('--registry-name', '-r', required=True)
parser.add_argument('--version', type=parseVersion, required=True)
parser.add_argument('--reader', action='append', required=True)
parser.add_argument('--reply-to', required=True, help='fixed authorized HTTP(S) evidence recipient')
parser.add_argument('--host', default='127.0.0.1')
parser.add_argument('--port', type=int, required=True)
parser.add_argument('--timeout', type=float, default=5.0)
parser.add_argument('--no-prompt', action='store_true')
parser.set_defaults(handler=legacy_evidence.serve)
