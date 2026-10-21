"""Publish a new witnessed blind while preserving a credential's current state."""
import argparse
from ....common import Parsery, public_evidence

parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.add_argument('--alias', '-a', required=True)
parser.add_argument('--registry-name', '-r', required=True)
parser.add_argument('--said', '-s', required=True)
parser.add_argument('--state', default='issued')
parser.add_argument('--bound-event')
parser.add_argument('--timeout', type=float, default=30.0)
parser.set_defaults(handler=lambda args: [public_evidence.Advance(args)])
