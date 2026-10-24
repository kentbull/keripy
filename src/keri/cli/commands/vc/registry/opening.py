"""Export one verified CESR state opening without exporting derivation custody."""
import argparse
from ....common import Parsery, public_evidence

parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
registry = parser.add_mutually_exclusive_group(required=True)
registry.add_argument('--registry-name', '-r')
registry.add_argument('--registry', help='accepted foreign registry SAID for a designated discloser')
parser.add_argument('--said', '-s', required=True)
parser.add_argument('--from-grant', help='admitted disclosure providing the exact credential material')
parser.add_argument('--ordinal', type=int, required=True)
parser.add_argument('--state', default='issued')
parser.add_argument('--bound-event')
parser.add_argument('--output', required=True)
parser.set_defaults(handler=public_evidence.opening)
