"""Inspect authenticated retained native IPEX evidence and exact disclosure views."""
import argparse
from ...common import Parsery, public_evidence

parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.add_argument('--said', '-s', required=True)
parser.set_defaults(handler=public_evidence.inspect)
