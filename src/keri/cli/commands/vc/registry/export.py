"""Export accepted public ACDC v2 registry evidence without a credential or root."""
import argparse

from ....common import Parsery, public_evidence


parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.add_argument('--registry', required=True, help='exact accepted ACDC v2 registry inception SAID')
parser.add_argument('--output', required=True, help='new public CESR proof file; existing paths are refused')
parser.set_defaults(handler=public_evidence.exportRegistry)
