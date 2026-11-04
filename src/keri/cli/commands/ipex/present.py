"""Present only the exact view selected by a locally accepted native Admit."""
import argparse

from ...common import Parsery, issuing, presenting
from ....kering import ConfigurationError, Vrsn_2_0

parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
issuing.options(parser)
parser.add_argument('--alias', '-a', required=True)
parser.add_argument('--from-grant', required=True, help='exact accepted Grant with a local accepted Admit')
parser.add_argument('--recipient', '-r', required=True)
parser.add_argument('--disclose', action='append', default=[], help='held origin attribute path a/..., repeated to narrow disclosure')
parser.add_argument('--plan', help='explicit native single-DAG q.dp JSON or @file; required for multiple nodes')
parser.add_argument('--respond-unblind', action='store_true', help='approve this outgoing Grant and remain live for Unblind and Admit')
parser.add_argument('--refresh', action='store_true', help='explicitly refresh proofs for this new presentation only')
parser.add_argument('--opening', action='append', default=[], help='exact CESR opening file, repeated; requires --refresh')
parser.add_argument('--derive', action='store_true', help='authorize ordinary proof derivation from this signer\'s encrypted Keeper root; requires --refresh')
parser.add_argument('--message', '-m', default='')
parser.add_argument('--proposal-output', help='exclusive-create the exact native group Grant proposal for member approval')
parser.add_argument('--proposal', help='explicitly contribute to this exact group proposal from the selected admitted view')
stages = parser.add_mutually_exclusive_group()
stages.add_argument('--prepare', action='store_true', help='retain one exact held-proof Grant for independent issuer endorsement; no delivery')
stages.add_argument('--resume', metavar='GRANT', help='resume an existing local preparation with authentication additions only')


def handler(args):
    if args.version != Vrsn_2_0:
        raise ConfigurationError('native presentation requires --version 2.0')
    return [presenting.NativePresentation(args, 'present')]
