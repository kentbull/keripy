"""Independently endorse one exact native Grant using its selected registry issuer."""
import argparse

from ...common import Parsery, issuing, presenting
from ....kering import ConfigurationError, Vrsn_2_0

parser = argparse.ArgumentParser(description=__doc__, parents=[Parsery.keystore()])
parser.set_defaults(handler=lambda args: handler(args))
issuing.options(parser)
parser.add_argument('--alias', '-a', required=True)
parser.add_argument('--said', required=True, help='exact Grant SAID')
parser.add_argument('--grant', required=True, help='one native Grant frame; nested bodies and proofs are preserved')
parser.add_argument('--contribution', action='append', default=[], help='group issuer contribution to this exact --grant; repeat for additional members')
parser.add_argument('--sender', required=True, help='actual discloser AID')
parser.add_argument('--recipient', required=True, help='selected verifier AID')


def handler(args):
    if args.version != Vrsn_2_0:
        raise ConfigurationError('native endorsement requires --version 2.0')
    return [presenting.NativePresentation(args, 'endorse')]
