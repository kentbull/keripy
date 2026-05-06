# -*- encoding: utf-8 -*-
"""
keri.cli.commands.annotate module
"""
import argparse
import sys

from keri.core.annotating import Annotator, annot


parser = argparse.ArgumentParser(description="Annotate a CESR stream")
parser.set_defaults(handler=lambda args: annotate(args))
parser.add_argument("--in", dest="inpath", default=None,
                    help="Input CESR stream path. Defaults to stdin.")
parser.add_argument("--out", dest="outpath", default=None,
                    help="Output annotation path. Defaults to stdout.")
parser.add_argument("--qb2", action="store_true",
                    help="Read input as binary-domain qb2 CESR.")
parser.add_argument("--pretty", action="store_true",
                    help="Pretty-print field-map message bodies when possible.")
parser.add_argument("--colored", action="store_true",
                    help="Colorize annotation output on stdout.")


def annotate(args):
    """Annotate one stream from stdin/file to stdout/file."""
    if args.inpath:
        with open(args.inpath, "rb") as infile:
            ims = infile.read()
    else:
        ims = sys.stdin.buffer.read()

    if args.outpath:
        ams = annot(ims, pretty=args.pretty)
        with open(args.outpath, "w", encoding="utf-8") as outfile:
            outfile.write(ams)
            outfile.write("\n")
    else:
        ams = Annotator(pretty=args.pretty).annotate(
            bytearray(ims), colored=args.colored)
        sys.stdout.write(ams)
        sys.stdout.write("\n")

    return []
