# -*- encoding: utf-8 -*-
"""
keri.cli.commands.deannotate module
"""
import argparse
import sys

from keri.core.annotating import denot


parser = argparse.ArgumentParser(description="Deannotate a CESR stream")
parser.set_defaults(handler=lambda args: deannotate(args))
parser.add_argument("--in", dest="inpath", default=None,
                    help="Input annotated CESR stream path. Defaults to stdin.")
parser.add_argument("--out", dest="outpath", default=None,
                    help="Output CESR stream path. Defaults to stdout.")


def deannotate(args):
    """Deannotate one stream from stdin/file to stdout/file."""
    if args.inpath:
        with open(args.inpath, "rb") as infile:
            ams = infile.read()
    else:
        ams = sys.stdin.buffer.read()

    dms = denot(ams)
    if args.outpath:
        with open(args.outpath, "wb") as outfile:
            outfile.write(dms)
    else:
        sys.stdout.buffer.write(dms)

    return []
