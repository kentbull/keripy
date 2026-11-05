# -*- encoding: utf-8 -*-
"""
keri.cli module

"""
import sys

import multicommand

from .. import help

from ..app import directing
from ..cli import commands


logger = help.ogler.getLogger()


def main():
    # Status symbols such as the check mark must not abort a command whose
    # stdout uses a narrower encoding, e.g. cp1252 when redirected on Windows.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    parser = multicommand.create_parser(commands)
    args = parser.parse_args()

    if not hasattr(args, 'handler'):
        parser.print_help()
        return

    try:
        doers = args.handler(args)
        directing.runController(doers=doers, expire=0.0)

    except Exception as ex:
        import os
        if os.getenv('DEBUG_KLI'):
            import traceback
            traceback.print_exc()
        else:
            print(f"ERR: {ex}")
        return -1


if __name__ == "__main__":
    main()
