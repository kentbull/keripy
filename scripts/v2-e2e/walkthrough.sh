#!/bin/sh
# Native independent processes plus the focused native/legacy webhook contract.
set -eu
scriptdir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$scriptdir/check.sh" -s tests/app/test_native_e2e.py tests/app/test_dolly.py "$@"
