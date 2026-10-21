#!/bin/sh
# Independent Bash stories drive installed KLI and standalone Dolly commands.
set -eu
scriptdir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$scriptdir/scenarios/run-all.sh" "$@"
