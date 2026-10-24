#!/bin/sh
# Copy source into Linux image storage; LMDB never touches a host bind mount.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
image=${V2_TEST_IMAGE:-keripy-v2-e2e:dev}
volume=${V2_TEST_VOLUME:-keripy-v2-e2e-tests}
docker build -t "$image" -f "$root/scripts/v2-e2e/Dockerfile" "$root"
if [ "$#" -eq 0 ]; then
    set -- tests/acdc
fi
docker run --rm \
    --mount "type=volume,src=$volume,dst=/tmp" \
    --mount "type=volume,src=$volume-state,dst=/usr/local/var" \
    -e PYTHONDONTWRITEBYTECODE=1 "$image" \
    python -m pytest -p no:cacheprovider -q "$@"
