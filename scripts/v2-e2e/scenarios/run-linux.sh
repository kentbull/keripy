#!/usr/bin/env bash
# Copy both authorized repositories into image storage, install wheels, run Bash.
set -Eeuo pipefail
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../../.." && pwd)
DOLLY_ROOT=${DOLLY_ROOT:-${DOLLY_SOURCE:?Set DOLLY_SOURCE to the standalone Dolly checkout}}
IMAGE=${SCENARIO_IMAGE:-keripy-v2-scenarios:dev}
BASE_IMAGE=${SCENARIO_BASE_IMAGE:-keripy-v2-scenarios:base}
VOLUME=${SCENARIO_VOLUME:-keripy-v2-scenarios}
KERIPY_DIRTY=false
DOLLY_DIRTY=false
[[ -z $(git -C "$ROOT" status --porcelain) ]] || KERIPY_DIRTY=true
[[ -z $(git -C "$DOLLY_ROOT" status --porcelain) ]] || DOLLY_DIRTY=true
SCENARIO=${1:-holder-full-then-graduated.sh}
[[ $SCENARIO != */* && -f "$HERE/$SCENARIO" ]]
if [[ ${SCENARIO_SKIP_BUILD:-0} != 1 ]]; then
docker build -t "$BASE_IMAGE" -f "$ROOT/scripts/v2-e2e/Dockerfile" "$ROOT"
docker build -t "$IMAGE" -f "$HERE/Dockerfile" \
    --build-context "dolly-src=$DOLLY_ROOT" --build-arg "KERIPY_IMAGE=$BASE_IMAGE" \
    --build-arg "KERIPY_REVISION=$(git -C "$ROOT" rev-parse HEAD)" \
    --build-arg "DOLLY_REVISION=$(git -C "$DOLLY_ROOT" rev-parse HEAD)" \
    --build-arg "KERIPY_WORKTREE_DIRTY=$KERIPY_DIRTY" \
    --build-arg "DOLLY_WORKTREE_DIRTY=$DOLLY_DIRTY" "$ROOT"
fi
docker run --rm --mount "type=volume,src=$VOLUME,dst=/tmp" \
    --mount "type=volume,src=$VOLUME-state,dst=/usr/local/var" \
    -e "SCENARIO_TRANSPORT=${SCENARIO_TRANSPORT:-http}" "$IMAGE" \
    "/workspace/scripts/v2-e2e/scenarios/$SCENARIO"
