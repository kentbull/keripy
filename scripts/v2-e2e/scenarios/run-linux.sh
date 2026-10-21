#!/usr/bin/env bash
# Copy both authorized repositories into image storage, install wheels, run Bash.
set -Eeuo pipefail
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../../.." && pwd)
DOLLY_ROOT=${DOLLY_ROOT:-${DOLLY_SOURCE:?Set DOLLY_SOURCE to the standalone Dolly checkout}}
IMAGE=${SCENARIO_IMAGE:-keripy-v2-scenarios:dev}
BASE_IMAGE=${SCENARIO_BASE_IMAGE:-keripy-v2-scenarios:base}
VOLUME=${SCENARIO_VOLUME:-keripy-v2-scenarios}
PROFILE=${SCENARIO_SERVICE_PROFILE:-kli}
WITNESS_PROFILE=${SCENARIO_WITNESS_PROFILE:-kli}
case "$WITNESS_PROFILE" in kli|hk) ;; *) exit 2;; esac
if [[ $WITNESS_PROFILE == hk ]]; then : "${WITNESS_HK_SOURCE:?Set the upgraded hosted witness checkout}"; fi
case "$PROFILE" in kli|kf) ;; *) printf 'Unknown service profile: %s\n' "$PROFILE" >&2; exit 2;; esac
if [[ $PROFILE == kf ]]; then
    : "${KF_REGISTRAR_SOURCE:?Set the upgraded registrar checkout}"
    : "${KF_OBSERVER_SOURCE:?Set the upgraded observer checkout}"
fi
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
if [[ $PROFILE == kf ]]; then
    KF_REGISTRAR_DIRTY=false
    KF_OBSERVER_DIRTY=false
    [[ -z $(git -C "$KF_REGISTRAR_SOURCE" status --porcelain) ]] || KF_REGISTRAR_DIRTY=true
    [[ -z $(git -C "$KF_OBSERVER_SOURCE" status --porcelain) ]] || KF_OBSERVER_DIRTY=true
    docker build -t "$IMAGE-kf" -f "$HERE/Dockerfile.kf" \
        --build-context "registrar-src=$KF_REGISTRAR_SOURCE" \
        --build-context "observer-src=$KF_OBSERVER_SOURCE" --build-arg "SCENARIO_IMAGE=$IMAGE" \
        --build-arg "REGISTRAR_REVISION=$(git -C "$KF_REGISTRAR_SOURCE" rev-parse HEAD)" \
        --build-arg "OBSERVER_REVISION=$(git -C "$KF_OBSERVER_SOURCE" rev-parse HEAD)" \
        --build-arg "REGISTRAR_DIRTY=$KF_REGISTRAR_DIRTY" \
        --build-arg "OBSERVER_DIRTY=$KF_OBSERVER_DIRTY" "$ROOT"
fi
fi
if [[ $PROFILE == kf ]]; then IMAGE="$IMAGE-kf"; fi
if [[ $WITNESS_PROFILE == hk ]]; then
    if [[ ${SCENARIO_SKIP_BUILD:-0} != 1 ]]; then
        WITNESS_DIRTY=false
        [[ -z $(git -C "$WITNESS_HK_SOURCE" status --porcelain) ]] || WITNESS_DIRTY=true
        docker build -t "$IMAGE-hk" -f "$HERE/Dockerfile.hk" \
            --build-context "witness-src=$WITNESS_HK_SOURCE" --build-arg "SCENARIO_IMAGE=$IMAGE" \
            --build-arg "WITNESS_REVISION=$(git -C "$WITNESS_HK_SOURCE" rev-parse HEAD)" \
            --build-arg "WITNESS_DIRTY=$WITNESS_DIRTY" "$ROOT"
    fi
    IMAGE="$IMAGE-hk"
fi
docker run --rm --mount "type=volume,src=$VOLUME,dst=/tmp" \
    --mount "type=volume,src=$VOLUME-state,dst=/usr/local/var" \
    -e "SCENARIO_WITNESS_PROFILE=$WITNESS_PROFILE" -e "SCENARIO_SERVICE_PROFILE=$PROFILE" \
    -e "SCENARIO_TRANSPORT=${SCENARIO_TRANSPORT:-http}" "$IMAGE" \
    "/workspace/scripts/v2-e2e/scenarios/$SCENARIO"
