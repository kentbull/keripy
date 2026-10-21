#!/usr/bin/env bash
# Six independent v2 stories share one exact installed image, never identity state.
set -Eeuo pipefail
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BASE_VOLUME=${SCENARIO_VOLUME:-keripy-v2-scenarios-qualified}
SCENARIOS=(
    holder-full-then-graduated.sh
    holder-partial-then-onward.sh
    holder-supplied-state-opening.sh
    holder-provisioned-state-derivation.sh
    holder-selected-discloser-openings.sh
    holder-selected-discloser-derivation.sh
)
INDEX=0
for SCENARIO in "${SCENARIOS[@]}"; do
    INDEX=$((INDEX + 1))
    TRANSPORT=http
    if (( INDEX % 2 == 0 )); then TRANSPORT=tcp; fi
    SCENARIO_TRANSPORT=$TRANSPORT SCENARIO_VOLUME="$BASE_VOLUME-s$INDEX" \
        SCENARIO_SKIP_BUILD=$(( INDEX > 1 )) "$HERE/run-linux.sh" "$SCENARIO"
done
