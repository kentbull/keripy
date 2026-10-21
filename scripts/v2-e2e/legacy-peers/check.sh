#!/bin/sh
# Released peers have isolated dependencies/state; only public wire crosses.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../../.." && pwd)
run="keripy-legacy-peers-$$"
current=${V2_MATRIX_IMAGE:-keripy-v2-e2e:dev}
printf 'Legacy matrix: %s\n' "$run"
cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        docker logs "$run-1214" >&2 || true
        docker logs "$run-136" >&2 || true
    fi
    docker rm -f "$run-1214" "$run-136" >/dev/null 2>&1 || true
    docker network rm "$run" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM
if [ "${LEGACY_SKIP_BUILD:-0}" != 1 ]; then
    for version in 1.2.14 1.3.6; do
        docker build --build-arg "KERI_VERSION=$version" -t "keripy-legacy-peer:$version" "$here"
    done
fi
docker network create "$run" >/dev/null
docker run -d --rm --name "$run-1214" --network "$run" \
    --mount "type=volume,src=$run-1214,dst=/tmp" \
    --mount "type=bind,src=$here,dst=/opt/legacy,readonly" keripy-legacy-peer:1.2.14 >/dev/null
docker run -d --rm --name "$run-136" --network "$run" \
    --mount "type=volume,src=$run-136,dst=/tmp" \
    --mount "type=bind,src=$here,dst=/opt/legacy,readonly" keripy-legacy-peer:1.3.6 >/dev/null
# The runner checks profile health with a bounded retry before pytest starts.
docker run --rm --name "$run-current" --network "$run" \
    --mount "type=bind,src=$root,dst=/workspace,readonly" \
    --mount "type=volume,src=$run-current,dst=/tmp" \
    -e PYTHONDONTWRITEBYTECODE=1 -e KERI_LEGACY_PEER_MATRIX=1 \
    -e "LEGACY_PEER_1_2_14_URL=http://$run-1214:7723/" \
    -e "LEGACY_PEER_1_3_6_URL=http://$run-136:7723/" \
    -e "LEGACY_MATRIX_CALLBACK_HOST=$run-current" "$current" \
    python scripts/v2-e2e/legacy-peers/run.py
