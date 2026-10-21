#!/usr/bin/env bash
# Infrastructure and assertions only. Credential/IPEX operations belong in stories.
set -Eeuo pipefail
umask 077
HERE=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
JSON="$HERE/helpers.py"
declare -A PIDS=() PORTS=() AIDS=() NAMES=()

# Print selected JSON value: artifact path, dotted path. Missing/invalid JSON fails.
value() { python "$JSON" field "$1" "$2"; }
# Compare artifact/path with a JSON literal; return nonzero on any mismatch/error.
assert_json() { python "$JSON" assert-json "$1" "$2" "$3"; }

# EXIT trap: preserve incoming status, stop owned children, retain diagnostics, exit.
cleanup() {
    local status=$?
    trap - EXIT
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
    printf 'Scenario diagnostics retained: %s (exit %s)\n' "$RUN_DIR" "$status"
    if (( status )); then
        for log in "$RUN_DIR"/*.log; do
            printf '\nLog: %s\n' "$log"
            tail -50 "$log" || true
        done
    fi
    exit "$status"
}

# Run one installed CLI command: actor role then public tokens. Return failure for
# timeout, nonzero process exit or KLI ERR output; capture exact store/command text.
k() {
    local role=$1
    shift
    printf 'kli ' >> "$RUN_DIR/commands.log"
    printf '%q ' "$@" >> "$RUN_DIR/commands.log"
    printf '%q %q %q %q\n' --name "${NAMES[$role]}" --base "$STORE_BASE" >> "$RUN_DIR/commands.log"
    if ! timeout "${SCENARIO_COMMAND_TIMEOUT:-45}" kli "$@" --name "${NAMES[$role]}" --base "$STORE_BASE" \
        | tee "$RUN_DIR/latest-$role.jsonl"; then return 1; fi
    if grep -q '^ERR:' "$RUN_DIR/latest-$role.jsonl"; then return 1; fi
}

# Start label plus argv as an owned process; capture logs and record its PID.
spawn() {
    local label=$1
    shift
    "$@" > "$RUN_DIR/$label.log" 2>&1 &
    PIDS[$label]=$!
}

# Stop/wait the owned label and remove its PID; missing labels/signals fail.
stop() {
    local label=$1
    kill "${PIDS[$label]}"
    wait "${PIDS[$label]}" || true
    unset 'PIDS[$label]'
}

# Retry command argv a bounded number of times; return success only on exit zero.
poll() {
    local deadline=$((SECONDS + ${SCENARIO_POLL_TIMEOUT:-60}))
    while (( SECONDS < deadline )); do
        if "$@"; then return 0; fi
        sleep 0.1
    done
    printf 'Polling deadline exceeded: %s\n' "$*" >&2
    return 1
}

# Verify retained EXN SAID in actor store via public CLI; absent/invalid fails.
accepted_exchange() {
    k "$1" ipex inspect -s "$2" > "$RUN_DIR/check-$1.jsonl" 2>&1
}

# Read public Dolly operator result for grant SAID; succeed only if delivered true.
delivered() {
    dolly inspect --name "${NAMES[dolly]}" --base "$STORE_BASE" --grant "$1" --no-prompt \
        > "$RUN_DIR/delivery.json"
    [[ $(value "$RUN_DIR/delivery.json" delivered) == true ]]
}

# Prepare a fresh named scenario: independent stores, three live witnesses/quorum
# two, real signed endpoint/KEL bootstrap and port readiness. Any failure exits.
prepare() {
    SCENARIO=$1
    TRANSPORT=${SCENARIO_TRANSPORT:-http}
    RUN_DIR=$(mktemp -d "${SCENARIO_RUN_ROOT:-/tmp}/$SCENARIO.XXXXXXXX")
    export RUN_DIR
    printf '%s\n' "${AUTHORIZATION_PROFILE:-Issuer-controlled registry; holder presents admitted material; no holder derivation custody}" > "$RUN_DIR/authorization.txt"
    printf '%s\n' "${DISCLOSER_ROLE:-issuer}" > "$RUN_DIR/discloser-role.txt"
    STORE_BASE="scenario-${RUN_DIR##*/}"
    export KLI_KEYSTORE_PASSCODE
    KLI_KEYSTORE_PASSCODE=$(kli passcode generate)
    trap cleanup EXIT
    ROLES=(witness1 witness2 witness3 issuer holder registrar observer dolly)
    if [[ $SCENARIO == *selected-discloser* ]]; then ROLES+=(presenter); fi
    python "$JSON" ports "${ROLES[@]}" witness1tcp witness2tcp witness3tcp dollytcp hook \
        > "$RUN_DIR/ports.json"
    local role
    for role in "${ROLES[@]}" witness1tcp witness2tcp witness3tcp dollytcp hook; do
        PORTS[$role]=$(value "$RUN_DIR/ports.json" "$role")
    done
    printf '{"transferable":false,"wits":[],"toad":0,"icount":1,"isith":"1","ncount":0,"nsith":"0"}\n' \
        > "$RUN_DIR/witness.json"
    printf '{"transferable":true,"wits":[],"toad":0,"icount":1,"isith":"1","ncount":1,"nsith":"1"}\n' \
        > "$RUN_DIR/plain.json"
    for role in "${ROLES[@]}"; do NAMES[$role]="${RUN_DIR##*/}-$role"; done
    : > "$RUN_DIR/witnesses.cesr"
    : > "$RUN_DIR/witness-kels.cesr"
    for role in witness1 witness2 witness3; do
        k "$role" init --version 2.0
        k "$role" incept -a "$role" --version 2.0 --file "$RUN_DIR/witness.json"
        AIDS[$role]=$(kli aid --name "${NAMES[$role]}" --base "$STORE_BASE" -a "$role")
        printf '%s\n' "${AIDS[$role]}" > "$RUN_DIR/$role.aid"
        k "$role" location add -a "$role" --version 2.0 --url "http://127.0.0.1:${PORTS[$role]}/"
        k "$role" ends add -a "$role" --version 2.0 --role controller --eid "${AIDS[$role]}"
        k "$role" kel export -a "$role" --ends --output "$RUN_DIR/$role.cesr"
        k "$role" kel export -a "$role" --output "$RUN_DIR/$role-kel.cesr"
        cat "$RUN_DIR/$role.cesr" >> "$RUN_DIR/witnesses.cesr"
        cat "$RUN_DIR/$role-kel.cesr" >> "$RUN_DIR/witness-kels.cesr"
        spawn "$role" kli witness start --name "${NAMES[$role]}" --base "$STORE_BASE" \
            -a "$role" --no-prompt -H "${PORTS[$role]}" -T "${PORTS[${role}tcp]}"
        python "$JSON" ready "http://127.0.0.1:${PORTS[$role]}/oobi" 15
    done
    for role in "${ROLES[@]:3}"; do
        k "$role" init --version 2.0
        k "$role" kel import --version 2.0 --file "$RUN_DIR/witnesses.cesr"
        if [[ $role == issuer || $role == holder || $role == presenter ]]; then
            k "$role" incept -a "$role" --version 2.0 --file "$RUN_DIR/plain.json" \
                --receipt-endpoint --wits "${AIDS[witness1]}" --wits "${AIDS[witness2]}" \
                --wits "${AIDS[witness3]}" --toad 2
        else
            k "$role" incept -a "$role" --version 2.0 --file "$RUN_DIR/plain.json"
        fi
        AIDS[$role]=$(kli aid --name "${NAMES[$role]}" --base "$STORE_BASE" -a "$role")
        printf '%s\n' "${AIDS[$role]}" > "$RUN_DIR/$role.aid"
        k "$role" kel export -a "$role" --output "$RUN_DIR/$role-initial.cesr"
    done
    cat "$RUN_DIR/witnesses.cesr" "$RUN_DIR"/*-initial.cesr > "$RUN_DIR/bootstrap-initial.cesr"
    for role in issuer holder dolly presenter; do
        if [[ -v NAMES[$role] ]]; then
            k "$role" kel import --file "$RUN_DIR/bootstrap-initial.cesr"
        fi
    done
    ISSUER_ENDPOINT="http://127.0.0.1:${PORTS[issuer]}/ingest"
    HOLDER_ENDPOINT="http://127.0.0.1:${PORTS[holder]}/ingest"
    OBSERVER_URL="http://127.0.0.1:${PORTS[observer]}/"
    DOLLY_ENDPOINT="http://127.0.0.1:${PORTS[dolly]}/ingest"
    if [[ $TRANSPORT == tcp ]]; then DOLLY_ENDPOINT="tcp://127.0.0.1:${PORTS[dollytcp]}"; fi
    kli version > "$RUN_DIR/kli-version.txt"
    python -c 'import importlib.metadata; print(importlib.metadata.version("dolly"))' > "$RUN_DIR/dolly-version.txt"
}

# Start owned services using prepared identities/evidence and publish/query the
# actual registry. Requires REGISTRY/SCHEMA/public.cesr; no credentials are granted.
services() {
    local role
    : > "$RUN_DIR/bootstrap.cesr"
    # Service --kel accepts KEL/TEL evidence, while endpoint reply bootstrap was
    # independently imported above through the public KEL import command.
    cat "$RUN_DIR/witness-kels.cesr" >> "$RUN_DIR/bootstrap.cesr"
    for role in "${ROLES[@]:3}"; do
        k "$role" kel export -a "$role" --output "$RUN_DIR/$role-current.cesr"
        cat "$RUN_DIR/$role-current.cesr" >> "$RUN_DIR/bootstrap.cesr"
    done
    spawn registrar kli registrar start --name "${NAMES[registrar]}" --base "$STORE_BASE" \
        --publisher "${AIDS[issuer]}" --observer "${AIDS[observer]}" --kel "$RUN_DIR/bootstrap.cesr" \
        --port "${PORTS[registrar]}" --no-prompt
    python "$JSON" ready "http://127.0.0.1:${PORTS[registrar]}/health" 15
    k issuer vc registry publish -a issuer --endpoint "http://127.0.0.1:${PORTS[registrar]}/ingest" --file "$RUN_DIR/public.cesr"
    local readers=(--reader "${AIDS[holder]}" --reader "${AIDS[dolly]}")
    if [[ -v AIDS[presenter] ]]; then readers+=(--reader "${AIDS[presenter]}"); fi
    spawn observer kli observer start --name "${NAMES[observer]}" --base "$STORE_BASE" \
        -a observer --registrar "http://127.0.0.1:${PORTS[registrar]}/" "${readers[@]}" \
        --kel "$RUN_DIR/bootstrap.cesr" --interval 0.2 --maximum-age 3 --timeout 1 \
        --port "${PORTS[observer]}" --no-prompt
    python "$JSON" ready "${OBSERVER_URL}health" 15
    poll k holder vc registry query -a holder --endpoint "$OBSERVER_URL" --registry "$REGISTRY" --output "$RUN_DIR/holder-public.cesr"
    python "$JSON" config "$RUN_DIR/dolly-policy.json" "${AIDS[issuer]}" "$SCHEMA" "$OBSERVER_URL" "http://127.0.0.1:${PORTS[hook]}/hook"
    spawn hook python -u "$JSON" hook "${PORTS[hook]}" "$RUN_DIR/hooks.jsonl"
    python "$JSON" ready "http://127.0.0.1:${PORTS[hook]}/" 15
    spawn dolly dolly server start --direct --name "${NAMES[dolly]}" --base "$STORE_BASE" -a dolly \
        --config "$RUN_DIR/dolly-policy.json" --kel "$RUN_DIR/bootstrap.cesr" \
        --http "${PORTS[dolly]}" --tcp "${PORTS[dollytcp]}" --no-prompt
    python "$JSON" ready "http://127.0.0.1:${PORTS[dolly]}/health" 15
    for role in issuer holder presenter; do
        if [[ -v NAMES[$role] ]]; then
            spawn "$role-intake" kli ipex receive --v2 --name "${NAMES[$role]}" --base "$STORE_BASE" \
                -a "$role" --port "${PORTS[$role]}"
            # Receiver POST readiness is checked by the bounded TCP connect.
            python "$JSON" tcp-ready 127.0.0.1 "${PORTS[$role]}" 15
        fi
    done
}

# Record public identifiers, wheel/source hashes and assertions after the story;
# missing artifacts or malformed JSON fail instead of writing a passing result.
result() {
    printf '%s\n' "$CREDENTIAL" > "$RUN_DIR/credential.ref"
    printf '%s\n' "$REGISTRY" > "$RUN_DIR/registry.ref"
    printf '%s\n' "$SCHEMA" > "$RUN_DIR/schema.ref"
    python "$JSON" manifest "$RUN_DIR" "$SCENARIO" "$TRANSPORT" "${ROLES[@]}"
    cat "$RUN_DIR/result.json"
}
