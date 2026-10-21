#!/usr/bin/env bash
# Existing hosted-provider onboarding: incept, provision/register, then rotate.
# Three independent processes each host a distinct witness for each controller.
start_hosted_witnesses() {
    local role
    mkdir -p "$RUN_DIR/private"
    for role in witness1 witness2 witness3; do
        spawn "$role" witopnet marshal start --base "$STORE_BASE-$role" \
            --http "${PORTS[$role]}" --bootport "${PORTS[${role}boot]}"
        python "$JSON" tcp-ready 127.0.0.1 "${PORTS[${role}boot]}" 15
    done
}

# Bind the existing actor to hosted witnesses before any credential authoring.
# Registration secret URLs remain owner-only and outside public result artifacts.
configure_hosted_actor() {
    local role=$1 index wit
    python "$HERE/hosted.py" provision "$RUN_DIR" "$role" "${AIDS[$role]}"
    k "$role" kel import --version 2.0 --file "$RUN_DIR/$role-witnesses.cesr"
    local witnesses=()
    for index in 0 1 2; do
        wit=$(value "$RUN_DIR/$role-hosted.json" "$index.eid")
        witnesses+=(--witnesses "$wit")
        timeout 45 kli witness authenticate --name "${NAMES[$role]}" --base "$STORE_BASE" \
            -a "$role" -w "$wit" --url-only > "$RUN_DIR/private/$role-$wit.txt"
        if [[ $role == issuer ]]; then
            AIDS[witness$((index + 1))]=$wit
            printf '%s\n' "$wit" > "$RUN_DIR/witness$((index + 1)).aid"
        fi
    done
    k "$role" rotate -a "$role" --version 2.0 --receipt-endpoint --toad 2 "${witnesses[@]}"
}
