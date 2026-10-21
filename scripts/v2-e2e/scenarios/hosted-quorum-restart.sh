#!/usr/bin/env bash
# Additional infrastructure gate: any two hosted witnesses, below-quorum refusal,
# and recovery through actual stopped/restarted provider binaries and stores.
set -Eeuo pipefail
source "$(dirname -- "$0")/common.sh"
export SCENARIO_WALLET_PROFILE=kli SCENARIO_WITNESS_PROFILE=hk
prepare hosted-quorum-restart

# Stop the FIRST configured destination: collection must not be order-dependent.
stop witness1
k issuer vc registry incept --v2 -a issuer -r two-alive --timeout 8
assert_json "$RUN_DIR/latest-issuer.jsonl" accepted true
FIRST_REGISTRY=$(value "$RUN_DIR/latest-issuer.jsonl" registry)

# One reachable witness cannot authorize another registry anchor.
stop witness2
if k issuer vc registry incept --v2 -a issuer -r below-quorum --timeout 3 > "$RUN_DIR/below-quorum.log" 2>&1; then
    printf 'One witness incorrectly authorized native registry inception\n' >&2
    exit 1
fi
grep -q 'pending authenticated anchor receipts' "$RUN_DIR/below-quorum.log"

# Restart the same provider store, then retry the retained inception/anchor.
spawn witness2 witopnet marshal start --base "$STORE_BASE-witness2" \
    --http "${PORTS[witness2]}" --bootport "${PORTS[witness2boot]}"
python "$JSON" tcp-ready 127.0.0.1 "${PORTS[witness2boot]}" 15
k issuer vc registry incept --v2 -a issuer -r below-quorum --timeout 8
assert_json "$RUN_DIR/latest-issuer.jsonl" accepted true
RECOVERED_REGISTRY=$(value "$RUN_DIR/latest-issuer.jsonl" registry)
[[ $FIRST_REGISTRY != "$RECOVERED_REGISTRY" ]]

# A second restart retains the original hosted witness identity and OOBI.
spawn witness1 witopnet marshal start --base "$STORE_BASE-witness1" \
    --http "${PORTS[witness1]}" --bootport "${PORTS[witness1boot]}"
python "$JSON" ready "http://127.0.0.1:${PORTS[witness1]}/oobi/${AIDS[witness1]}/controller" 15
printf '{"result":"passed","witnesses":3,"quorum":2,"firstDestinationOffline":true,"belowQuorumRefused":true,"providerRestart":true}\n' > "$RUN_DIR/result.json"
cat "$RUN_DIR/result.json"
