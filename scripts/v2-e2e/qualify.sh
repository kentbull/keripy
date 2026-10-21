#!/bin/sh
# Qualify the declared Python profile and both separately installed legacy peers.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$here/check.sh" \
    tests/acdc \
    tests/core/test_native_registry_framing.py \
    tests/core/test_threshold_distinct_indices.py \
    tests/core/test_coring.py tests/core/test_serdering.py tests/core/test_parsing.py \
    tests/core/test_eventing_v1.py tests/core/test_eventing_v2.py tests/core/test_eventing_messagize.py \
    tests/db/test_basing.py tests/peer/test_exchanging.py \
    tests/app/test_native_wallet.py tests/app/test_native_services.py \
    tests/app/test_native_cli.py tests/app/test_native_ipex_cli.py tests/app/test_native_groups.py \
    tests/app/test_dolly.py tests/app/test_native_e2e.py \
    tests/app/test_forwarding.py tests/app/test_indirecting.py \
    tests/app/test_grouping.py tests/app/test_group_persistence.py \
    tests/vdr/test_eventing.py tests/vdr/test_credentialing.py \
    tests/cli/test_kli_commands.py tests/cli/commands/vc/test_vc_schema_validation.py
exec "$here/legacy-peers/check.sh"
