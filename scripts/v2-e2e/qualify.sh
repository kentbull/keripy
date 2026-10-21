#!/bin/sh
# Qualify protocol core, the standalone Dolly application, and released peers.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${DOLLY_SOURCE:?Set DOLLY_SOURCE to the standalone Dolly checkout}"
keri_source=$(CDPATH= cd -- "$here/../.." && pwd)
"$here/check.sh" \
    tests/acdc \
    tests/core/test_native_registry_framing.py \
    tests/core/test_threshold_distinct_indices.py \
    tests/core/test_coring.py tests/core/test_serdering.py tests/core/test_parsing.py \
    tests/core/test_eventing_v1.py tests/core/test_eventing_v2.py tests/core/test_eventing_messagize.py \
    tests/db/test_basing.py tests/peer/test_exchanging.py \
    tests/app/test_native_wallet.py tests/app/test_native_services.py \
    tests/app/test_native_cli.py tests/app/test_native_ipex_cli.py tests/app/test_native_groups.py \
    tests/app/test_registry_custody.py tests/app/test_public_evidence_cli.py \
    tests/app/test_native_ipex_transport.py tests/app/test_legacy_negotiation_cli.py \
    tests/app/test_tcp_stream_delivery.py tests/app/test_signing.py \
    tests/app/test_signing_stream_genus.py tests/app/test_legacy_evidence_cli.py \
    tests/app/test_witness_protocol_cli.py tests/app/test_schema_import_cli.py \
    tests/app/test_legacy_author_cli.py \
    tests/app/test_native_group_pruning.py tests/app/test_native_service_pruning.py \
    tests/core/test_kraming.py \
    tests/app/test_forwarding.py tests/app/test_indirecting.py \
    tests/app/test_grouping.py tests/app/test_group_persistence.py \
    tests/vdr/test_eventing.py tests/vdr/test_credentialing.py \
    tests/cli/test_kli_commands.py tests/cli/commands/vc/test_vc_schema_validation.py
KERI_SOURCE="$keri_source" "$DOLLY_SOURCE/scripts/check.sh"
"$DOLLY_SOURCE/scripts/legacy-peers/check.sh"
KERI_SOURCE="$keri_source" "$DOLLY_SOURCE/scripts/operator/run-legacy-v1.sh"
exec "$here/scenarios/run-all.sh"
