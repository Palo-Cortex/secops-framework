#!/usr/bin/env bash
#
# platform_health_check.sh — Pre-upload platform API health check
#
# Verifies XSIAM API endpoints are responding. If the pack being uploaded
# contains correlation rules, also tests the write path with a round-trip
# CREATE/DELETE. Packs without correlation rules skip the write test.
#
# On failure, writes a diagnostic report to output/platform_diagnostic.txt.
#
# Usage:
#   bash tools/platform_health_check.sh                              # standalone, GET only
#   bash tools/platform_health_check.sh Packs/soc-crowdstrike-falcon # standalone, auto-detects
#   source tools/platform_health_check.sh && check_platform_health "$PACK_PATH"
#
# Requires: DEMISTO_BASE_URL, DEMISTO_API_KEY, XSIAM_AUTH_ID

_HEALTH_TEST_RULE_NAME="_health_check_delete_me_$(date +%s)"
_DIAG_FILE="output/platform_diagnostic.txt"

_api_call() {
    local uri="$1"
    local body="$2"
    local tmpfile
    tmpfile=$(mktemp)

    local http_code
    http_code=$(curl -s -w "%{http_code}" -o "$tmpfile" \
        -X POST "${DEMISTO_BASE_URL}${uri}" \
        -H "Authorization: ${DEMISTO_API_KEY}" \
        -H "x-xdr-auth-id: ${XSIAM_AUTH_ID}" \
        -H "Content-Type: application/json" \
        -d "$body" \
        --connect-timeout 10 \
        --max-time 30 2>/dev/null)

    local response_body
    response_body=$(cat "$tmpfile" 2>/dev/null)
    rm -f "$tmpfile"

    echo "$http_code"
    echo "$response_body"
}

_pack_has_correlation_rules() {
    local pack_path="$1"
    [ -d "${pack_path}/CorrelationRules" ] && \
        [ -n "$(find "${pack_path}/CorrelationRules" -name '*.yml' -not -name '.*' 2>/dev/null)" ]
}

_diag_header() {
    mkdir -p output
    local sdk_version
    sdk_version=$(demisto-sdk --version 2>/dev/null | grep "demisto-sdk version" || echo "unknown")
    local python_version
    python_version=$(python3 --version 2>/dev/null || echo "unknown")

    cat > "$_DIAG_FILE" <<EOF
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Platform Diagnostic Report
  Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Tenant:  ${DEMISTO_BASE_URL}
  SDK:     ${sdk_version}
  Python:  ${python_version}
  OS:      $(uname -srm)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
}

_diag_append() {
    local label="$1"
    local uri="$2"
    local request_body="$3"
    local http_code="$4"
    local response_body="$5"

    cat >> "$_DIAG_FILE" <<EOF

── ${label} ──────────────────────────────────────────────────────
  Endpoint:  POST ${DEMISTO_BASE_URL}${uri}
  HTTP:      ${http_code}
  Request:   ${request_body}
  Response:  ${response_body}
EOF
}

check_platform_health() {
    local pack_path="${1:-}"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Platform Health Check — ${DEMISTO_BASE_URL}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    local failed=0
    local diag_needed=0

    # ── Step 1: GET correlations — read path ──────────────────────────────────
    local get_uri="/public_api/v1/correlations/get"
    local get_body='{"request_data": {}}'
    local get_raw
    get_raw=$(_api_call "$get_uri" "$get_body")

    local get_code
    get_code=$(echo "$get_raw" | head -1)
    local get_response
    get_response=$(echo "$get_raw" | tail -n +2)

    if [ "$get_code" = "200" ] && echo "$get_response" | grep -q '"objects_count"'; then
        local count
        count=$(echo "$get_response" | grep -o '"objects_count":[0-9]*' | grep -o '[0-9]*')
        echo "  ✓ Correlations GET — ${count:-?} rule(s) on tenant"
    else
        echo "  ✗ Correlations GET — HTTP ${get_code}"
        failed=$((failed + 1))
        diag_needed=1
    fi

    # ── Step 2: CREATE/DELETE test rule — write path ──────────────────────────
    # Only runs when the pack contains correlation rules. Packs with only
    # playbooks, scripts, or lists skip this — the write path doesn't apply.
    local test_write=0
    local create_code=""
    local create_response=""
    local create_uri="/public_api/v1/correlations/create_or_update"
    local create_body=""

    if [ -n "$pack_path" ] && _pack_has_correlation_rules "$pack_path"; then
        test_write=1
    elif [ -z "$pack_path" ]; then
        test_write=1
    fi

    if [ "$test_write" -eq 1 ] && [ "$failed" -eq 0 ]; then
        create_body="{\"request_data\": [{\"name\": \"${_HEALTH_TEST_RULE_NAME}\", \"severity\": \"SEV_010_INFO\", \"xql_query\": \"dataset = xdr_data | filter event_type = ENUM.PROCESS | fields agent_hostname\", \"is_enabled\": \"false\", \"description\": \"Health check probe — safe to delete\", \"alert_name\": \"Health Check\", \"alert_category\": \"OTHER\", \"alert_description\": \"health check\", \"alert_fields\": {}, \"execution_mode\": \"SCHEDULED\", \"search_window\": \"10 minutes\", \"simple_schedule\": \"10 minutes\", \"timezone\": \"UTC\", \"crontab\": \"*/10 * * * *\", \"suppression_enabled\": false, \"suppression_duration\": null, \"suppression_fields\": null, \"dataset\": \"alerts\", \"user_defined_severity\": null, \"user_defined_category\": null, \"mitre_defs\": {}, \"investigation_query_link\": null, \"drilldown_query_timeframe\": \"ALERT\", \"mapping_strategy\": \"AUTO\"}]}"

        local create_raw
        create_raw=$(_api_call "$create_uri" "$create_body")

        create_code=$(echo "$create_raw" | head -1)
        create_response=$(echo "$create_raw" | tail -n +2)

        if [ "$create_code" = "200" ]; then
            echo "  ✓ Correlations CREATE — write path healthy"

            # ── Step 3: DELETE test rule — clean up ───────────────────────────
            local rule_id
            rule_id=$(echo "$create_response" | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*')

            if [ -n "$rule_id" ]; then
                local delete_raw
                delete_raw=$(_api_call "/public_api/v1/correlations/delete" \
                    "{\"request_data\": {\"correlation_ids\": [${rule_id}]}}")
                local delete_code
                delete_code=$(echo "$delete_raw" | head -1)

                if [ "$delete_code" = "200" ]; then
                    echo "  ✓ Correlations DELETE — cleanup OK (rule_id ${rule_id})"
                else
                    echo "  ⚠ Correlations DELETE — HTTP ${delete_code} (rule_id ${rule_id} may need manual cleanup)"
                fi
            else
                echo "  ⚠ Could not extract rule_id for cleanup — check tenant for '${_HEALTH_TEST_RULE_NAME}'"
            fi
        else
            echo "  ✗ Correlations CREATE — HTTP ${create_code}"
            echo "    Write path is broken. Correlation rule uploads will fail."
            echo "    This is a platform issue, not a pack issue."
            failed=$((failed + 1))
            diag_needed=1
        fi
    elif [ "$test_write" -eq 0 ]; then
        echo "  – Correlations CREATE — skipped (no correlation rules in pack)"
    fi

    # ── Write diagnostic report if anything failed ────────────────────────────
    if [ "$diag_needed" -eq 1 ]; then
        _diag_header
        _diag_append "Correlations GET (read path)" \
            "$get_uri" "$get_body" "$get_code" "$get_response"

        if [ -n "$create_code" ]; then
            _diag_append "Correlations CREATE (write path)" \
                "$create_uri" "$create_body" "$create_code" "$create_response"

            if echo "$create_response" | grep -q '"Bytes"'; then
                local decoded
                decoded=$(python3 -c "
import json, sys
try:
    resp = json.loads(sys.argv[1])
    body = resp.get('Body', '')
    if 'Bytes' in str(resp):
        for v in resp.values():
            if isinstance(v, dict) and 'Bytes' in v:
                print(''.join(chr(b) for b in v['Bytes']))
                break
    else:
        print(body)
except: print('(could not decode)')
" "$create_response" 2>/dev/null)

                if [ -n "$decoded" ]; then
                    echo "" >> "$_DIAG_FILE"
                    echo "── Decoded Error Body ─────────────────────────────────────────" >> "$_DIAG_FILE"
                    echo "  ${decoded}" >> "$_DIAG_FILE"
                fi
            fi
        fi

        echo "" >> "$_DIAG_FILE"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$_DIAG_FILE"
        echo "  Attach this file to your support ticket." >> "$_DIAG_FILE"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$_DIAG_FILE"

        echo ""
        echo "  Diagnostic report written to: ${_DIAG_FILE}"
    fi

    echo ""
    if [ "$failed" -gt 0 ]; then
        echo "  ✗ Platform unhealthy — do not upload."
        echo "    Check: https://status.paloaltonetworks.com"
        echo ""
        return 1
    else
        echo "  ✓ Platform healthy — all tested paths verified"
        echo ""
        return 0
    fi
}

# Run if executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [ -z "$DEMISTO_BASE_URL" ] || [ -z "$DEMISTO_API_KEY" ] || [ -z "$XSIAM_AUTH_ID" ]; then
        echo "  ✗ Missing env vars: DEMISTO_BASE_URL, DEMISTO_API_KEY, XSIAM_AUTH_ID"
        exit 1
    fi
    check_platform_health "$1"
    exit $?
fi
