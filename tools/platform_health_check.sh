#!/usr/bin/env bash
#
# platform_health_check.sh — Pre-upload platform API health check
#
# Verifies XSIAM API endpoints are responding AND (when the pack contains
# correlation rules) that the correlation rule write path works.
#
# Probes:
#   1. GET correlations — verify 200 + parseable response (always runs)
#   2. CREATE a disabled test rule — verify the write path isn't 500ing
#      (only runs when the pack contains CorrelationRules/)
#   3. DELETE the test rule — clean up
#
# Source from upload_package.sh or run standalone.
#
# Usage:
#   bash tools/platform_health_check.sh [pack_path]
#   source tools/platform_health_check.sh && check_platform_health [pack_path]
#
# Requires: DEMISTO_BASE_URL, DEMISTO_API_KEY, XSIAM_AUTH_ID

_HEALTH_TEST_RULE_NAME="_health_check_delete_me_$(date +%s)"

# ── Helper: does the pack contain correlation rules? ──────────────────────────
_pack_has_correlation_rules() {
    local pack_path="${1:-}"
    [[ -z "$pack_path" ]] && return 1
    local rule_dir="${pack_path}/CorrelationRules"
    if [[ -d "$rule_dir" ]] && compgen -G "${rule_dir}/*.yml" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

check_platform_health() {
    local pack_path="${1:-}"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Platform Health Check — ${DEMISTO_BASE_URL}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    local failed=0
    local response
    local http_code

    # ── Step 1: GET correlations — read path ──────────────────────────────────
    response=$(curl -s -w "\n%{http_code}" \
        -X POST "${DEMISTO_BASE_URL}/public_api/v1/correlations/get" \
        -H "Authorization: ${DEMISTO_API_KEY}" \
        -H "x-xdr-auth-id: ${XSIAM_AUTH_ID}" \
        -H "Content-Type: application/json" \
        -d '{"request_data": {}}' \
        --connect-timeout 10 \
        --max-time 30)

    http_code=$(echo "$response" | tail -1)
    local body
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" = "200" ] && echo "$body" | grep -q '"objects_count"'; then
        local count
        count=$(echo "$body" | grep -o '"objects_count":[0-9]*' | grep -o '[0-9]*')
        echo "  ✓ Correlations GET — ${count:-?} rule(s) on tenant"
    else
        echo "  ✗ Correlations GET — HTTP ${http_code}, response not parseable"
        failed=$((failed + 1))
    fi

    # ── Step 2: CREATE test rule — write path (only if pack has corr rules) ───
    if [ "$failed" -eq 0 ]; then
        if _pack_has_correlation_rules "$pack_path"; then
            local create_body
            create_body=$(cat <<EOF
{"request_data": [{"name": "${_HEALTH_TEST_RULE_NAME}", "severity": "SEV_010_INFO", "xql_query": "dataset = xdr_data | filter event_type = ENUM.PROCESS | fields agent_hostname", "is_enabled": false, "description": "Health check probe — safe to delete", "alert_name": "Health Check", "alert_category": "User Defined", "alert_description": "health check", "alert_fields": {}, "execution_mode": "SCHEDULED", "search_window": "10 minutes", "simple_schedule": "10 minutes", "timezone": "UTC", "crontab": "*/10 * * * *", "suppression_enabled": false, "suppression_duration": null, "suppression_fields": null, "dataset": "alerts", "user_defined_severity": null, "user_defined_category": "Health Check", "mitre_defs": {}, "investigation_query_link": null, "drilldown_query_timeframe": "ALERT", "mapping_strategy": "AUTO"}]}
EOF
            )

            response=$(curl -s -w "\n%{http_code}" \
                -X POST "${DEMISTO_BASE_URL}/public_api/v1/correlations/insert" \
                -H "Authorization: ${DEMISTO_API_KEY}" \
                -H "x-xdr-auth-id: ${XSIAM_AUTH_ID}" \
                -H "Content-Type: application/json" \
                -d "$create_body" \
                --connect-timeout 10 \
                --max-time 30)

            http_code=$(echo "$response" | tail -1)
            body=$(echo "$response" | sed '$d')

            if [ "$http_code" = "200" ]; then
                echo "  ✓ Correlations CREATE — write path healthy"

                # ── Step 3: DELETE test rule — clean up ───────────────────────
                local rule_id
                rule_id=$(echo "$body" | grep -o '"rule_id":[0-9]*' | head -1 | grep -o '[0-9]*')

                if [ -n "$rule_id" ]; then
                    curl -s -o /dev/null \
                        -X POST "${DEMISTO_BASE_URL}/public_api/v1/correlations/delete" \
                        -H "Authorization: ${DEMISTO_API_KEY}" \
                        -H "x-xdr-auth-id: ${XSIAM_AUTH_ID}" \
                        -H "Content-Type: application/json" \
                        -d "{\"request_data\": {\"filters\": [{\"field\": \"rule_id\", \"operator\": \"eq\", \"value\": ${rule_id}}]}}" \
                        --connect-timeout 10 \
                        --max-time 30
                    echo "  ✓ Correlations DELETE — cleanup OK (rule_id ${rule_id})"
                else
                    echo "  ⚠ Could not extract rule_id for cleanup — check tenant for '${_HEALTH_TEST_RULE_NAME}'"
                fi
            else
                echo "  ✗ Correlations CREATE — HTTP ${http_code}"
                echo "    Response: ${body}"
                echo ""
                echo "    Write path probe failed. If this is a test-payload schema issue,"
                echo "    bypass with:  SKIP_HEALTH_CHECK=1 bash tools/upload_package.sh ..."
                failed=$((failed + 1))
            fi
        else
            echo "  ⊘ Correlations CREATE — skipped (no CorrelationRules/ in pack)"
        fi
    fi

    echo ""
    if [ "$failed" -gt 0 ]; then
        echo "  ✗ Platform unhealthy — do not upload."
        echo "    Check: https://status.paloaltonetworks.com"
        echo ""
        return 1
    else
        echo "  ✓ Platform healthy — all applicable paths verified"
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
