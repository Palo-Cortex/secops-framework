#!/usr/bin/env bash
# =============================================================================
# deploy_and_test.sh — SOC Framework full deploy + test pipeline
#
# Runs every step in order, captures output, writes a timestamped results file.
#
# Usage:
#   bash tools/deploy_and_test.sh                          # full pipeline
#   bash tools/deploy_and_test.sh --skip-upload            # validate + test only
#   bash tools/deploy_and_test.sh --skip-smoke             # validate + upload only
#   bash tools/deploy_and_test.sh --scenario SC-01         # single smoke scenario
#   bash tools/deploy_and_test.sh --dry-run                # print steps, do nothing
#
# Output: results/deploy_YYYYMMDD_HHMMSS.txt
# =============================================================================

set -euo pipefail

# ── Repo root ─────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ── Defaults ──────────────────────────────────────────────────────────────────
SKIP_UPLOAD=false
SKIP_SMOKE=false
DRY_RUN=false
SMOKE_SCENARIO=""
SMOKE_TIMEOUT=300
PACKS=(
    "Packs/soc-optimization-unified"
    "Packs/soc-framework-nist-ir"
)

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-upload)   SKIP_UPLOAD=true  ;;
        --skip-smoke)    SKIP_SMOKE=true   ;;
        --dry-run)       DRY_RUN=true      ;;
        --scenario)      SMOKE_SCENARIO="$2"; shift ;;
        --timeout)       SMOKE_TIMEOUT="$2"; shift ;;
        *) echo "Unknown argument: $1"; exit 2 ;;
    esac
    shift
done

# ── Output file ───────────────────────────────────────────────────────────────
mkdir -p "$REPO_ROOT/results"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUTFILE="$REPO_ROOT/results/deploy_${TIMESTAMP}.txt"
LATEST="$REPO_ROOT/results/deploy_latest.txt"

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN='\033[92m'
RED='\033[91m'
YELLOW='\033[93m'
CYAN='\033[96m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
STEP=0
PASS=0
FAIL=0
FAIL_STEPS=()

log() {
    echo -e "$*"
    echo -e "$*" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUTFILE"
}

separator() {
    log "${DIM}──────────────────────────────────────────────────────${RESET}"
}

run_step() {
    local label="$1"
    shift
    STEP=$((STEP + 1))

    log ""
    separator
    log "${BOLD}Step $STEP — $label${RESET}"
    log "${DIM}$ $*${RESET}"
    log ""

    if [[ "$DRY_RUN" == "true" ]]; then
        log "${YELLOW}[DRY RUN — skipped]${RESET}"
        return 0
    fi

    local tmpout
    tmpout="$(mktemp)"

    # Run command, tee output to both terminal and file
    if "$@" 2>&1 | tee "$tmpout"; then
        local exit_code=0
    else
        local exit_code=$?
    fi

    # Append captured output to results file (strip colour for file)
    cat "$tmpout" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUTFILE"
    rm -f "$tmpout"

    if [[ $exit_code -eq 0 ]]; then
        PASS=$((PASS + 1))
        log ""
        log "${GREEN}✅ Step $STEP PASSED — $label${RESET}"
    else
        FAIL=$((FAIL + 1))
        FAIL_STEPS+=("Step $STEP: $label")
        log ""
        log "${RED}❌ Step $STEP FAILED — $label (exit $exit_code)${RESET}"
        # Don't exit — continue remaining steps so we get full picture
    fi

    return $exit_code
}

# ── Header ────────────────────────────────────────────────────────────────────
log ""
log "${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
log "${BOLD}║   SOC Framework — Deploy + Test Pipeline             ║${RESET}"
log "${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
log "  Date:       $(date)"
log "  Repo root:  $REPO_ROOT"
log "  Output:     $OUTFILE"
log "  Skip upload: $SKIP_UPLOAD  |  Skip smoke: $SKIP_SMOKE  |  Dry run: $DRY_RUN"
if [[ -n "$SMOKE_SCENARIO" ]]; then
    log "  Scenario:   $SMOKE_SCENARIO"
fi

# ── Step 1: Static contract validation ───────────────────────────────────────
for pack in "${PACKS[@]}"; do
    pack_name="$(basename "$pack")"
    run_step "socfw_validate: $pack_name" \
        python3 tools/socfw_validate.py --pack "$pack" || true
done

# ── Step 2: SDK validation ────────────────────────────────────────────────────
for pack in "${PACKS[@]}"; do
    pack_name="$(basename "$pack")"
    run_step "sdk_classify: $pack_name" \
        python3 tools/sdk_classify.py --pack "$pack" || true
done

# ── Step 3: Unit tests ────────────────────────────────────────────────────────
run_step "Unit tests: SOCCommandWrapper" \
    pytest Packs/soc-optimization-unified/Scripts/SOCCommandWrapper/SOCCommandWrapper_test.py \
    -v --tb=short 2>/dev/null || \
    python3 -m pytest Packs/soc-optimization-unified/Scripts/SOCCommandWrapper/SOCCommandWrapper_test.py \
    -v --tb=short || true

if [[ -f "tools/SOCCommandWrapper_test_soc_detonate_file.py" ]]; then
    run_step "Unit tests: soc-detonate-file + FeatureFlags" \
        python3 -m pytest tools/SOCCommandWrapper_test_soc_detonate_file.py \
        -v --tb=short || true
fi

# ── Step 4: Pack prep ─────────────────────────────────────────────────────────
if [[ "$SKIP_UPLOAD" == "false" ]]; then
    for pack in "${PACKS[@]}"; do
        pack_name="$(basename "$pack")"
        run_step "pack_prep: $pack_name" \
            python3 tools/pack_prep.py "$pack" || true
    done
fi

# ── Step 5: Fix errors ────────────────────────────────────────────────────────
# fix_errors.py takes the SDK output FILE produced by pack_prep, not a pack dir.
# pack_prep writes SDK errors to output/sdk_errors.txt before each upload.
if [[ "$SKIP_UPLOAD" == "false" ]]; then
    if [[ -f "tools/fix_errors.py" && -f "output/sdk_errors.txt" ]]; then
        run_step "fix_errors: all packs" \
            python3 tools/fix_errors.py output/sdk_errors.txt || true
    fi
fi

# ── Step 6: Upload ────────────────────────────────────────────────────────────
if [[ "$SKIP_UPLOAD" == "false" ]]; then
    for pack in "${PACKS[@]}"; do
        pack_name="$(basename "$pack")"
        run_step "upload: $pack_name" \
            bash tools/upload_package.sh "$pack" || true
    done

    # Brief pause — XSIAM needs time to index uploaded content
    if [[ "$DRY_RUN" == "false" ]]; then
        log ""
        log "${DIM}  Waiting 60s for content registration...${RESET}"
        sleep 60
    fi
fi

# ── Step 7: Smoke tests ───────────────────────────────────────────────────────
if [[ "$SKIP_SMOKE" == "false" ]]; then
    smoke_args=(python3 tools/socfw_smoke.py --wait "$SMOKE_TIMEOUT")
    if [[ -n "$SMOKE_SCENARIO" ]]; then
        smoke_args+=(--scenario "$SMOKE_SCENARIO")
    fi
    run_step "smoke tests" "${smoke_args[@]}" || true
fi

# ── Summary ───────────────────────────────────────────────────────────────────
log ""
separator
log ""
log "${BOLD}Pipeline Summary${RESET}"
log "  Steps run:  $STEP"
log "  Passed:     ${GREEN}$PASS${RESET}"
log "  Failed:     ${RED}$FAIL${RESET}"
log ""

if [[ ${#FAIL_STEPS[@]} -gt 0 ]]; then
    log "${RED}Failed steps:${RESET}"
    for s in "${FAIL_STEPS[@]}"; do
        log "  ${RED}❌  $s${RESET}"
    done
    log ""
fi

log "  Results file: $OUTFILE"

# ── Copy to latest ────────────────────────────────────────────────────────────
cp "$OUTFILE" "$LATEST"
log "  Latest link:  $LATEST"

if [[ "$DRY_RUN" == "true" ]]; then
    log ""
    log "${YELLOW}DRY RUN — no commands were executed${RESET}"
fi

log ""

if [[ $FAIL -eq 0 ]]; then
    log "${GREEN}${BOLD}✅ All steps passed${RESET}"
    exit 0
else
    log "${RED}${BOLD}❌ $FAIL step(s) failed — review $OUTFILE${RESET}"
    exit 1
fi
