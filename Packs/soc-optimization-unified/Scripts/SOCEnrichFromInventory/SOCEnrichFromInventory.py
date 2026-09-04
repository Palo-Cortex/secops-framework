"""
SOCEnrichFromInventory
======================
Foundation / Upon Trigger identity resolver. Resolves the alert's raw identity
(often a down-level SAM such as domain\\#### with no UPN or email) against
XSIAM's Unified Asset Inventory (dataset = asset_inventory) and writes the
resolved, cross-provider identity into the SOCFramework contract so every
downstream enricher, analysis phase, and containment action reads one canonical
identity.

WHY TWO HOPS
  Some sources (e.g. Okta XSIAM Identity Analytics) emit only the down-level SAM
  on the alert. The inventory stitches a person's accounts across providers using
  email as the primary correlation key, and each provider facet carries its own
  SAM. The alert's SAM therefore can't be matched against the unified key
  directly, so resolve in two hops:
    1. SAM  -> email : match one facet by sam_account_name, read its email.
    2. email -> all  : match every facet by that email, fold by provider.
  If an email is supplied directly (arg override, or a source that carries one),
  hop 1 is skipped.

CONTRACT (in-place, fail-open)
  On a hit, overwrites SOCFramework.Artifacts.Identity.User.* with resolved values
  and adds a per-provider Providers block. On any miss (no SAM facet, facet has no
  email, ambiguous SAM->multiple-email, or no email facets) it writes nothing and
  leaves the normalized rule identity untouched. asset_inventory is the source of
  truth; the normalized rule value is the default.

TELEMETRY
  Writes one identity_resolve row (status + query_cost) to
  xsiam_socfw_ir_execution_raw via the socfw_ir_execution_writer instance.
  Telemetry never fails the phase.
"""
import json
import re

from CommonServerPython import *  # noqa: F401,F403

IDENTITY_ROOT = "SOCFramework.Artifacts.Identity.User"


# --- helpers ----------------------------------------------------------------
def _g(row, key):
    v = row.get(key)
    return v if v not in (None, "", [], {}) else None


def _safe(value):
    # Values interpolate into an XQL filter string; drop characters that could
    # break or inject into the query.
    return re.sub(r'["\\|\n\r]', "", str(value)) if value else value


def _bare_sam(value):
    # domain\\#### / corp\\#### -> ####. Tolerates a plain #### or user@domain.
    if not value:
        return None
    v = str(value).strip()
    if "\\" in v:
        v = v.rsplit("\\", 1)[-1]
    return v or None


def _cost(c):
    if isinstance(c, (int, float)):
        return float(c)
    if isinstance(c, dict):  # query_cost is commonly a per-tenant map
        return sum(float(v) for v in c.values() if isinstance(v, (int, float)))
    return 0.0


# --- XQL --------------------------------------------------------------------
def _run_xql(query):
    """Run an asset_inventory query; return (rows, query_cost). Fail-open.

    xdr-xql-generic-query has no existing framework caller, and its result shape
    varies, so read defensively: prefer the structured XQL EntryContext block,
    fall back to Contents.
    """
    try:
        res = demisto.executeCommand("xdr-xql-generic-query", {"query": query})
    except Exception as e:  # noqa: BLE001
        demisto.debug(f"SOCEnrichFromInventory: xql call failed: {e}")
        return [], 0.0

    rows, cost = [], 0.0
    for entry in res or []:
        if is_error(entry):
            demisto.debug(f"SOCEnrichFromInventory: xql error: {get_error(entry)}")
            continue
        block = None
        for k, v in (entry.get("EntryContext") or {}).items():
            if "XQL" in k and isinstance(v, dict) and "results" in v:
                block = v
                break
        if block is None:
            c = entry.get("Contents")
            if isinstance(c, str):
                try:
                    c = json.loads(c)
                except Exception:  # noqa: BLE001
                    c = None
            if isinstance(c, dict):
                block = c
        if isinstance(block, dict):
            results = block.get("results")
            if isinstance(results, list):
                rows.extend(r for r in results if isinstance(r, dict))
            cost += _cost(block.get("query_cost"))
    return rows, cost


def _q_by_sam(sam):
    return (
        'config timeframe = 7d | dataset = asset_inventory '
        '| filter xdm.asset.type.class = "Identity" '
        f'| filter xdm.identity.sam_account_name = "{sam}" '
        '| fields xdm.asset.provider, xdm.identity.email, xdm.identity.employee_id '
        '| limit 25'
    )


def _q_by_email(email):
    return (
        'config timeframe = 7d | dataset = asset_inventory '
        '| filter xdm.asset.type.class = "Identity" '
        f'| filter xdm.identity.email = "{email}" '
        '| fields xdm.asset.provider, xdm.asset.realm, xdm.asset.id, xdm.asset.name, '
        'xdm.identity.sam_account_name, xdm.identity.upn, xdm.identity.email, '
        'xdm.identity.guid, xdm.identity.employee_id, xdm.identity.first_name, '
        'xdm.identity.last_name, xdm.identity.is_disabled '
        '| limit 50'
    )


# --- fold -------------------------------------------------------------------
def _fold(rows):
    """Fold N provider facets into a canonical identity + per-provider block."""
    providers = {}
    canon = {"UPN": None, "Email": None, "DisplayName": None, "Disabled": None}
    for row in rows:
        prov = _g(row, "xdm.asset.provider") or "UNKNOWN"
        facet = {
            "ID": _g(row, "xdm.identity.guid") or _g(row, "xdm.asset.id"),
            "StrongID": _g(row, "xdm.asset.strong_id"),
            "UPN": _g(row, "xdm.identity.upn"),
            "Email": _g(row, "xdm.identity.email"),
            "Realm": _g(row, "xdm.asset.realm"),
            "SAM": _g(row, "xdm.identity.sam_account_name"),
        }
        providers[prov] = {k: v for k, v in facet.items() if v is not None}
        canon["UPN"] = canon["UPN"] or facet["UPN"]
        canon["Email"] = canon["Email"] or facet["Email"]
        name = _g(row, "xdm.asset.name") or " ".join(
            x for x in [_g(row, "xdm.identity.first_name"), _g(row, "xdm.identity.last_name")] if x
        ) or None
        canon["DisplayName"] = canon["DisplayName"] or name
        disabled = _g(row, "xdm.identity.is_disabled")
        if canon["Disabled"] is None and disabled is not None:
            canon["Disabled"] = disabled
    return canon, providers


# --- telemetry --------------------------------------------------------------
def _emit(status, sam, email, provider_count, cost):
    issue = demisto.incident() or {}
    payload = {
        "event_type": "identity_resolve",
        "resolve_status": status,  # resolved | no_sam_match | ambiguous | no_email | no_input
        "sam": sam,
        "email": email,
        "provider_count": provider_count,
        "query_cost": cost,
        "incident_id": issue.get("id"),
        "alert_name": issue.get("name"),
        "lifecycle": demisto.dt(demisto.context(), "SOCFramework.Lifecycle") or "NIST_IR",
        "alert_category": demisto.dt(demisto.context(), "SOCFramework.Product.category"),
    }
    try:
        demisto.executeCommand(
            "socfw-post-to-dataset",
            {"using": "socfw_ir_execution_writer", "JSON": json.dumps(payload)},
        )
    except Exception as e:  # noqa: BLE001 - telemetry must never fail the phase
        demisto.debug(f"SOCEnrichFromInventory: telemetry row not written: {e}")


def main():
    args = demisto.args() or {}
    ctx = demisto.context()

    email = _safe(args.get("email")) or None
    sam = _safe(
        args.get("sam")
        or _bare_sam(
            demisto.dt(ctx, f"{IDENTITY_ROOT}.SAM")
            or demisto.dt(ctx, f"{IDENTITY_ROOT}.Name")
            or demisto.dt(ctx, f"{IDENTITY_ROOT}.UPN")
        )
    )

    # Idempotency: already resolved this identity in this context -> don't re-query.
    if (
        not args.get("email")
        and demisto.dt(ctx, f"{IDENTITY_ROOT}.ResolvedVia") == "asset_inventory"
        and demisto.dt(ctx, f"{IDENTITY_ROOT}.SAM") == sam
    ):
        return_results(CommandResults(readable_output="### SOCEnrichFromInventory\n- already resolved this identity; skipping."))
        return

    if not email and not sam:
        _emit("no_input", None, None, 0, 0.0)
        return_results(CommandResults(readable_output="### SOCEnrichFromInventory\n- no identity on the contract; nothing to resolve."))
        return

    total_cost = 0.0

    # HOP 1: SAM -> email (skipped when an email is supplied directly)
    if not email:
        rows, c = _run_xql(_q_by_sam(sam))
        total_cost += c
        emails = sorted({_g(r, "xdm.identity.email") for r in rows if _g(r, "xdm.identity.email")})
        if not emails:
            _emit("no_sam_match", sam, None, 0, total_cost)
            return_results(CommandResults(readable_output=f"### SOCEnrichFromInventory\n- SAM `{sam}` matched no inventory facet with an email \u2014 leaving normalized identity as-is."))
            return
        if len(emails) > 1:
            _emit("ambiguous", sam, ";".join(emails), 0, total_cost)
            return_results(CommandResults(readable_output=f"### SOCEnrichFromInventory\n- \u26a0 SAM `{sam}` resolved to {len(emails)} distinct emails \u2014 ambiguous, not resolving: {', '.join(emails)}"))
            return
        email = emails[0]

    # HOP 2: email -> all provider facets
    rows, c = _run_xql(_q_by_email(email))
    total_cost += c
    if not rows:
        _emit("no_email", sam, email, 0, total_cost)
        return_results(CommandResults(readable_output=f"### SOCEnrichFromInventory\n- email `{email}` matched no facets \u2014 leaving normalized identity as-is."))
        return

    canon, providers = _fold(rows)

    # In-place overwrite. Only reached on a hit, so fail-open is already satisfied.
    demisto.setContext(f"{IDENTITY_ROOT}.Email", canon["Email"] or email)
    if canon["UPN"]:
        demisto.setContext(f"{IDENTITY_ROOT}.UPN", canon["UPN"])
    if canon["DisplayName"]:
        demisto.setContext(f"{IDENTITY_ROOT}.DisplayName", canon["DisplayName"])
    if canon["Disabled"] is not None:
        demisto.setContext(f"{IDENTITY_ROOT}.Disabled", canon["Disabled"])
    if sam:
        demisto.setContext(f"{IDENTITY_ROOT}.SAM", sam)
    demisto.setContext(f"{IDENTITY_ROOT}.Providers", providers)
    demisto.setContext(f"{IDENTITY_ROOT}.ResolvedVia", "asset_inventory")
    # Coverage: which providers were present in the inventory at resolution time.
    # asset_inventory is freshness-gated (a facet vanishes after ~7 days without
    # reporting), so a provider NOT listed here is "unknown", not confirmed-absent —
    # containment must not conclude an account doesn't exist from its absence.
    demisto.setContext(f"{IDENTITY_ROOT}.ProvidersFound", sorted(providers.keys()))
    demisto.setContext(f"{IDENTITY_ROOT}.CoverageSource", "asset_inventory (freshness-gated; absence != confirmed-absent)")

    _emit("resolved", sam, canon["Email"] or email, len(providers), total_cost)

    prov_list = ", ".join(sorted(providers))
    upn_note = f", UPN `{canon['UPN']}`" if canon["UPN"] else ""
    return_results(CommandResults(readable_output=(
        f"### SOCEnrichFromInventory\n"
        f"- resolved **{canon['DisplayName'] or email}** across {len(providers)} provider(s): {prov_list}\n"
        f"- email `{email}`{upn_note}\n"
        f"- query cost {round(total_cost, 4)}"
    )))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
