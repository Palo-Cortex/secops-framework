"""
The shipped soc-framework-nist-ir-ai NIST IR contract, run through the real
SOCNormalizeFromList functions: an email issue's threat-URL domain must reach
SOCFramework.Artifacts.Network.DNS.Query, which soc-block-domain blocks.

On TAP issues the rule writes the threat URL's host to dns_query_name (issue
field dnsqueryname) - a string on some issues, a list on others (deathstar,
27 Oct 2026). The sender's domain must never land there.

Run: python3 -m pytest tools/test_normalize_map_email_domain.py -q
"""
import builtins
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAP = ROOT / "Packs/soc-framework-nist-ir-ai/Lists/SOCFrameworkNormalizeMap_NIST_IR/SOCFrameworkNormalizeMap_NIST_IR_data.json"


class _Demisto:
    def debug(self, *a, **kw):
        pass


builtins.demisto = _Demisto()
builtins.return_error = lambda m: (_ for _ in ()).throw(RuntimeError(m))
builtins.return_results = lambda x: None
builtins.CommandResults = lambda **kw: kw
sys.path.insert(0, str(ROOT / "Packs/soc-optimization-unified/Scripts/SOCNormalizeFromList"))
from SOCNormalizeFromList import apply_mappings, apply_mirrors, apply_stamps  # noqa: E402

TARGET = "Artifacts.Network.DNS.Query"


def normalize(category, fields):
    section = json.loads(MAP.read_text())["categories"][category]
    writes, skipped = {}, defaultdict(list)
    apply_mappings(section, fields, writes, skipped)
    apply_stamps(section, None, writes, skipped)
    apply_mirrors(section, writes, skipped)
    return writes


TAP = {"socfwemailthreaturl": "http://brieftragerin.skt.local/update/NTFVersion.exe",
       "emailsender": "noreply@sktlocal.it", "username": "Gunter@SKT.LOCAL"}


def test_email_threat_domain_reaches_dns_query_as_list():
    w = normalize("email", dict(TAP, dnsqueryname=["brieftragerin.skt.local"]))
    assert w[TARGET] == ["brieftragerin.skt.local"]


def test_email_threat_domain_reaches_dns_query_as_string():
    w = normalize("email", dict(TAP, dnsqueryname="brieftragerin.skt.local"))
    assert w[TARGET] == "brieftragerin.skt.local"


def test_email_several_threat_domains_all_reach_dns_query():
    w = normalize("email", dict(TAP, dnsqueryname=["a.example", "b.example"]))
    assert w[TARGET] == ["a.example", "b.example"]


def test_email_without_a_threat_domain_writes_nothing():
    w = normalize("email", dict(TAP))
    assert TARGET not in w


def test_sender_domain_never_reaches_dns_query():
    w = normalize("email", dict(TAP, dnsqueryname="brieftragerin.skt.local", domain="sktlocal.it"))
    assert "sktlocal.it" not in json.dumps(w.get(TARGET))


def test_network_band_unchanged():
    w = normalize("network", {"dnsqueryname": ["evil.example"]})
    assert w[TARGET] == ["evil.example"]


def test_endpoint_band_does_not_feed_block_domain():
    # Every domain a host looked up is not a block list; endpoint stays analyst-chosen.
    w = normalize("endpoint", {"dnsqueryname": ["login.microsoftonline.com", "evil.example"]})
    assert TARGET not in w
