"""
The shipped soc-framework-nist-ir-ai NIST IR contract, run through the real
SOCNormalizeFromList functions: what an endpoint issue's host connected to and
looked up reaches SOCFramework.Endpoint.remote_ips and .dns_queries - where
emergency response reads its C2 destinations - and never the block keys
(Artifacts.Network.Destination.IP, Artifacts.Network.DNS.Query), so the analyst
and AI block actions do not fan out to every address a host touched.

The CrowdStrike rule writes network_accesses remote_address to remoteip and
dns_requests domain_name to dnsqueryname (deathstar, 29 Oct 2026).

Run: python3 -m pytest tools/test_normalize_map_endpoint_destinations.py -q
"""
from test_normalize_map_email_domain import normalize

C2 = {"remoteip": ["176.59.15.33"], "dnsqueryname": ["anto-int.com"], "hostname": "hobgoblin"}


def test_remote_addresses_reach_endpoint_remote_ips():
    assert normalize("endpoint", C2)["Endpoint.remote_ips"] == ["176.59.15.33"]


def test_several_remote_addresses_all_arrive():
    w = normalize("endpoint", dict(C2, remoteip=["176.59.15.33", "91.52.62.64"]))
    assert w["Endpoint.remote_ips"] == ["176.59.15.33", "91.52.62.64"]


def test_lookups_reach_endpoint_dns_queries():
    assert normalize("endpoint", C2)["Endpoint.dns_queries"] == ["anto-int.com"]


def test_endpoint_never_fills_the_block_keys():
    w = normalize("endpoint", C2)
    assert "Artifacts.Network.Destination.IP" not in w
    assert "Artifacts.Network.DNS.Query" not in w


def test_an_issue_without_connections_writes_no_remote_ips():
    assert "Endpoint.remote_ips" not in normalize("endpoint", {"hostname": "hobgoblin"})
