
from app.ipqs import Ipqs
from app.model.request_body import RequestBody
from pykson import Pykson
import json
pykson = Pykson()
integration_class = ipqs()


connection_params = {
    "base_url": "https://mockapi.local",
    "api_key": "mockapikey",
    "timeout": 5
}

# Sample IPs
sample_ips = ["1.1.1.1", "8.8.8.8"]

# ------------------------------------------------------------
# Helper: create RequestBody
# ------------------------------------------------------------
def create_request_body(ips):
    req_json = {
        "connectionParameters": connection_params,
        "parameters": {"ips": ips}
    }
    return pykson.from_json(req_json, RequestBody, True)

# ------------------------------------------------------------
# Mock requests for _lookup_ip
# ------------------------------------------------------------
import requests
from unittest.mock import patch

def mocked_lookup_ip(ip):
    # Return mock data based on IP
    mock_data = {
        "1.1.1.1": {
            "is_residential_proxy": True,
            "is_vpn": False,
            "is_tor": False,
            "is_proxy": True,
            "is_bot": False,
            "risk_score": 80
        },
        "8.8.8.8": {
            "is_residential_proxy": False,
            "is_vpn": True,
            "is_tor": True,
            "is_proxy": False,
            "is_bot": True,
            "risk_score": 20
        }
    }
    return mock_data.get(ip, {})

# ------------------------------------------------------------
# Test all actions
# ------------------------------------------------------------
@patch.object(IpThreatIntel, '_lookup_ip', side_effect=mocked_lookup_ip)
def test_detect_residential_proxies(mock_lookup):
    req = create_request_body(sample_ips)
    resp = integration_class.detect_residential_proxies(req)
    assert resp is not None
    assert any(r["category"] == "Residential Proxy" for r in resp["results"])

@patch.object(IpThreatIntel, '_lookup_ip', side_effect=mocked_lookup_ip)
def test_detect_private_vpn(mock_lookup):
    req = create_request_body(sample_ips)
    resp = integration_class.detect_private_vpn(req)
    assert resp is not None
    assert any(r["category"] == "Private VPN" for r in resp["results"])

@patch.object(IpThreatIntel, '_lookup_ip', side_effect=mocked_lookup_ip)
def test_detect_tor_nodes(mock_lookup):
    req = create_request_body(sample_ips)
    resp = integration_class.detect_tor_nodes(req)
    assert resp is not None
    assert any(r["category"] == "Tor Node" for r in resp["results"])

@patch.object(IpThreatIntel, '_lookup_ip', side_effect=mocked_lookup_ip)
def test_detect_anonymous_proxies(mock_lookup):
    req = create_request_body(sample_ips)
    resp = integration_class.detect_anonymous_proxies(req)
    assert resp is not None
    assert any(r["category"] == "Anonymous Proxy" for r in resp["results"])

@patch.object(IpThreatIntel, '_lookup_ip', side_effect=mocked_lookup_ip)
def test_detect_botnets(mock_lookup):
    req = create_request_body(sample_ips)
    resp = integration_class.detect_botnets(req)
    assert resp is not None
    assert any(r["category"] == "Botnet" for r in resp["results"])

@patch.object(IpThreatIntel, '_lookup_ip', side_effect=mocked_lookup_ip)
def test_detect_malicious_ips(mock_lookup):
    req = create_request_body(sample_ips)
    resp = integration_class.detect_malicious_ips(req)
    assert resp is not None
    assert any(r["category"] == "Malicious IP" for r in resp["results"])