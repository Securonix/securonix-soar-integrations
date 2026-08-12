import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.ipqs import Ipqs
from app.model.request_body import RequestBody
from pykson import Pykson
from unittest.mock import patch, MagicMock

pykson = Pykson()
integration_class = Ipqs()

connection_params = {
    "base_url": "https://mockapi.local",
    "api_key": "mockapikey",
    "timeout": 5
}

sample_ips = ["1.1.1.1", "8.8.8.8"]


def create_request_body(ips):
    req_json = {
        "connectionParameters": connection_params,
        "parameters": {"ips": ips}
    }
    return pykson.from_json(req_json, RequestBody, True)


MOCK_DATA = {
    "1.1.1.1": {
        "is_residential_proxy": True,
        "vpn": False,
        "tor": False,
        "proxy": True,
        "bot_status": False,
        "fraud_score": 80
    },
    "8.8.8.8": {
        "is_residential_proxy": False,
        "vpn": True,
        "tor": True,
        "proxy": False,
        "bot_status": True,
        "fraud_score": 20
    }
}


def mocked_lookup_ip(base_url, api_key, timeout, ip):
    return MOCK_DATA.get(ip, {})


@patch("app.ipqs._lookup_ip", side_effect=mocked_lookup_ip)
def test_detect_residential_proxies(mock_lookup):
    req = create_request_body(sample_ips)
    resp = integration_class.detect_residential_proxies(req)
    assert resp is not None
    assert any(r["category"] == "Residential Proxy" for r in resp["results"])
    assert any(r["category"] == "Not a Residential Proxy" for r in resp["results"])


@patch("app.ipqs._lookup_ip", side_effect=mocked_lookup_ip)
def test_detect_private_vpn(mock_lookup):
    req = create_request_body(sample_ips)
    resp = integration_class.detect_private_vpn(req)
    assert resp is not None
    assert any(r["category"] == "Private VPN" for r in resp["results"])
    assert any(r["category"] == "Not a VPN" for r in resp["results"])


@patch("app.ipqs._lookup_ip", side_effect=mocked_lookup_ip)
def test_detect_tor_nodes(mock_lookup):
    req = create_request_body(sample_ips)
    resp = integration_class.detect_tor_nodes(req)
    assert resp is not None
    assert any(r["category"] == "Tor Node" for r in resp["results"])
    assert any(r["category"] == "Not a Tor Node" for r in resp["results"])


@patch("app.ipqs._lookup_ip", side_effect=mocked_lookup_ip)
def test_detect_anonymous_proxies(mock_lookup):
    req = create_request_body(sample_ips)
    resp = integration_class.detect_anonymous_proxies(req)
    assert resp is not None
    assert any(r["category"] == "Anonymous Proxy" for r in resp["results"])
    assert any(r["category"] == "Not a Proxy" for r in resp["results"])


@patch("app.ipqs._lookup_ip", side_effect=mocked_lookup_ip)
def test_detect_botnets(mock_lookup):
    req = create_request_body(sample_ips)
    resp = integration_class.detect_botnets(req)
    assert resp is not None
    assert any(r["category"] == "Botnet" for r in resp["results"])
    assert any(r["category"] == "Not a Botnet" for r in resp["results"])


@patch("app.ipqs._lookup_ip", side_effect=mocked_lookup_ip)
def test_detect_malicious_ips(mock_lookup):
    req = create_request_body(sample_ips)
    resp = integration_class.detect_malicious_ips(req)
    assert resp is not None
    assert any(r["category"] == "Malicious IP" for r in resp["results"])
    assert any(r["category"] == "Not Malicious" for r in resp["results"])


@patch("requests.get")
def test_test_connection(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"success": True, "proxy": False, "fraud_score": 0}
    mock_get.return_value = mock_response

    result = integration_class.test_connection({
        "base_url": "https://ipqualityscore.com",
        "api_key": "mockapikey",
        "timeout": 10
    })

    assert result["status"] == "success"
    assert "Connected to IPQualityScore successfully." in result["message"]
