import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.ipqs import Ipqs
from app.model.request_body import RequestBody
from pykson import Pykson
import json
from unittest.mock import patch, MagicMock

# ---------------------------
# Dummy logger for test_connection
# ---------------------------
class DummyObj:
    class logger:
        @staticmethod
        def debug(*args, **kwargs):
            pass
        @staticmethod
        def error(*args, **kwargs):
            pass

# ---------------------------
# Setup
# ---------------------------
pykson = Pykson()
integration_class = Ipqs()

connection_params = {
    "base_url": "https://mockapi.local",
    "api_key": "mockapikey",
    "timeout": 5
}

sample_ips = ["1.1.1.1", "8.8.8.8"]

# ---------------------------
# Helper: create RequestBody
# ---------------------------
def create_request_body(ips):
    req_json = {
        "connectionParameters": connection_params,
        "parameters": {"ips": ips}
    }
    return pykson.from_json(req_json, RequestBody, True)

# ---------------------------
# Mock _lookup_ip method
# ---------------------------
def mocked_lookup_ip(ip):
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

# ---------------------------
# Tests for IP detection
# ---------------------------
@patch.object(Ipqs, '_lookup_ip', side_effect=mocked_lookup_ip)
def test_detect_residential_proxies(mock_lookup):
    req = create_request_body(sample_ips)
    resp = integration_class.detect_residential_proxies(req)
    assert resp is not None
    assert any(r["category"] == "Residential Proxy" for r in resp["results"])

@patch.object(Ipqs, '_lookup_ip', side_effect=mocked_lookup_ip)
def test_detect_private_vpn(mock_lookup):
    req = create_request_body(sample_ips)
    resp = integration_class.detect_private_vpn(req)
    assert resp is not None
    assert any(r["category"] == "Private VPN" for r in resp["results"])

@patch.object(Ipqs, '_lookup_ip', side_effect=mocked_lookup_ip)
def test_detect_tor_nodes(mock_lookup):
    req = create_request_body(sample_ips)
    resp = integration_class.detect_tor_nodes(req)
    assert resp is not None
    assert any(r["category"] == "Tor Node" for r in resp["results"])

@patch.object(Ipqs, '_lookup_ip', side_effect=mocked_lookup_ip)
def test_detect_anonymous_proxies(mock_lookup):
    req = create_request_body(sample_ips)
    resp = integration_class.detect_anonymous_proxies(req)
    assert resp is not None
    assert any(r["category"] == "Anonymous Proxy" for r in resp["results"])

@patch.object(Ipqs, '_lookup_ip', side_effect=mocked_lookup_ip)
def test_detect_botnets(mock_lookup):
    req = create_request_body(sample_ips)
    resp = integration_class.detect_botnets(req)
    assert resp is not None
    assert any(r["category"] == "Botnet" for r in resp["results"])

@patch.object(Ipqs, '_lookup_ip', side_effect=mocked_lookup_ip)
def test_detect_malicious_ips(mock_lookup):
    req = create_request_body(sample_ips)
    resp = integration_class.detect_malicious_ips(req)
    assert resp is not None
    assert any(r["category"] == "Malicious IP" for r in resp["results"])

# ---------------------------
# Test connection
# ---------------------------
@patch("requests.get")
def test_test_connection(mock_get):
    # Mock API response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"success": True, "proxy": False, "fraud_score": 0}
    mock_get.return_value = mock_response

    connectionParameters = {
        "base_url": "https://ipqualityscore.com",
        "api_key": "dpopsQzcDEzd2xEgjo1B93IyNQkcXE4H",
        "timeout": 10
    }

    # call as method of Ipqs instance
    result = integration_class.test_connection(connectionParameters)

    assert result["status"] == "success"
    assert "Connection Successful" in result["message"]

