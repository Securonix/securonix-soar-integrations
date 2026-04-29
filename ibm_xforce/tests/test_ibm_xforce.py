import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.ibm_xforce import IbmXforce
from app.model.request_body import RequestBody
from pykson import Pykson
from unittest.mock import patch, MagicMock

import requests as req_lib

pykson = Pykson()
integration_class = IbmXforce()

connection_params = {
    "base_url": "https://api.xforce.ibmcloud.com",
    "api_key": "mock-api-key",
    "api_password": "mock-api-password"
}


def create_request_body(parameters):
    req_json = {
        "connectionParameters": connection_params,
        "parameters": parameters
    }
    return pykson.from_json(req_json, RequestBody, True)


# --- Test Connection ---

@patch("requests.get")
def test_test_connection_success(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"ip": "8.8.8.8", "score": 1}
    mock_get.return_value = mock_response

    result = integration_class.test_connection(connection_params)
    assert result["status"] == "success"
    mock_get.assert_called_once()


@patch("requests.get")
def test_test_connection_auth_failure(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.text = "Unauthorized"
    mock_get.return_value = mock_response

    try:
        integration_class.test_connection(connection_params)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Authentication failed" in str(e)


@patch("requests.get", side_effect=req_lib.exceptions.ConnectionError("Connection refused"))
def test_test_connection_connection_error(mock_get):
    try:
        integration_class.test_connection(connection_params)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Unable to connect" in str(e)


@patch("requests.get", side_effect=req_lib.exceptions.Timeout("Timed out"))
def test_test_connection_timeout(mock_get):
    try:
        integration_class.test_connection(connection_params)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "timed out" in str(e)


# --- Lookup IP ---

@patch("requests.get")
def test_lookup_ip(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "ip": "1.1.1.1",
        "score": 1,
        "cats": {},
        "geo": {"country": "Australia"}
    }
    mock_get.return_value = mock_response

    req = create_request_body({"ips": ["1.1.1.1"]})
    resp = integration_class.lookup_ip(req)

    assert resp["status"] == "success"
    assert len(resp["results"]) == 1
    assert resp["results"][0]["ip"] == "1.1.1.1"
    assert "reputation" in resp["results"][0]


@patch("requests.get")
def test_lookup_ip_comma_separated(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"ip": "test", "score": 1}
    mock_get.return_value = mock_response

    req = create_request_body({"ips": "1.1.1.1, 8.8.8.8"})
    resp = integration_class.lookup_ip(req)

    assert resp["status"] == "success"
    assert len(resp["results"]) == 2


# --- Lookup Domain ---

@patch("requests.get")
def test_lookup_domain(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "result": {"url": "example.com", "score": 1, "cats": {}}
    }
    mock_get.return_value = mock_response

    req = create_request_body({"domains": ["example.com"]})
    resp = integration_class.lookup_domain(req)

    assert resp["status"] == "success"
    assert len(resp["results"]) == 1
    assert resp["results"][0]["domain"] == "example.com"
    assert "reputation" in resp["results"][0]


# --- Lookup URL ---

@patch("requests.get")
def test_lookup_url(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "result": {"url": "https://example.com/path", "score": 5, "cats": {"Malware": True}}
    }
    mock_get.return_value = mock_response

    req = create_request_body({"urls": ["https://example.com/path"]})
    resp = integration_class.lookup_url(req)

    assert resp["status"] == "success"
    assert len(resp["results"]) == 1
    assert resp["results"][0]["url"] == "https://example.com/path"
    assert "reputation" in resp["results"][0]


# --- Error Handling ---

@patch("requests.get", side_effect=Exception("API Error"))
def test_lookup_ip_error_handling(mock_get):
    req = create_request_body({"ips": ["1.1.1.1"]})
    try:
        integration_class.lookup_ip(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "API Error" in str(e)
