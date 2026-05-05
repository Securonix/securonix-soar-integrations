import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.opencti import Opencti
from app.model.request_body import RequestBody
from pykson import Pykson
from unittest.mock import patch, MagicMock

import requests as req_lib

pykson = Pykson()
integration_class = Opencti()

connection_params = {
    "base_url": "https://opencti.example.com",
    "api_token": "mock-api-token"
}


def create_request_body(parameters):
    req_json = {
        "connectionParameters": connection_params,
        "parameters": parameters
    }
    return pykson.from_json(req_json, RequestBody, True)


def mock_graphql_response(data, errors=None):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    result = {"data": data}
    if errors:
        result["errors"] = errors
    mock_resp.json.return_value = result
    return mock_resp


# --- Test Connection ---

@patch("requests.post")
def test_test_connection_success(mock_post):
    mock_post.return_value = mock_graphql_response({"about": {"version": "5.12.0"}})
    result = integration_class.test_connection(connection_params)
    assert result["status"] == "success"
    mock_post.assert_called_once()


@patch("requests.post")
def test_test_connection_auth_failure(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_post.return_value = mock_resp
    try:
        integration_class.test_connection(connection_params)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Authentication failed" in str(e)


@patch("requests.post", side_effect=req_lib.exceptions.ConnectionError("Connection refused"))
def test_test_connection_connection_error(mock_post):
    try:
        integration_class.test_connection(connection_params)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Unable to connect" in str(e)


@patch("requests.post", side_effect=req_lib.exceptions.Timeout("Timed out"))
def test_test_connection_timeout(mock_post):
    try:
        integration_class.test_connection(connection_params)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "timed out" in str(e)


# --- Lookup Observable ---

@patch("requests.post")
def test_lookup_observable_success(mock_post):
    mock_post.return_value = mock_graphql_response({
        "stixCyberObservables": {
            "edges": [{
                "node": {
                    "id": "obs-1",
                    "entity_type": "IPv4-Addr",
                    "observable_value": "1.1.1.1",
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-01T00:00:00Z",
                    "objectLabel": [{"value": "malicious"}],
                    "objectMarking": [],
                    "indicators": {"edges": []}
                }
            }]
        }
    })
    req = create_request_body({"observables": ["1.1.1.1"], "observable_type": "IPv4-Addr"})
    resp = integration_class.lookup_observable(req)
    assert resp["status"] == "success"
    assert len(resp["results"]) == 1
    assert resp["results"][0]["observable"] == "1.1.1.1"
    assert len(resp["results"][0]["matches"]) == 1


@patch("requests.post")
def test_lookup_observable_comma_separated(mock_post):
    mock_post.return_value = mock_graphql_response({
        "stixCyberObservables": {"edges": []}
    })
    req = create_request_body({"observables": "1.1.1.1, 8.8.8.8", "observable_type": "IPv4-Addr"})
    resp = integration_class.lookup_observable(req)
    assert resp["status"] == "success"
    assert len(resp["results"]) == 2


def test_lookup_observable_invalid_type():
    req = create_request_body({"observables": ["1.1.1.1"], "observable_type": "InvalidType"})
    try:
        integration_class.lookup_observable(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Invalid observable_type" in str(e)


def test_lookup_observable_empty_list():
    req = create_request_body({"observables": [], "observable_type": "IPv4-Addr"})
    try:
        integration_class.lookup_observable(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "observables is required" in str(e)


@patch("requests.post")
def test_lookup_observable_no_matches(mock_post):
    mock_post.return_value = mock_graphql_response({
        "stixCyberObservables": {"edges": []}
    })
    req = create_request_body({"observables": ["10.0.0.1"], "observable_type": "IPv4-Addr"})
    resp = integration_class.lookup_observable(req)
    assert resp["status"] == "success"
    assert resp["results"][0]["matches"] == []


# --- Get Indicator Details ---

@patch("requests.post")
def test_get_indicator_details_success(mock_post):
    mock_post.return_value = mock_graphql_response({
        "indicator": {
            "id": "ind-1",
            "name": "Malicious IP",
            "pattern": "[ipv4-addr:value = '1.1.1.1']",
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00Z",
            "valid_until": "2025-01-01T00:00:00Z",
            "confidence": 85,
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "objectLabel": [],
            "objectMarking": [],
            "createdBy": {"name": "MITRE"},
            "killChainPhases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]
        }
    })
    req = create_request_body({"indicator_ids": ["ind-1"]})
    resp = integration_class.get_indicator_details(req)
    assert resp["status"] == "success"
    assert len(resp["results"]) == 1
    assert resp["results"][0]["name"] == "Malicious IP"


@patch("requests.post")
def test_get_indicator_details_not_found(mock_post):
    mock_post.return_value = mock_graphql_response({"indicator": None})
    req = create_request_body({"indicator_ids": ["nonexistent-id"]})
    try:
        integration_class.get_indicator_details(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "No indicator found" in str(e)


def test_get_indicator_details_empty_list():
    req = create_request_body({"indicator_ids": []})
    try:
        integration_class.get_indicator_details(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "indicator_ids is required" in str(e)


@patch("requests.post")
def test_get_indicator_details_comma_separated(mock_post):
    mock_post.return_value = mock_graphql_response({
        "indicator": {
            "id": "ind-1", "name": "Test", "pattern": "[x:y='z']",
            "pattern_type": "stix", "valid_from": None, "valid_until": None,
            "confidence": 50, "created": None, "modified": None,
            "objectLabel": [], "objectMarking": [], "createdBy": None,
            "killChainPhases": []
        }
    })
    req = create_request_body({"indicator_ids": "ind-1, ind-2"})
    resp = integration_class.get_indicator_details(req)
    assert resp["status"] == "success"
    assert len(resp["results"]) == 2


# --- Search Entities ---

@patch("requests.post")
def test_search_entities_success(mock_post):
    mock_post.return_value = mock_graphql_response({
        "stixDomainObjects": {
            "edges": [{
                "node": {
                    "id": "sdo-1",
                    "entity_type": "Malware",
                    "name": "Emotet",
                    "description": "Banking trojan",
                    "created": "2024-01-01T00:00:00Z",
                    "modified": "2024-01-01T00:00:00Z",
                    "objectLabel": [{"value": "malware"}]
                }
            }]
        }
    })
    req = create_request_body({"search_term": "Emotet"})
    resp = integration_class.search_entities(req)
    assert resp["status"] == "success"
    assert len(resp["results"]) == 1
    assert resp["results"][0]["name"] == "Emotet"


@patch("requests.post")
def test_search_entities_with_type_filter(mock_post):
    mock_post.return_value = mock_graphql_response({
        "stixDomainObjects": {"edges": []}
    })
    req = create_request_body({"search_term": "APT28", "entity_type": "Threat-Actor"})
    resp = integration_class.search_entities(req)
    assert resp["status"] == "success"
    mock_post.assert_called_once()
    call_body = mock_post.call_args[1]["json"]
    assert "Threat-Actor" in call_body["variables"]["types"]


def test_search_entities_empty_search_term():
    req = create_request_body({"search_term": ""})
    try:
        integration_class.search_entities(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "search_term is required" in str(e)


@patch("requests.post")
def test_search_entities_with_limit(mock_post):
    mock_post.return_value = mock_graphql_response({
        "stixDomainObjects": {"edges": []}
    })
    req = create_request_body({"search_term": "test", "limit": "10"})
    resp = integration_class.search_entities(req)
    assert resp["status"] == "success"
    call_body = mock_post.call_args[1]["json"]
    assert call_body["variables"]["first"] == 10


# --- Connection Parameter Validation ---

def test_missing_base_url():
    bad_params = {"base_url": "", "api_token": "token"}
    try:
        integration_class.test_connection(bad_params)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "base_url is required" in str(e)


def test_missing_api_token():
    bad_params = {"base_url": "https://opencti.example.com", "api_token": ""}
    try:
        integration_class.test_connection(bad_params)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "api_token is required" in str(e)


# --- GraphQL Error Handling ---

@patch("requests.post")
def test_graphql_error_response(mock_post):
    mock_post.return_value = mock_graphql_response(
        {}, errors=[{"message": "Field not found"}]
    )
    req = create_request_body({"observables": ["1.1.1.1"], "observable_type": "IPv4-Addr"})
    try:
        integration_class.lookup_observable(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "GraphQL error" in str(e)


@patch("requests.post", side_effect=req_lib.exceptions.ConnectionError("Connection refused"))
def test_lookup_observable_connection_error(mock_post):
    req = create_request_body({"observables": ["1.1.1.1"], "observable_type": "IPv4-Addr"})
    try:
        integration_class.lookup_observable(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Unable to connect" in str(e)


@patch("requests.post", side_effect=req_lib.exceptions.Timeout("Timed out"))
def test_get_indicator_details_timeout(mock_post):
    req = create_request_body({"indicator_ids": ["ind-1"]})
    try:
        integration_class.get_indicator_details(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "timed out" in str(e)


@patch("requests.post")
def test_non_json_response(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("No JSON")
    mock_post.return_value = mock_resp
    req = create_request_body({"observables": ["1.1.1.1"], "observable_type": "IPv4-Addr"})
    try:
        integration_class.lookup_observable(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Invalid JSON response" in str(e)
