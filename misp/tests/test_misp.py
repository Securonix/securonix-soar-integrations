import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.misp import Misp
from app.model.request_body import RequestBody
from pykson import Pykson
from unittest.mock import patch, MagicMock

import requests as req_lib

pykson = Pykson()
integration_class = Misp()

connection_params = {
    "server_url": "https://misp.example.com",
    "api_key": "mock-api-key"
}


def create_request_body(parameters):
    req_json = {
        "connectionParameters": connection_params,
        "parameters": parameters
    }
    return pykson.from_json(req_json, RequestBody, True)


# --- Helper Methods ---

def test_normalize_list_string():
    result = Misp._normalize_list("a, b, c")
    assert result == ["a", "b", "c"]


def test_normalize_list_already_list():
    result = Misp._normalize_list(["a", "b"])
    assert result == ["a", "b"]


def test_normalize_list_invalid():
    try:
        Misp._normalize_list(123)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Invalid input format" in str(e)


def test_validate_attribute_type_valid():
    Misp._validate_attribute_type("ip-src")


def test_validate_attribute_type_invalid():
    try:
        Misp._validate_attribute_type("invalid-type")
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Unsupported attribute type" in str(e)


def test_get_headers():
    headers = Misp._get_headers("test-key")
    assert headers["Authorization"] == "test-key"
    assert headers["Accept"] == "application/json"
    assert headers["Content-Type"] == "application/json"
    assert len(headers) == 3


# --- Test Connection ---

@patch("requests.get")
def test_test_connection_success(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"version": "2.4.170"}
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


# --- Search Events ---

@patch("requests.post")
def test_search_events(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"response": [{"Event": {"id": "1", "info": "test"}}]}
    mock_post.return_value = mock_response

    req = create_request_body({"value": "1.2.3.4"})
    resp = integration_class.search_events(req)

    assert resp["status"] == "success"
    assert resp["count"] == 1


@patch("requests.post")
def test_search_events_empty(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"response": []}
    mock_post.return_value = mock_response

    req = create_request_body({})
    resp = integration_class.search_events(req)

    assert resp["status"] == "success"
    assert resp["count"] == 0


# --- Create Event ---

@patch("requests.post")
def test_create_event(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"Event": {"id": "42"}}
    mock_post.return_value = mock_response

    req = create_request_body({
        "info": "Test event",
        "distribution": 0,
        "threat_level_id": 2,
        "analysis": 0
    })
    resp = integration_class.create_event(req)

    assert resp["status"] == "success"
    assert resp["event_id"] == "42"


def test_create_event_missing_required():
    req = create_request_body({"info": "Test"})
    try:
        integration_class.create_event(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Missing required parameter" in str(e)


# --- Get Event ---

@patch("requests.get")
def test_get_event(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"Event": {"id": "1", "info": "test"}}
    mock_get.return_value = mock_response

    req = create_request_body({"event_id": "1"})
    resp = integration_class.get_event(req)

    assert resp["status"] == "success"
    assert resp["event"]["id"] == "1"


def test_get_event_missing_id():
    req = create_request_body({})
    try:
        integration_class.get_event(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Missing required parameter" in str(e)


# --- Add Attribute ---

@patch("requests.post")
def test_add_attribute(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"Attribute": {"id": "100"}}
    mock_post.return_value = mock_response

    req = create_request_body({"event_id": "1", "type": "ip-src", "value": "1.2.3.4"})
    resp = integration_class.add_attribute(req)

    assert resp["status"] == "success"
    assert resp["attribute_id"] == "100"


def test_add_attribute_invalid_type():
    req = create_request_body({"event_id": "1", "type": "invalid", "value": "test"})
    try:
        integration_class.add_attribute(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Unsupported attribute type" in str(e)


# --- Search Attributes ---

@patch("requests.post")
def test_search_attributes(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"response": {"Attribute": [{"id": "1", "value": "1.2.3.4"}]}}
    mock_post.return_value = mock_response

    req = create_request_body({"value": "1.2.3.4"})
    resp = integration_class.search_attributes(req)

    assert resp["status"] == "success"
    assert resp["count"] == 1


@patch("requests.post")
def test_search_attributes_comma_separated(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"response": {"Attribute": []}}
    mock_post.return_value = mock_response

    req = create_request_body({"value": "1.2.3.4, 5.6.7.8"})
    integration_class.search_attributes(req)

    call_payload = mock_post.call_args[1]["json"]
    assert call_payload["value"] == "1.2.3.4|5.6.7.8"


# --- Add Tag ---

@patch("requests.post")
@patch("requests.get")
def test_add_tag(mock_get, mock_post):
    mock_get_resp = MagicMock()
    mock_get_resp.status_code = 200
    mock_get_resp.json.return_value = {"Tag": [{"name": "tlp:white"}, {"name": "tlp:green"}]}
    mock_get.return_value = mock_get_resp

    mock_post_resp = MagicMock()
    mock_post_resp.status_code = 200
    mock_post_resp.json.return_value = {"saved": True}
    mock_post.return_value = mock_post_resp

    req = create_request_body({"target_type": "event", "target_id": "1", "tag_name": "tlp:white"})
    resp = integration_class.add_tag(req)

    assert resp["status"] == "success"
    assert "tlp:white" in resp["message"]


@patch("requests.get")
def test_add_tag_not_found(mock_get):
    mock_get_resp = MagicMock()
    mock_get_resp.status_code = 200
    mock_get_resp.json.return_value = {"Tag": [{"name": "tlp:white"}]}
    mock_get.return_value = mock_get_resp

    req = create_request_body({"target_type": "event", "target_id": "1", "tag_name": "nonexistent"})
    try:
        integration_class.add_tag(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "does not exist" in str(e)


def test_add_tag_invalid_target_type():
    req = create_request_body({"target_type": "invalid", "target_id": "1", "tag_name": "test"})
    try:
        integration_class.add_tag(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "target_type" in str(e)


# --- Remove Tag ---

@patch("requests.post")
def test_remove_tag(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"saved": True}
    mock_post.return_value = mock_response

    req = create_request_body({"target_type": "event", "target_id": "1", "tag_name": "tlp:white"})
    resp = integration_class.remove_tag(req)

    assert resp["status"] == "success"


# --- Add Sighting ---

@patch("requests.post")
def test_add_sighting_by_id(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"id": "10"}
    mock_post.return_value = mock_response

    req = create_request_body({"attribute_id": "5", "type": 0})
    resp = integration_class.add_sighting(req)

    assert resp["status"] == "success"
    assert resp["sighting_id"] == "10"


@patch("requests.post")
def test_add_sighting_by_value(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"id": "11"}
    mock_post.return_value = mock_response

    req = create_request_body({"attribute_value": "1.2.3.4"})
    resp = integration_class.add_sighting(req)

    assert resp["status"] == "success"


def test_add_sighting_missing_both():
    req = create_request_body({})
    try:
        integration_class.add_sighting(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "attribute_id or attribute_value" in str(e)


def test_add_sighting_invalid_type():
    req = create_request_body({"attribute_id": "1", "type": 5})
    try:
        integration_class.add_sighting(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Sighting type" in str(e)


# --- Get Feeds ---

@patch("requests.get")
def test_get_feeds(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [{"Feed": {"id": "1", "name": "CIRCL"}}]
    mock_get.return_value = mock_response

    req = create_request_body({})
    resp = integration_class.get_feeds(req)

    assert resp["status"] == "success"
    assert resp["count"] == 1


# --- Enable Feed ---

@patch("requests.post")
def test_enable_feed(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"message": "Feed enabled."}
    mock_post.return_value = mock_response

    req = create_request_body({"feed_id": "1"})
    resp = integration_class.enable_feed(req)

    assert resp["status"] == "success"
    assert resp["feed_id"] == "1"


# --- Disable Feed ---

@patch("requests.post")
def test_disable_feed(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"message": "Feed disabled."}
    mock_post.return_value = mock_response

    req = create_request_body({"feed_id": "1"})
    resp = integration_class.disable_feed(req)

    assert resp["status"] == "success"


# --- Fetch Feed ---

@patch("requests.post")
def test_fetch_feed(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"message": "Pull queued."}
    mock_post.return_value = mock_response

    req = create_request_body({"feed_id": "1"})
    resp = integration_class.fetch_feed(req)

    assert resp["status"] == "success"
    assert "triggered" in resp["message"]


def test_fetch_feed_missing_id():
    req = create_request_body({})
    try:
        integration_class.fetch_feed(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Missing required parameter" in str(e)


# --- Check Warninglists ---

@patch("requests.post")
def test_check_warninglists_match(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [{"Warninglist": {"name": "RFC 5735 CIDR"}}]
    mock_post.return_value = mock_response

    req = create_request_body({"value": "10.0.0.1"})
    resp = integration_class.check_warninglists(req)

    assert resp["status"] == "success"
    assert resp["matched"] is True
    assert len(resp["warninglists"]) == 1


@patch("requests.post")
def test_check_warninglists_no_match(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = []
    mock_post.return_value = mock_response

    req = create_request_body({"value": "8.8.8.8"})
    resp = integration_class.check_warninglists(req)

    assert resp["status"] == "success"
    assert resp["matched"] is False


def test_check_warninglists_missing_value():
    req = create_request_body({})
    try:
        integration_class.check_warninglists(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Missing required parameter" in str(e)


# --- HTTP Error Handling ---

@patch("requests.get")
def test_handle_response_404(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.text = "Not Found"
    mock_get.return_value = mock_response

    req = create_request_body({"event_id": "999"})
    try:
        integration_class.get_event(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Resource not found" in str(e)


@patch("requests.get")
def test_handle_response_500(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    mock_get.return_value = mock_response

    req = create_request_body({"event_id": "1"})
    try:
        integration_class.get_event(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "MISP server error" in str(e)
