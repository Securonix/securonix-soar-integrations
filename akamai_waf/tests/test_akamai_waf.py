from app.akamai_waf import (
    AkamaiWaf,
    _get_session,
    _get_network_list,
    _update_network_list,
    _handle_error,
    _normalize_ips,
)
from app.model.request_body import RequestBody
from pykson import Pykson
from unittest.mock import Mock, patch
import json

pykson = Pykson()
integration_class = AkamaiWaf()

@patch('app.akamai_waf.requests.Session')
def test_block_ip(mock_session):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"list": ["1.1.1.1"], "name": "test", "type": "IP"}
    mock_session.return_value.get.return_value = mock_response

    req = '{"connectionParameters": {"host": "https://test.com", "client_token": "token", "client_secret": "secret", "access_token": "access"}, "parameters": {"network_list_id": "123", "ip_addresses": ["2.2.2.2"]}}'
    req = pykson.from_json(req, RequestBody, True)

    with patch('app.akamai_waf._update_network_list', return_value=({}, None)):
        resp = integration_class.block_ip(req)

    assert resp["status"] == "success"
    assert "successfully added" in resp["message"]

@patch('app.akamai_waf.requests.Session')
def test_block_ip_already_exists(mock_session):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"list": ["2.2.2.2"], "name": "test", "type": "IP"}
    mock_session.return_value.get.return_value = mock_response

    req = '{"connectionParameters": {"host": "https://test.com", "client_token": "token", "client_secret": "secret", "access_token": "access"}, "parameters": {"network_list_id": "123", "ip_addresses": ["2.2.2.2"]}}'
    req = pykson.from_json(req, RequestBody, True)

    resp = integration_class.block_ip(req)

    assert resp["status"] == "success"
    assert "already present" in resp["message"]

@patch('app.akamai_waf.requests.Session')
def test_block_ip_get_error(mock_session):
    mock_response = Mock()
    mock_response.status_code = 404
    mock_session.return_value.get.return_value = mock_response

    req = '{"connectionParameters": {"host": "https://test.com", "client_token": "token", "client_secret": "secret", "access_token": "access"}, "parameters": {"network_list_id": "123", "ip_addresses": ["2.2.2.2"]}}'
    req = pykson.from_json(req, RequestBody, True)

    resp = integration_class.block_ip(req)

    assert resp["status"] == "error"
    assert resp["status_code"] == 404

@patch('app.akamai_waf.requests.Session')
def test_block_ip_update_error(mock_session):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"list": ["1.1.1.1"], "name": "test", "type": "IP"}
    mock_session.return_value.get.return_value = mock_response

    req = '{"connectionParameters": {"host": "https://test.com", "client_token": "token", "client_secret": "secret", "access_token": "access"}, "parameters": {"network_list_id": "123", "ip_addresses": ["2.2.2.2"]}}'
    req = pykson.from_json(req, RequestBody, True)

    with patch('app.akamai_waf._update_network_list', return_value=(None, {"status": "error", "status_code": 500})):
        resp = integration_class.block_ip(req)

    assert resp["status"] == "error"

@patch('app.akamai_waf.requests.Session')
def test_unblock_ip(mock_session):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"list": ["1.1.1.1", "2.2.2.2"], "name": "test", "type": "IP"}
    mock_session.return_value.get.return_value = mock_response

    req = '{"connectionParameters": {"host": "https://test.com", "client_token": "token", "client_secret": "secret", "access_token": "access"}, "parameters": {"network_list_id": "123", "ip_addresses": ["2.2.2.2"]}}'
    req = pykson.from_json(req, RequestBody, True)

    with patch('app.akamai_waf._update_network_list', return_value=({}, None)):
        resp = integration_class.unblock_ip(req)

    assert resp["status"] == "success"
    assert "successfully removed" in resp["message"]

@patch('app.akamai_waf.requests.Session')
def test_unblock_ip_not_found(mock_session):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"list": ["1.1.1.1"], "name": "test", "type": "IP"}
    mock_session.return_value.get.return_value = mock_response

    req = '{"connectionParameters": {"host": "https://test.com", "client_token": "token", "client_secret": "secret", "access_token": "access"}, "parameters": {"network_list_id": "123", "ip_addresses": ["2.2.2.2"]}}'
    req = pykson.from_json(req, RequestBody, True)

    resp = integration_class.unblock_ip(req)

    assert resp["status"] == "success"
    assert "No matching IP" in resp["message"]

@patch('app.akamai_waf.requests.Session')
def test_unblock_ip_get_error(mock_session):
    mock_response = Mock()
    mock_response.status_code = 404
    mock_session.return_value.get.return_value = mock_response

    req = '{"connectionParameters": {"host": "https://test.com", "client_token": "token", "client_secret": "secret", "access_token": "access"}, "parameters": {"network_list_id": "123", "ip_addresses": ["2.2.2.2"]}}'
    req = pykson.from_json(req, RequestBody, True)

    resp = integration_class.unblock_ip(req)

    assert resp["status"] == "error"
    assert resp["status_code"] == 404

@patch('app.akamai_waf.requests.Session')
def test_unblock_ip_update_error(mock_session):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"list": ["1.1.1.1", "2.2.2.2"], "name": "test", "type": "IP"}
    mock_session.return_value.get.return_value = mock_response

    req = '{"connectionParameters": {"host": "https://test.com", "client_token": "token", "client_secret": "secret", "access_token": "access"}, "parameters": {"network_list_id": "123", "ip_addresses": ["2.2.2.2"]}}'
    req = pykson.from_json(req, RequestBody, True)

    with patch('app.akamai_waf._update_network_list', return_value=(None, {"status": "error", "status_code": 500})):
        resp = integration_class.unblock_ip(req)

    assert resp["status"] == "error"

@patch('app.akamai_waf.requests.Session')
def test_get_security_events(mock_session):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"events": [{"id": 1}, {"id": 2}]}
    mock_session.return_value.get.return_value = mock_response

    req = '{"connectionParameters": {"host": "https://test.com", "client_token": "token", "client_secret": "secret", "access_token": "access"}, "parameters": {"config_id": "cfg-1", "start_time": "2024-01-01T00:00:00Z", "end_time": "2024-01-02T00:00:00Z", "policy_id": null, "attack_type": null, "ip_address": null, "limit": 100}}'
    req = pykson.from_json(req, RequestBody, True)

    resp = integration_class.get_security_events(req)

    assert resp["status"] == "success"
    assert resp["event_count"] == 2

@patch('app.akamai_waf.requests.Session')
def test_get_security_events_with_filters(mock_session):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"events": [{"id": 1}]}
    mock_session.return_value.get.return_value = mock_response

    req = '{"connectionParameters": {"host": "https://test.com", "client_token": "token", "client_secret": "secret", "access_token": "access"}, "parameters": {"config_id": "cfg-1", "start_time": "2024-01-01T00:00:00Z", "end_time": "2024-01-02T00:00:00Z", "policy_id": "123", "attack_type": "SQL", "ip_address": "1.1.1.1", "limit": 50}}'
    req = pykson.from_json(req, RequestBody, True)

    resp = integration_class.get_security_events(req)

    assert resp["status"] == "success"
    assert resp["event_count"] == 1

@patch('app.akamai_waf.requests.Session')
def test_get_security_events_error(mock_session):
    mock_response = Mock()
    mock_response.status_code = 500
    mock_session.return_value.get.return_value = mock_response

    req = '{"connectionParameters": {"host": "https://test.com", "client_token": "token", "client_secret": "secret", "access_token": "access"}, "parameters": {"config_id": "cfg-1", "start_time": "2024-01-01T00:00:00Z", "end_time": "2024-01-02T00:00:00Z", "policy_id": null, "attack_type": null, "ip_address": null, "limit": 100}}'
    req = pykson.from_json(req, RequestBody, True)

    resp = integration_class.get_security_events(req)

    assert resp["status"] == "error"
    assert resp["status_code"] == 500

@patch('app.akamai_waf.requests.Session')
def test_test_connection(mock_session):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"list": []}
    mock_session.return_value.get.return_value = mock_response

    connection_params = {"host": "https://test.com", "client_token": "token", "client_secret": "secret", "access_token": "access"}

    resp = integration_class.test_connection(connection_params)

    assert resp == "Connection Successful"

@patch('app.akamai_waf.requests.Session')
def test_test_connection_failure(mock_session):
    mock_response = Mock()
    mock_response.status_code = 401
    mock_session.return_value.get.return_value = mock_response

    connection_params = {"host": "https://test.com", "client_token": "token", "client_secret": "secret", "access_token": "access"}

    try:
        integration_class.test_connection(connection_params)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Invalid Akamai API credentials" in str(e)

def test_test_connection_exception():
    connection_params = {"host": "https://test.com", "client_token": "token", "client_secret": "secret", "access_token": "access"}

    with patch('app.akamai_waf._get_session', side_effect=Exception("Network error")):
        try:
            integration_class.test_connection(connection_params)
            assert False, "Should have raised exception"
        except Exception as e:
            assert "Network error" in str(e)

def test_get_session():
    session = _get_session("token", "secret", "access")
    assert session is not None
    assert "Content-Type" in session.headers
    assert session.headers["Content-Type"] == "application/json"

def test_normalize_ips():
    assert _normalize_ips("10.1.1.1") == ["10.1.1.1"]
    assert _normalize_ips("10.1.1.1, 10.1.1.2") == ["10.1.1.1", "10.1.1.2"]
    assert _normalize_ips(["10.1.1.1", "10.1.1.2"]) == ["10.1.1.1", "10.1.1.2"]
    assert _normalize_ips(None) == []
    assert _normalize_ips("  10.1.1.1  ") == ["10.1.1.1"]

def test_get_network_list_success():
    mock_session = Mock()
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"list": ["1.1.1.1"]}
    mock_session.get.return_value = mock_response

    data, error = _get_network_list("123", "https://test.com", mock_session)

    assert data == {"list": ["1.1.1.1"]}
    assert error is None

def test_get_network_list_error():
    mock_session = Mock()
    mock_response = Mock()
    mock_response.status_code = 404
    mock_session.get.return_value = mock_response

    data, error = _get_network_list("123", "https://test.com", mock_session)

    assert data is None
    assert error["status"] == "error"
    assert error["status_code"] == 404

def test_update_network_list():
    payload = {"name": "test", "type": "IP", "list": ["1.1.1.1"]}
    session = Mock()
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"success": True}
    session.put.return_value = mock_response

    data, error = _update_network_list("https://test.com", "123", payload, session)

    assert data == {"success": True}
    assert error is None

def test_update_network_list_error():
    payload = {"name": "test", "type": "IP", "list": ["1.1.1.1"]}
    session = Mock()
    mock_response = Mock()
    mock_response.status_code = 500
    session.put.return_value = mock_response

    data, error = _update_network_list("https://test.com", "123", payload, session)

    assert data is None
    assert error["status"] == "error"
    assert error["status_code"] == 500

def test_handle_error():
    mock_response = Mock()
    mock_response.status_code = 404

    error_result = _handle_error(mock_response)

    assert error_result["status"] == "error"
    assert "404" in error_result["message"]
    assert error_result["status_code"] == 404
