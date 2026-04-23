import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.workday import Workday
from app.model.request_body import RequestBody
from pykson import Pykson
from unittest.mock import patch, MagicMock

# ---------------------------
# Setup
# ---------------------------
pykson = Pykson()
integration_class = Workday()

connection_params = {
    "base_url": "https://mock-workday.com",
    "tenant": "test_tenant",
    "client_id": "mock_client_id",
    "client_secret": "mock_secret",
    "refresh_token": "mock_refresh",
    "token_url": "https://mock-workday.com/oauth/token",
    "timeout": 5
}

# ---------------------------
# Helper: create RequestBody
# ---------------------------
def create_request_body(params):
    req_json = {
        "connectionParameters": connection_params,
        "parameters": params
    }
    return pykson.from_json(req_json, RequestBody, True)

# ---------------------------
# Mock token generator
# ---------------------------
def mock_access_token(*args, **kwargs):
    return "mock_access_token"

# ---------------------------
# Test: Get Employee Details
# ---------------------------
@patch("app.workday.get_access_token", side_effect=mock_access_token)
@patch("requests.get")
def test_get_employee_details(mock_get, mock_token):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "id": "E123",
        "name": "John Doe",
        "department": "IT"
    }
    mock_get.return_value = mock_response

    req = create_request_body({"employee_id": "E123"})
    resp = integration_class.get_employee_details(req)

    assert resp["status"] == "success"
    assert resp["employee"]["id"] == "E123"

# ---------------------------
# Test: Get User Risk Profile
# ---------------------------
@patch("app.workday.get_access_token", side_effect=mock_access_token)
@patch("requests.get")
def test_get_user_risk_profile(mock_get, mock_token):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "employee_id": "E123",
        "risk_score": 85
    }
    mock_get.return_value = mock_response

    req = create_request_body({"employee_id": "E123"})
    resp = integration_class.get_user_risk_profile(req)

    assert resp["status"] == "success"
    assert resp["risk_profile"]["risk_score"] == 85

# ---------------------------
# Test: Trigger Onboarding
# ---------------------------
@patch("app.workday.get_access_token", side_effect=mock_access_token)
@patch("requests.post")
def test_trigger_onboarding(mock_post, mock_token):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"message": "Onboarding triggered"}
    mock_post.return_value = mock_response

    req = create_request_body({
        "employee_id": "E123",
        "name": "John",
        "department": "IT",
        "start_date": "2026-04-01"
    })

    resp = integration_class.trigger_onboarding(req)

    assert resp["status"] == "success"
    assert "Onboarding" in resp["response"]["message"]

# ---------------------------
# Test: Sync Employee Data
# ---------------------------
@patch("app.workday.get_access_token", side_effect=mock_access_token)
@patch("requests.get")
def test_sync_employee_data(mock_get, mock_token):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "employees": [
            {"id": "E1"},
            {"id": "E2"}
        ]
    }
    mock_get.return_value = mock_response

    req = create_request_body({})
    resp = integration_class.sync_employee_data(req)

    assert resp["status"] == "success"
    assert resp["count"] == 2

# ---------------------------
# Test Connection
# ---------------------------
@patch("requests.post")
def test_test_connection(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "mock_access_token"
    }
    mock_post.return_value = mock_response

    result = integration_class.test_connection(connection_params)

    assert result["status"] == "success"
    assert "successfully" in result["message"].lower()