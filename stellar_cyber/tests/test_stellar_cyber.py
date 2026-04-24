from app.stellar_cyber import StellarCyber
from app.model.request_body import RequestBody
from pykson import Pykson
from unittest.mock import patch, Mock
import json

pykson = Pykson()
integration_class = StellarCyber()

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

BASE_URL = "https://stellarcyber.example.com"
API_TOKEN = "mock-api-token"
EMAIL = "admin@example.com"
MOCK_JWT = "mock-jwt"

CONN_PARAMS = {"base_url": BASE_URL, "api_token": API_TOKEN, "email": EMAIL}
CONN_TUPLE = (BASE_URL, API_TOKEN, MOCK_JWT, EMAIL)


def mock_token_response():
    resp = Mock()
    resp.json.return_value = {"access_token": MOCK_JWT}
    resp.raise_for_status = Mock()
    resp.text = '{"access_token": "mock-jwt"}'
    return resp


def mock_api_response(data):
    resp = Mock()
    resp.json.return_value = data
    resp.raise_for_status = Mock()
    resp.status_code = 200
    resp.text = json.dumps(data)
    return resp


def make_request_json(parameters):
    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s",
            "email": "%s"
        },
        "parameters": %s
    }
    """ % (BASE_URL, API_TOKEN, EMAIL, json.dumps(parameters))
    return pykson.from_json(req, RequestBody, True)


# -------------------------------------------------------------------
# test_connection
# -------------------------------------------------------------------

@patch('requests.post')
def test_connection_success(mock_post):
    mock_post.return_value = mock_token_response()
    resp = integration_class.test_connection(CONN_PARAMS)
    assert resp["status"] == "success"
    # Should use Basic auth since email is provided
    mock_post.assert_called_once()
    call_kwargs = mock_post.call_args
    assert call_kwargs[1].get("auth") == (EMAIL, API_TOKEN)


@patch('requests.post')
def test_connection_no_token(mock_post):
    resp = Mock()
    resp.json.return_value = {}
    resp.raise_for_status = Mock()
    mock_post.return_value = resp
    try:
        integration_class.test_connection(CONN_PARAMS)
        assert False, "Expected exception"
    except Exception as e:
        assert "Failed to retrieve access token" in str(e)


@patch('requests.post')
def test_connection_http_error(mock_post):
    mock_post.side_effect = Exception("Connection refused")
    try:
        integration_class.test_connection(CONN_PARAMS)
        assert False, "Expected exception"
    except Exception as e:
        assert "Connection refused" in str(e)


@patch('requests.post')
def test_connection_bearer_auth_no_email(mock_post):
    mock_post.return_value = mock_token_response()
    conn = {"base_url": BASE_URL, "api_token": API_TOKEN}
    resp = integration_class.test_connection(conn)
    assert resp["status"] == "success"
    call_kwargs = mock_post.call_args
    assert call_kwargs[1].get("auth") is None


# -------------------------------------------------------------------
# _request error handling
# -------------------------------------------------------------------

@patch('requests.request')
@patch('requests.post')
def test_request_401_retry_success(mock_post, mock_request):
    mock_post.return_value = mock_token_response()

    resp_401 = Mock()
    resp_401.status_code = 401
    resp_401.text = "Unauthorized"

    resp_200 = mock_api_response({"result": "ok"})
    mock_request.side_effect = [resp_401, resp_200]

    result = integration_class._request(CONN_TUPLE, "GET", "/cases/123/summary")
    assert result == {"result": "ok"}
    assert mock_post.call_count == 1  # token refresh


@patch('requests.request')
@patch('requests.post')
def test_request_401_double_failure(mock_post, mock_request):
    mock_post.return_value = mock_token_response()

    resp_401 = Mock()
    resp_401.status_code = 401
    resp_401.text = "Unauthorized"
    mock_request.side_effect = [resp_401, resp_401]

    try:
        integration_class._request(CONN_TUPLE, "GET", "/cases/123/summary")
        assert False, "Expected exception"
    except Exception as e:
        assert "Authentication failed" in str(e)


@patch('requests.request')
def test_request_400_error(mock_request):
    resp_400 = Mock()
    resp_400.status_code = 400
    resp_400.text = "Bad request body"
    mock_request.return_value = resp_400

    try:
        integration_class._request(CONN_TUPLE, "POST", "/cases")
        assert False, "Expected exception"
    except Exception as e:
        assert "Invalid request" in str(e)


@patch('requests.request')
def test_request_403_error(mock_request):
    resp_403 = Mock()
    resp_403.status_code = 403
    resp_403.text = "Forbidden"
    mock_request.return_value = resp_403

    try:
        integration_class._request(CONN_TUPLE, "GET", "/cases/123")
        assert False, "Expected exception"
    except Exception as e:
        assert "Permission denied" in str(e)


@patch('requests.request')
def test_request_404_error(mock_request):
    resp_404 = Mock()
    resp_404.status_code = 404
    resp_404.text = "Not found"
    mock_request.return_value = resp_404

    try:
        integration_class._request(CONN_TUPLE, "GET", "/cases/nonexistent")
        assert False, "Expected exception"
    except Exception as e:
        assert "Case not found" in str(e)


@patch('requests.request')
def test_request_500_error(mock_request):
    resp_500 = Mock()
    resp_500.status_code = 500
    resp_500.text = "Internal server error"
    mock_request.return_value = resp_500

    try:
        integration_class._request(CONN_TUPLE, "GET", "/cases")
        assert False, "Expected exception"
    except Exception as e:
        assert "Stellar Cyber server error" in str(e)


@patch('requests.request')
def test_request_timeout(mock_request):
    import requests as req_lib
    mock_request.side_effect = req_lib.exceptions.Timeout("timed out")

    try:
        integration_class._request(CONN_TUPLE, "GET", "/cases")
        assert False, "Expected exception"
    except Exception as e:
        assert "Connection timed out" in str(e)


@patch('requests.request')
def test_request_connection_error(mock_request):
    import requests as req_lib
    mock_request.side_effect = req_lib.exceptions.ConnectionError("refused")

    try:
        integration_class._request(CONN_TUPLE, "GET", "/cases")
        assert False, "Expected exception"
    except Exception as e:
        assert "Failed to connect to Stellar Cyber" in str(e)


# -------------------------------------------------------------------
# create_case
# -------------------------------------------------------------------

@patch('requests.request')
@patch('requests.post')
def test_create_case_success(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    mock_request.return_value = mock_api_response({
        "_id": "case-001", "severity": "High", "name": "Test Case"
    })

    req = make_request_json({
        "name": "Test Case", "description": "A test case",
        "severity": "High", "status": "New",
        "assignee": "analyst1", "tags": "tag1,tag2"
    })
    resp = integration_class.create_case(req)

    assert resp["status"] == "success"
    assert resp["case_id"] == "case-001"
    assert resp["severity"] == "High"


@patch('requests.request')
@patch('requests.post')
def test_create_case_name_only(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    mock_request.return_value = mock_api_response({"_id": "case-002", "name": "Minimal Case"})

    req = make_request_json({"name": "Minimal Case"})
    resp = integration_class.create_case(req)

    assert resp["status"] == "success"
    assert resp["case_id"] == "case-002"


@patch('requests.post')
def test_create_case_missing_name(mock_post):
    mock_post.return_value = mock_token_response()
    req = make_request_json({})
    try:
        integration_class.create_case(req)
        assert False, "Expected exception"
    except Exception:
        pass


# -------------------------------------------------------------------
# update_case
# -------------------------------------------------------------------

@patch('requests.request')
@patch('requests.post')
def test_update_case_success(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    mock_request.return_value = mock_api_response({"_id": "case-001", "status": "Resolved"})

    req = make_request_json({
        "case_id": "case-001", "status": "Resolved",
        "severity": "Critical", "assignee": "analyst2"
    })
    resp = integration_class.update_case(req)

    assert resp["status"] == "success"
    assert resp["case_id"] == "case-001"
    assert "status" in resp["updated_fields"]
    assert "severity" in resp["updated_fields"]
    assert "assignee" in resp["updated_fields"]


@patch('requests.post')
def test_update_case_missing_case_id(mock_post):
    mock_post.return_value = mock_token_response()
    req = make_request_json({})
    try:
        integration_class.update_case(req)
        assert False, "Expected exception"
    except Exception:
        pass


# -------------------------------------------------------------------
# add_case_comment
# -------------------------------------------------------------------

@patch('requests.request')
@patch('requests.post')
def test_add_case_comment_success(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    mock_request.return_value = mock_api_response({"_id": "comment-001", "comment": "Investigation started"})

    req = make_request_json({"case_id": "case-001", "comment": "Investigation started"})
    resp = integration_class.add_case_comment(req)

    assert resp["status"] == "success"
    assert resp["case_id"] == "case-001"
    assert resp["comment_id"] == "comment-001"


@patch('requests.post')
def test_add_case_comment_missing_fields(mock_post):
    mock_post.return_value = mock_token_response()
    req = make_request_json({"comment": "Some comment"})
    try:
        integration_class.add_case_comment(req)
        assert False, "Expected exception"
    except Exception:
        pass


# -------------------------------------------------------------------
# get_case_summary
# -------------------------------------------------------------------

@patch('requests.request')
@patch('requests.post')
def test_get_case_summary_success(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    summary_data = {"_id": "case-001", "name": "Test", "severity": "High", "score": 85}
    mock_request.return_value = mock_api_response(summary_data)

    req = make_request_json({"case_id": "case-001"})
    resp = integration_class.get_case_summary(req)

    assert resp["status"] == "success"
    assert resp["case_id"] == "case-001"
    assert resp["summary"] == summary_data


# -------------------------------------------------------------------
# get_case_scores
# -------------------------------------------------------------------

@patch('requests.request')
@patch('requests.post')
def test_get_case_scores_success(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    scores_data = {"fidelity": 80, "severity": 90, "overall": 85}
    mock_request.return_value = mock_api_response(scores_data)

    req = make_request_json({"case_id": "case-001"})
    resp = integration_class.get_case_scores(req)

    assert resp["status"] == "success"
    assert resp["score_details"] == scores_data


# -------------------------------------------------------------------
# get_case_alerts
# -------------------------------------------------------------------

@patch('requests.request')
@patch('requests.post')
def test_get_case_alerts_success(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    alerts = [{"_id": "alert-1", "name": "Malware"}, {"_id": "alert-2", "name": "Phishing"}]
    mock_request.return_value = mock_api_response(alerts)

    req = make_request_json({"case_id": "case-001"})
    resp = integration_class.get_case_alerts(req)

    assert resp["status"] == "success"
    assert resp["alerts"] == alerts
    assert resp["total_count"] == 2


@patch('requests.request')
@patch('requests.post')
def test_get_case_alerts_wrapped_response(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    alerts = [{"_id": "alert-1"}, {"_id": "alert-2"}]
    mock_request.return_value = mock_api_response({"data": alerts})

    req = make_request_json({"case_id": "case-001"})
    resp = integration_class.get_case_alerts(req)

    assert resp["alerts"] == alerts
    assert resp["total_count"] == 2


# -------------------------------------------------------------------
# get_case_observables
# -------------------------------------------------------------------

@patch('requests.request')
@patch('requests.post')
def test_get_case_observables_success(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    observables = [{"type": "ip", "value": "1.2.3.4"}, {"type": "domain", "value": "evil.com"}]
    mock_request.return_value = mock_api_response(observables)

    req = make_request_json({"case_id": "case-001"})
    resp = integration_class.get_case_observables(req)

    assert resp["status"] == "success"
    assert resp["observables"] == observables
    assert resp["total_count"] == 2


# -------------------------------------------------------------------
# list_cases
# -------------------------------------------------------------------

@patch('requests.request')
@patch('requests.post')
def test_list_cases_success(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    cases = [{"_id": "case-001", "name": "Case 1"}, {"_id": "case-002", "name": "Case 2"}]
    mock_request.return_value = mock_api_response(cases)

    req = make_request_json({"status": "New", "severity": "High"})
    resp = integration_class.list_cases(req)

    assert resp["status"] == "success"
    assert resp["cases"] == cases
    assert resp["total_count"] == 2


@patch('requests.request')
@patch('requests.post')
def test_list_cases_empty(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    empty_resp = Mock()
    empty_resp.status_code = 200
    empty_resp.text = "[]"
    empty_resp.json.return_value = []
    mock_request.return_value = empty_resp

    req = make_request_json({})
    resp = integration_class.list_cases(req)

    assert resp["cases"] == []
    assert resp["total_count"] == 0


# -------------------------------------------------------------------
# get_case_details
# -------------------------------------------------------------------

@patch('requests.request')
@patch('requests.post')
def test_get_case_details_success(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    case_data = {"_id": "case-001", "name": "Test Case", "severity": "High"}
    mock_request.return_value = mock_api_response(case_data)

    req = make_request_json({"case_id": "case-001"})
    resp = integration_class.get_case_details(req)

    assert resp["status"] == "success"
    assert resp["case_id"] == "case-001"
    assert resp["case_details"] == case_data
