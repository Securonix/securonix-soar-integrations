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
MOCK_JWT = "mock-jwt"


def mock_token_response():
    """Return a mock successful token response."""
    resp = Mock()
    resp.json.return_value = {"access_token": MOCK_JWT}
    resp.raise_for_status = Mock()
    resp.text = '{"access_token": "mock-jwt"}'
    return resp


def mock_api_response(data):
    """Return a mock successful API response."""
    resp = Mock()
    resp.json.return_value = data
    resp.raise_for_status = Mock()
    resp.status_code = 200
    resp.text = json.dumps(data)
    return resp


# -------------------------------------------------------------------
# test_connection
# -------------------------------------------------------------------

@patch('requests.post')
def test_connection_success(mock_post):
    mock_post.return_value = mock_token_response()

    conn_params = {
        "base_url": BASE_URL,
        "api_token": API_TOKEN
    }

    resp = integration_class.test_connection(conn_params)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["message"] == "Connected to Stellar Cyber successfully."


@patch('requests.post')
def test_connection_no_token(mock_post):
    resp = Mock()
    resp.json.return_value = {}
    resp.raise_for_status = Mock()
    mock_post.return_value = resp

    conn_params = {
        "base_url": BASE_URL,
        "api_token": API_TOKEN
    }

    try:
        integration_class.test_connection(conn_params)
        assert False, "Expected exception"
    except Exception as e:
        assert "Failed to retrieve access token" in str(e)


@patch('requests.post')
def test_connection_http_error(mock_post):
    mock_post.side_effect = Exception("Connection refused")

    conn_params = {
        "base_url": BASE_URL,
        "api_token": API_TOKEN
    }

    try:
        integration_class.test_connection(conn_params)
        assert False, "Expected exception"
    except Exception as e:
        assert "Connection refused" in str(e)


# -------------------------------------------------------------------
# _request 401 retry and error handling
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

    integration_class._init_connection({"base_url": BASE_URL, "api_token": API_TOKEN})
    result = integration_class._request("GET", "/cases/123/summary")

    assert result == {"result": "ok"}
    assert mock_post.call_count == 2


@patch('requests.request')
@patch('requests.post')
def test_request_401_double_failure(mock_post, mock_request):
    mock_post.return_value = mock_token_response()

    resp_401 = Mock()
    resp_401.status_code = 401
    resp_401.text = "Unauthorized"

    mock_request.side_effect = [resp_401, resp_401]

    integration_class._init_connection({"base_url": BASE_URL, "api_token": API_TOKEN})
    try:
        integration_class._request("GET", "/cases/123/summary")
        assert False, "Expected exception"
    except Exception as e:
        assert "Authentication failed" in str(e)


@patch('requests.request')
@patch('requests.post')
def test_request_400_error(mock_post, mock_request):
    mock_post.return_value = mock_token_response()

    resp_400 = Mock()
    resp_400.status_code = 400
    resp_400.text = "Bad request body"
    mock_request.return_value = resp_400

    integration_class._init_connection({"base_url": BASE_URL, "api_token": API_TOKEN})
    try:
        integration_class._request("POST", "/cases")
        assert False, "Expected exception"
    except Exception as e:
        assert "Invalid request" in str(e)


@patch('requests.request')
@patch('requests.post')
def test_request_403_error(mock_post, mock_request):
    mock_post.return_value = mock_token_response()

    resp_403 = Mock()
    resp_403.status_code = 403
    resp_403.text = "Forbidden"
    mock_request.return_value = resp_403

    integration_class._init_connection({"base_url": BASE_URL, "api_token": API_TOKEN})
    try:
        integration_class._request("GET", "/cases/123")
        assert False, "Expected exception"
    except Exception as e:
        assert "Permission denied" in str(e)


@patch('requests.request')
@patch('requests.post')
def test_request_404_error(mock_post, mock_request):
    mock_post.return_value = mock_token_response()

    resp_404 = Mock()
    resp_404.status_code = 404
    resp_404.text = "Not found"
    mock_request.return_value = resp_404

    integration_class._init_connection({"base_url": BASE_URL, "api_token": API_TOKEN})
    try:
        integration_class._request("GET", "/cases/nonexistent")
        assert False, "Expected exception"
    except Exception as e:
        assert "Case not found" in str(e)


@patch('requests.request')
@patch('requests.post')
def test_request_500_error(mock_post, mock_request):
    mock_post.return_value = mock_token_response()

    resp_500 = Mock()
    resp_500.status_code = 500
    resp_500.text = "Internal server error"
    mock_request.return_value = resp_500

    integration_class._init_connection({"base_url": BASE_URL, "api_token": API_TOKEN})
    try:
        integration_class._request("GET", "/cases")
        assert False, "Expected exception"
    except Exception as e:
        assert "Stellar Cyber server error" in str(e)


@patch('requests.request')
@patch('requests.post')
def test_request_timeout(mock_post, mock_request):
    import requests as req_lib
    mock_post.return_value = mock_token_response()
    mock_request.side_effect = req_lib.exceptions.Timeout("timed out")

    integration_class._init_connection({"base_url": BASE_URL, "api_token": API_TOKEN})
    try:
        integration_class._request("GET", "/cases")
        assert False, "Expected exception"
    except Exception as e:
        assert "Connection timed out" in str(e)


@patch('requests.request')
@patch('requests.post')
def test_request_connection_error(mock_post, mock_request):
    import requests as req_lib
    mock_post.return_value = mock_token_response()
    mock_request.side_effect = req_lib.exceptions.ConnectionError("refused")

    integration_class._init_connection({"base_url": BASE_URL, "api_token": API_TOKEN})
    try:
        integration_class._request("GET", "/cases")
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
        "_id": "case-001",
        "severity": "High",
        "name": "Test Case"
    })

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "name": "Test Case",
            "description": "A test case",
            "severity": "High",
            "status": "New",
            "assignee": "analyst1",
            "tags": "tag1,tag2"
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.create_case(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["case_id"] == "case-001"
    assert resp["severity"] == "High"


@patch('requests.request')
@patch('requests.post')
def test_create_case_name_only(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    mock_request.return_value = mock_api_response({
        "_id": "case-002",
        "name": "Minimal Case"
    })

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "name": "Minimal Case"
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.create_case(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["case_id"] == "case-002"


@patch('requests.post')
def test_create_case_missing_name(mock_post):
    mock_post.return_value = mock_token_response()

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {}
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
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

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "case_id": "case-001",
            "status": "Resolved",
            "severity": "Critical",
            "assignee": "analyst2"
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.update_case(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["case_id"] == "case-001"
    assert "status" in resp["updated_fields"]
    assert "severity" in resp["updated_fields"]
    assert "assignee" in resp["updated_fields"]


@patch('requests.request')
@patch('requests.post')
def test_update_case_with_tags(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    mock_request.return_value = mock_api_response({"_id": "case-001"})

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "case_id": "case-001",
            "tags_to_add": ["urgent", "reviewed"],
            "tags_to_remove": ["pending"]
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.update_case(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert "tags" in resp["updated_fields"]

    call_kwargs = mock_request.call_args
    payload = call_kwargs[1].get("json") if call_kwargs[1] else call_kwargs.kwargs.get("json")
    assert "tags" in payload
    assert payload["tags"]["add"] == ["urgent", "reviewed"]
    assert payload["tags"]["delete"] == ["pending"]


@patch('requests.post')
def test_update_case_missing_case_id(mock_post):
    mock_post.return_value = mock_token_response()

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {}
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
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
    mock_request.return_value = mock_api_response({
        "_id": "comment-001",
        "comment": "Investigation started"
    })

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "case_id": "case-001",
            "comment": "Investigation started"
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.add_case_comment(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["case_id"] == "case-001"
    assert resp["comment_id"] == "comment-001"


@patch('requests.post')
def test_add_case_comment_missing_case_id(mock_post):
    mock_post.return_value = mock_token_response()

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "comment": "Some comment"
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    try:
        integration_class.add_case_comment(req)
        assert False, "Expected exception"
    except Exception:
        pass


@patch('requests.post')
def test_add_case_comment_missing_comment(mock_post):
    mock_post.return_value = mock_token_response()

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "case_id": "case-001"
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
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

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "case_id": "case-001"
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.get_case_summary(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["case_id"] == "case-001"
    assert resp["summary"] == summary_data


@patch('requests.request')
@patch('requests.post')
def test_get_case_summary_empty(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    empty_resp = Mock()
    empty_resp.status_code = 200
    empty_resp.text = ""
    empty_resp.json.return_value = {}
    mock_request.return_value = empty_resp

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "case_id": "case-001"
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.get_case_summary(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["summary"] == {}


@patch('requests.post')
def test_get_case_summary_missing_case_id(mock_post):
    mock_post.return_value = mock_token_response()

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {}
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    try:
        integration_class.get_case_summary(req)
        assert False, "Expected exception"
    except Exception:
        pass


# -------------------------------------------------------------------
# get_case_scores
# -------------------------------------------------------------------

@patch('requests.request')
@patch('requests.post')
def test_get_case_scores_success(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    scores_data = {"fidelity": 80, "severity": 90, "overall": 85}
    mock_request.return_value = mock_api_response(scores_data)

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "case_id": "case-001"
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.get_case_scores(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["case_id"] == "case-001"
    assert resp["score_details"] == scores_data


@patch('requests.request')
@patch('requests.post')
def test_get_case_scores_empty(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    empty_resp = Mock()
    empty_resp.status_code = 200
    empty_resp.text = ""
    empty_resp.json.return_value = {}
    mock_request.return_value = empty_resp

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "case_id": "case-001"
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.get_case_scores(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["score_details"] == {}


@patch('requests.post')
def test_get_case_scores_missing_case_id(mock_post):
    mock_post.return_value = mock_token_response()

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {}
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    try:
        integration_class.get_case_scores(req)
        assert False, "Expected exception"
    except Exception:
        pass


# -------------------------------------------------------------------
# get_case_alerts
# -------------------------------------------------------------------

@patch('requests.request')
@patch('requests.post')
def test_get_case_alerts_success(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    alerts = [{"_id": "alert-1", "name": "Malware"}, {"_id": "alert-2", "name": "Phishing"}]
    mock_request.return_value = mock_api_response(alerts)

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "case_id": "case-001"
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.get_case_alerts(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["case_id"] == "case-001"
    assert resp["alerts"] == alerts
    assert resp["total_count"] == 2


@patch('requests.request')
@patch('requests.post')
def test_get_case_alerts_wrapped_response(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    alerts = [{"_id": "alert-1"}, {"_id": "alert-2"}]
    mock_request.return_value = mock_api_response({"data": alerts})

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "case_id": "case-001"
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.get_case_alerts(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["alerts"] == alerts
    assert resp["total_count"] == 2


@patch('requests.post')
def test_get_case_alerts_missing_case_id(mock_post):
    mock_post.return_value = mock_token_response()

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {}
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    try:
        integration_class.get_case_alerts(req)
        assert False, "Expected exception"
    except Exception:
        pass


# -------------------------------------------------------------------
# get_case_observables
# -------------------------------------------------------------------

@patch('requests.request')
@patch('requests.post')
def test_get_case_observables_success(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    observables = [{"type": "ip", "value": "1.2.3.4"}, {"type": "domain", "value": "evil.com"}]
    mock_request.return_value = mock_api_response(observables)

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "case_id": "case-001"
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.get_case_observables(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["case_id"] == "case-001"
    assert resp["observables"] == observables
    assert resp["total_count"] == 2


@patch('requests.request')
@patch('requests.post')
def test_get_case_observables_wrapped_response(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    observables = [{"type": "ip", "value": "5.6.7.8"}]
    mock_request.return_value = mock_api_response({"data": observables})

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "case_id": "case-001"
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.get_case_observables(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["observables"] == observables
    assert resp["total_count"] == 1


@patch('requests.post')
def test_get_case_observables_missing_case_id(mock_post):
    mock_post.return_value = mock_token_response()

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {}
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    try:
        integration_class.get_case_observables(req)
        assert False, "Expected exception"
    except Exception:
        pass


# -------------------------------------------------------------------
# list_cases
# -------------------------------------------------------------------

@patch('requests.request')
@patch('requests.post')
def test_list_cases_success(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    cases = [
        {"_id": "case-001", "name": "Case 1", "severity": "High"},
        {"_id": "case-002", "name": "Case 2", "severity": "Low"}
    ]
    mock_request.return_value = mock_api_response(cases)

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "status": "New",
            "severity": "High"
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.list_cases(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["cases"] == cases
    assert resp["total_count"] == 2


@patch('requests.request')
@patch('requests.post')
def test_list_cases_wrapped_response(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    cases = [{"_id": "case-001"}]
    mock_request.return_value = mock_api_response({"data": cases})

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {}
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.list_cases(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["cases"] == cases
    assert resp["total_count"] == 1


@patch('requests.request')
@patch('requests.post')
def test_list_cases_empty(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    empty_resp = Mock()
    empty_resp.status_code = 200
    empty_resp.text = "[]"
    empty_resp.json.return_value = []
    mock_request.return_value = empty_resp

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {}
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.list_cases(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["cases"] == []
    assert resp["total_count"] == 0


@patch('requests.request')
@patch('requests.post')
def test_list_cases_with_tags_string(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    mock_request.return_value = mock_api_response([])

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "tags": "urgent,reviewed"
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.list_cases(req)

    assert resp is not None
    assert resp["status"] == "success"

    call_kwargs = mock_request.call_args
    params = call_kwargs[1].get("params") if call_kwargs[1] else call_kwargs.kwargs.get("params")
    assert params["tags"] == ["urgent", "reviewed"]


@patch('requests.request')
@patch('requests.post')
def test_list_cases_with_pagination(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    mock_request.return_value = mock_api_response([{"_id": "case-010"}])

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "page": 2,
            "size": 10
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.list_cases(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["total_count"] == 1

    call_kwargs = mock_request.call_args
    params = call_kwargs[1].get("params") if call_kwargs[1] else call_kwargs.kwargs.get("params")
    assert params["page"] == 2
    assert params["size"] == 10


# -------------------------------------------------------------------
# get_case_details
# -------------------------------------------------------------------

@patch('requests.request')
@patch('requests.post')
def test_get_case_details_success(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    case_data = {
        "_id": "case-001",
        "name": "Test Case",
        "severity": "High",
        "status": "New",
        "assignee": "analyst1",
        "tags": ["urgent"],
        "description": "Full details"
    }
    mock_request.return_value = mock_api_response(case_data)

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "case_id": "case-001"
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.get_case_details(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["case_id"] == "case-001"
    assert resp["case_details"] == case_data


@patch('requests.request')
@patch('requests.post')
def test_get_case_details_empty(mock_post, mock_request):
    mock_post.return_value = mock_token_response()
    empty_resp = Mock()
    empty_resp.status_code = 200
    empty_resp.text = ""
    empty_resp.json.return_value = {}
    mock_request.return_value = empty_resp

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {
            "case_id": "case-001"
        }
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.get_case_details(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["case_details"] == {}


@patch('requests.post')
def test_get_case_details_missing_case_id(mock_post):
    mock_post.return_value = mock_token_response()

    req = """
    {
        "connectionParameters": {
            "base_url": "%s",
            "api_token": "%s"
        },
        "parameters": {}
    }
    """ % (BASE_URL, API_TOKEN)

    req = pykson.from_json(req, RequestBody, True)
    try:
        integration_class.get_case_details(req)
        assert False, "Expected exception"
    except Exception:
        pass
