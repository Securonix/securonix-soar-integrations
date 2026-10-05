import json
import pytest
from unittest.mock import patch, MagicMock
from pykson import Pykson
from app.checkpoint_xdr import CheckpointXdr
from app.model.request_body import RequestBody

pykson = Pykson()

CP = {
    "gateway_url": "https://cloudinfra-gw.portal.checkpoint.com",
    "client_id": "test-client",
    "access_key": "test-key",
}

# Minimal JWT with exp = far future (base64url of {"exp": 9999999999})
_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.sig"


def _make_request(params=None, cp=None):
    body = {"connectionParameters": cp or CP, "parameters": params or {}}
    return pykson.from_json(json.dumps(body), RequestBody, True)


def _token_resp():
    m = MagicMock()
    m.status_code = 200
    m.json.return_value = {"data": {"token": _JWT}}
    return m


def _ok(body):
    m = MagicMock()
    m.status_code = 200
    m.content = b"x"
    m.json.return_value = body
    return m


def _no_content():
    m = MagicMock()
    m.status_code = 204
    m.content = b""
    return m


def _err(status, body=None):
    m = MagicMock()
    m.status_code = status
    m.content = b"x"
    m.json.return_value = body or {"message": "error"}
    m.text = "error"
    return m


# ------------------------------------------------------------------
# Token acquisition and caching
# ------------------------------------------------------------------
class TestGetToken:
    def test_success_and_cache(self):
        import app.checkpoint_xdr as mod
        mod._token_cache.clear()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()) as mock_post:
            t1 = mod._get_token("https://gw", "cid", "key", 30, True, None)
            t2 = mod._get_token("https://gw", "cid", "key", 30, True, None)
        assert t1 == _JWT
        assert mock_post.call_count == 1  # second call served from cache

    def test_401_raises(self):
        import app.checkpoint_xdr as mod
        mod._token_cache.clear()
        with patch("app.checkpoint_xdr.requests.post", return_value=_err(401)):
            with pytest.raises(Exception, match="Authentication failed"):
                mod._get_token("https://gw", "cid", "key", 30, True, None)

    def test_connection_error_raises(self):
        import requests as req
        import app.checkpoint_xdr as mod
        mod._token_cache.clear()
        with patch("app.checkpoint_xdr.requests.post", side_effect=req.exceptions.ConnectionError):
            with pytest.raises(Exception, match="Unable to connect"):
                mod._get_token("https://gw", "cid", "key", 30, True, None)

    def test_timeout_raises(self):
        import requests as req
        import app.checkpoint_xdr as mod
        mod._token_cache.clear()
        with patch("app.checkpoint_xdr.requests.post", side_effect=req.exceptions.Timeout):
            with pytest.raises(Exception, match="timed out"):
                mod._get_token("https://gw", "cid", "key", 30, True, None)


# ------------------------------------------------------------------
# 401 retry on API call
# ------------------------------------------------------------------
class TestRetry:
    def test_401_retry_reacquires_token(self):
        xdr = CheckpointXdr()
        token_resp = _token_resp()
        first_401 = _err(401)
        second_ok = _ok({"id": "inc1"})
        with patch("app.checkpoint_xdr.requests.post", return_value=token_resp), \
             patch("app.checkpoint_xdr.requests.request", side_effect=[first_401, second_ok]):
            result = xdr.get_incident_by_id(_make_request({"incident_id": "inc1"}))
        assert result["status"] == "success"


# ------------------------------------------------------------------
# test_connection
# ------------------------------------------------------------------
class TestTestConnection:
    def test_success(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok({"version": "1.0"})):
            result = xdr.test_connection(CP)
        assert result["status"] == "success"
        assert "CheckPoint XDR" in result["message"]

    def test_connection_error(self):
        import requests as req
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", side_effect=req.exceptions.ConnectionError):
            with pytest.raises(Exception, match="Unable to connect"):
                xdr.test_connection(CP)


# ------------------------------------------------------------------
# get_incidents
# ------------------------------------------------------------------
class TestGetIncidents:
    def test_params_mapped(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok([])) as mock_req:
            xdr.get_incidents(_make_request({
                "from_date": "2024-01-01T00:00:00Z",
                "to_date": "2024-01-31T00:00:00Z",
                "filter_by": "createdAt",
                "limit": "100",
                "offset": "50",
            }))
        params = mock_req.call_args.kwargs["params"]
        assert params["from"] == "2024-01-01T00:00:00Z"
        assert params["to"] == "2024-01-31T00:00:00Z"
        assert params["filterBy"] == "createdAt"
        assert params["limit"] == 100
        assert params["offset"] == 50

    def test_success(self):
        xdr = CheckpointXdr()
        incidents = [{"id": "1"}]
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok(incidents)):
            result = xdr.get_incidents(_make_request({}))
        assert result["status"] == "success"
        assert result["incidents"] == incidents


# ------------------------------------------------------------------
# get_incident_by_id
# ------------------------------------------------------------------
class TestGetIncidentById:
    def test_success(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok({"id": "abc"})):
            result = xdr.get_incident_by_id(_make_request({"incident_id": "abc"}))
        assert result["incident"]["id"] == "abc"

    def test_404_raises(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_err(404)):
            with pytest.raises(Exception, match="not found"):
                xdr.get_incident_by_id(_make_request({"incident_id": "missing"}))


# ------------------------------------------------------------------
# update_incident
# ------------------------------------------------------------------
class TestUpdateIncident:
    def test_status_required_in_body(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok({"id": "1"})) as mock_req:
            xdr.update_incident(_make_request({"incident_id": "1", "status": "in progress"}))
        body = mock_req.call_args.kwargs["json"]
        assert body["status"] == "in progress"

    def test_optional_fields_camelcase(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok({"id": "1"})) as mock_req:
            xdr.update_incident(_make_request({
                "incident_id": "1",
                "status": "new",
                "assignee_name": "John",
                "assignee_email": "j@example.com",
                "is_prevented": True,
                "follow_up": False,
            }))
        body = mock_req.call_args.kwargs["json"]
        assert body["assigneeName"] == "John"
        assert body["assigneeEmail"] == "j@example.com"
        assert body["isPrevented"] is True
        assert body["followUp"] is False

    def test_optional_fields_absent_when_not_provided(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok({"id": "1"})) as mock_req:
            xdr.update_incident(_make_request({"incident_id": "1", "status": "new"}))
        body = mock_req.call_args.kwargs["json"]
        assert "assigneeName" not in body
        assert "followUp" not in body


# ------------------------------------------------------------------
# get_incident_comments
# ------------------------------------------------------------------
class TestGetIncidentComments:
    def test_success(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok([{"text": "hi"}])):
            result = xdr.get_incident_comments(_make_request({"incident_id": "1"}))
        assert result["status"] == "success"
        assert result["comments"] == [{"text": "hi"}]


# ------------------------------------------------------------------
# add_incident_comment
# ------------------------------------------------------------------
class TestAddIncidentComment:
    def test_body_and_success(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok({})) as mock_req:
            result = xdr.add_incident_comment(_make_request({"incident_id": "1", "comment": "test"}))
        assert result["message"] == "Comment added successfully."
        assert mock_req.call_args.kwargs["json"] == {"comment": "test"}


# ------------------------------------------------------------------
# get_audit_logs
# ------------------------------------------------------------------
class TestGetAuditLogs:
    def test_page_limit_params(self):
        xdr = CheckpointXdr()
        api_resp = {"limit": 10, "offset": 0, "total": 5, "hasNext": False, "results": []}
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok(api_resp)) as mock_req:
            result = xdr.get_audit_logs(_make_request({"limit": "10", "page": "2"}))
        params = mock_req.call_args.kwargs["params"]
        assert params["limit"] == 10
        assert params["page"] == 2
        assert result["total"] == 5
        assert result["hasNext"] is False

    def test_date_mapping(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok({})) as mock_req:
            xdr.get_audit_logs(_make_request({"from_date": "2024-01-01", "to_date": "2024-01-31"}))
        params = mock_req.call_args.kwargs["params"]
        assert params["fromDate"] == "2024-01-01"
        assert params["toDate"] == "2024-01-31"

    def test_array_params(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok({})) as mock_req:
            xdr.get_audit_logs(_make_request({"status": ["Completed", "Failed"]}))
        params = mock_req.call_args.kwargs["params"]
        assert params["status"] == ["Completed", "Failed"]


# ------------------------------------------------------------------
# create_exclusion
# ------------------------------------------------------------------
class TestCreateExclusion:
    def test_required_fields(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok({"id": "ex1"})) as mock_req:
            result = xdr.create_exclusion(_make_request({"exclusion_type": "ip", "value": "1.2.3.4"}))
        body = mock_req.call_args.kwargs["json"]
        assert body["type"] == "ip"
        assert body["value"] == "1.2.3.4"
        assert "comment" not in body
        assert "expirationDate" not in body
        assert result["status"] == "success"

    def test_optional_fields_included(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok({})) as mock_req:
            xdr.create_exclusion(_make_request({
                "exclusion_type": "host",
                "value": "evil.com",
                "comment": "test",
                "expiration_date": "2025-12-31T00:00:00Z",
            }))
        body = mock_req.call_args.kwargs["json"]
        assert body["comment"] == "test"
        assert body["expirationDate"] == "2025-12-31T00:00:00Z"


# ------------------------------------------------------------------
# get_exclusions
# ------------------------------------------------------------------
class TestGetExclusions:
    def test_page_limit_from_to(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok([])) as mock_req:
            xdr.get_exclusions(_make_request({
                "limit": "50", "page": "3",
                "from_date": "2024-01-01", "to_date": "2024-06-01",
            }))
        params = mock_req.call_args.kwargs["params"]
        assert params["limit"] == 50
        assert params["page"] == 3
        assert params["fromDate"] == "2024-01-01"
        assert params["toDate"] == "2024-06-01"


# ------------------------------------------------------------------
# get_exclusion_by_id
# ------------------------------------------------------------------
class TestGetExclusionById:
    def test_success(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok({"id": "ex1"})):
            result = xdr.get_exclusion_by_id(_make_request({"exclusion_id": "ex1"}))
        assert result["exclusion"]["id"] == "ex1"

    def test_404_raises(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_err(404)):
            with pytest.raises(Exception, match="not found"):
                xdr.get_exclusion_by_id(_make_request({"exclusion_id": "missing"}))


# ------------------------------------------------------------------
# update_exclusion
# ------------------------------------------------------------------
class TestUpdateExclusion:
    def test_only_comment_and_expiration_in_body(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok({})) as mock_req:
            xdr.update_exclusion(_make_request({
                "exclusion_id": "ex1",
                "comment": "updated",
                "expiration_date": "2026-01-01T00:00:00Z",
            }))
        body = mock_req.call_args.kwargs["json"]
        assert body == {"comment": "updated", "expirationDate": "2026-01-01T00:00:00Z"}
        assert "type" not in body
        assert "value" not in body

    def test_empty_body_when_no_optional_fields(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok({})) as mock_req:
            xdr.update_exclusion(_make_request({"exclusion_id": "ex1"}))
        body = mock_req.call_args.kwargs["json"]
        assert body == {}

    def test_404_raises(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_err(404)):
            with pytest.raises(Exception, match="not found"):
                xdr.update_exclusion(_make_request({"exclusion_id": "missing"}))


# ------------------------------------------------------------------
# delete_exclusion
# ------------------------------------------------------------------
class TestDeleteExclusion:
    def test_success(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_no_content()):
            result = xdr.delete_exclusion(_make_request({"exclusion_id": "ex1"}))
        assert result["message"] == "Exclusion deleted successfully."

    def test_404_raises(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_err(404)):
            with pytest.raises(Exception, match="not found"):
                xdr.delete_exclusion(_make_request({"exclusion_id": "missing"}))


# ------------------------------------------------------------------
# get_responses_by_incident
# ------------------------------------------------------------------
class TestGetResponsesByIncident:
    def test_success(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok([{"id": "r1"}])):
            result = xdr.get_responses_by_incident(_make_request({"incident_id": "inc1"}))
        assert result["responses"] == [{"id": "r1"}]


# ------------------------------------------------------------------
# execute_response_action
# ------------------------------------------------------------------
class TestExecuteResponseAction:
    @pytest.mark.parametrize("action", ["apply", "revert", "reject"])
    def test_action_and_body(self, action):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok({"success": True})) as mock_req:
            result = xdr.execute_response_action(_make_request({
                "action": action,
                "response_ids": ["r1", "r2"],
            }))
        url = mock_req.call_args.args[1]
        assert url.endswith(f"/responses/action/{action}")
        assert mock_req.call_args.kwargs["json"] == {"responsesIds": ["r1", "r2"]}
        assert result["status"] == "success"

    def test_string_response_ids_wrapped(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok({})) as mock_req:
            xdr.execute_response_action(_make_request({"action": "apply", "response_ids": "r1"}))
        assert mock_req.call_args.kwargs["json"] == {"responsesIds": ["r1"]}


# ------------------------------------------------------------------
# get_data_sources
# ------------------------------------------------------------------
class TestGetDataSources:
    def test_success(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_ok([{"name": "ds1"}])):
            result = xdr.get_data_sources(_make_request({}))
        assert result["data_sources"] == [{"name": "ds1"}]


# ------------------------------------------------------------------
# Error handling
# ------------------------------------------------------------------
class TestErrorHandling:
    def test_403_raises(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_err(403)):
            with pytest.raises(Exception, match="Authorization failed"):
                xdr.get_data_sources(_make_request({}))

    def test_500_raises(self):
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", return_value=_err(500)):
            with pytest.raises(Exception, match="server error"):
                xdr.get_data_sources(_make_request({}))

    def test_connection_error_on_api_call(self):
        import requests as req
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", side_effect=req.exceptions.ConnectionError):
            with pytest.raises(Exception, match="Unable to connect"):
                xdr.get_data_sources(_make_request({}))

    def test_timeout_on_api_call(self):
        import requests as req
        xdr = CheckpointXdr()
        with patch("app.checkpoint_xdr.requests.post", return_value=_token_resp()), \
             patch("app.checkpoint_xdr.requests.request", side_effect=req.exceptions.Timeout):
            with pytest.raises(Exception, match="timed out"):
                xdr.get_data_sources(_make_request({}))
