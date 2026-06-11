import pytest
from unittest.mock import patch, MagicMock
from app.wiz import Wiz
from app.model.request_body import RequestBody
from pykson import Pykson
import json

pykson = Pykson()
integration_class = Wiz()

CONNECTION_PARAMS = {
    "client_id": "test_client_id",
    "client_secret": "test_client_secret",
    "region": "us1",
}

AUTH_SUCCESS = {"access_token": "test_token_123"}


def _make_request(params=None):
    body = {"connectionParameters": CONNECTION_PARAMS, "parameters": params or {}}
    return pykson.from_json(json.dumps(body), RequestBody, True)


def _mock_response(status_code=200, json_data=None):
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_data if json_data is not None else {}
    return mock


class TestTestConnection:
    @patch("app.wiz.requests.post")
    def test_success(self, mock_post):
        mock_post.side_effect = [
            _mock_response(200, AUTH_SUCCESS),
            _mock_response(200, {"data": {"userInfo": {"id": "1", "email": "u@wiz.io"}}}),
        ]
        result = integration_class.test_connection(CONNECTION_PARAMS)
        assert result["status"] == "success"

    @patch("app.wiz.requests.post")
    def test_auth_failure(self, mock_post):
        mock_post.return_value = _mock_response(401, {"error": "invalid_client"})
        with pytest.raises(Exception, match="Authentication failed"):
            integration_class.test_connection(CONNECTION_PARAMS)

    def test_missing_client_id(self):
        with pytest.raises(Exception, match="client_id is required"):
            integration_class.test_connection({"client_secret": "secret", "region": "us1"})

    def test_missing_client_secret(self):
        with pytest.raises(Exception, match="client_secret is required"):
            integration_class.test_connection({"client_id": "id", "region": "us1"})


class TestGetIssues:
    @patch("app.wiz.requests.post")
    def test_success(self, mock_post):
        mock_post.side_effect = [
            _mock_response(200, AUTH_SUCCESS),
            _mock_response(200, {"data": {"issues": {
                "nodes": [{"id": "issue-1", "title": "Finding", "severity": "HIGH"}],
                "totalCount": 1,
                "pageInfo": {"hasNextPage": False, "endCursor": None},
            }}}),
        ]
        resp = integration_class.get_issues(_make_request({"severity": "HIGH"}))
        assert resp["status"] == "success"
        assert len(resp["issues"]) == 1
        assert resp["issues"][0]["id"] == "issue-1"
        assert resp["total_count"] == 1

    @patch("app.wiz.requests.post")
    def test_no_filters(self, mock_post):
        mock_post.side_effect = [
            _mock_response(200, AUTH_SUCCESS),
            _mock_response(200, {"data": {"issues": {"nodes": [], "totalCount": 0, "pageInfo": {}}}}),
        ]
        resp = integration_class.get_issues(_make_request())
        assert resp["issues"] == []
        assert resp["total_count"] == 0


class TestGetIssueById:
    @patch("app.wiz.requests.post")
    def test_success(self, mock_post):
        mock_post.side_effect = [
            _mock_response(200, AUTH_SUCCESS),
            _mock_response(200, {"data": {"issue": {"id": "issue-123", "title": "Test", "severity": "CRITICAL"}}}),
        ]
        resp = integration_class.get_issue_by_id(_make_request({"issue_id": "issue-123"}))
        assert resp["status"] == "success"
        assert resp["issue"]["id"] == "issue-123"

    @patch("app.wiz.requests.post")
    def test_missing_issue_id(self, mock_post):
        mock_post.return_value = _mock_response(200, AUTH_SUCCESS)
        with pytest.raises(Exception, match="issue_id is required"):
            integration_class.get_issue_by_id(_make_request({}))

    @patch("app.wiz.requests.post")
    def test_empty_issue_id(self, mock_post):
        mock_post.return_value = _mock_response(200, AUTH_SUCCESS)
        with pytest.raises(Exception, match="issue_id is required"):
            integration_class.get_issue_by_id(_make_request({"issue_id": ""}))


class TestGetIssueEvidence:
    @patch("app.wiz.requests.post")
    def test_success(self, mock_post):
        mock_post.side_effect = [
            _mock_response(200, AUTH_SUCCESS),
            _mock_response(200, {"data": {"issue": {
                "id": "issue-123", "title": "Test",
                "evidence": {"currentValue": "open", "expectedValue": "closed"},
                "notes": [{"text": "Investigating", "createdAt": "2025-01-01"}],
            }}}),
        ]
        resp = integration_class.get_issue_evidence(_make_request({"issue_id": "issue-123"}))
        assert resp["status"] == "success"
        assert resp["issue_id"] == "issue-123"
        assert resp["evidence"]["currentValue"] == "open"
        assert len(resp["notes"]) == 1

    @patch("app.wiz.requests.post")
    def test_missing_issue_id(self, mock_post):
        mock_post.return_value = _mock_response(200, AUTH_SUCCESS)
        with pytest.raises(Exception, match="issue_id is required"):
            integration_class.get_issue_evidence(_make_request({}))


class TestGetResources:
    @patch("app.wiz.requests.post")
    def test_success_with_filters(self, mock_post):
        mock_post.side_effect = [
            _mock_response(200, AUTH_SUCCESS),
            _mock_response(200, {"data": {"resources": {
                "nodes": [{"id": "res-1", "name": "my-vm", "type": "VirtualMachine"}],
                "totalCount": 1,
                "pageInfo": {"hasNextPage": False},
            }}}),
        ]
        resp = integration_class.get_resources(_make_request({
            "resource_type": "VirtualMachine", "project_name": "my-project"
        }))
        assert resp["status"] == "success"
        assert len(resp["resources"]) == 1
        assert resp["resources"][0]["name"] == "my-vm"

    @patch("app.wiz.requests.post")
    def test_empty_results(self, mock_post):
        mock_post.side_effect = [
            _mock_response(200, AUTH_SUCCESS),
            _mock_response(200, {"data": {"resources": {"nodes": [], "totalCount": 0, "pageInfo": {}}}}),
        ]
        resp = integration_class.get_resources(_make_request())
        assert resp["resources"] == []


class TestGetResource:
    @patch("app.wiz.requests.post")
    def test_by_resource_id(self, mock_post):
        mock_post.side_effect = [
            _mock_response(200, AUTH_SUCCESS),
            _mock_response(200, {"data": {"resource": {"id": "res-123", "name": "my-instance", "type": "EC2"}}}),
        ]
        resp = integration_class.get_resource(_make_request({"resource_id": "res-123"}))
        assert resp["status"] == "success"
        assert resp["resource"]["id"] == "res-123"

    @patch("app.wiz.requests.post")
    def test_by_resource_name(self, mock_post):
        mock_post.side_effect = [
            _mock_response(200, AUTH_SUCCESS),
            _mock_response(200, {"data": {"resources": {
                "nodes": [{"id": "res-456", "name": "my-bucket", "type": "S3"}],
                "totalCount": 1,
            }}}),
        ]
        resp = integration_class.get_resource(_make_request({"resource_name": "my-bucket"}))
        assert resp["status"] == "success"
        assert resp["resource"]["name"] == "my-bucket"

    @patch("app.wiz.requests.post")
    def test_missing_both_params(self, mock_post):
        mock_post.return_value = _mock_response(200, AUTH_SUCCESS)
        with pytest.raises(Exception, match="At least one of"):
            integration_class.get_resource(_make_request({}))


class TestGetProjectTeam:
    @patch("app.wiz.requests.post")
    def test_success(self, mock_post):
        mock_post.side_effect = [
            _mock_response(200, AUTH_SUCCESS),
            _mock_response(200, {"data": {"projects": {"nodes": [{
                "id": "proj-1", "name": "my-project",
                "owners": [{"id": "u1", "email": "owner@test.com", "name": "Owner"}],
                "securityChampions": [{"id": "u2", "email": "sec@test.com", "name": "Sec"}],
                "projectMembers": [{"id": "u3", "email": "dev@test.com", "name": "Dev"}],
            }]}}}),
        ]
        resp = integration_class.get_project_team(_make_request({"project_name": "my-project"}))
        assert resp["status"] == "success"
        assert resp["project_name"] == "my-project"
        assert len(resp["owners"]) == 1
        assert len(resp["security_champions"]) == 1
        assert len(resp["members"]) == 1

    @patch("app.wiz.requests.post")
    def test_project_not_found(self, mock_post):
        mock_post.side_effect = [
            _mock_response(200, AUTH_SUCCESS),
            _mock_response(200, {"data": {"projects": {"nodes": []}}}),
        ]
        resp = integration_class.get_project_team(_make_request({"project_name": "nonexistent"}))
        assert resp["project_name"] == "nonexistent"
        assert resp["owners"] == []

    @patch("app.wiz.requests.post")
    def test_missing_project_name(self, mock_post):
        mock_post.return_value = _mock_response(200, AUTH_SUCCESS)
        with pytest.raises(Exception, match="project_name is required"):
            integration_class.get_project_team(_make_request({}))


class TestErrorHandling:
    @patch("app.wiz.requests.post")
    def test_connection_error_auth(self, mock_post):
        import requests as req
        mock_post.side_effect = req.exceptions.ConnectionError()
        with pytest.raises(Exception, match="Unable to connect"):
            integration_class.test_connection(CONNECTION_PARAMS)

    @patch("app.wiz.requests.post")
    def test_timeout_auth(self, mock_post):
        import requests as req
        mock_post.side_effect = req.exceptions.Timeout()
        with pytest.raises(Exception, match="timed out"):
            integration_class.test_connection(CONNECTION_PARAMS)

    @patch("app.wiz.requests.post")
    def test_graphql_error(self, mock_post):
        mock_post.side_effect = [
            _mock_response(200, AUTH_SUCCESS),
            _mock_response(200, {"errors": [{"message": "Field not found"}], "data": None}),
        ]
        with pytest.raises(Exception, match="GraphQL error"):
            integration_class.get_issues(_make_request())

    @patch("app.wiz.time.sleep")
    @patch("app.wiz.requests.post")
    def test_429_retry_then_success(self, mock_post, mock_sleep):
        mock_post.side_effect = [
            _mock_response(200, AUTH_SUCCESS),
            _mock_response(429),
            _mock_response(200, {"data": {"issues": {"nodes": [], "totalCount": 0, "pageInfo": {}}}}),
        ]
        resp = integration_class.get_issues(_make_request())
        assert resp["status"] == "success"
        assert mock_sleep.call_count == 1

    @patch("app.wiz.time.sleep")
    @patch("app.wiz.requests.post")
    def test_429_retry_exhausted(self, mock_post, mock_sleep):
        mock_post.side_effect = [
            _mock_response(200, AUTH_SUCCESS),
            _mock_response(429),
            _mock_response(429),
            _mock_response(429),
        ]
        with pytest.raises(Exception, match="Rate limit exceeded"):
            integration_class.get_issues(_make_request())

    @patch("app.wiz.time.sleep")
    @patch("app.wiz.requests.post")
    def test_500_retry_then_success(self, mock_post, mock_sleep):
        mock_post.side_effect = [
            _mock_response(200, AUTH_SUCCESS),
            _mock_response(500),
            _mock_response(200, {"data": {"issues": {"nodes": [], "totalCount": 0, "pageInfo": {}}}}),
        ]
        resp = integration_class.get_issues(_make_request())
        assert resp["status"] == "success"
        assert mock_sleep.call_count == 1

    @patch("app.wiz.requests.post")
    def test_timeout_graphql(self, mock_post):
        import requests as req
        mock_post.side_effect = [
            _mock_response(200, AUTH_SUCCESS),
            req.exceptions.Timeout(),
        ]
        with pytest.raises(Exception, match="timed out"):
            integration_class.get_issues(_make_request())
