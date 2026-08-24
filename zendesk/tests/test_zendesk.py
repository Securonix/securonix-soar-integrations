import pytest
from unittest.mock import patch, MagicMock
from app.zendesk import Zendesk


def _conn_params():
    return {
        "subdomain": "testcompany",
        "email": "agent@testcompany.com",
        "api_token": "test_token_123",
        "timeout": "30",
        "verify_ssl": "true",
    }


def _request(parameters=None, connection_params=None):
    req = MagicMock()
    req.parameters = parameters or {}
    req.connectionParameters = connection_params or _conn_params()
    return req


def _mock_response(status_code=200, json_data=None, headers=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.headers = headers or {}
    return resp


class TestTestConnection:

    @patch("app.zendesk.requests.request")
    def test_success(self, mock_request):
        mock_request.return_value = _mock_response(200, {"user": {"name": "Test Agent", "email": "agent@testcompany.com"}})
        z = Zendesk()
        result = z.test_connection(_conn_params())
        assert result["status"] == "success"
        assert "Test Agent" in result["message"]

    @patch("app.zendesk.requests.request")
    def test_auth_failure(self, mock_request):
        mock_request.return_value = _mock_response(401)
        z = Zendesk()
        with pytest.raises(Exception, match="Authentication failed"):
            z.test_connection(_conn_params())

    def test_missing_subdomain(self):
        z = Zendesk()
        params = _conn_params()
        params["subdomain"] = ""
        with pytest.raises(Exception, match="subdomain is required"):
            z.test_connection(params)

    def test_missing_api_token(self):
        z = Zendesk()
        params = _conn_params()
        params["api_token"] = ""
        with pytest.raises(Exception, match="api_token is required"):
            z.test_connection(params)

    def test_invalid_timeout(self):
        z = Zendesk()
        params = _conn_params()
        params["timeout"] = "-5"
        with pytest.raises(Exception, match="timeout must be a positive integer"):
            z.test_connection(params)

    def test_non_numeric_timeout(self):
        z = Zendesk()
        params = _conn_params()
        params["timeout"] = "abc"
        with pytest.raises(Exception, match="timeout must be a positive integer"):
            z.test_connection(params)

    def test_invalid_verify_ssl_type(self):
        z = Zendesk()
        params = _conn_params()
        params["verify_ssl"] = ["true"]
        with pytest.raises(Exception, match="verify_ssl must be a boolean value"):
            z.test_connection(params)


class TestCreateTicket:

    @patch("app.zendesk.requests.request")
    def test_success(self, mock_request):
        mock_request.return_value = _mock_response(200, {"ticket": {"id": 1, "subject": "Test", "status": "new"}})
        z = Zendesk()
        req = _request({"subject": "Test", "description": "Test body"})
        result = z.create_ticket(req)
        assert result["status"] == "success"
        assert result["ticket"]["id"] == 1

    @patch("app.zendesk.requests.request")
    def test_with_priority_and_tags(self, mock_request):
        mock_request.return_value = _mock_response(200, {"ticket": {"id": 2, "priority": "high", "tags": ["security"]}})
        z = Zendesk()
        req = _request({"subject": "Urgent", "description": "Body", "priority": "high", "tags": "security,incident"})
        result = z.create_ticket(req)
        assert result["status"] == "success"

    @patch("app.zendesk.requests.request")
    def test_with_assignee_email_resolution(self, mock_request):
        responses = [
            _mock_response(200, {"users": [{"id": 42}]}),
            _mock_response(200, {"ticket": {"id": 3, "assignee_id": 42}}),
        ]
        mock_request.side_effect = responses
        z = Zendesk()
        req = _request({"subject": "Assigned", "description": "Body", "assignee_email": "user@test.com"})
        result = z.create_ticket(req)
        assert result["status"] == "success"

    def test_missing_subject(self):
        z = Zendesk()
        req = _request({"description": "Body"})
        with pytest.raises(Exception, match="subject is required"):
            z.create_ticket(req)

    def test_missing_description(self):
        z = Zendesk()
        req = _request({"subject": "Test"})
        with pytest.raises(Exception, match="description is required"):
            z.create_ticket(req)

    def test_subject_too_long(self):
        z = Zendesk()
        req = _request({"subject": "x" * 151, "description": "Body"})
        with pytest.raises(Exception, match="exceeds maximum length"):
            z.create_ticket(req)

    def test_invalid_priority(self):
        z = Zendesk()
        req = _request({"subject": "Test", "description": "Body", "priority": "critical"})
        with pytest.raises(Exception, match="priority must be one of"):
            z.create_ticket(req)

    def test_invalid_status(self):
        z = Zendesk()
        req = _request({"subject": "Test", "description": "Body", "status": "closed"})
        with pytest.raises(Exception, match="status must be one of"):
            z.create_ticket(req)


class TestGetTicketDetails:

    @patch("app.zendesk.requests.request")
    def test_success(self, mock_request):
        mock_request.return_value = _mock_response(200, {"ticket": {"id": 1, "subject": "Test", "status": "open"}})
        z = Zendesk()
        req = _request({"ticket_id": "1"})
        result = z.get_ticket_details(req)
        assert result["status"] == "success"
        assert result["ticket"]["id"] == 1

    @patch("app.zendesk.requests.request")
    def test_not_found(self, mock_request):
        mock_request.return_value = _mock_response(404)
        z = Zendesk()
        req = _request({"ticket_id": "999"})
        result = z.get_ticket_details(req)
        assert result["status"] == "success"
        assert result["ticket"] == {}
        assert "not found" in result["message"]

    def test_missing_ticket_id(self):
        z = Zendesk()
        req = _request({})
        with pytest.raises(Exception, match="ticket_id is required"):
            z.get_ticket_details(req)

    def test_invalid_ticket_id(self):
        z = Zendesk()
        req = _request({"ticket_id": "abc"})
        with pytest.raises(Exception, match="ticket_id must be a positive integer"):
            z.get_ticket_details(req)


class TestUpdateTicket:

    @patch("app.zendesk.requests.request")
    def test_success(self, mock_request):
        mock_request.return_value = _mock_response(200, {"ticket": {"id": 1, "priority": "high"}})
        z = Zendesk()
        req = _request({"ticket_id": "1", "priority": "high"})
        result = z.update_ticket(req)
        assert result["status"] == "success"

    def test_no_fields_to_update(self):
        z = Zendesk()
        req = _request({"ticket_id": "1"})
        with pytest.raises(Exception, match="At least one field"):
            z.update_ticket(req)

    def test_invalid_status_closed(self):
        z = Zendesk()
        req = _request({"ticket_id": "1", "status": "closed"})
        with pytest.raises(Exception, match="status must be one of"):
            z.update_ticket(req)


class TestAddComment:

    @patch("app.zendesk.requests.request")
    def test_public_comment(self, mock_request):
        mock_request.return_value = _mock_response(200, {"ticket": {"id": 1}})
        z = Zendesk()
        req = _request({"ticket_id": "1", "comment_body": "This is a comment"})
        result = z.add_comment(req)
        assert result["status"] == "success"
        call_kwargs = mock_request.call_args
        body = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert body["ticket"]["comment"]["public"] is True

    @patch("app.zendesk.requests.request")
    def test_internal_note(self, mock_request):
        mock_request.return_value = _mock_response(200, {"ticket": {"id": 1}})
        z = Zendesk()
        req = _request({"ticket_id": "1", "comment_body": "Internal note", "public": "false"})
        result = z.add_comment(req)
        assert result["status"] == "success"
        call_kwargs = mock_request.call_args
        body = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert body["ticket"]["comment"]["public"] is False

    def test_missing_comment_body(self):
        z = Zendesk()
        req = _request({"ticket_id": "1"})
        with pytest.raises(Exception, match="comment_body is required"):
            z.add_comment(req)


class TestSearchTickets:

    @patch("app.zendesk.requests.request")
    def test_keyword_search(self, mock_request):
        mock_request.return_value = _mock_response(200, {"results": [{"id": 1}], "count": 1, "next_page": None})
        z = Zendesk()
        req = _request({"query": "ransomware"})
        result = z.search_tickets(req)
        assert result["status"] == "success"
        assert result["count"] == 1
        call_kwargs = mock_request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params")
        assert "type:ticket" in params["query"]
        assert "ransomware" in params["query"]

    @patch("app.zendesk.requests.request")
    def test_with_filters(self, mock_request):
        mock_request.return_value = _mock_response(200, {"results": [], "count": 0, "next_page": None})
        z = Zendesk()
        req = _request({"status": "open", "tags": "security,urgent", "created_after": "2024-01-01"})
        result = z.search_tickets(req)
        assert result["status"] == "success"
        call_kwargs = mock_request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params")
        assert "status:open" in params["query"]
        assert "tags:security" in params["query"]
        assert "created>2024-01-01" in params["query"]

    @patch("app.zendesk.requests.request")
    def test_with_assignee_email(self, mock_request):
        mock_request.return_value = _mock_response(200, {"results": [], "count": 0, "next_page": None})
        z = Zendesk()
        req = _request({"assignee_email": "agent@test.com"})
        result = z.search_tickets(req)
        assert result["status"] == "success"
        call_kwargs = mock_request.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params")
        assert "assignee:agent@test.com" in params["query"]

    @patch("app.zendesk.requests.request")
    def test_pagination(self, mock_request):
        mock_request.return_value = _mock_response(200, {"results": [{"id": 1}], "count": 50, "next_page": "https://test.zendesk.com/api/v2/search.json?page=2"})
        z = Zendesk()
        req = _request({"query": "test", "page_size": "10"})
        result = z.search_tickets(req)
        assert result["has_more"] is True
        assert result["next_page"] is not None

    def test_invalid_page_size(self):
        z = Zendesk()
        req = _request({"query": "test", "page_size": "200"})
        with pytest.raises(Exception, match="page_size must be between 1 and 100"):
            z.search_tickets(req)

    def test_invalid_status(self):
        z = Zendesk()
        req = _request({"status": "invalid"})
        with pytest.raises(Exception, match="status must be one of"):
            z.search_tickets(req)

    def test_invalid_created_after_format(self):
        z = Zendesk()
        req = _request({"created_after": "not-a-date"})
        with pytest.raises(Exception, match="created_after must be a valid ISO date"):
            z.search_tickets(req)

    def test_invalid_created_before_format(self):
        z = Zendesk()
        req = _request({"created_before": "01/15/2024"})
        with pytest.raises(Exception, match="created_before must be a valid ISO date"):
            z.search_tickets(req)

    def test_invalid_date_values(self):
        z = Zendesk()
        req = _request({"created_after": "2025-02-31"})
        with pytest.raises(Exception, match="created_after must be a valid ISO date"):
            z.search_tickets(req)


class TestSearchUsers:

    @patch("app.zendesk.requests.request")
    def test_success(self, mock_request):
        mock_request.return_value = _mock_response(200, {"users": [{"id": 1, "name": "John", "email": "john@test.com"}], "count": 1, "next_page": None})
        z = Zendesk()
        req = _request({"query": "john@test.com"})
        result = z.search_users(req)
        assert result["status"] == "success"
        assert len(result["users"]) == 1

    def test_missing_query(self):
        z = Zendesk()
        req = _request({})
        with pytest.raises(Exception, match="query is required"):
            z.search_users(req)


class TestChangeTicketStatus:

    @patch("app.zendesk.requests.request")
    def test_success(self, mock_request):
        mock_request.return_value = _mock_response(200, {"ticket": {"id": 1, "status": "solved"}})
        z = Zendesk()
        req = _request({"ticket_id": "1", "status": "solved"})
        result = z.change_ticket_status(req)
        assert result["status"] == "success"
        assert result["ticket"]["status"] == "solved"

    def test_invalid_status_closed(self):
        z = Zendesk()
        req = _request({"ticket_id": "1", "status": "closed"})
        with pytest.raises(Exception, match="status must be one of"):
            z.change_ticket_status(req)

    def test_missing_status(self):
        z = Zendesk()
        req = _request({"ticket_id": "1"})
        with pytest.raises(Exception, match="status is required"):
            z.change_ticket_status(req)


class TestGetTicketComments:

    @patch("app.zendesk.requests.request")
    def test_success(self, mock_request):
        mock_request.return_value = _mock_response(200, {
            "comments": [{"id": 1, "body": "First comment", "public": True}],
            "count": 1,
            "next_page": None,
        })
        z = Zendesk()
        req = _request({"ticket_id": "1"})
        result = z.get_ticket_comments(req)
        assert result["status"] == "success"
        assert len(result["comments"]) == 1

    def test_missing_ticket_id(self):
        z = Zendesk()
        req = _request({})
        with pytest.raises(Exception, match="ticket_id is required"):
            z.get_ticket_comments(req)


class TestListTicketAttachments:

    @patch("app.zendesk.requests.request")
    def test_success(self, mock_request):
        mock_request.return_value = _mock_response(200, {
            "comments": [
                {"id": 1, "attachments": [
                    {"id": 10, "file_name": "report.pdf", "content_url": "https://cdn.zendesk.com/report.pdf", "content_type": "application/pdf", "size": 1024}
                ]},
                {"id": 2, "attachments": []},
            ]
        })
        z = Zendesk()
        req = _request({"ticket_id": "1"})
        result = z.list_ticket_attachments(req)
        assert result["status"] == "success"
        assert result["count"] == 1
        assert result["attachments"][0]["filename"] == "report.pdf"

    @patch("app.zendesk.requests.request")
    def test_no_attachments(self, mock_request):
        mock_request.return_value = _mock_response(200, {"comments": [{"id": 1, "attachments": []}]})
        z = Zendesk()
        req = _request({"ticket_id": "1"})
        result = z.list_ticket_attachments(req)
        assert result["status"] == "success"
        assert result["count"] == 0


class TestErrorHandling:

    @patch("app.zendesk.requests.request")
    def test_rate_limit_retry_with_retry_after(self, mock_request):
        rate_resp = _mock_response(429, headers={"Retry-After": "1"})
        success_resp = _mock_response(200, {"user": {"name": "Agent", "email": "a@t.com"}})
        mock_request.side_effect = [rate_resp, success_resp]
        z = Zendesk()
        result = z.test_connection(_conn_params())
        assert result["status"] == "success"
        assert mock_request.call_count == 2

    @patch("app.zendesk.requests.request")
    def test_rate_limit_exhausted(self, mock_request):
        mock_request.return_value = _mock_response(429, headers={"Retry-After": "0"})
        z = Zendesk()
        with pytest.raises(Exception, match="Rate limit exceeded"):
            z.test_connection(_conn_params())

    @patch("app.zendesk.requests.request")
    def test_server_error_retry(self, mock_request):
        error_resp = _mock_response(500)
        success_resp = _mock_response(200, {"user": {"name": "Agent", "email": "a@t.com"}})
        mock_request.side_effect = [error_resp, success_resp]
        z = Zendesk()
        result = z.test_connection(_conn_params())
        assert result["status"] == "success"

    @patch("app.zendesk.requests.request")
    def test_connection_error(self, mock_request):
        import requests as req_lib
        mock_request.side_effect = req_lib.exceptions.ConnectionError()
        z = Zendesk()
        with pytest.raises(Exception, match="Unable to connect"):
            z.test_connection(_conn_params())

    @patch("app.zendesk.requests.request")
    def test_timeout_error(self, mock_request):
        import requests as req_lib
        mock_request.side_effect = req_lib.exceptions.Timeout()
        z = Zendesk()
        with pytest.raises(Exception, match="timed out"):
            z.test_connection(_conn_params())

    @patch("app.zendesk.requests.request")
    def test_validation_error_422(self, mock_request):
        mock_request.return_value = _mock_response(422, {"error": "RecordInvalid", "description": "Subject is too short"})
        z = Zendesk()
        req = _request({"subject": "T", "description": "Body"})
        with pytest.raises(Exception, match="Validation error"):
            z.create_ticket(req)

    @patch("app.zendesk.requests.request")
    def test_user_not_found_for_email_resolution(self, mock_request):
        mock_request.return_value = _mock_response(200, {"users": []})
        z = Zendesk()
        req = _request({"subject": "Test", "description": "Body", "assignee_email": "nobody@test.com"})
        with pytest.raises(Exception, match="User not found"):
            z.create_ticket(req)

    @patch("app.zendesk.requests.request")
    def test_resolve_user_exact_email_match(self, mock_request):
        responses = [
            _mock_response(200, {"users": [
                {"id": 10, "email": "john.doe@test.com"},
                {"id": 20, "email": "john@test.com"},
            ]}),
            _mock_response(200, {"ticket": {"id": 1, "assignee_id": 20}}),
        ]
        mock_request.side_effect = responses
        z = Zendesk()
        req = _request({"subject": "Test", "description": "Body", "assignee_email": "john@test.com"})
        result = z.create_ticket(req)
        assert result["status"] == "success"
