import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import unittest
from unittest.mock import patch, MagicMock

from app.zoom import Zoom


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

CONNECTION_PARAMS = {
    "account_id": "acc123",
    "client_id": "cid123",
    "client_secret": "secret123",
    "verify_ssl": "true",
}


def make_request(parameters: dict):
    req = MagicMock()
    req.connectionParameters = CONNECTION_PARAMS
    req.parameters = parameters
    return req


def mock_token_response():
    """Mock a successful S2S OAuth token response (requests.post)."""
    resp = MagicMock()
    resp.json.return_value = {"access_token": "tok-abc", "token_type": "bearer", "expires_in": 3599}
    resp.raise_for_status = MagicMock()
    return resp


def mock_api_response(data, status_code=200):
    """Mock a successful API response (requests.request)."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = b"x" if data else b""
    resp.json.return_value = data
    resp.raise_for_status = MagicMock()
    return resp


def mock_empty_response(status_code=204):
    """Mock an empty 204 response (DELETE/PUT)."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = b""
    resp.raise_for_status = MagicMock()
    return resp


# -------------------------------------------------------------------
# Test Class
# -------------------------------------------------------------------

class TestZoom(unittest.TestCase):

    def setUp(self):
        self.connector = Zoom()

    # ---------------------------------------------------------------
    # test_connection
    # ---------------------------------------------------------------

    @patch("app.zoom.requests.post")
    def test_connection_success(self, mock_post):
        mock_post.return_value = mock_token_response()
        result = self.connector.test_connection(CONNECTION_PARAMS)
        self.assertEqual(result["status"], "success")
        self.assertIn("Connected to Zoom successfully", result["message"])

    @patch("app.zoom.requests.post")
    def test_connection_no_token(self, mock_post):
        resp = MagicMock()
        resp.json.return_value = {}
        resp.raise_for_status = MagicMock()
        mock_post.return_value = resp
        with self.assertRaises(Exception) as ctx:
            self.connector.test_connection(CONNECTION_PARAMS)
        self.assertIn("Failed to retrieve access token", str(ctx.exception))

    @patch("app.zoom.requests.post")
    def test_connection_http_error(self, mock_post):
        mock_post.side_effect = Exception("Connection refused")
        with self.assertRaises(Exception) as ctx:
            self.connector.test_connection(CONNECTION_PARAMS)
        self.assertIn("Connection refused", str(ctx.exception))

    # ---------------------------------------------------------------
    # Users — read
    # ---------------------------------------------------------------

    @patch("app.zoom.requests.request")
    @patch("app.zoom.requests.post")
    def test_list_users_success(self, mock_post, mock_request):
        mock_post.return_value = mock_token_response()
        users = {"users": [{"id": "u1", "email": "a@b.com"}], "total_records": 1}
        mock_request.return_value = mock_api_response(users)

        result = self.connector.list_users(make_request({"status": "active", "page_size": 50}))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"], users)

    @patch("app.zoom.requests.request")
    @patch("app.zoom.requests.post")
    def test_list_users_no_filters(self, mock_post, mock_request):
        mock_post.return_value = mock_token_response()
        mock_request.return_value = mock_api_response({"users": []})
        result = self.connector.list_users(make_request({}))
        self.assertEqual(result["status"], "success")

    @patch("app.zoom.requests.request")
    @patch("app.zoom.requests.post")
    def test_get_user_success(self, mock_post, mock_request):
        mock_post.return_value = mock_token_response()
        mock_request.return_value = mock_api_response({"id": "u1", "email": "a@b.com"})
        result = self.connector.get_user(make_request({"user_id": "u1"}))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["id"], "u1")

    @patch("app.zoom.requests.post")
    def test_get_user_missing_id(self, mock_post):
        mock_post.return_value = mock_token_response()
        with self.assertRaises(KeyError):
            self.connector.get_user(make_request({}))

    @patch("app.zoom.requests.request")
    @patch("app.zoom.requests.post")
    def test_get_user_settings_success(self, mock_post, mock_request):
        mock_post.return_value = mock_token_response()
        mock_request.return_value = mock_api_response({"recording": {"local_recording": True}})
        result = self.connector.get_user_settings(make_request({"user_id": "u1"}))
        self.assertEqual(result["status"], "success")

    @patch("app.zoom.requests.request")
    @patch("app.zoom.requests.post")
    def test_get_user_permissions_success(self, mock_post, mock_request):
        mock_post.return_value = mock_token_response()
        mock_request.return_value = mock_api_response({"permissions": ["User:Read"]})
        result = self.connector.get_user_permissions(make_request({"user_id": "u1"}))
        self.assertEqual(result["status"], "success")

    @patch("app.zoom.requests.request")
    @patch("app.zoom.requests.post")
    def test_get_user_presence_status_success(self, mock_post, mock_request):
        mock_post.return_value = mock_token_response()
        mock_request.return_value = mock_api_response({"status": "Available"})
        result = self.connector.get_user_presence_status(make_request({"user_id": "u1"}))
        self.assertEqual(result["status"], "success")

    @patch("app.zoom.requests.post")
    def test_get_user_presence_status_missing_id(self, mock_post):
        mock_post.return_value = mock_token_response()
        with self.assertRaises(KeyError):
            self.connector.get_user_presence_status(make_request({}))

    # ---------------------------------------------------------------
    # Meetings — read
    # ---------------------------------------------------------------

    @patch("app.zoom.requests.request")
    @patch("app.zoom.requests.post")
    def test_list_meetings_success(self, mock_post, mock_request):
        mock_post.return_value = mock_token_response()
        mock_request.return_value = mock_api_response({"meetings": [{"id": 123}]})
        result = self.connector.list_meetings(make_request({"user_id": "u1", "type": "scheduled"}))
        self.assertEqual(result["status"], "success")

    @patch("app.zoom.requests.post")
    def test_list_meetings_missing_user(self, mock_post):
        mock_post.return_value = mock_token_response()
        with self.assertRaises(KeyError):
            self.connector.list_meetings(make_request({}))

    @patch("app.zoom.requests.request")
    @patch("app.zoom.requests.post")
    def test_get_meeting_success(self, mock_post, mock_request):
        mock_post.return_value = mock_token_response()
        mock_request.return_value = mock_api_response({"id": 123, "topic": "Sync"})
        result = self.connector.get_meeting(make_request({"meeting_id": "123"}))
        self.assertEqual(result["status"], "success")

    @patch("app.zoom.requests.post")
    def test_get_meeting_missing_id(self, mock_post):
        mock_post.return_value = mock_token_response()
        with self.assertRaises(KeyError):
            self.connector.get_meeting(make_request({}))

    @patch("app.zoom.requests.request")
    @patch("app.zoom.requests.post")
    def test_get_past_meeting_details_success(self, mock_post, mock_request):
        mock_post.return_value = mock_token_response()
        mock_request.return_value = mock_api_response({"uuid": "abc==", "participants_count": 5})
        result = self.connector.get_past_meeting_details(make_request({"meeting_id": "123"}))
        self.assertEqual(result["status"], "success")

    @patch("app.zoom.requests.request")
    @patch("app.zoom.requests.post")
    def test_get_past_meeting_participants_success(self, mock_post, mock_request):
        mock_post.return_value = mock_token_response()
        mock_request.return_value = mock_api_response({"participants": [{"name": "Joe"}]})
        result = self.connector.get_past_meeting_participants(make_request({"meeting_id": "123"}))
        self.assertEqual(result["status"], "success")

    @patch("app.zoom.requests.post")
    def test_get_past_meeting_participants_missing_id(self, mock_post):
        mock_post.return_value = mock_token_response()
        with self.assertRaises(KeyError):
            self.connector.get_past_meeting_participants(make_request({}))

    # ---------------------------------------------------------------
    # Reports — audit
    # ---------------------------------------------------------------

    @patch("app.zoom.requests.request")
    @patch("app.zoom.requests.post")
    def test_get_signin_signout_activity_success(self, mock_post, mock_request):
        mock_post.return_value = mock_token_response()
        mock_request.return_value = mock_api_response({"activity_logs": [{"type": "Sign in"}]})
        result = self.connector.get_signin_signout_activity(
            make_request({"from": "2026-01-01", "to": "2026-01-31"}))
        self.assertEqual(result["status"], "success")

    @patch("app.zoom.requests.request")
    @patch("app.zoom.requests.post")
    def test_get_signin_signout_activity_no_dates(self, mock_post, mock_request):
        # from/to are optional per the Zoom spec
        mock_post.return_value = mock_token_response()
        mock_request.return_value = mock_api_response({"activity_logs": []})
        result = self.connector.get_signin_signout_activity(make_request({}))
        self.assertEqual(result["status"], "success")

    @patch("app.zoom.requests.request")
    @patch("app.zoom.requests.post")
    def test_get_operation_logs_success(self, mock_post, mock_request):
        mock_post.return_value = mock_token_response()
        mock_request.return_value = mock_api_response({"operation_logs": [{"action": "Update"}]})
        result = self.connector.get_operation_logs(
            make_request({"from": "2026-01-01", "to": "2026-01-31", "category_type": "user"}))
        self.assertEqual(result["status"], "success")

    @patch("app.zoom.requests.request")
    @patch("app.zoom.requests.post")
    def test_get_active_inactive_hosts_success(self, mock_post, mock_request):
        mock_post.return_value = mock_token_response()
        mock_request.return_value = mock_api_response({"users": [{"id": "u1"}]})
        result = self.connector.get_active_inactive_hosts(
            make_request({"from": "2026-01-01", "to": "2026-01-31", "type": "active"}))
        self.assertEqual(result["status"], "success")

    @patch("app.zoom.requests.post")
    def test_get_active_inactive_hosts_missing_dates(self, mock_post):
        mock_post.return_value = mock_token_response()
        with self.assertRaises(KeyError):
            self.connector.get_active_inactive_hosts(make_request({"to": "2026-01-31"}))

    # ---------------------------------------------------------------
    # Remediation
    # ---------------------------------------------------------------

    @patch("app.zoom.requests.request")
    @patch("app.zoom.requests.post")
    def test_update_user_status_success(self, mock_post, mock_request):
        mock_post.return_value = mock_token_response()
        mock_request.return_value = mock_empty_response()  # 204 no body
        result = self.connector.update_user_status(
            make_request({"user_id": "u1", "action": "deactivate"}))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["action"], "deactivate")

    @patch("app.zoom.requests.post")
    def test_update_user_status_missing_action(self, mock_post):
        mock_post.return_value = mock_token_response()
        with self.assertRaises(KeyError):
            self.connector.update_user_status(make_request({"user_id": "u1"}))

    @patch("app.zoom.requests.request")
    @patch("app.zoom.requests.post")
    def test_revoke_user_sso_token_success(self, mock_post, mock_request):
        mock_post.return_value = mock_token_response()
        mock_request.return_value = mock_empty_response()
        result = self.connector.revoke_user_sso_token(make_request({"user_id": "u1"}))
        self.assertEqual(result["status"], "success")
        self.assertIn("revoked", result["results"]["message"])

    @patch("app.zoom.requests.post")
    def test_revoke_user_sso_token_missing_id(self, mock_post):
        mock_post.return_value = mock_token_response()
        with self.assertRaises(KeyError):
            self.connector.revoke_user_sso_token(make_request({}))

    @patch("app.zoom.requests.request")
    @patch("app.zoom.requests.post")
    def test_delete_meeting_success(self, mock_post, mock_request):
        mock_post.return_value = mock_token_response()
        mock_request.return_value = mock_empty_response()
        result = self.connector.delete_meeting(
            make_request({"meeting_id": "123", "notify_hosts": "true"}))
        self.assertEqual(result["status"], "success")
        self.assertIn("deleted", result["results"]["message"])
        # confirm the correct Zoom query param is used
        _, kwargs = mock_request.call_args
        self.assertEqual(kwargs["params"].get("cancel_meeting_reminder"), "true")

    @patch("app.zoom.requests.post")
    def test_delete_meeting_missing_id(self, mock_post):
        mock_post.return_value = mock_token_response()
        with self.assertRaises(KeyError):
            self.connector.delete_meeting(make_request({}))

    # ---------------------------------------------------------------
    # error propagation
    # ---------------------------------------------------------------

    @patch("app.zoom.requests.post")
    def test_list_users_token_failure(self, mock_post):
        mock_post.side_effect = Exception("Auth failed")
        with self.assertRaises(Exception) as ctx:
            self.connector.list_users(make_request({}))
        self.assertIn("Auth failed", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
