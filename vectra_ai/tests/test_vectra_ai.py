import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import unittest
import requests
from unittest.mock import patch, MagicMock, Mock
from datetime import datetime

from app.vectra_ai import VectraAi


# -------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------

API_HOST = "https://vectra.example.com"
CLIENT_ID = "test_client_id"
CLIENT_SECRET = "test_client_secret"
VERIFY_SSL = False

CONNECTION_PARAMS = {
    "api_host": API_HOST,
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    "verify_ssl": VERIFY_SSL
}


# -------------------------------------------------------------------
# Mock Helper Functions
# -------------------------------------------------------------------

def mock_token_response(access_token="test_token", expires_in=3600, refresh_token="refresh_123"):
    """Create a mock OAuth2 token response."""
    resp = MagicMock()
    resp.json.return_value = {
        "access_token": access_token,
        "expires_in": expires_in,
        "refresh_expires_in": 86400,
        "refresh_token": refresh_token,
        "token_type": "Bearer"
    }
    resp.raise_for_status = MagicMock()
    resp.status_code = 200
    return resp


def mock_error_response(status_code, error_json=None, text=None):
    """Create a mock error response."""
    resp = MagicMock()
    resp.status_code = status_code
    if error_json:
        resp.json.return_value = error_json
        resp.text = str(error_json)
    else:
        resp.text = text or f"Error {status_code}"
    resp.raise_for_status = MagicMock(side_effect=requests.exceptions.HTTPError(f"HTTP {status_code}"))
    return resp


def make_request(parameters: dict):
    """Build a mock RequestBody with connectionParameters and parameters."""
    req = MagicMock()
    req.connectionParameters = CONNECTION_PARAMS
    req.parameters = parameters
    return req


# -------------------------------------------------------------------
# Test Class
# -------------------------------------------------------------------

class TestVectraAi(unittest.TestCase):

    def setUp(self):
        self.connector = VectraAi()

    # ---------------------------------------------------------------
    # Test Connection
    # ---------------------------------------------------------------

    @patch("app.vectra_ai.requests.post")
    def test_connection_success(self, mock_post):
        """Test successful connection with valid credentials."""
        mock_post.return_value = mock_token_response()
        
        result = self.connector.test_connection(CONNECTION_PARAMS)
        
        self.assertEqual(result["status"], "success")
        self.assertIn("Connected to Vectra AI successfully", result["message"])

    @patch("app.vectra_ai.requests.post")
    def test_connection_missing_params(self, mock_post):
        """Test connection with missing required parameters."""
        incomplete_params = {"api_host": API_HOST}
        
        result = self.connector.test_connection(incomplete_params)
        
        self.assertEqual(result["status"], "error")
        self.assertIn("Missing required connection parameters", result["message"])

    @patch("app.vectra_ai.requests.post")
    def test_connection_invalid_credentials(self, mock_post):
        """Test connection with invalid credentials (401)."""
        mock_post.return_value = mock_error_response(401, error_json={"detail": "Unauthorized"})
        
        result = self.connector.test_connection(CONNECTION_PARAMS)
        
        self.assertEqual(result["status"], "error")
        self.assertIn("Authentication failed", result["message"])

    @patch("app.vectra_ai.requests.post")
    def test_connection_rate_limit(self, mock_post):
        """Test connection with rate limiting (429)."""
        mock_post.return_value = mock_error_response(429, error_json={"detail": "Rate limit exceeded"})
        
        result = self.connector.test_connection(CONNECTION_PARAMS)
        
        self.assertEqual(result["status"], "error")
        self.assertIn("Rate limit exceeded", result["message"])

    @patch("app.vectra_ai.requests.post")
    def test_connection_service_unavailable(self, mock_post):
        """Test connection with service unavailable (503)."""
        mock_post.return_value = mock_error_response(503, error_json={"detail": "Service unavailable"})
        
        result = self.connector.test_connection(CONNECTION_PARAMS)
        
        self.assertEqual(result["status"], "error")
        self.assertIn("Service unavailable", result["message"])

    @patch("app.vectra_ai.requests.post")
    def test_connection_timeout(self, mock_post):
        """Test connection with gateway timeout (504)."""
        mock_post.return_value = mock_error_response(504, error_json={"detail": "Gateway timeout"})
        
        result = self.connector.test_connection(CONNECTION_PARAMS)
        
        self.assertEqual(result["status"], "error")
        self.assertIn("Gateway timeout", result["message"])

    # ---------------------------------------------------------------
    # OAuth2 Token Management
    # ---------------------------------------------------------------

    @patch("app.vectra_ai.requests.post")
    def test_get_oauth2_token_success(self, mock_post):
        """Test successful OAuth2 token retrieval."""
        mock_post.return_value = mock_token_response()
        
        result = self.connector._get_oauth2_token(API_HOST, CLIENT_ID, CLIENT_SECRET)
        
        self.assertEqual(result["access_token"], "test_token")
        self.assertEqual(result["expires_in"], 3600)

    @patch("app.vectra_ai.requests.post")
    def test_get_oauth2_token_expired(self, mock_post):
        """Test token refresh when expired."""
        mock_post.side_effect = [
            mock_token_response(access_token="token1"),
            mock_token_response(access_token="token2")
        ]
        
        token1 = self.connector._get_oauth2_token(API_HOST, CLIENT_ID, CLIENT_SECRET)
        token2 = self.connector._get_oauth2_token(API_HOST, CLIENT_ID, CLIENT_SECRET)
        
        self.assertEqual(token1["access_token"], "token1")
        self.assertEqual(token2["access_token"], "token2")

    # ---------------------------------------------------------------
    # Detection Operations
    # ---------------------------------------------------------------

    @patch("app.vectra_ai.requests.request")
    @patch("app.vectra_ai.requests.post")
    def test_get_detections_success(self, mock_post, mock_request):
        """Test successful detection listing."""
        mock_post.return_value = mock_token_response()
        mock_request.return_value = Mock()
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            "count": 2,
            "results": [
                {"id": 1, "detection": "C2 Beacon", "src_ip": "192.168.1.100"},
                {"id": 2, "detection": "Data Exfiltration", "src_ip": "192.168.1.101"}
            ]
        }
        mock_request.return_value.raise_for_status = Mock()
        
        request = make_request({"page": 1, "page_size": 10})
        result = self.connector.get_detections(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["count"], 2)
        self.assertEqual(len(result["results"]["results"]), 2)

    @patch("app.vectra_ai.requests.request")
    @patch("app.vectra_ai.requests.post")
    def test_get_detections_with_filters(self, mock_post, mock_request):
        """Test detection listing with filters."""
        mock_post.return_value = mock_token_response()
        mock_request.return_value = Mock()
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {"count": 1, "results": []}
        mock_request.return_value.raise_for_status = Mock()
        
        request = make_request({
            "detection_category": "command",
            "threat": 80,
            "state": "active"
        })
        self.connector.get_detections(request)
        
        call_args = mock_request.call_args
        params = call_args[1]['params']
        self.assertEqual(params.get('detection_category'), 'command')
        self.assertEqual(params.get('threat'), 80)
        self.assertEqual(params.get('state'), 'active')

    @patch("app.vectra_ai.requests.request")
    @patch("app.vectra_ai.requests.post")
    def test_get_detection_by_id_success(self, mock_post, mock_request):
        """Test getting single detection by ID."""
        mock_post.return_value = mock_token_response()
        mock_request.return_value = Mock()
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            "id": 123,
            "detection": "C2 Beacon",
            "src_ip": "192.168.1.100"
        }
        mock_request.return_value.raise_for_status = Mock()
        
        request = make_request({"detection_id": 123})
        result = self.connector.get_detection_by_id(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["id"], 123)

    @patch("app.vectra_ai.requests.request")
    @patch("app.vectra_ai.requests.post")
    def test_mark_detection_fixed_success(self, mock_post, mock_request):
        """Test marking detections as fixed."""
        mock_post.return_value = mock_token_response()
        mock_request.return_value = Mock()
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            "_meta": {
                "level": "Success",
                "message": "Successfully marked detections"
            }
        }
        mock_request.return_value.raise_for_status = Mock()
        
        request = make_request({
            "detection_id_list": [1, 2, 3],
            "external_reference_id": "TICKET-123",
            "investigation_status": "acknowledged"
        })
        result = self.connector.mark_detection_fixed(request)
        
        self.assertEqual(result["status"], "success")
        self.assertIn("Successfully marked detections", result["results"]["_meta"]["message"])

    @patch("app.vectra_ai.requests.request")
    @patch("app.vectra_ai.requests.post")
    def test_mark_detection_fixed_string_list(self, mock_post, mock_request):
        """Test marking detections with comma-separated string list."""
        mock_post.return_value = mock_token_response()
        mock_request.return_value = Mock()
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {"_meta": {"level": "Success"}}
        mock_request.return_value.raise_for_status = Mock()
        
        request = make_request({
            "detection_id_list": "1, 2, 3"
        })
        self.connector.mark_detection_fixed(request)
        
        call_args = mock_request.call_args
        payload = call_args[1]['json']
        self.assertEqual(payload["detectionIdList"], [1, 2, 3])

    # ---------------------------------------------------------------
    # Account Operations
    # ---------------------------------------------------------------

    @patch("app.vectra_ai.requests.request")
    @patch("app.vectra_ai.requests.post")
    def test_get_accounts_success(self, mock_post, mock_request):
        """Test successful account listing."""
        mock_post.return_value = mock_token_response()
        mock_request.return_value = Mock()
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            "count": 1,
            "results": [{"id": 456, "name": "john.doe", "threat": 75}]
        }
        mock_request.return_value.raise_for_status = Mock()
        
        request = make_request({})
        result = self.connector.get_accounts(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(result["results"]["results"]), 1)

    @patch("app.vectra_ai.requests.request")
    @patch("app.vectra_ai.requests.post")
    def test_close_account_success(self, mock_post, mock_request):
        """Test closing an account."""
        mock_post.return_value = mock_token_response()
        mock_request.return_value = Mock()
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            "_meta": {
                "level": "Success",
                "message": {"reason": "Successfully closed account as remediated"}
            },
            "detections_closed": [1, 2, 3]
        }
        mock_request.return_value.raise_for_status = Mock()
        
        request = make_request({
            "account_id": 456,
            "reason": "remediated"
        })
        result = self.connector.close_account(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["detections_closed"], [1, 2, 3])

    # ---------------------------------------------------------------
    # Host Operations
    # ---------------------------------------------------------------

    @patch("app.vectra_ai.requests.request")
    @patch("app.vectra_ai.requests.post")
    def test_get_hosts_success(self, mock_post, mock_request):
        """Test successful host listing."""
        mock_post.return_value = mock_token_response()
        mock_request.return_value = Mock()
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            "count": 1,
            "results": [{"id": 789, "name": "workstation-100", "threat": 60}]
        }
        mock_request.return_value.raise_for_status = Mock()
        
        request = make_request({})
        result = self.connector.get_hosts(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(result["results"]["results"]), 1)

    @patch("app.vectra_ai.requests.request")
    @patch("app.vectra_ai.requests.post")
    def test_set_host_as_key_asset_success(self, mock_post, mock_request):
        """Test marking host as key asset."""
        mock_post.return_value = mock_token_response()
        mock_request.return_value = Mock()
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            "message": "Successfully updated host 789 as key asset"
        }
        mock_request.return_value.raise_for_status = Mock()
        
        request = make_request({
            "host_id": 789,
            "key_asset": True
        })
        result = self.connector.set_host_as_key_asset(request)
        
        self.assertEqual(result["status"], "success")
        
        call_args = mock_request.call_args
        payload = call_args[1]['json']
        self.assertEqual(payload["key_asset"], "true")

    # ---------------------------------------------------------------
    # Entity Operations
    # ---------------------------------------------------------------

    @patch("app.vectra_ai.requests.request")
    @patch("app.vectra_ai.requests.post")
    def test_get_entities_success(self, mock_post, mock_request):
        """Test successful entity listing."""
        mock_post.return_value = mock_token_response()
        mock_request.return_value = Mock()
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            "count": 2,
            "results": [
                {"id": 789, "type": "host", "name": "workstation-100"},
                {"id": 456, "type": "account", "name": "john.doe"}
            ]
        }
        mock_request.return_value.raise_for_status = Mock()
        
        request = make_request({"type": "host"})
        result = self.connector.get_entities(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["count"], 2)

    @patch("app.vectra_ai.requests.request")
    @patch("app.vectra_ai.requests.post")
    def test_get_entity_by_id_success(self, mock_post, mock_request):
        """Test getting single entity by ID."""
        mock_post.return_value = mock_token_response()
        mock_request.return_value = Mock()
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            "id": 789,
            "type": "host",
            "name": "workstation-100"
        }
        mock_request.return_value.raise_for_status = Mock()
        
        request = make_request({
            "entity_id": 789,
            "type": "host"
        })
        result = self.connector.get_entity_by_id(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["type"], "host")

    # ---------------------------------------------------------------
    # Search Operations
    # ---------------------------------------------------------------

    @patch("app.vectra_ai.requests.request")
    @patch("app.vectra_ai.requests.post")
    def test_search_detections_success(self, mock_post, mock_request):
        """Test searching detections by criteria."""
        mock_post.return_value = mock_token_response()
        mock_request.return_value = Mock()
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {
            "count": 1,
            "results": [{"id": 123, "detection": "C2 Beacon", "src_ip": "192.168.1.100"}]
        }
        mock_request.return_value.raise_for_status = Mock()
        
        request = make_request({
            "src_ip": "192.168.1.100",
            "threat_gte": 80,
            "detection_category": "command"
        })
        result = self.connector.search_detections_by_criteria(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(result["results"]["results"]), 1)

    # ---------------------------------------------------------------
    # Error Handling
    # ---------------------------------------------------------------

    @patch("app.vectra_ai.requests.request")
    @patch("app.vectra_ai.requests.post")
    def test_get_detection_not_found(self, mock_post, mock_request):
        """Test getting non-existent detection (404)."""
        mock_post.return_value = mock_token_response()
        mock_request.return_value = mock_error_response(404, error_json={"detail": "Not found"})
        
        request = make_request({"detection_id": 9999})
        result = self.connector.get_detection_by_id(request)
        
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["status_code"], 404)

    @patch("app.vectra_ai.requests.request")
    @patch("app.vectra_ai.requests.post")
    def test_mark_detection_fixed_forbidden(self, mock_post, mock_request):
        """Test marking detection as fixed without permission (403)."""
        mock_post.return_value = mock_token_response()
        mock_request.return_value = mock_error_response(403, error_json={"detail": "Forbidden"})
        
        request = make_request({"detection_id_list": [1]})
        result = self.connector.mark_detection_fixed(request)
        
        self.assertEqual(result["status"], "error")
        self.assertIn("Authorization error", result["message"])

    @patch("app.vectra_ai.requests.request")
    @patch("app.vectra_ai.requests.post")
    def test_mark_detection_fixed_rate_limited(self, mock_post, mock_request):
        """Test marking detection with rate limiting (429)."""
        mock_post.return_value = mock_token_response()
        mock_request.return_value = mock_error_response(429, error_json={"detail": "Too many requests"})
        
        request = make_request({"detection_id_list": [1]})
        result = self.connector.mark_detection_fixed(request)
        
        self.assertEqual(result["status"], "error")
        self.assertIn("Rate limit exceeded", result["message"])

    @patch("app.vectra_ai.requests.post")
    def test_token_refresh_on_expiration(self, mock_post):
        """Test that token is refreshed when expired."""
        mock_post.return_value = mock_token_response()
        token1 = self.connector._get_oauth2_token(API_HOST, CLIENT_ID, CLIENT_SECRET)
        
        self.connector._token_expiry = datetime(2020, 1, 1)
        
        result = self.connector._ensure_token_valid(API_HOST, CLIENT_ID, CLIENT_SECRET)
        
        self.assertEqual(result, "test_token")


if __name__ == "__main__":
    unittest.main()
