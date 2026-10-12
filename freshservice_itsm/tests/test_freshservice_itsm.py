import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import unittest
import requests
from unittest.mock import patch, Mock

from app.freshservice_itsm import FreshserviceItsm


# -------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------

API_HOST = "https://company.freshservice.com"
API_KEY = "test_api_key"
VERIFY_SSL = False

CONNECTION_PARAMS = {
    "api_host": API_HOST,
    "api_key": API_KEY,
    "verify_ssl": VERIFY_SSL
}


# -------------------------------------------------------------------
# Mock Helper Functions
# -------------------------------------------------------------------

def mock_success_response(status_code=200, data=None):
    """Create a mock success response."""
    resp = Mock()
    resp.status_code = status_code
    resp.json.return_value = data or {}
    resp.raise_for_status = Mock()
    return resp


def mock_error_response(status_code, error_json=None, text=None):
    """Create a mock error response."""
    resp = Mock()
    resp.status_code = status_code
    if error_json:
        resp.json.return_value = error_json
        resp.text = str(error_json)
    else:
        resp.text = text or f"Error {status_code}"
    resp.raise_for_status = Mock(side_effect=requests.exceptions.HTTPError(f"HTTP {status_code}"))
    return resp


def make_request(parameters: dict):
    """Build a mock RequestBody with connectionParameters and parameters."""
    req = Mock()
    req.connectionParameters = CONNECTION_PARAMS
    req.parameters = parameters
    return req


# -------------------------------------------------------------------
# Test Class
# -------------------------------------------------------------------

class TestFreshserviceItsm(unittest.TestCase):

    def setUp(self):
        self.connector = FreshserviceItsm()

    # ---------------------------------------------------------------
    # Test Connection
    # ---------------------------------------------------------------

    @patch("app.freshservice_itsm.requests.request")
    def test_connection_success(self, mock_request):
        """Test successful connection with valid API key."""
        mock_request.return_value = mock_success_response(
            200,
            {"tickets": [], "total": 0, "page": 1, "per_page": 1}
        )
        
        result = self.connector.test_connection(CONNECTION_PARAMS)
        
        self.assertEqual(result["status"], "success")
        self.assertIn("tickets", result["results"])

    @patch("app.freshservice_itsm.requests.request")
    def test_connection_missing_params(self, mock_request):
        """Test connection with missing required parameters."""
        incomplete_params = {"api_host": API_HOST}
        
        result = self.connector.test_connection(incomplete_params)
        
        self.assertEqual(result["status"], "error")
        self.assertIn("Missing required connection parameters", result["message"])

    @patch("app.freshservice_itsm.requests.request")
    def test_connection_invalid_api_key(self, mock_request):
        """Test connection with invalid API key (401)."""
        mock_request.return_value = mock_error_response(
            401,
            {"description": "Invalid API key"}
        )
        
        result = self.connector.test_connection(CONNECTION_PARAMS)
        
        self.assertEqual(result["status"], "error")
        self.assertIn("Authentication error", result["message"])

    @patch("app.freshservice_itsm.requests.request")
    def test_connection_rate_limit(self, mock_request):
        """Test connection with rate limiting (429)."""
        mock_request.return_value = mock_error_response(
            429,
            {"description": "Rate limit exceeded"}
        )
        
        result = self.connector.test_connection(CONNECTION_PARAMS)
        
        self.assertEqual(result["status"], "error")
        self.assertIn("Rate limit exceeded", result["message"])

    @patch("app.freshservice_itsm.requests.request")
    def test_connection_service_unavailable(self, mock_request):
        """Test connection with service unavailable (503)."""
        mock_request.return_value = mock_error_response(
            503,
            {"description": "Service unavailable"}
        )
        
        result = self.connector.test_connection(CONNECTION_PARAMS)
        
        self.assertEqual(result["status"], "error")
        self.assertIn("Service unavailable", result["message"])

    @patch("app.freshservice_itsm.requests.request")
    def test_connection_timeout(self, mock_request):
        """Test connection with gateway timeout (504)."""
        mock_request.return_value = mock_error_response(
            504,
            {"description": "Gateway timeout"}
        )
        
        result = self.connector.test_connection(CONNECTION_PARAMS)
        
        self.assertEqual(result["status"], "error")
        self.assertIn("Gateway timeout", result["message"])

    # ---------------------------------------------------------------
    # Ticket Operations
    # ---------------------------------------------------------------

    @patch("app.freshservice_itsm.requests.request")
    def test_get_tickets_success(self, mock_request):
        """Test successful ticket listing."""
        mock_request.return_value = mock_success_response(
            200,
            {
                "tickets": [
                    {"id": 1, "subject": "Test Ticket", "status": 1, "priority": 2},
                    {"id": 2, "subject": "Another Ticket", "status": 2, "priority": 3}
                ],
                "page": 1,
                "per_page": 20,
                "total": 2
            }
        )
        
        request = make_request({"page": 1, "per_page": 10})
        result = self.connector.get_tickets(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(result["results"]["tickets"]), 2)

    @patch("app.freshservice_itsm.requests.request")
    def test_get_tickets_with_filters(self, mock_request):
        """Test ticket listing with filters."""
        mock_request.return_value = mock_success_response(
            200,
            {"tickets": [{"id": 1, "subject": "Test Ticket"}], "page": 1, "per_page": 20}
        )
        
        request = make_request({
            "filter": "new_and_my_open",
            "priority": 1,
            "status": 2
        })
        self.connector.get_tickets(request)
        
        call_args = mock_request.call_args
        params = call_args[1]['params']
        self.assertEqual(params.get('filter'), 'new_and_my_open')

    @patch("app.freshservice_itsm.requests.request")
    def test_get_ticket_by_id_success(self, mock_request):
        """Test getting single ticket by ID."""
        mock_request.return_value = mock_success_response(
            200,
            {"id": 123, "subject": "Test Ticket", "status": 1, "priority": 2}
        )
        
        request = make_request({"ticket_id": 123})
        result = self.connector.get_ticket_by_id(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["id"], 123)

    @patch("app.freshservice_itsm.requests.request")
    def test_search_tickets_success(self, mock_request):
        """Test searching tickets by criteria."""
        mock_request.return_value = mock_success_response(
            200,
            {
                "tickets": [{"id": 1, "subject": "Test Ticket", "priority": 1}],
                "page": 1,
                "per_page": 20
            }
        )
        
        request = make_request({
            "query": "priority: 1 AND status: 2",
            "page": 1,
            "per_page": 10
        })
        result = self.connector.search_tickets_by_criteria(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(result["results"]["tickets"]), 1)

    @patch("app.freshservice_itsm.requests.request")
    def test_create_ticket_success(self, mock_request):
        """Test creating a new ticket."""
        mock_request.return_value = mock_success_response(
            201,
            {"id": 456, "subject": "New Ticket", "status": 1, "priority": 2}
        )
        
        request = make_request({
            "subject": "New Ticket",
            "description": "Test ticket description",
            "requester_id": 123
        })
        result = self.connector.create_ticket(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["id"], 456)

    @patch("app.freshservice_itsm.requests.request")
    def test_update_ticket_success(self, mock_request):
        """Test updating an existing ticket."""
        mock_request.return_value = mock_success_response(
            200,
            {"id": 123, "subject": "Updated Ticket", "status": 2}
        )
        
        request = make_request({
            "ticket_id": 123,
            "subject": "Updated Ticket",
            "status": 2
        })
        result = self.connector.update_ticket(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["status"], 2)

    @patch("app.freshservice_itsm.requests.request")
    def test_close_ticket_success(self, mock_request):
        """Test closing a ticket."""
        mock_request.return_value = mock_success_response(
            200,
            {"id": 123, "subject": "Closed Ticket", "status": 4}
        )
        
        request = make_request({"ticket_id": 123})
        result = self.connector.close_ticket(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["status"], 4)

    @patch("app.freshservice_itsm.requests.request")
    def test_resolve_ticket_success(self, mock_request):
        """Test resolving a ticket."""
        mock_request.return_value = mock_success_response(
            200,
            {"id": 123, "subject": "Resolved Ticket", "status": 3}
        )
        
        request = make_request({"ticket_id": 123})
        result = self.connector.resolve_ticket(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["status"], 3)

    @patch("app.freshservice_itsm.requests.request")
    def test_delete_ticket_success(self, mock_request):
        """Test deleting a ticket."""
        mock_request.return_value = mock_success_response(
            204,
            {}
        )
        
        request = make_request({"ticket_id": 123})
        result = self.connector.delete_ticket(request)
        
        self.assertEqual(result["status"], "success")

    @patch("app.freshservice_itsm.requests.request")
    def test_get_ticket_not_found(self, mock_request):
        """Test getting non-existent ticket (404)."""
        mock_request.return_value = mock_error_response(
            404,
            {"description": "Ticket not found"}
        )
        
        request = make_request({"ticket_id": 9999})
        result = self.connector.get_ticket_by_id(request)
        
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["status_code"], 404)

    # ---------------------------------------------------------------
    # Agent Operations
    # ---------------------------------------------------------------

    @patch("app.freshservice_itsm.requests.request")
    def test_get_agents_success(self, mock_request):
        """Test successful agent listing."""
        mock_request.return_value = mock_success_response(
            200,
            {
                "agents": [{"id": 1, "name": "John Doe", "email": "john@company.com"}],
                "page": 1,
                "per_page": 20
            }
        )
        
        request = make_request({})
        result = self.connector.get_agents(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(result["results"]["agents"]), 1)

    @patch("app.freshservice_itsm.requests.request")
    def test_get_agent_by_id_success(self, mock_request):
        """Test getting single agent by ID."""
        mock_request.return_value = mock_success_response(
            200,
            {"id": 1, "name": "John Doe", "email": "john@company.com"}
        )
        
        request = make_request({"agent_id": 1})
        result = self.connector.get_agent_by_id(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["id"], 1)

    # ---------------------------------------------------------------
    # Requester/Contact Operations
    # ---------------------------------------------------------------

    @patch("app.freshservice_itsm.requests.request")
    def test_get_requesters_success(self, mock_request):
        """Test successful requester listing."""
        mock_request.return_value = mock_success_response(
            200,
            {
                "requesters": [
                    {"id": 1, "name": "Jane Doe", "email": "jane@company.com"}
                ],
                "page": 1,
                "per_page": 20
            }
        )
        
        request = make_request({})
        result = self.connector.get_requesters(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(result["results"]["requesters"]), 1)

    @patch("app.freshservice_itsm.requests.request")
    def test_get_requester_by_id_success(self, mock_request):
        """Test getting single requester by ID."""
        mock_request.return_value = mock_success_response(
            200,
            {"id": 1, "name": "Jane Doe", "email": "jane@company.com"}
        )
        
        request = make_request({"requester_id": 1})
        result = self.connector.get_requester_by_id(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["id"], 1)

    # ---------------------------------------------------------------
    # Asset Operations
    # ---------------------------------------------------------------

    @patch("app.freshservice_itsm.requests.request")
    def test_get_assets_success(self, mock_request):
        """Test successful asset listing."""
        mock_request.return_value = mock_success_response(
            200,
            {
                "assets": [
                    {"display_id": "AST001", "name": "Laptop-001", "asset_type_id": 1}
                ],
                "page": 1,
                "per_page": 20
            }
        )
        
        request = make_request({})
        result = self.connector.get_assets(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(result["results"]["assets"]), 1)

    @patch("app.freshservice_itsm.requests.request")
    def test_get_asset_by_id_success(self, mock_request):
        """Test getting single asset by ID."""
        mock_request.return_value = mock_success_response(
            200,
            {"display_id": "AST001", "name": "Laptop-001", "asset_type_id": 1}
        )
        
        request = make_request({"display_id": "AST001"})
        result = self.connector.get_asset_by_id(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["display_id"], "AST001")

    # ---------------------------------------------------------------
    # Location Operations
    # ---------------------------------------------------------------

    @patch("app.freshservice_itsm.requests.request")
    def test_get_locations_success(self, mock_request):
        """Test successful location listing."""
        mock_request.return_value = mock_success_response(
            200,
            {
                "locations": [
                    {"id": 1, "name": "Headquarters", "address": "123 Main St"}
                ],
                "page": 1,
                "per_page": 20
            }
        )
        
        request = make_request({})
        result = self.connector.get_locations(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(result["results"]["locations"]), 1)

    @patch("app.freshservice_itsm.requests.request")
    def test_get_location_by_id_success(self, mock_request):
        """Test getting single location by ID."""
        mock_request.return_value = mock_success_response(
            200,
            {"id": 1, "name": "Headquarters", "address": "123 Main St"}
        )
        
        request = make_request({"location_id": 1})
        result = self.connector.get_location_by_id(request)
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["id"], 1)

    # ---------------------------------------------------------------
    # Error Handling
    # ---------------------------------------------------------------

    @patch("app.freshservice_itsm.requests.request")
    def test_authentication_error(self, mock_request):
        """Test authentication error (401)."""
        mock_request.return_value = mock_error_response(
            401,
            {"description": "Invalid API key"}
        )
        
        request = make_request({"ticket_id": 123})
        result = self.connector.get_ticket_by_id(request)
        
        self.assertEqual(result["status"], "error")
        self.assertIn("Authentication error", result["message"])

    @patch("app.freshservice_itsm.requests.request")
    def test_forbidden_error(self, mock_request):
        """Test forbidden error (403)."""
        mock_request.return_value = mock_error_response(
            403,
            {"description": "Insufficient permissions"}
        )
        
        request = make_request({"ticket_id": 123})
        result = self.connector.get_ticket_by_id(request)
        
        self.assertEqual(result["status"], "error")
        self.assertIn("Authorization error", result["message"])

    @patch("app.freshservice_itsm.requests.request")
    def test_rate_limited(self, mock_request):
        """Test rate limiting error (429)."""
        mock_request.return_value = mock_error_response(
            429,
            {"description": "Rate limit exceeded"}
        )
        
        request = make_request({"ticket_id": 123})
        result = self.connector.get_ticket_by_id(request)
        
        self.assertEqual(result["status"], "error")
        self.assertIn("Rate limit exceeded", result["message"])


if __name__ == "__main__":
    unittest.main()
