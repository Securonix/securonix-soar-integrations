"""
Unit tests for CiscoDuo integration - duo_get_user_groups action.
"""

import json
from unittest.mock import Mock, patch

import pytest
import requests
from pykson import Pykson

from app.cisco_duo import CiscoDuo
from app.model.request_body import RequestBody


def _make_request_body(parameters: dict, connection_params: dict = None) -> RequestBody:
    """Helper to create a RequestBody from dicts."""
    if connection_params is None:
        connection_params = {
            "api_hostname": "api-test.duosecurity.com",
            "integration_key": "test_integration_key",
            "secret_key": "test_secret_key"
        }
    fixture = {
        "parameters": parameters,
        "connectionParameters": connection_params
    }
    return Pykson().from_json(json.dumps(fixture), RequestBody, accept_unknown=True)


class TestDuoGetUserGroups:
    """Tests for the duo_get_user_groups action."""

    def setup_method(self):
        self.duo = CiscoDuo()

    @patch('requests.get')
    def test_get_user_groups_by_user_id_success(self, mock_get):
        """Test successful retrieval of user groups by user_id."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [
                {
                    "group_id": "DGXXXXXXXXXXXXXXXXXX",
                    "name": "Engineering",
                    "desc": "Engineering team",
                    "status": "Active",
                    "mobile_otp_enabled": True
                },
                {
                    "group_id": "DGYYYYYYYYYYYYYYYYYY",
                    "name": "VPN Users",
                    "desc": "VPN access group",
                    "status": "Active",
                    "mobile_otp_enabled": False
                }
            ]
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"user_id": "DUXXXXXXXXXXXXXXXXXX"})
        result = self.duo.duo_get_user_groups(request)

        assert result["status"] == "success"
        assert result["message"] == "User groups retrieved successfully."
        assert len(result["groups"]) == 2
        assert result["count"] == 2
        assert result["groups"][0]["group_id"] == "DGXXXXXXXXXXXXXXXXXX"
        assert result["groups"][0]["name"] == "Engineering"

    @patch('requests.get')
    def test_get_user_groups_by_username_success(self, mock_get):
        """Test successful retrieval of user groups by username (resolves to user_id first)."""
        # First call resolves username to user_id
        mock_resolve_response = Mock()
        mock_resolve_response.status_code = 200
        mock_resolve_response.json.return_value = {
            "stat": "OK",
            "response": [{"user_id": "DUXXXXXXXXXXXXXXXXXX", "username": "jsmith"}]
        }

        # Second call retrieves groups
        mock_groups_response = Mock()
        mock_groups_response.status_code = 200
        mock_groups_response.json.return_value = {
            "stat": "OK",
            "response": [
                {
                    "group_id": "DGXXXXXXXXXXXXXXXXXX",
                    "name": "Engineering",
                    "desc": "Engineering team",
                    "status": "Active",
                    "mobile_otp_enabled": True
                }
            ]
        }

        mock_get.side_effect = [mock_resolve_response, mock_groups_response]

        request = _make_request_body({"username": "jsmith"})
        result = self.duo.duo_get_user_groups(request)

        assert result["status"] == "success"
        assert result["message"] == "User groups retrieved successfully."
        assert len(result["groups"]) == 1
        assert result["count"] == 1
        assert result["groups"][0]["name"] == "Engineering"

    @patch('requests.get')
    def test_get_user_groups_empty_groups(self, mock_get):
        """Test user with no groups returns empty list."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": []
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"user_id": "DUXXXXXXXXXXXXXXXXXX"})
        result = self.duo.duo_get_user_groups(request)

        assert result["status"] == "success"
        assert result["groups"] == []
        assert result["count"] == 0

    def test_get_user_groups_no_params(self):
        """Test that missing both user_id and username returns failed status."""
        request = _make_request_body({})
        result = self.duo.duo_get_user_groups(request)

        assert result["status"] == "failed"
        assert "user_id or username" in result["message"]

    @patch('requests.get')
    def test_get_user_groups_username_not_found(self, mock_get):
        """Test that unresolvable username returns failed status."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": []
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"username": "nonexistent_user"})
        result = self.duo.duo_get_user_groups(request)

        assert result["status"] == "failed"
        assert "User not found: nonexistent_user" in result["message"]

    @patch('requests.get')
    def test_get_user_groups_api_error(self, mock_get):
        """Test that a non-OK stat from Duo API returns failed status."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "FAIL",
            "message": "Invalid user_id"
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"user_id": "INVALID_ID"})
        result = self.duo.duo_get_user_groups(request)

        assert result["status"] == "failed"
        assert "Invalid user_id" in result["message"]

    @patch('requests.get')
    def test_get_user_groups_user_id_prioritized(self, mock_get):
        """Test that user_id is used when both user_id and username are provided."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [
                {"group_id": "DG001", "name": "Group1", "desc": "", "status": "Active", "mobile_otp_enabled": False}
            ]
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"user_id": "DUXXXXXXXXXXXXXXXXXX", "username": "jsmith"})
        result = self.duo.duo_get_user_groups(request)

        assert result["status"] == "success"
        # Only one call should be made (direct groups lookup, no username resolution)
        assert mock_get.call_count == 1

    @patch('requests.get')
    def test_get_user_groups_http_error_raises(self, mock_get):
        """Test that HTTP errors from the API are properly raised."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.json.return_value = {"stat": "FAIL", "message": "Invalid credentials"}
        mock_response.text = "Unauthorized"
        mock_get.return_value = mock_response

        request = _make_request_body({"user_id": "DUXXXXXXXXXXXXXXXXXX"})

        with pytest.raises(Exception) as exc_info:
            self.duo.duo_get_user_groups(request)
        assert "Authentication failed" in str(exc_info.value)


class TestDuoSearchUsers:
    """Tests for the duo_search_users action."""

    def setup_method(self):
        self.duo = CiscoDuo()

    @patch('requests.get')
    def test_search_users_success(self, mock_get):
        """Test successful user search with default params."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [
                {"user_id": "DUSR1", "username": "user1", "email": "user1@example.com", "status": "active"},
                {"user_id": "DUSR2", "username": "user2", "email": "user2@example.com", "status": "active"}
            ],
            "metadata": {"total_objects": 2}
        }
        mock_get.return_value = mock_response

        request = _make_request_body({})
        result = self.duo.duo_search_users(request)

        assert result["status"] == "success"
        assert result["message"] == "Users retrieved successfully."
        assert len(result["users"]) == 2
        assert result["total_objects"] == 2
        assert result["count"] == 2
        assert "pagination" not in result

    @patch('requests.get')
    def test_search_users_with_filters(self, mock_get):
        """Test user search with username, email, and status filters."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [
                {"user_id": "DUSR1", "username": "jsmith", "email": "jsmith@example.com", "status": "active"}
            ],
            "metadata": {"total_objects": 1}
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"username": "jsmith", "email": "jsmith@example.com", "status": "active"})
        result = self.duo.duo_search_users(request)

        assert result["status"] == "success"
        assert result["count"] == 1
        # Verify query params include filters
        call_kwargs = mock_get.call_args
        params_sent = call_kwargs[1].get('params') or call_kwargs.kwargs.get('params', {})
        assert params_sent.get('username') == 'jsmith'
        assert params_sent.get('email') == 'jsmith@example.com'
        assert params_sent.get('status') == 'active'

    @patch('requests.get')
    def test_search_users_limit_capped_at_300(self, mock_get):
        """Test that limit is capped at 300 when a higher value is provided."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [],
            "metadata": {"total_objects": 0}
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"limit": 500})
        result = self.duo.duo_search_users(request)

        assert result["status"] == "success"
        # Verify limit was capped to 300 in the request
        call_kwargs = mock_get.call_args
        params_sent = call_kwargs[1].get('params') or call_kwargs.kwargs.get('params', {})
        assert params_sent.get('limit') == '300'

    @patch('requests.get')
    def test_search_users_pagination_metadata(self, mock_get):
        """Test pagination metadata is included when more pages are available."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [{"user_id": f"DUSR{i}"} for i in range(100)],
            "metadata": {"total_objects": 250}
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"limit": 100, "offset": 0})
        result = self.duo.duo_search_users(request)

        assert result["status"] == "success"
        assert "pagination" in result
        assert result["pagination"]["offset"] == 0
        assert result["pagination"]["limit"] == 100
        assert result["pagination"]["total_objects"] == 250
        assert result["pagination"]["next_offset"] == 100

    @patch('requests.get')
    def test_search_users_no_pagination_when_all_fetched(self, mock_get):
        """Test no pagination metadata when all results fit in one page."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [{"user_id": "DUSR1"}],
            "metadata": {"total_objects": 1}
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"limit": 100, "offset": 0})
        result = self.duo.duo_search_users(request)

        assert result["status"] == "success"
        assert "pagination" not in result

    def test_search_users_invalid_status_filter(self):
        """Test that invalid status filter raises an exception."""
        request = _make_request_body({"status": "invalid_status"})

        with pytest.raises(Exception, match="Invalid status filter"):
            self.duo.duo_search_users(request)

    def test_search_users_offset_exceeds_10000(self):
        """Test that offset > 10000 raises an exception."""
        request = _make_request_body({"offset": 10001})

        with pytest.raises(Exception, match="Offset exceeds maximum retrievable records limit of 10000"):
            self.duo.duo_search_users(request)

    @patch('requests.get')
    def test_search_users_empty_results(self, mock_get):
        """Test search with no matching users returns success with empty list."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [],
            "metadata": {"total_objects": 0}
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"username": "nonexistent"})
        result = self.duo.duo_search_users(request)

        assert result["status"] == "success"
        assert result["users"] == []
        assert result["total_objects"] == 0
        assert result["count"] == 0

    @patch('requests.get')
    def test_search_users_api_error_raises(self, mock_get):
        """Test that API errors are properly raised."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_get.return_value = mock_response

        request = _make_request_body({})

        with pytest.raises(Exception, match="Authentication failed"):
            self.duo.duo_search_users(request)


class TestDuoGetUser:
    """Tests for the duo_get_user action."""

    def setup_method(self):
        self.duo = CiscoDuo()

    @patch('requests.get')
    def test_get_user_by_id_success(self, mock_get):
        """Test successful user retrieval by user_id."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": {
                "user_id": "DUSR12345",
                "username": "jsmith",
                "realname": "John Smith",
                "email": "jsmith@example.com",
                "status": "active",
                "created": 1234567890,
                "last_login": 1234567899,
                "groups": [],
                "phones": [],
                "tokens": []
            }
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"user_id": "DUSR12345"})
        result = self.duo.duo_get_user(request)

        assert result["status"] == "success"
        assert result["message"] == "User retrieved successfully."
        assert result["user"]["user_id"] == "DUSR12345"
        assert result["user"]["username"] == "jsmith"
        assert result["user_id"] == "DUSR12345"

    @patch('requests.get')
    def test_get_user_by_username_success(self, mock_get):
        """Test successful user retrieval by username."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [
                {
                    "user_id": "DUSR12345",
                    "username": "jsmith",
                    "realname": "John Smith",
                    "email": "jsmith@example.com",
                    "status": "active"
                }
            ]
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"username": "jsmith"})
        result = self.duo.duo_get_user(request)

        assert result["status"] == "success"
        assert result["user"]["username"] == "jsmith"
        assert result["user_id"] == "DUSR12345"

    @patch('requests.get')
    def test_get_user_by_id_prioritized_over_username(self, mock_get):
        """When both user_id and username are provided, user_id is prioritized."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": {
                "user_id": "DUSR12345",
                "username": "jsmith"
            }
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"user_id": "DUSR12345", "username": "jsmith"})
        result = self.duo.duo_get_user(request)

        assert result["status"] == "success"
        # Verify the call was to /admin/v1/users/DUSR12345 (user_id path)
        call_url = mock_get.call_args[0][0]
        assert "/admin/v1/users/DUSR12345" in call_url

    @patch('requests.get')
    def test_get_user_by_username_not_found(self, mock_get):
        """Test user not found by username returns failed status."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": []
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"username": "nonexistent"})
        result = self.duo.duo_get_user(request)

        assert result["status"] == "failed"
        assert "nonexistent" in result["message"]

    @patch('requests.get')
    def test_get_user_by_id_not_found_404(self, mock_get):
        """Test user not found by user_id (404 from API) returns failed status."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Resource not found"
        mock_response.json.return_value = {
            "stat": "FAIL",
            "message": "Resource not found"
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"user_id": "DUSR_INVALID"})
        result = self.duo.duo_get_user(request)

        assert result["status"] == "failed"
        assert "DUSR_INVALID" in result["message"]

    def test_get_user_neither_param_provided(self):
        """Test that exception is raised when neither user_id nor username is provided."""
        request = _make_request_body({})

        with pytest.raises(Exception, match="Either user_id or username must be provided"):
            self.duo.duo_get_user(request)

    @patch('requests.get')
    def test_get_user_by_id_stat_not_ok(self, mock_get):
        """Test user_id lookup where stat is not OK returns failed."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "FAIL",
            "message": "Invalid user_id"
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"user_id": "DUSR_BAD"})
        result = self.duo.duo_get_user(request)

        assert result["status"] == "failed"
        assert "DUSR_BAD" in result["message"]


class TestDuoAddUserToGroup:
    """Tests for the duo_add_user_to_group action."""

    def setup_method(self):
        self.duo = CiscoDuo()

    @patch('requests.post')
    def test_add_user_to_group_success(self, mock_post):
        """Test successful addition of user to group."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": ""
        }
        mock_post.return_value = mock_response

        request = _make_request_body({"user_id": "DUXXXXXXXXXXXXXXXXXX", "group_id": "DGXXXXXXXXXXXXXXXXXX"})
        result = self.duo.duo_add_user_to_group(request)

        assert result["status"] == "success"
        assert result["message"] == "User added to group successfully."
        assert result["user_id"] == "DUXXXXXXXXXXXXXXXXXX"
        assert result["group_id"] == "DGXXXXXXXXXXXXXXXXXX"

    @patch('requests.post')
    def test_add_user_to_group_verifies_post_params(self, mock_post):
        """Test that group_id is sent as form-encoded body data."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"stat": "OK", "response": ""}
        mock_post.return_value = mock_response

        request = _make_request_body({"user_id": "DUSR123", "group_id": "DGRP456"})
        self.duo.duo_add_user_to_group(request)

        # Verify POST was called with group_id in body data
        call_kwargs = mock_post.call_args
        assert call_kwargs[1].get('data') == {"group_id": "DGRP456"}
        # Verify URL contains user_id
        call_url = call_kwargs[0][0]
        assert "/admin/v1/users/DUSR123/groups" in call_url

    def test_add_user_to_group_missing_user_id(self):
        """Test that missing user_id raises an exception."""
        request = _make_request_body({"group_id": "DGXXXXXXXXXXXXXXXXXX"})

        with pytest.raises(Exception, match="Missing required parameter: user_id"):
            self.duo.duo_add_user_to_group(request)

    def test_add_user_to_group_missing_group_id(self):
        """Test that missing group_id raises an exception."""
        request = _make_request_body({"user_id": "DUXXXXXXXXXXXXXXXXXX"})

        with pytest.raises(Exception, match="Missing required parameter: group_id"):
            self.duo.duo_add_user_to_group(request)

    def test_add_user_to_group_missing_both_params(self):
        """Test that missing both params raises exception for user_id first."""
        request = _make_request_body({})

        with pytest.raises(Exception, match="Missing required parameter: user_id"):
            self.duo.duo_add_user_to_group(request)

    @patch('requests.post')
    def test_add_user_to_group_api_error(self, mock_post):
        """Test that non-OK stat from Duo API raises an exception."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "FAIL",
            "message": "Resource not found"
        }
        mock_post.return_value = mock_response

        request = _make_request_body({"user_id": "DUSR_INVALID", "group_id": "DGRP456"})

        with pytest.raises(Exception, match="Resource not found"):
            self.duo.duo_add_user_to_group(request)

    @patch('requests.post')
    def test_add_user_to_group_http_401_error(self, mock_post):
        """Test that HTTP 401 errors are properly raised."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_response.json.return_value = {"stat": "FAIL", "message": "Invalid credentials"}
        mock_post.return_value = mock_response

        request = _make_request_body({"user_id": "DUSR123", "group_id": "DGRP456"})

        with pytest.raises(Exception, match="Authentication failed"):
            self.duo.duo_add_user_to_group(request)


class TestDuoRemoveUserFromGroup:
    """Tests for the duo_remove_user_from_group action."""

    def setup_method(self):
        self.duo = CiscoDuo()

    @patch('requests.delete')
    def test_remove_user_from_group_success(self, mock_delete):
        """Test successful removal of user from group."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": ""
        }
        mock_delete.return_value = mock_response

        request = _make_request_body({"user_id": "DUXXXXXXXXXXXXXXXXXX", "group_id": "DGXXXXXXXXXXXXXXXXXX"})
        result = self.duo.duo_remove_user_from_group(request)

        assert result["status"] == "success"
        assert result["message"] == "User removed from group successfully."
        assert result["user_id"] == "DUXXXXXXXXXXXXXXXXXX"
        assert result["group_id"] == "DGXXXXXXXXXXXXXXXXXX"

    @patch('requests.delete')
    def test_remove_user_from_group_not_member_404(self, mock_delete):
        """Test that 404 response returns failed status indicating user is not a member."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Resource Not Found"
        mock_response.json.return_value = {
            "stat": "FAIL",
            "message": "Resource not found"
        }
        mock_delete.return_value = mock_response

        request = _make_request_body({"user_id": "DUXXXXXXXXXXXXXXXXXX", "group_id": "DGXXXXXXXXXXXXXXXXXX"})
        result = self.duo.duo_remove_user_from_group(request)

        assert result["status"] == "failed"
        assert "not a member" in result["message"]

    def test_remove_user_from_group_missing_user_id(self):
        """Test that missing user_id raises exception."""
        request = _make_request_body({"group_id": "DGXXXXXXXXXXXXXXXXXX"})

        with pytest.raises(Exception, match="Missing required parameter: user_id"):
            self.duo.duo_remove_user_from_group(request)

    def test_remove_user_from_group_missing_group_id(self):
        """Test that missing group_id raises exception."""
        request = _make_request_body({"user_id": "DUXXXXXXXXXXXXXXXXXX"})

        with pytest.raises(Exception, match="Missing required parameter: group_id"):
            self.duo.duo_remove_user_from_group(request)

    def test_remove_user_from_group_both_params_missing(self):
        """Test that missing both params raises exception for user_id first."""
        request = _make_request_body({})

        with pytest.raises(Exception, match="Missing required parameter: user_id"):
            self.duo.duo_remove_user_from_group(request)

    @patch('requests.delete')
    def test_remove_user_from_group_api_stat_fail(self, mock_delete):
        """Test that non-OK stat from API returns failed status."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "FAIL",
            "message": "Invalid group_id"
        }
        mock_delete.return_value = mock_response

        request = _make_request_body({"user_id": "DUXXXXXXXXXXXXXXXXXX", "group_id": "INVALID_GROUP"})
        result = self.duo.duo_remove_user_from_group(request)

        assert result["status"] == "failed"
        assert "Invalid group_id" in result["message"]

    @patch('requests.delete')
    def test_remove_user_from_group_auth_error_raises(self, mock_delete):
        """Test that HTTP 401 from the API raises an exception."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_response.json.return_value = {"stat": "FAIL", "message": "Invalid credentials"}
        mock_delete.return_value = mock_response

        request = _make_request_body({"user_id": "DUXXXXXXXXXXXXXXXXXX", "group_id": "DGXXXXXXXXXXXXXXXXXX"})

        with pytest.raises(Exception, match="Authentication failed"):
            self.duo.duo_remove_user_from_group(request)


class TestDuoTestConnection:
    """Tests for the test_connection action."""

    def setup_method(self):
        self.duo = CiscoDuo()
        self.connection_params = {
            "api_hostname": "api-test.duosecurity.com",
            "integration_key": "test_integration_key",
            "secret_key": "test_secret_key"
        }

    @patch('requests.get')
    def test_connection_success(self, mock_get):
        """Test successful connection verification."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": {"admin_count": 1, "user_count": 50}
        }
        mock_get.return_value = mock_response

        result = self.duo.test_connection(self.connection_params)

        assert result["status"] == "success"
        assert "Connected" in result["message"] or "success" in result["message"].lower()

    @patch('requests.get')
    def test_connection_auth_failure_401(self, mock_get):
        """Test authentication failure (401) raises Exception."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.json.return_value = {"stat": "FAIL", "message": "Invalid credentials"}
        mock_response.text = "Unauthorized"
        mock_get.return_value = mock_response

        with pytest.raises(Exception) as exc_info:
            self.duo.test_connection(self.connection_params)
        assert "Authentication failed" in str(exc_info.value)

    @patch('requests.get')
    def test_connection_network_error(self, mock_get):
        """Test network connectivity error raises Exception."""
        mock_get.side_effect = Exception("Unable to connect to Duo API. Please check network connectivity and hostname.")

        with pytest.raises(Exception) as exc_info:
            self.duo.test_connection(self.connection_params)
        assert "Unable to connect" in str(exc_info.value) or "connect" in str(exc_info.value).lower()

    def test_connection_missing_api_hostname(self):
        """Test missing api_hostname raises Exception."""
        params = {
            "api_hostname": "",
            "integration_key": "test_integration_key",
            "secret_key": "test_secret_key"
        }

        with pytest.raises(Exception) as exc_info:
            self.duo.test_connection(params)
        assert "api_hostname" in str(exc_info.value)

    def test_connection_missing_integration_key(self):
        """Test missing integration_key raises Exception."""
        params = {
            "api_hostname": "api-test.duosecurity.com",
            "integration_key": "",
            "secret_key": "test_secret_key"
        }

        with pytest.raises(Exception) as exc_info:
            self.duo.test_connection(params)
        assert "integration_key" in str(exc_info.value)

    def test_connection_missing_secret_key(self):
        """Test missing secret_key raises Exception."""
        params = {
            "api_hostname": "api-test.duosecurity.com",
            "integration_key": "test_integration_key",
            "secret_key": ""
        }

        with pytest.raises(Exception) as exc_info:
            self.duo.test_connection(params)
        assert "secret_key" in str(exc_info.value)


class TestDuoGetAuthLogs:
    """Tests for the duo_get_auth_logs action."""

    def setup_method(self):
        self.duo = CiscoDuo()

    @patch('requests.get')
    def test_get_auth_logs_success(self, mock_get):
        """Test successful retrieval of authentication logs."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": {
                "authlogs": [
                    {
                        "timestamp": 1234567890,
                        "user": {"name": "jsmith"},
                        "result": "success",
                        "reason": "user_approved",
                        "factor": "duo_push"
                    }
                ],
                "metadata": {
                    "total_objects": 1
                }
            }
        }
        mock_get.return_value = mock_response

        request = _make_request_body({})
        result = self.duo.duo_get_auth_logs(request)

        assert result["status"] == "success"
        assert result["message"] == "Authentication logs retrieved successfully."
        assert len(result["authlogs"]) == 1
        assert result["count"] == 1

    @patch('requests.get')
    def test_get_auth_logs_with_pagination(self, mock_get):
        """Test auth logs response with next_offset for pagination."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": {
                "authlogs": [{"timestamp": i} for i in range(100)],
                "metadata": {
                    "total_objects": 500,
                    "next_offset": "1234567890123_abc123"
                }
            }
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"limit": 100})
        result = self.duo.duo_get_auth_logs(request)

        assert result["status"] == "success"
        assert "pagination" in result
        assert result["pagination"]["next_offset"] == "1234567890123_abc123"
        assert result["next_offset"] == "1234567890123_abc123"

    def test_get_auth_logs_mintime_invalid_format(self):
        """Test that invalid mintime format raises Exception."""
        request = _make_request_body({"mintime": "123456"})

        with pytest.raises(Exception) as exc_info:
            self.duo.duo_get_auth_logs(request)
        assert "Invalid mintime" in str(exc_info.value)

    def test_get_auth_logs_mintime_too_old(self):
        """Test that mintime older than 180 days raises Exception."""
        import time as time_module
        # Create a timestamp that is 200 days old
        old_timestamp = str(int((time_module.time() - (200 * 24 * 60 * 60)) * 1000))

        request = _make_request_body({"mintime": old_timestamp})

        with pytest.raises(Exception) as exc_info:
            self.duo.duo_get_auth_logs(request)
        assert "180 days" in str(exc_info.value)

    @patch('requests.get')
    def test_get_auth_logs_limit_capped_at_1000(self, mock_get):
        """Test that limit is capped at 1000 when higher value provided."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": {
                "authlogs": [],
                "metadata": {"total_objects": 0}
            }
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"limit": 5000})
        result = self.duo.duo_get_auth_logs(request)

        assert result["status"] == "success"
        # Verify limit was capped to 1000 in the request
        call_kwargs = mock_get.call_args
        params_sent = call_kwargs[1].get('params') or call_kwargs.kwargs.get('params', {})
        assert params_sent.get('limit') == '1000'

    @patch('requests.get')
    def test_get_auth_logs_api_error(self, mock_get):
        """Test that API error returns failed status."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "FAIL",
            "response": {},
            "message": "Invalid parameters"
        }
        mock_get.return_value = mock_response

        request = _make_request_body({})
        result = self.duo.duo_get_auth_logs(request)

        assert result["status"] == "failed"


class TestDuoGetUserDevices:
    """Tests for the duo_get_user_devices action."""

    def setup_method(self):
        self.duo = CiscoDuo()

    @patch('requests.get')
    def test_get_user_devices_by_user_id_success(self, mock_get):
        """Test successful device retrieval by user_id."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [
                {
                    "phone_id": "DPXXXXXXXXXXXXXXXXXX",
                    "type": "Mobile",
                    "name": "iPhone",
                    "platform": "Apple iOS",
                    "number": "+1234567890",
                    "activated": True,
                    "last_seen": "2023-01-01T00:00:00"
                }
            ]
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"user_id": "DUSR12345"})
        result = self.duo.duo_get_user_devices(request)

        assert result["status"] == "success"
        assert result["message"] == "User devices retrieved successfully."
        assert len(result["phones"]) == 1
        assert result["count"] == 1
        assert result["phones"][0]["phone_id"] == "DPXXXXXXXXXXXXXXXXXX"

    @patch('requests.get')
    def test_get_user_devices_by_username_success(self, mock_get):
        """Test successful device retrieval by username (with resolution)."""
        # First call resolves username to user_id
        mock_resolve_response = Mock()
        mock_resolve_response.status_code = 200
        mock_resolve_response.json.return_value = {
            "stat": "OK",
            "response": [{"user_id": "DUSR12345", "username": "jsmith"}]
        }

        # Second call retrieves phones
        mock_phones_response = Mock()
        mock_phones_response.status_code = 200
        mock_phones_response.json.return_value = {
            "stat": "OK",
            "response": [
                {"phone_id": "DPXXXXXXXXXXXXXXXXXX", "type": "Mobile", "name": "iPhone"}
            ]
        }

        mock_get.side_effect = [mock_resolve_response, mock_phones_response]

        request = _make_request_body({"username": "jsmith"})
        result = self.duo.duo_get_user_devices(request)

        assert result["status"] == "success"
        assert len(result["phones"]) == 1
        assert result["count"] == 1

    @patch('requests.get')
    def test_get_user_devices_empty_phones(self, mock_get):
        """Test user with no registered devices returns empty list."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": []
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"user_id": "DUSR12345"})
        result = self.duo.duo_get_user_devices(request)

        assert result["status"] == "success"
        assert result["phones"] == []
        assert result["count"] == 0

    def test_get_user_devices_missing_params(self):
        """Test that missing both user_id and username returns failed status."""
        request = _make_request_body({})
        result = self.duo.duo_get_user_devices(request)

        assert result["status"] == "failed"
        assert "user_id or username" in result["message"] or "Either" in result["message"]

    @patch('requests.get')
    def test_get_user_devices_username_not_found(self, mock_get):
        """Test that unresolvable username returns failed status."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": []
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"username": "nonexistent_user"})
        result = self.duo.duo_get_user_devices(request)

        assert result["status"] == "failed"
        assert "nonexistent_user" in result["message"]


class TestDuoUpdateUserStatus:
    """Tests for the duo_update_user_status action."""

    def setup_method(self):
        self.duo = CiscoDuo()

    @patch('requests.post')
    def test_update_user_status_success(self, mock_post):
        """Test successful user status update."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": {
                "user_id": "DUSR12345",
                "username": "jsmith",
                "status": "disabled"
            }
        }
        mock_post.return_value = mock_response

        request = _make_request_body({"user_id": "DUSR12345", "status": "disabled"})
        result = self.duo.duo_update_user_status(request)

        assert result["status"] == "success"
        assert "disabled" in result["message"]
        assert result["user"]["status"] == "disabled"
        assert result["user_id"] == "DUSR12345"

    def test_update_user_status_invalid_status(self):
        """Test that invalid status raises Exception."""
        request = _make_request_body({"user_id": "DUSR12345", "status": "invalid_status"})

        with pytest.raises(Exception) as exc_info:
            self.duo.duo_update_user_status(request)
        assert "Invalid status" in str(exc_info.value)

    def test_update_user_status_missing_status(self):
        """Test that missing status parameter raises Exception."""
        request = _make_request_body({"user_id": "DUSR12345"})

        with pytest.raises(Exception) as exc_info:
            self.duo.duo_update_user_status(request)
        assert "status" in str(exc_info.value).lower()

    @patch('requests.get')
    @patch('requests.post')
    def test_update_user_status_username_resolution(self, mock_post, mock_get):
        """Test status update with username resolution."""
        # First call resolves username to user_id
        mock_resolve_response = Mock()
        mock_resolve_response.status_code = 200
        mock_resolve_response.json.return_value = {
            "stat": "OK",
            "response": [{"user_id": "DUSR12345", "username": "jsmith"}]
        }
        mock_get.return_value = mock_resolve_response

        # POST to update status
        mock_post_response = Mock()
        mock_post_response.status_code = 200
        mock_post_response.json.return_value = {
            "stat": "OK",
            "response": {
                "user_id": "DUSR12345",
                "username": "jsmith",
                "status": "bypass"
            }
        }
        mock_post.return_value = mock_post_response

        request = _make_request_body({"username": "jsmith", "status": "bypass"})
        result = self.duo.duo_update_user_status(request)

        assert result["status"] == "success"
        assert result["user"]["status"] == "bypass"

    def test_update_user_status_missing_user_id_and_username(self):
        """Test that missing both user_id and username raises Exception."""
        request = _make_request_body({"status": "active"})

        with pytest.raises(Exception) as exc_info:
            self.duo.duo_update_user_status(request)
        assert "user_id or username" in str(exc_info.value) or "Either" in str(exc_info.value)


class TestDuoRateLimitRetry:
    """Tests for rate limit retry behavior (HTTP 429)."""

    def setup_method(self):
        self.duo = CiscoDuo()

    @patch('time.sleep')
    @patch('requests.get')
    def test_rate_limit_retry_then_success(self, mock_get, mock_sleep):
        """Test that 429 is retried and eventually succeeds."""
        # First response: 429 Rate Limited
        mock_429_response = Mock()
        mock_429_response.status_code = 429
        mock_429_response.headers = {"Retry-After": "2"}

        # Second response: 200 OK
        mock_200_response = Mock()
        mock_200_response.status_code = 200
        mock_200_response.json.return_value = {
            "stat": "OK",
            "response": {
                "user_id": "DUSR12345",
                "username": "jsmith",
                "status": "active"
            }
        }

        mock_get.side_effect = [mock_429_response, mock_200_response]

        request = _make_request_body({"user_id": "DUSR12345"})
        result = self.duo.duo_get_user(request)

        assert result["status"] == "success"
        assert result["user"]["user_id"] == "DUSR12345"
        # Verify time.sleep was called with retry_after value
        mock_sleep.assert_called_once_with(2)
        # Verify 2 GET requests were made
        assert mock_get.call_count == 2

    @patch('time.sleep')
    @patch('requests.get')
    def test_rate_limit_exhausted_after_max_retries(self, mock_get, mock_sleep):
        """Test that exceeding max retries raises Exception."""
        mock_429_response = Mock()
        mock_429_response.status_code = 429
        mock_429_response.headers = {"Retry-After": "1"}

        # All 3 attempts return 429
        mock_get.return_value = mock_429_response

        request = _make_request_body({"user_id": "DUSR12345"})

        with pytest.raises(Exception) as exc_info:
            self.duo.duo_get_user(request)
        assert "Rate limited" in str(exc_info.value) or "rate" in str(exc_info.value).lower()


class TestDuoTimeout:
    """Tests for timeout handling."""

    def setup_method(self):
        self.duo = CiscoDuo()

    @patch('requests.get')
    def test_timeout_raises_exception(self, mock_get):
        """Test that a timeout raises an appropriate Exception."""
        mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")

        request = _make_request_body({"user_id": "DUSR12345"})

        with pytest.raises(Exception) as exc_info:
            self.duo.duo_get_user(request)
        assert "timed out" in str(exc_info.value).lower() or "timeout" in str(exc_info.value).lower()


class TestDuoSigningUtility:
    """Tests for the duo_auth.py signing utility functions."""

    def test_build_canonical_string_known_inputs(self):
        """Test build_canonical_string produces correct output for known inputs."""
        from app.duo_auth import build_canonical_string

        date = "Tue, 21 Aug 2012 17:29:18 -0000"
        method = "POST"
        host = "api-XXXXXXXX.duosecurity.com"
        path = "/admin/v1/users"
        params = {"realname": "First Last", "username": "jsmith"}

        result = build_canonical_string(date, method, host, path, params)

        # Verify structure: 5 components separated by 4 newlines
        parts = result.split("\n")
        assert len(parts) == 5
        assert parts[0] == date
        assert parts[1] == "POST"  # uppercased
        assert parts[2] == "api-xxxxxxxx.duosecurity.com"  # lowercased
        assert parts[3] == "/admin/v1/users"
        # Params should be sorted and URL-encoded
        assert "realname=First%20Last" in parts[4]
        assert "username=jsmith" in parts[4]
        # realname comes before username alphabetically
        assert parts[4].index("realname") < parts[4].index("username")

    def test_sign_request_produces_128_char_hex(self):
        """Test that sign_request produces a 128-character hex string (SHA-512)."""
        from app.duo_auth import sign_request

        date = "Tue, 21 Aug 2012 17:29:18 -0000"
        method = "GET"
        host = "api-test.duosecurity.com"
        path = "/admin/v1/info/summary"
        params = {}
        secret_key = "test_secret_key"

        result = sign_request(date, method, host, path, params, secret_key)

        # SHA-512 hex digest is 128 characters
        assert len(result) == 128
        # All hex characters
        assert all(c in '0123456789abcdef' for c in result)

    def test_sign_request_raises_for_empty_secret_key(self):
        """Test that sign_request raises ValueError for empty secret_key."""
        from app.duo_auth import sign_request

        with pytest.raises(ValueError) as exc_info:
            sign_request("date", "GET", "host", "/path", {}, "")
        assert "secret_key" in str(exc_info.value).lower()

    def test_sign_request_raises_for_none_secret_key(self):
        """Test that sign_request raises ValueError for None secret_key."""
        from app.duo_auth import sign_request

        with pytest.raises(ValueError) as exc_info:
            sign_request("date", "GET", "host", "/path", {}, None)
        assert "secret_key" in str(exc_info.value).lower()

    def test_build_authorization_header_format(self):
        """Test that build_authorization_header returns properly formatted header."""
        import base64
        from app.duo_auth import build_authorization_header

        ikey = "test_integration_key"
        signature = "a" * 128  # Fake hex signature

        result = build_authorization_header(ikey, signature)

        # Should start with "Basic "
        assert result.startswith("Basic ")
        # Decode the base64 portion
        encoded_part = result[len("Basic "):]
        decoded = base64.b64decode(encoded_part).decode("utf-8")
        assert decoded == f"{ikey}:{signature}"


class TestDuoGetGroups:
    """Tests for the duo_get_groups action."""

    def setup_method(self):
        self.duo = CiscoDuo()

    @patch('requests.get')
    def test_get_groups_success(self, mock_get):
        """Test successful retrieval of groups with metadata."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [
                {"group_id": "DG001", "name": "Engineering", "desc": "Eng team", "status": "Active"},
                {"group_id": "DG002", "name": "VPN Users", "desc": "VPN", "status": "Active"}
            ],
            "metadata": {"total_objects": 2}
        }
        mock_get.return_value = mock_response

        request = _make_request_body({})
        result = self.duo.duo_get_groups(request)

        assert result["status"] == "success"
        assert result["message"] == "Groups retrieved successfully."
        assert len(result["groups"]) == 2
        assert result["count"] == 2
        assert result["total_objects"] == 2
        assert "pagination" not in result

    @patch('requests.get')
    def test_get_groups_limit_capped_at_300(self, mock_get):
        """Test that limit is capped at 300 when a higher value is provided."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [],
            "metadata": {"total_objects": 0}
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"limit": 500})
        result = self.duo.duo_get_groups(request)

        assert result["status"] == "success"
        call_kwargs = mock_get.call_args
        params_sent = call_kwargs[1].get('params') or call_kwargs.kwargs.get('params', {})
        assert params_sent.get('limit') == '300'

    @patch('requests.get')
    def test_get_groups_pagination_metadata(self, mock_get):
        """Test pagination metadata is present when total_objects exceeds offset+limit."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [{"group_id": f"DG{i}"} for i in range(100)],
            "metadata": {"total_objects": 250}
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"limit": 100, "offset": 0})
        result = self.duo.duo_get_groups(request)

        assert result["status"] == "success"
        assert "pagination" in result
        assert result["pagination"]["offset"] == 0
        assert result["pagination"]["limit"] == 100
        assert result["pagination"]["total_objects"] == 250
        assert result["pagination"]["next_offset"] == 100

    @patch('requests.get')
    def test_get_groups_no_pagination_when_all_fetched(self, mock_get):
        """Test no pagination metadata when all results fit in one page."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [{"group_id": "DG001"}],
            "metadata": {"total_objects": 1}
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"limit": 100, "offset": 0})
        result = self.duo.duo_get_groups(request)

        assert result["status"] == "success"
        assert "pagination" not in result

    def test_get_groups_offset_exceeds_10000(self):
        """Test that offset > 10000 raises an exception."""
        request = _make_request_body({"offset": 10001})

        with pytest.raises(Exception, match="Offset exceeds maximum retrievable records limit of 10000"):
            self.duo.duo_get_groups(request)

    @patch('requests.get')
    def test_get_groups_api_stat_fail(self, mock_get):
        """Test that non-OK stat from Duo API returns failed status."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "FAIL",
            "message": "Something went wrong"
        }
        mock_get.return_value = mock_response

        request = _make_request_body({})
        result = self.duo.duo_get_groups(request)

        assert result["status"] == "failed"
        assert "Something went wrong" in result["message"]

    @patch('requests.get')
    def test_get_groups_http_401_raises(self, mock_get):
        """Test that HTTP 401 errors are properly raised."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_response.json.return_value = {"stat": "FAIL", "message": "Invalid credentials"}
        mock_get.return_value = mock_response

        request = _make_request_body({})

        with pytest.raises(Exception, match="Authentication failed"):
            self.duo.duo_get_groups(request)

    @patch('time.sleep')
    @patch('requests.get')
    def test_get_groups_rate_limit_retry_then_success(self, mock_get, mock_sleep):
        """Test that 429 is retried and eventually succeeds for duo_get_groups."""
        mock_429_response = Mock()
        mock_429_response.status_code = 429
        mock_429_response.headers = {"Retry-After": "2"}

        mock_200_response = Mock()
        mock_200_response.status_code = 200
        mock_200_response.json.return_value = {
            "stat": "OK",
            "response": [{"group_id": "DG001", "name": "Engineering"}],
            "metadata": {"total_objects": 1}
        }

        mock_get.side_effect = [mock_429_response, mock_200_response]

        request = _make_request_body({})
        result = self.duo.duo_get_groups(request)

        assert result["status"] == "success"
        assert result["count"] == 1
        mock_sleep.assert_called_once_with(2)
        assert mock_get.call_count == 2


class TestDuoSearchGroups:
    """Tests for the duo_search_groups action."""

    def setup_method(self):
        self.duo = CiscoDuo()

    @patch('requests.get')
    def test_search_groups_success_case_insensitive(self, mock_get):
        """Test that group_name matches a subset case-insensitively."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [
                {"group_id": "DG001", "name": "Engineering"},
                {"group_id": "DG002", "name": "VPN Users"},
                {"group_id": "DG003", "name": "engineering-admins"}
            ],
            "metadata": {"total_objects": 3}
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"group_name": "engineering"})
        result = self.duo.duo_search_groups(request)

        assert result["status"] == "success"
        assert result["count"] == 2
        matched_names = [g["name"] for g in result["groups"]]
        assert "Engineering" in matched_names
        assert "engineering-admins" in matched_names
        assert "VPN Users" not in matched_names

    def test_search_groups_missing_group_name(self):
        """Test that missing group_name raises an exception."""
        request = _make_request_body({})

        with pytest.raises(Exception, match="Missing required parameter: group_name"):
            self.duo.duo_search_groups(request)

    @patch('requests.get')
    def test_search_groups_no_matches(self, mock_get):
        """Test search returning no matches yields success with empty groups."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [
                {"group_id": "DG001", "name": "Engineering"},
                {"group_id": "DG002", "name": "VPN Users"}
            ],
            "metadata": {"total_objects": 2}
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"group_name": "nonexistent"})
        result = self.duo.duo_search_groups(request)

        assert result["status"] == "success"
        assert result["groups"] == []
        assert result["count"] == 0

    @patch('requests.get')
    def test_search_groups_api_stat_fail(self, mock_get):
        """Test that non-OK stat from Duo API returns failed status."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "FAIL",
            "message": "Something went wrong"
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"group_name": "engineering"})
        result = self.duo.duo_search_groups(request)

        assert result["status"] == "failed"
        assert "Something went wrong" in result["message"]


class TestDuoGetDevice:
    """Tests for the duo_get_device action."""

    def setup_method(self):
        self.duo = CiscoDuo()

    @patch('requests.get')
    def test_get_device_success(self, mock_get):
        """Test successful retrieval of a device by phone_id."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": {
                "phone_id": "DPXXXXXXXXXXXXXXXXXX",
                "number": "+15555550100",
                "type": "mobile",
                "platform": "Apple iOS"
            }
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"phone_id": "DPXXXXXXXXXXXXXXXXXX"})
        result = self.duo.duo_get_device(request)

        assert result["status"] == "success"
        assert result["message"] == "Device retrieved successfully."
        assert result["phone"]["phone_id"] == "DPXXXXXXXXXXXXXXXXXX"
        assert result["phone_id"] == "DPXXXXXXXXXXXXXXXXXX"

    def test_get_device_missing_phone_id(self):
        """Test that missing phone_id raises an exception."""
        request = _make_request_body({})

        with pytest.raises(Exception, match="Missing required parameter: phone_id"):
            self.duo.duo_get_device(request)

    @patch('requests.get')
    def test_get_device_not_found_404(self, mock_get):
        """Test that a 404 returns failed status with Device not found."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Resource not found"
        mock_response.json.return_value = {"stat": "FAIL", "message": "Resource not found"}
        mock_get.return_value = mock_response

        request = _make_request_body({"phone_id": "DP_INVALID"})
        result = self.duo.duo_get_device(request)

        assert result["status"] == "failed"
        assert "Device not found" in result["message"]
        assert "DP_INVALID" in result["message"]

    @patch('requests.get')
    def test_get_device_stat_not_ok(self, mock_get):
        """Test that a non-OK stat returns failed status."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "FAIL",
            "message": "Invalid phone_id"
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"phone_id": "DP_BAD"})
        result = self.duo.duo_get_device(request)

        assert result["status"] == "failed"
        assert "Device not found" in result["message"]


class TestDuoSearchDevices:
    """Tests for the duo_search_devices action."""

    def setup_method(self):
        self.duo = CiscoDuo()

    @patch('requests.get')
    def test_search_devices_success(self, mock_get):
        """Test successful retrieval of devices with metadata."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [
                {"phone_id": "DP001", "number": "+15555550100"},
                {"phone_id": "DP002", "number": "+15555550101"}
            ],
            "metadata": {"total_objects": 2}
        }
        mock_get.return_value = mock_response

        request = _make_request_body({})
        result = self.duo.duo_search_devices(request)

        assert result["status"] == "success"
        assert result["message"] == "Devices retrieved successfully."
        assert len(result["phones"]) == 2
        assert result["count"] == 2
        assert result["total_objects"] == 2
        assert "pagination" not in result

    @patch('requests.get')
    def test_search_devices_with_filters(self, mock_get):
        """Test that number and extension filters are sent as query params."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [{"phone_id": "DP001", "number": "+15555550100", "extension": "123"}],
            "metadata": {"total_objects": 1}
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"number": "+15555550100", "extension": "123"})
        result = self.duo.duo_search_devices(request)

        assert result["status"] == "success"
        call_kwargs = mock_get.call_args
        params_sent = call_kwargs[1].get('params') or call_kwargs.kwargs.get('params', {})
        assert params_sent.get('number') == '+15555550100'
        assert params_sent.get('extension') == '123'

    @patch('requests.get')
    def test_search_devices_limit_capped_at_300(self, mock_get):
        """Test that limit is capped at 300 when a higher value is provided."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [],
            "metadata": {"total_objects": 0}
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"limit": 500})
        result = self.duo.duo_search_devices(request)

        assert result["status"] == "success"
        call_kwargs = mock_get.call_args
        params_sent = call_kwargs[1].get('params') or call_kwargs.kwargs.get('params', {})
        assert params_sent.get('limit') == '300'

    @patch('requests.get')
    def test_search_devices_pagination_metadata(self, mock_get):
        """Test pagination metadata is present when more pages are available."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": [{"phone_id": f"DP{i}"} for i in range(100)],
            "metadata": {"total_objects": 250}
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"limit": 100, "offset": 0})
        result = self.duo.duo_search_devices(request)

        assert result["status"] == "success"
        assert "pagination" in result
        assert result["pagination"]["next_offset"] == 100
        assert result["pagination"]["total_objects"] == 250

    def test_search_devices_offset_exceeds_10000(self):
        """Test that offset > 10000 raises an exception."""
        request = _make_request_body({"offset": 10001})

        with pytest.raises(Exception, match="Offset exceeds maximum retrievable records limit of 10000"):
            self.duo.duo_search_devices(request)

    @patch('requests.get')
    def test_search_devices_api_stat_fail(self, mock_get):
        """Test that non-OK stat from Duo API returns failed status."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "FAIL",
            "message": "Something went wrong"
        }
        mock_get.return_value = mock_response

        request = _make_request_body({})
        result = self.duo.duo_search_devices(request)

        assert result["status"] == "failed"
        assert "Something went wrong" in result["message"]


class TestDuoGetAdminLogs:
    """Tests for the duo_get_admin_logs action."""

    def setup_method(self):
        self.duo = CiscoDuo()

    @patch('requests.get')
    def test_get_admin_logs_success(self, mock_get):
        """Test successful retrieval of administrator logs from response.items."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": {
                "items": [
                    {"username": "admin1@x.com", "action": "user_update"},
                    {"username": "admin2@x.com", "action": "admin_login"}
                ],
                "metadata": {"total_objects": 2}
            }
        }
        mock_get.return_value = mock_response

        request = _make_request_body({})
        result = self.duo.duo_get_admin_logs(request)

        assert result["status"] == "success"
        assert result["message"] == "Administrator logs retrieved successfully."
        assert len(result["adminlogs"]) == 2
        assert result["count"] == 2
        assert result["total_objects"] == 2

    @patch('requests.get')
    def test_get_admin_logs_pagination(self, mock_get):
        """Test pagination metadata when next_offset is present."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": {
                "items": [{"username": "admin1@x.com", "action": "user_update"}],
                "metadata": {"total_objects": 500, "next_offset": "1571780764000,5bf98546-f4c1"}
            }
        }
        mock_get.return_value = mock_response

        request = _make_request_body({})
        result = self.duo.duo_get_admin_logs(request)

        assert result["status"] == "success"
        assert "pagination" in result
        assert result["pagination"]["next_offset"] == "1571780764000,5bf98546-f4c1"
        assert result["next_offset"] == "1571780764000,5bf98546-f4c1"

    @patch('requests.get')
    def test_get_admin_logs_limit_capped_at_1000(self, mock_get):
        """Test that limit is capped at 1000 when a higher value is provided."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": {"items": [], "metadata": {"total_objects": 0}}
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"limit": 5000})
        result = self.duo.duo_get_admin_logs(request)

        assert result["status"] == "success"
        call_kwargs = mock_get.call_args
        params_sent = call_kwargs[1].get('params') or call_kwargs.kwargs.get('params', {})
        assert params_sent.get('limit') == '1000'

    def test_get_admin_logs_invalid_mintime_format(self):
        """Test that an invalid mintime format raises an exception."""
        request = _make_request_body({"mintime": "123456"})

        with pytest.raises(Exception, match="Invalid mintime"):
            self.duo.duo_get_admin_logs(request)

    def test_get_admin_logs_mintime_older_than_180_days(self):
        """Test that a mintime older than 180 days raises an exception."""
        # A 13-digit ms timestamp well over 180 days in the past (year 2001)
        request = _make_request_body({"mintime": "1000000000000"})

        with pytest.raises(Exception, match="180 days"):
            self.duo.duo_get_admin_logs(request)

    @patch('requests.get')
    def test_get_admin_logs_administrator_filter(self, mock_get):
        """Test client-side administrator filter on username."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": {
                "items": [
                    {"username": "admin1@x.com", "action": "user_update"},
                    {"username": "admin2@x.com", "action": "admin_login"}
                ],
                "metadata": {"total_objects": 2}
            }
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"administrator": "admin1"})
        result = self.duo.duo_get_admin_logs(request)

        assert result["status"] == "success"
        assert result["count"] == 1
        assert result["adminlogs"][0]["username"] == "admin1@x.com"

    @patch('requests.get')
    def test_get_admin_logs_action_filter(self, mock_get):
        """Test client-side action filter."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": {
                "items": [
                    {"username": "admin1@x.com", "action": "user_update"},
                    {"username": "admin2@x.com", "action": "admin_login"}
                ],
                "metadata": {"total_objects": 2}
            }
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"action": "login"})
        result = self.duo.duo_get_admin_logs(request)

        assert result["status"] == "success"
        assert result["count"] == 1
        assert result["adminlogs"][0]["action"] == "admin_login"

    @patch('requests.get')
    def test_get_admin_logs_api_stat_fail(self, mock_get):
        """Test that non-OK stat from Duo API returns failed status."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "FAIL",
            "message": "Something went wrong"
        }
        mock_get.return_value = mock_response

        request = _make_request_body({})
        result = self.duo.duo_get_admin_logs(request)

        assert result["status"] == "failed"
        assert "Something went wrong" in result["message"]


class TestDuoGetTelephonyLogs:
    """Tests for the duo_get_telephony_logs action."""

    def setup_method(self):
        self.duo = CiscoDuo()

    @patch('requests.get')
    def test_get_telephony_logs_success(self, mock_get):
        """Test successful retrieval of telephony logs from response.items."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": {
                "items": [
                    {"context": "authentication", "type": "sms", "credits": 1},
                    {"context": "enrollment", "type": "phone", "credits": 2}
                ],
                "metadata": {"total_objects": 2}
            }
        }
        mock_get.return_value = mock_response

        request = _make_request_body({})
        result = self.duo.duo_get_telephony_logs(request)

        assert result["status"] == "success"
        assert result["message"] == "Telephony logs retrieved successfully."
        assert len(result["telephonylogs"]) == 2
        assert result["count"] == 2
        assert result["total_objects"] == 2

    @patch('requests.get')
    def test_get_telephony_logs_pagination(self, mock_get):
        """Test pagination metadata when next_offset is present."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": {
                "items": [{"context": "authentication", "type": "sms"}],
                "metadata": {"total_objects": 500, "next_offset": "1571780764000,abc123"}
            }
        }
        mock_get.return_value = mock_response

        request = _make_request_body({})
        result = self.duo.duo_get_telephony_logs(request)

        assert result["status"] == "success"
        assert "pagination" in result
        assert result["pagination"]["next_offset"] == "1571780764000,abc123"
        assert result["next_offset"] == "1571780764000,abc123"

    @patch('requests.get')
    def test_get_telephony_logs_limit_capped_at_1000(self, mock_get):
        """Test that limit is capped at 1000 when a higher value is provided."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "OK",
            "response": {"items": [], "metadata": {"total_objects": 0}}
        }
        mock_get.return_value = mock_response

        request = _make_request_body({"limit": 5000})
        result = self.duo.duo_get_telephony_logs(request)

        assert result["status"] == "success"
        call_kwargs = mock_get.call_args
        params_sent = call_kwargs[1].get('params') or call_kwargs.kwargs.get('params', {})
        assert params_sent.get('limit') == '1000'

    def test_get_telephony_logs_invalid_mintime_format(self):
        """Test that an invalid mintime format raises an exception."""
        request = _make_request_body({"mintime": "123456"})

        with pytest.raises(Exception, match="Invalid mintime"):
            self.duo.duo_get_telephony_logs(request)

    @patch('requests.get')
    def test_get_telephony_logs_api_stat_fail(self, mock_get):
        """Test that non-OK stat from Duo API returns failed status."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "stat": "FAIL",
            "message": "Something went wrong"
        }
        mock_get.return_value = mock_response

        request = _make_request_body({})
        result = self.duo.duo_get_telephony_logs(request)

        assert result["status"] == "failed"
        assert "Something went wrong" in result["message"]
