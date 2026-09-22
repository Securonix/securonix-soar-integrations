import pytest
from unittest.mock import patch, MagicMock
from app.ping_one import PingOne
from app.model.request_body import RequestBody


ENV_ID = "env-123"
CLIENT_ID = "client-abc"
CLIENT_SECRET = "secret-xyz"

CP = {
    "environment_id": ENV_ID,
    "region": "NorthAmerica",
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
}

AUTH_URL = f"https://auth.pingone.com/{ENV_ID}/as/token"


def _mock_token_response():
    m = MagicMock()
    m.status_code = 200
    m.json.return_value = {"access_token": "tok", "expires_in": 3600}
    return m


def _mock_ok(body=None):
    m = MagicMock()
    m.status_code = 200
    m.content = b"ok"
    m.json.return_value = body or {}
    return m


def _mock_no_content():
    m = MagicMock()
    m.status_code = 204
    m.content = b""
    return m


def _mock_404():
    m = MagicMock()
    m.status_code = 404
    m.content = b"not found"
    return m


def _make_request(params, cp=None):
    r = RequestBody()
    r.parameters = params
    r.connectionParameters = cp or CP
    return r


# ---------------------------------------------------------------------------
# test_connection
# ---------------------------------------------------------------------------
class TestTestConnection:
    def test_success(self):
        connector = PingOne()
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_ok({"_embedded": {"users": []}})):
            result = connector.test_connection(CP)
        assert result["status"] == "success"

    def test_connection_error(self):
        import requests as req
        connector = PingOne()
        with patch("app.ping_one.requests.post", side_effect=req.exceptions.ConnectionError):
            with pytest.raises(Exception, match="Unable to connect"):
                connector.test_connection(CP)


# ---------------------------------------------------------------------------
# unlock_user
# ---------------------------------------------------------------------------
class TestUnlockUser:
    def test_success(self):
        connector = PingOne()
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_no_content()):
            result = connector.unlock_user(_make_request({"user_id": "u1"}))
        assert result["status"] == "success"
        assert "unlocked" in result["message"]

    def test_user_not_found(self):
        connector = PingOne()
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_404()):
            with pytest.raises(Exception, match="Resource not found"):
                connector.unlock_user(_make_request({"user_id": "bad"}))


# ---------------------------------------------------------------------------
# deactivate_user
# ---------------------------------------------------------------------------
class TestDeactivateUser:
    def test_success(self):
        connector = PingOne()
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_no_content()):
            result = connector.deactivate_user(_make_request({"user_id": "u1"}))
        assert result["status"] == "success"
        assert "deactivated" in result["message"]


# ---------------------------------------------------------------------------
# activate_user
# ---------------------------------------------------------------------------
class TestActivateUser:
    def test_success(self):
        connector = PingOne()
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_no_content()):
            result = connector.activate_user(_make_request({"user_id": "u1"}))
        assert result["status"] == "success"
        assert "activated" in result["message"]


# ---------------------------------------------------------------------------
# set_password
# ---------------------------------------------------------------------------
class TestSetPassword:
    def test_success(self):
        connector = PingOne()
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_no_content()):
            result = connector.set_password(_make_request({"user_id": "u1", "new_password": "P@ss1"}))
        assert result["status"] == "success"

    def test_user_not_found(self):
        connector = PingOne()
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_404()):
            with pytest.raises(Exception, match="Resource not found"):
                connector.set_password(_make_request({"user_id": "bad", "new_password": "P@ss1"}))


# ---------------------------------------------------------------------------
# force_password_change
# ---------------------------------------------------------------------------
class TestForcePasswordChange:
    def test_success(self):
        connector = PingOne()
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_no_content()):
            result = connector.force_password_change(_make_request({"user_id": "u1"}))
        assert result["status"] == "success"
        assert "next sign-in" in result["message"]


# ---------------------------------------------------------------------------
# get_password_state
# ---------------------------------------------------------------------------
class TestGetPasswordState:
    def test_success(self):
        connector = PingOne()
        state = {"status": "OK", "lastChangedAt": "2024-01-01"}
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_ok(state)):
            result = connector.get_password_state(_make_request({"user_id": "u1"}))
        assert result["status"] == "success"
        assert result["password_state"] == state


# ---------------------------------------------------------------------------
# add_user_to_group
# ---------------------------------------------------------------------------
class TestAddUserToGroup:
    def test_success(self):
        connector = PingOne()
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_ok()):
            result = connector.add_user_to_group(_make_request({"user_id": "u1", "group_id": "g1"}))
        assert result["status"] == "success"
        assert "added" in result["message"]


# ---------------------------------------------------------------------------
# remove_user_from_group
# ---------------------------------------------------------------------------
class TestRemoveUserFromGroup:
    def test_success(self):
        connector = PingOne()
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_no_content()):
            result = connector.remove_user_from_group(_make_request({"user_id": "u1", "group_id": "g1"}))
        assert result["status"] == "success"
        assert "removed" in result["message"]


# ---------------------------------------------------------------------------
# get_user_groups
# ---------------------------------------------------------------------------
class TestGetUserGroups:
    def test_success_no_next_page(self):
        connector = PingOne()
        body = {"_embedded": {"groupMemberships": [{"id": "g1"}]}}
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_ok(body)):
            result = connector.get_user_groups(_make_request({"user_id": "u1"}))
        assert result["status"] == "success"
        assert len(result["groups"]) == 1
        assert result["next_cursor"] is None

    def test_success_with_next_cursor(self):
        connector = PingOne()
        body = {
            "_embedded": {"groupMemberships": [{"id": "g1"}]},
            "_links": {"next": {"href": "https://api.pingone.com/v1/environments/env-123/users/u1/memberOfGroups?cursor=abc123"}},
        }
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_ok(body)):
            result = connector.get_user_groups(_make_request({"user_id": "u1"}))
        assert result["next_cursor"] == "abc123"


# ---------------------------------------------------------------------------
# get_user
# ---------------------------------------------------------------------------
class TestGetUser:
    def test_by_user_id(self):
        connector = PingOne()
        user = {"id": "u1", "username": "jdoe"}
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_ok(user)):
            result = connector.get_user(_make_request({"user_id": "u1", "username": ""}))
        assert result["user"]["id"] == "u1"

    def test_by_username(self):
        connector = PingOne()
        body = {"_embedded": {"users": [{"id": "u1", "username": "jdoe"}]}}
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_ok(body)):
            result = connector.get_user(_make_request({"user_id": "", "username": "jdoe"}))
        assert result["user"]["username"] == "jdoe"

    def test_not_found_by_username(self):
        connector = PingOne()
        body = {"_embedded": {"users": []}}
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_ok(body)):
            with pytest.raises(Exception, match="User not found"):
                connector.get_user(_make_request({"user_id": "", "username": "ghost"}))

    def test_neither_provided(self):
        connector = PingOne()
        with pytest.raises(Exception, match="Either user_id or username must be provided"):
            connector.get_user(_make_request({"user_id": "", "username": ""}))


# ---------------------------------------------------------------------------
# create_user
# ---------------------------------------------------------------------------
class TestCreateUser:
    def test_success(self):
        connector = PingOne()
        created = {"id": "u2", "username": "newuser", "email": {"address": "new@example.com"}}
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_ok(created)):
            result = connector.create_user(_make_request({
                "username": "newuser",
                "email": "new@example.com",
                "population_id": "pop1",
            }))
        assert result["status"] == "success"
        assert result["user"]["id"] == "u2"


# ---------------------------------------------------------------------------
# update_user
# ---------------------------------------------------------------------------
class TestUpdateUser:
    def test_success(self):
        connector = PingOne()
        updated = {"id": "u1", "name": {"given": "Jane"}}
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_ok(updated)):
            result = connector.update_user(_make_request({"user_id": "u1", "given_name": "Jane"}))
        assert result["status"] == "success"

    def test_no_fields_raises(self):
        connector = PingOne()
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()):
            with pytest.raises(Exception, match="At least one field"):
                connector.update_user(_make_request({"user_id": "u1"}))


# ---------------------------------------------------------------------------
# delete_user
# ---------------------------------------------------------------------------
class TestDeleteUser:
    def test_by_user_id(self):
        connector = PingOne()
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_no_content()):
            result = connector.delete_user(_make_request({"user_id": "u1", "username": ""}))
        assert result["status"] == "success"

    def test_by_username_not_found(self):
        connector = PingOne()
        body = {"_embedded": {"users": []}}
        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", return_value=_mock_ok(body)):
            with pytest.raises(Exception, match="User not found"):
                connector.delete_user(_make_request({"user_id": "", "username": "ghost"}))

    def test_neither_provided(self):
        connector = PingOne()
        with pytest.raises(Exception, match="Either user_id or username must be provided"):
            connector.delete_user(_make_request({"user_id": "", "username": ""}))


# ---------------------------------------------------------------------------
# Token refresh on 401
# ---------------------------------------------------------------------------
class TestTokenRefreshOn401:
    def test_retries_once_on_401(self):
        connector = PingOne()
        mock_401 = MagicMock()
        mock_401.status_code = 401
        mock_401.content = b"unauthorized"

        call_count = {"n": 0}

        def side_effect(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return mock_401
            return _mock_no_content()

        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", side_effect=side_effect):
            result = connector.unlock_user(_make_request({"user_id": "u1"}))
        assert result["status"] == "success"
        assert call_count["n"] == 2

    def test_unlock_user_retry_preserves_content_type(self):
        """On 401 retry, unlock_user must still send the vendor Content-Type, not application/json."""
        connector = PingOne()
        mock_401 = MagicMock()
        mock_401.status_code = 401
        mock_401.content = b"unauthorized"

        captured_headers = []
        call_count = {"n": 0}

        def side_effect(*args, **kwargs):
            captured_headers.append(kwargs.get("headers", {}))
            call_count["n"] += 1
            if call_count["n"] == 1:
                return mock_401
            return _mock_no_content()

        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", side_effect=side_effect):
            connector.unlock_user(_make_request({"user_id": "u1"}))

        assert call_count["n"] == 2
        for headers in captured_headers:
            assert headers.get("Content-Type") == "application/vnd.pingidentity.password.unlock+json"

    def test_force_password_change_retry_preserves_content_type(self):
        """On 401 retry, force_password_change must still send the vendor Content-Type."""
        connector = PingOne()
        mock_401 = MagicMock()
        mock_401.status_code = 401
        mock_401.content = b"unauthorized"

        captured_headers = []
        call_count = {"n": 0}

        def side_effect(*args, **kwargs):
            captured_headers.append(kwargs.get("headers", {}))
            call_count["n"] += 1
            if call_count["n"] == 1:
                return mock_401
            return _mock_no_content()

        with patch("app.ping_one.requests.post", return_value=_mock_token_response()), \
             patch("app.ping_one.requests.request", side_effect=side_effect):
            connector.force_password_change(_make_request({"user_id": "u1"}))

        assert call_count["n"] == 2
        for headers in captured_headers:
            assert headers.get("Content-Type") == "application/vnd.pingidentity.password.forceChange"
