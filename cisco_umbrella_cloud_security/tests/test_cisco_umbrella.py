import pytest
import time
from unittest.mock import patch, MagicMock
from app.cisco_umbrella_cloud_security import CiscoUmbrella, _detect_type, _is_valid_ipv4, _is_valid_url, _is_valid_domain
from app.model.request_body import RequestBody


BASE_URL = "https://api.umbrella.com"
CONN = {
    "client_id": "test_client_id",
    "client_secret": "test_client_secret",
    "base_url": BASE_URL,
    "timeout": "30",
    "verify_ssl": "true",
}


def _make_request(params: dict) -> RequestBody:
    req = RequestBody()
    req.connectionParameters = CONN
    req.parameters = params
    return req


def _mock_token_response():
    m = MagicMock()
    m.status_code = 200
    m.json.return_value = {"access_token": "test_token", "expires_in": 3600}
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


def _mock_error(status_code, body=None):
    m = MagicMock()
    m.status_code = status_code
    m.content = b"err"
    m.json.return_value = body or {"message": "error"}
    m.text = "error"
    return m


# -----------------------------------------------------------------------
# Token acquisition
# -----------------------------------------------------------------------
class TestGetToken:

    def test_token_success(self):
        connector = CiscoUmbrella()
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()):
            token = connector._get_token(BASE_URL, "id", "secret", 30, True, None)
        assert token == "test_token"

    def test_token_cached(self):
        connector = CiscoUmbrella()
        connector._token_cache[(BASE_URL, "id")] = {"token": "cached_token", "expiry": time.time() + 3600}
        with patch("app.cisco_umbrella_cloud_security.requests.post") as mock_post:
            token = connector._get_token(BASE_URL, "id", "secret", 30, True, None)
        mock_post.assert_not_called()
        assert token == "cached_token"

    def test_token_refresh_when_expired(self):
        connector = CiscoUmbrella()
        connector._token_cache[(BASE_URL, "id")] = {"token": "old_token", "expiry": time.time() - 1}
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()):
            token = connector._get_token(BASE_URL, "id", "secret", 30, True, None)
        assert token == "test_token"

    def test_token_401(self):
        connector = CiscoUmbrella()
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_error(401)):
            with pytest.raises(Exception, match="Authentication failed"):
                connector._get_token(BASE_URL, "id", "secret", 30, True, None)

    def test_token_403(self):
        connector = CiscoUmbrella()
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_error(403)):
            with pytest.raises(Exception, match="Authorization failed"):
                connector._get_token(BASE_URL, "id", "secret", 30, True, None)

    def test_token_missing_access_token(self):
        connector = CiscoUmbrella()
        m = MagicMock()
        m.status_code = 200
        m.json.return_value = {}
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=m):
            with pytest.raises(Exception, match="missing access_token"):
                connector._get_token(BASE_URL, "id", "secret", 30, True, None)

    def test_token_connection_error(self):
        import requests as req_lib
        connector = CiscoUmbrella()
        with patch("app.cisco_umbrella_cloud_security.requests.post", side_effect=req_lib.exceptions.ConnectionError):
            with pytest.raises(Exception, match="Unable to connect"):
                connector._get_token(BASE_URL, "id", "secret", 30, True, None)

    def test_token_timeout(self):
        import requests as req_lib
        connector = CiscoUmbrella()
        with patch("app.cisco_umbrella_cloud_security.requests.post", side_effect=req_lib.exceptions.Timeout):
            with pytest.raises(Exception, match="timed out"):
                connector._get_token(BASE_URL, "id", "secret", 30, True, None)

    def test_token_cache_isolated_by_client_id(self):
        connector = CiscoUmbrella()
        connector._token_cache[(BASE_URL, "id_a")] = {"token": "token_a", "expiry": time.time() + 3600}
        connector._token_cache[(BASE_URL, "id_b")] = {"token": "token_b", "expiry": time.time() + 3600}
        with patch("app.cisco_umbrella_cloud_security.requests.post") as mock_post:
            token_a = connector._get_token(BASE_URL, "id_a", "secret", 30, True, None)
            token_b = connector._get_token(BASE_URL, "id_b", "secret", 30, True, None)
        mock_post.assert_not_called()
        assert token_a == "token_a"
        assert token_b == "token_b"


# -----------------------------------------------------------------------
# _get_timeout validation
# -----------------------------------------------------------------------
class TestGetTimeout:
    from app.cisco_umbrella_cloud_security import _get_timeout

    def test_missing_uses_default(self):
        from app.cisco_umbrella_cloud_security import _get_timeout
        assert _get_timeout({}) == 30

    def test_none_string_uses_default(self):
        from app.cisco_umbrella_cloud_security import _get_timeout
        assert _get_timeout({"timeout": "None"}) == 30

    def test_valid_timeout(self):
        from app.cisco_umbrella_cloud_security import _get_timeout
        assert _get_timeout({"timeout": "60"}) == 60

    def test_invalid_string_raises(self):
        from app.cisco_umbrella_cloud_security import _get_timeout
        with pytest.raises(Exception, match="timeout must be a positive integer"):
            _get_timeout({"timeout": "abc"})

    def test_zero_raises(self):
        from app.cisco_umbrella_cloud_security import _get_timeout
        with pytest.raises(Exception, match="timeout must be a positive integer"):
            _get_timeout({"timeout": "0"})

    def test_negative_raises(self):
        from app.cisco_umbrella_cloud_security import _get_timeout
        with pytest.raises(Exception, match="timeout must be a positive integer"):
            _get_timeout({"timeout": "-5"})


# -----------------------------------------------------------------------
# Destination type detection
# -----------------------------------------------------------------------

    def test_valid_ipv4(self):
        assert _detect_type("8.8.8.8") == "IPV4"
        assert _detect_type("192.168.1.1") == "IPV4"

    def test_invalid_ipv4_raises(self):
        with pytest.raises(Exception, match="Cannot auto-detect"):
            _detect_type("999.999.999.999")

    def test_valid_url(self):
        assert _detect_type("https://example.com/path") == "URL"
        assert _detect_type("http://sub.example.com") == "URL"

    def test_url_without_hostname_raises(self):
        with pytest.raises(Exception, match="Cannot auto-detect"):
            _detect_type("https://")

    def test_valid_domain(self):
        assert _detect_type("example.com") == "DOMAIN"
        assert _detect_type("sub.example.com") == "DOMAIN"

    def test_invalid_value_raises(self):
        with pytest.raises(Exception, match="Cannot auto-detect"):
            _detect_type("hello")
        with pytest.raises(Exception, match="Cannot auto-detect"):
            _detect_type("not a domain")


# -----------------------------------------------------------------------
# test_connection
# -----------------------------------------------------------------------
class TestTestConnection:

    def test_success(self):
        connector = CiscoUmbrella()
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_ok({"data": []})):
            result = connector.test_connection(CONN)
        assert result["status"] == "success"
        assert "Connected" in result["message"]

    def test_token_failure_propagates(self):
        connector = CiscoUmbrella()
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_error(401)):
            with pytest.raises(Exception, match="Authentication failed"):
                connector.test_connection(CONN)

    def test_destinationlists_403(self):
        connector = CiscoUmbrella()
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_error(403)):
            with pytest.raises(Exception, match="Authorization failed"):
                connector.test_connection(CONN)

    def test_connection_error(self):
        import requests as req_lib
        connector = CiscoUmbrella()
        with patch("app.cisco_umbrella_cloud_security.requests.post", side_effect=req_lib.exceptions.ConnectionError):
            with pytest.raises(Exception, match="Unable to connect"):
                connector.test_connection(CONN)

    def test_timeout(self):
        import requests as req_lib
        connector = CiscoUmbrella()
        with patch("app.cisco_umbrella_cloud_security.requests.post", side_effect=req_lib.exceptions.Timeout):
            with pytest.raises(Exception, match="timed out"):
                connector.test_connection(CONN)


# -----------------------------------------------------------------------
# add_destination
# -----------------------------------------------------------------------
class TestAddDestination:

    def test_success_single(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123", "destinations": "evil.com"})
        resp_body = {"data": [{"destination": "evil.com"}]}
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_ok(resp_body)):
            result = connector.add_destination(req)
        assert result["status"] == "success"
        assert len(result["added"]) == 1

    def test_success_multiple_csv(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123", "destinations": "a.com, b.com, c.com"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_ok({"data": []})):
            result = connector.add_destination(req)
        assert result["status"] == "success"

    def test_batch_over_500(self):
        connector = CiscoUmbrella()
        destinations = [f"host{i}.com" for i in range(600)]
        req = _make_request({"destination_list_id": "123", "destinations": destinations})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_ok({"data": []})) as mock_req:
            connector.add_destination(req)
        # Should have made 2 POST calls (500 + 100)
        assert mock_req.call_count == 2

    def test_empty_destinations_raises(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123", "destinations": ""})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()):
            with pytest.raises(Exception, match="cannot be empty"):
                connector.add_destination(req)

    def test_invalid_destination_list_id(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "abc", "destinations": "evil.com"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()):
            with pytest.raises(Exception, match="positive integer"):
                connector.add_destination(req)

    def test_invalid_destination_type_raises(self):
        connector = CiscoUmbrella()
        req = _make_request({
            "destination_list_id": "123",
            "destinations": "evil.com",
            "destination_type": "WHATEVER",
        })
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()):
            with pytest.raises(Exception, match="destination_type must be one of"):
                connector.add_destination(req)

    def test_auto_detect_ipv4(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123", "destinations": "8.8.8.8"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_ok({"data": []})) as mock_req:
            connector.add_destination(req)
        body = mock_req.call_args[1]["json"]
        assert body[0]["type"] == "IPV4"

    def test_auto_detect_url(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123", "destinations": "https://evil.com/path"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_ok({"data": []})) as mock_req:
            connector.add_destination(req)
        body = mock_req.call_args[1]["json"]
        assert body[0]["type"] == "URL"

    def test_auto_detect_domain(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123", "destinations": "evil.com"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_ok({"data": []})) as mock_req:
            connector.add_destination(req)
        body = mock_req.call_args[1]["json"]
        assert body[0]["type"] == "DOMAIN"

    def test_with_type_and_comment(self):
        connector = CiscoUmbrella()
        req = _make_request({
            "destination_list_id": "123",
            "destinations": "evil.com",
            "destination_type": "DOMAIN",
            "comment": "blocked by SOAR",
        })
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_ok({"data": []})) as mock_req:
            connector.add_destination(req)
        call_kwargs = mock_req.call_args
        body = call_kwargs[1]["json"]
        assert body[0]["type"] == "DOMAIN"
        assert body[0]["comment"] == "blocked by SOAR"


# -----------------------------------------------------------------------
# get_destinations
# -----------------------------------------------------------------------
class TestGetDestinations:

    def test_success(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123"})
        resp_body = {"data": [{"destination": "evil.com"}], "meta": {"total": 1}}
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_ok(resp_body)):
            result = connector.get_destinations(req)
        assert result["status"] == "success"
        assert result["total"] == 1

    def test_pagination_params_passed(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123", "page": "3", "limit": "50"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_ok({"data": []})) as mock_req:
            connector.get_destinations(req)
        params = mock_req.call_args[1]["params"]
        assert params["page"] == 3
        assert params["limit"] == 50

    def test_invalid_page_raises(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123", "page": "abc"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()):
            with pytest.raises(Exception, match="page must be"):
                connector.get_destinations(req)

    def test_page_less_than_1_raises(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123", "page": "0"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()):
            with pytest.raises(Exception, match="page must be"):
                connector.get_destinations(req)

    def test_invalid_limit_raises(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123", "limit": "abc"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()):
            with pytest.raises(Exception, match="limit must be"):
                connector.get_destinations(req)

    def test_limit_over_100_raises(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123", "limit": "500"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()):
            with pytest.raises(Exception, match="limit must be"):
                connector.get_destinations(req)

    def test_limit_zero_raises(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123", "limit": "0"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()):
            with pytest.raises(Exception, match="limit must be"):
                connector.get_destinations(req)

    def test_404_raises(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "999"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_error(404)):
            with pytest.raises(Exception, match="not found"):
                connector.get_destinations(req)


# -----------------------------------------------------------------------
# delete_destination
# -----------------------------------------------------------------------
class TestDeleteDestination:

    def test_success(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123", "destination_ids": "1001,1002"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_no_content()):
            result = connector.delete_destination(req)
        assert result["status"] == "success"
        assert result["deleted_count"] == 2

    def test_ids_normalized_to_int(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123", "destination_ids": "1001, 1002"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_no_content()) as mock_req:
            connector.delete_destination(req)
        body = mock_req.call_args[1]["json"]
        assert body == [1001, 1002]

    def test_ids_as_list(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123", "destination_ids": [1001, 1002, 1003]})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_no_content()):
            result = connector.delete_destination(req)
        assert result["deleted_count"] == 3

    def test_over_500_raises(self):
        connector = CiscoUmbrella()
        ids = [str(i) for i in range(501)]
        req = _make_request({"destination_list_id": "123", "destination_ids": ids})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()):
            with pytest.raises(Exception, match="Maximum 500"):
                connector.delete_destination(req)

    def test_empty_ids_raises(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123", "destination_ids": ""})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()):
            with pytest.raises(Exception, match="cannot be empty"):
                connector.delete_destination(req)

    def test_non_integer_id_raises(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123", "destination_ids": "abc"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()):
            with pytest.raises(Exception, match="positive integer"):
                connector.delete_destination(req)


# -----------------------------------------------------------------------
# create_destination_list
# -----------------------------------------------------------------------
class TestCreateDestinationList:

    def test_success_allow(self):
        connector = CiscoUmbrella()
        req = _make_request({"name": "My Allow List", "access": "allow"})
        resp_body = {"data": {"id": 1, "name": "My Allow List", "access": "allow"}}
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_ok(resp_body)):
            result = connector.create_destination_list(req)
        assert result["status"] == "success"
        assert result["destination_list"]["access"] == "allow"

    def test_success_block(self):
        connector = CiscoUmbrella()
        req = _make_request({"name": "My Block List", "access": "block"})
        resp_body = {"data": {"id": 2, "name": "My Block List", "access": "block"}}
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_ok(resp_body)):
            result = connector.create_destination_list(req)
        assert result["destination_list"]["access"] == "block"

    def test_missing_name_raises(self):
        connector = CiscoUmbrella()
        req = _make_request({"name": "", "access": "allow"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()):
            with pytest.raises(Exception, match="name is required"):
                connector.create_destination_list(req)

    def test_invalid_access_raises(self):
        connector = CiscoUmbrella()
        req = _make_request({"name": "Test", "access": "deny"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()):
            with pytest.raises(Exception, match="allow.*block"):
                connector.create_destination_list(req)

    def test_invalid_bundle_type_id_raises(self):
        connector = CiscoUmbrella()
        req = _make_request({"name": "Test", "access": "block", "bundle_type_id": "999"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()):
            with pytest.raises(Exception, match="bundle_type_id must be one of"):
                connector.create_destination_list(req)

    def test_invalid_is_global_raises(self):
        connector = CiscoUmbrella()
        req = _make_request({"name": "Test", "access": "block", "is_global": "banana"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()):
            with pytest.raises(Exception, match="is_global must be"):
                connector.create_destination_list(req)

    def test_optional_fields_included(self):
        connector = CiscoUmbrella()
        req = _make_request({"name": "Test", "access": "block", "is_global": "true", "bundle_type_id": "1"})
        resp_body = {"data": {"id": 3, "name": "Test", "access": "block"}}
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_ok(resp_body)) as mock_req:
            connector.create_destination_list(req)
        body = mock_req.call_args[1]["json"]
        assert body["isGlobal"] is True
        assert body["bundleTypeId"] == 1


# -----------------------------------------------------------------------
# update_destination_list
# -----------------------------------------------------------------------
class TestUpdateDestinationList:

    def test_success(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123", "name": "New Name"})
        resp_body = {"data": {"id": 123, "name": "New Name"}}
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_ok(resp_body)):
            result = connector.update_destination_list(req)
        assert result["status"] == "success"
        assert result["destination_list"]["name"] == "New Name"

    def test_missing_name_raises(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123", "name": ""})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()):
            with pytest.raises(Exception, match="name is required"):
                connector.update_destination_list(req)

    def test_invalid_dl_id_raises(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "not-an-int", "name": "Test"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()):
            with pytest.raises(Exception, match="positive integer"):
                connector.update_destination_list(req)

    def test_404_raises(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "999", "name": "Test"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_error(404)):
            with pytest.raises(Exception, match="not found"):
                connector.update_destination_list(req)


# -----------------------------------------------------------------------
# Shared error handling
# -----------------------------------------------------------------------
class TestErrorHandling:

    def test_401_message(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_error(401)):
            with pytest.raises(Exception, match="Authentication failed"):
                connector.get_destinations(req)

    def test_403_message(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_error(403)):
            with pytest.raises(Exception, match="Authorization failed"):
                connector.get_destinations(req)

    def test_500_message(self):
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", return_value=_mock_error(500)):
            with pytest.raises(Exception, match="server error"):
                connector.get_destinations(req)

    def test_connection_error_in_action(self):
        import requests as req_lib
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", side_effect=req_lib.exceptions.ConnectionError):
            with pytest.raises(Exception, match="Unable to connect"):
                connector.get_destinations(req)

    def test_timeout_in_action(self):
        import requests as req_lib
        connector = CiscoUmbrella()
        req = _make_request({"destination_list_id": "123"})
        with patch("app.cisco_umbrella_cloud_security.requests.post", return_value=_mock_token_response()), \
             patch("app.cisco_umbrella_cloud_security.requests.request", side_effect=req_lib.exceptions.Timeout):
            with pytest.raises(Exception, match="timed out"):
                connector.get_destinations(req)
