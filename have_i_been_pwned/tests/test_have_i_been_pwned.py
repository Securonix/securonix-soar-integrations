import json
import pytest
from unittest.mock import patch, MagicMock

from app.have_i_been_pwned import HaveIBeenPwned
from app.model.request_body import RequestBody
from pykson import Pykson

pykson = Pykson()
integration_class = HaveIBeenPwned()

CONNECTION_PARAMS = {
    "base_url": "https://haveibeenpwned.com/api/v3",
    "passwords_base_url": "https://api.pwnedpasswords.com",
    "api_key": "0123456789abcdef0123456789abcdef",
    "user_agent": "Securonix-Test-Agent",
}


def _make_request(params=None, connection=None):
    body = {
        "connectionParameters": connection if connection is not None else CONNECTION_PARAMS,
        "parameters": params or {},
    }
    return pykson.from_json(json.dumps(body), RequestBody, True)


def _mock_response(status_code=200, json_data=None, text=None, headers=None):
    mock = MagicMock()
    mock.status_code = status_code
    mock.headers = headers or {}
    if text is not None:
        mock.text = text
    else:
        mock.text = "" if json_data is None else json.dumps(json_data)
    mock.json.return_value = json_data if json_data is not None else {}
    return mock


BREACH_TRUNCATED = [{"Name": "Adobe"}, {"Name": "Gawker"}, {"Name": "Stratfor"}]
BREACH_FULL = [{
    "Name": "Adobe",
    "Title": "Adobe",
    "Domain": "adobe.com",
    "BreachDate": "2013-10-04",
    "PwnCount": 152445165,
    "DataClasses": ["Email addresses", "Passwords"],
    "IsVerified": True,
}]
DOMAIN_RESPONSE = {"alias1": ["Adobe"], "alias2": ["Adobe", "Gawker", "Stratfor"]}
PASTE_RESPONSE = [
    {"Source": "Pastebin", "Id": "8Q0BvKD8", "Title": "syslog", "Date": "2014-03-04T19:14:54Z", "EmailCount": 139},
]
STEALER_RESPONSE = ["netflix.com", "spotify.com"]
ACCOUNT_RANGE_RESPONSE = [{"hashSuffix": "D24EFA7B55DF63CB0BA56C1D67EAADDEF6", "websites": ["Adobe", "Gawker"]}]
LATEST_BREACH = {"Name": "SomeBreach", "Title": "Some Breach", "AddedDate": "2025-01-01T00:00Z"}


# ---------------------------------------------------------------------------
# test_connection
# ---------------------------------------------------------------------------
class TestTestConnection:
    @patch("app.have_i_been_pwned.requests.get")
    def test_success_with_api_key(self, mock_get):
        mock_get.return_value = _mock_response(200, BREACH_TRUNCATED)
        result = integration_class.test_connection(CONNECTION_PARAMS)
        assert result["status"] == "success"
        assert "Connected" in result["message"]
        # Authenticated test hits the subscription status endpoint.
        call_url = mock_get.call_args[0][0]
        assert "/subscription/status" in call_url
        headers = mock_get.call_args[1]["headers"]
        assert headers["hibp-api-key"] == CONNECTION_PARAMS["api_key"]
        assert headers["user-agent"] == "Securonix-Test-Agent"

    @patch("app.have_i_been_pwned.requests.get")
    def test_non_error_status_is_success(self, mock_get):
        # test_connection only fails on error status codes (e.g. 401); any
        # non-error response confirms the key/user-agent are accepted.
        mock_get.return_value = _mock_response(404)
        result = integration_class.test_connection(CONNECTION_PARAMS)
        assert result["status"] == "success"

    @patch("app.have_i_been_pwned.requests.get")
    def test_invalid_api_key(self, mock_get):
        mock_get.return_value = _mock_response(401)
        with pytest.raises(Exception, match="Authentication failed"):
            integration_class.test_connection(CONNECTION_PARAMS)


# ---------------------------------------------------------------------------
# check_breached_account
# ---------------------------------------------------------------------------
class TestCheckBreachedAccount:
    @patch("app.have_i_been_pwned.requests.get")
    def test_success_truncated_default(self, mock_get):
        mock_get.return_value = _mock_response(200, BREACH_TRUNCATED)
        resp = integration_class.check_breached_account(_make_request({"account": "test@example.com"}))
        assert resp["status"] == "success"
        assert resp["breached"] is True
        assert resp["total"] == 3
        assert resp["truncated"] is True
        # account URL-encoded in the path
        assert "/breachedaccount/test%40example.com" in mock_get.call_args[0][0]
        # default query params
        params = mock_get.call_args[1]["params"]
        assert params["truncateResponse"] == "true"
        assert params["IncludeUnverified"] == "true"

    @patch("app.have_i_been_pwned.requests.get")
    def test_full_response_and_domain_filter(self, mock_get):
        mock_get.return_value = _mock_response(200, BREACH_FULL)
        resp = integration_class.check_breached_account(_make_request({
            "account": "test@example.com",
            "truncate_response": "false",
            "domain": "adobe.com",
            "include_unverified": "false",
        }))
        assert resp["truncated"] is False
        assert resp["breaches"][0]["Domain"] == "adobe.com"
        params = mock_get.call_args[1]["params"]
        assert params["truncateResponse"] == "false"
        assert params["IncludeUnverified"] == "false"
        assert params["domain"] == "adobe.com"

    @patch("app.have_i_been_pwned.requests.get")
    def test_not_breached_returns_empty(self, mock_get):
        mock_get.return_value = _mock_response(404)
        resp = integration_class.check_breached_account(_make_request({"account": "clean@example.com"}))
        assert resp["breached"] is False
        assert resp["breaches"] == []
        assert resp["total"] == 0

    def test_missing_account(self):
        with pytest.raises(Exception, match="account is required"):
            integration_class.check_breached_account(_make_request({}))


# ---------------------------------------------------------------------------
# check_breached_domain
# ---------------------------------------------------------------------------
class TestCheckBreachedDomain:
    @patch("app.have_i_been_pwned.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(200, DOMAIN_RESPONSE)
        resp = integration_class.check_breached_domain(_make_request({"domain": "example.com"}))
        assert resp["status"] == "success"
        assert resp["total"] == 2
        assert resp["breached_accounts"]["alias2"] == ["Adobe", "Gawker", "Stratfor"]
        assert "/breacheddomain/example.com" in mock_get.call_args[0][0]

    @patch("app.have_i_been_pwned.requests.get")
    def test_no_results_404(self, mock_get):
        mock_get.return_value = _mock_response(404)
        resp = integration_class.check_breached_domain(_make_request({"domain": "example.com"}))
        assert resp["breached_accounts"] == {}
        assert resp["total"] == 0

    @patch("app.have_i_been_pwned.requests.get")
    def test_unverified_domain_forbidden(self, mock_get):
        # Searching an unverified domain returns HTTP 403.
        mock_get.return_value = _mock_response(403)
        with pytest.raises(Exception, match="Forbidden"):
            integration_class.check_breached_domain(_make_request({"domain": "notmine.com"}))

    def test_missing_domain(self):
        with pytest.raises(Exception, match="domain is required"):
            integration_class.check_breached_domain(_make_request({}))


# ---------------------------------------------------------------------------
# check_paste_account
# ---------------------------------------------------------------------------
class TestCheckPasteAccount:
    @patch("app.have_i_been_pwned.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(200, PASTE_RESPONSE)
        resp = integration_class.check_paste_account(_make_request({"account": "test@example.com"}))
        assert resp["status"] == "success"
        assert resp["total"] == 1
        assert resp["pastes"][0]["Source"] == "Pastebin"
        assert "/pasteaccount/test%40example.com" in mock_get.call_args[0][0]

    @patch("app.have_i_been_pwned.requests.get")
    def test_no_pastes_404(self, mock_get):
        mock_get.return_value = _mock_response(404)
        resp = integration_class.check_paste_account(_make_request({"account": "clean@example.com"}))
        assert resp["pastes"] == []
        assert resp["total"] == 0

    def test_missing_account(self):
        with pytest.raises(Exception, match="account is required"):
            integration_class.check_paste_account(_make_request({}))


# ---------------------------------------------------------------------------
# check_stealer_logs_by_email
# ---------------------------------------------------------------------------
class TestCheckStealerLogsByEmail:
    @patch("app.have_i_been_pwned.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(200, STEALER_RESPONSE)
        resp = integration_class.check_stealer_logs_by_email(_make_request({"email": "jane@example.com"}))
        assert resp["status"] == "success"
        assert resp["website_domains"] == ["netflix.com", "spotify.com"]
        assert resp["total"] == 2
        assert "/stealerlogsbyemail/jane%40example.com" in mock_get.call_args[0][0]

    @patch("app.have_i_been_pwned.requests.get")
    def test_no_results_404(self, mock_get):
        mock_get.return_value = _mock_response(404)
        resp = integration_class.check_stealer_logs_by_email(_make_request({"email": "jane@example.com"}))
        assert resp["website_domains"] == []
        assert resp["total"] == 0

    @patch("app.have_i_been_pwned.requests.get")
    def test_unverified_domain_forbidden(self, mock_get):
        mock_get.return_value = _mock_response(403)
        with pytest.raises(Exception, match="Forbidden"):
            integration_class.check_stealer_logs_by_email(_make_request({"email": "jane@notmine.com"}))

    def test_missing_email(self):
        with pytest.raises(Exception, match="email is required"):
            integration_class.check_stealer_logs_by_email(_make_request({}))


# ---------------------------------------------------------------------------
# check_password_range
# ---------------------------------------------------------------------------
class TestCheckPasswordRange:
    RANGE_TEXT = "0018A45C4D1DEF81644B54AB7F969B88D65:12\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n"
    PADDED_TEXT = "0018A45C4D1DEF81644B54AB7F969B88D65:12\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\r\n"

    @patch("app.have_i_been_pwned.requests.get")
    def test_success_sha1(self, mock_get):
        mock_get.return_value = _mock_response(200, text=self.RANGE_TEXT)
        resp = integration_class.check_password_range(_make_request({"hash_prefix": "21BD1"}))
        assert resp["status"] == "success"
        assert resp["mode"] == "sha1"
        assert resp["total"] == 2
        assert resp["results"][0] == {"hashSuffix": "0018A45C4D1DEF81644B54AB7F969B88D65", "count": 12}
        # Unauthenticated: no api key header, but user-agent present.
        headers = mock_get.call_args[1]["headers"]
        assert "hibp-api-key" not in headers
        assert headers["user-agent"] == "Securonix-Test-Agent"
        assert "/range/21BD1" in mock_get.call_args[0][0]

    @patch("app.have_i_been_pwned.requests.get")
    def test_padding_rows_discarded(self, mock_get):
        mock_get.return_value = _mock_response(200, text=self.PADDED_TEXT)
        resp = integration_class.check_password_range(_make_request({"hash_prefix": "21BD1", "add_padding": "true"}))
        # Only the count>0 row survives.
        assert resp["total"] == 1
        assert all(r["count"] > 0 for r in resp["results"])
        assert mock_get.call_args[1]["headers"]["Add-Padding"] == "true"

    @patch("app.have_i_been_pwned.requests.get")
    def test_ntlm_mode(self, mock_get):
        mock_get.return_value = _mock_response(200, text=self.RANGE_TEXT)
        resp = integration_class.check_password_range(_make_request({"hash_prefix": "ABCDE", "mode": "ntlm"}))
        assert resp["mode"] == "ntlm"
        assert mock_get.call_args[1]["params"]["mode"] == "ntlm"

    def test_missing_prefix(self):
        with pytest.raises(Exception, match="hash_prefix is required"):
            integration_class.check_password_range(_make_request({}))

    def test_invalid_prefix_length(self):
        with pytest.raises(Exception, match="first 5 hexadecimal"):
            integration_class.check_password_range(_make_request({"hash_prefix": "21BD"}))

    def test_invalid_prefix_non_hex(self):
        with pytest.raises(Exception, match="first 5 hexadecimal"):
            integration_class.check_password_range(_make_request({"hash_prefix": "ZZZZZ"}))


# ---------------------------------------------------------------------------
# check_breached_account_range
# ---------------------------------------------------------------------------
class TestCheckBreachedAccountRange:
    @patch("app.have_i_been_pwned.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(200, ACCOUNT_RANGE_RESPONSE)
        resp = integration_class.check_breached_account_range(_make_request({"hash_prefix": "072EC1"}))
        assert resp["status"] == "success"
        assert resp["total"] == 1
        assert resp["results"][0]["hashSuffix"].startswith("D24EFA")
        assert "/breachedaccount/range/072EC1" in mock_get.call_args[0][0]
        assert mock_get.call_args[1]["headers"]["hibp-api-key"] == CONNECTION_PARAMS["api_key"]

    def test_invalid_prefix_length(self):
        with pytest.raises(Exception, match="first 6 hexadecimal"):
            integration_class.check_breached_account_range(_make_request({"hash_prefix": "072E"}))



# ---------------------------------------------------------------------------
# Enrichment helpers
# ---------------------------------------------------------------------------
class TestEnrichmentHelpers:
    @patch("app.have_i_been_pwned.requests.get")
    def test_get_latest_breach(self, mock_get):
        mock_get.return_value = _mock_response(200, LATEST_BREACH)
        resp = integration_class.get_latest_breach(_make_request({}))
        assert resp["status"] == "success"
        assert resp["breach"]["Name"] == "SomeBreach"
        assert "/latestbreach" in mock_get.call_args[0][0]
        assert "hibp-api-key" not in mock_get.call_args[1]["headers"]

    @patch("app.have_i_been_pwned.requests.get")
    def test_get_breaches_with_filters(self, mock_get):
        mock_get.return_value = _mock_response(200, BREACH_FULL)
        resp = integration_class.get_breaches(_make_request({"domain": "adobe.com", "is_spam_list": "false"}))
        assert resp["status"] == "success"
        assert resp["total"] == 1
        params = mock_get.call_args[1]["params"]
        assert params["Domain"] == "adobe.com"
        assert params["IsSpamList"] == "false"

    @patch("app.have_i_been_pwned.requests.get")
    def test_get_data_classes(self, mock_get):
        mock_get.return_value = _mock_response(200, ["Email addresses", "Passwords", "Usernames"])
        resp = integration_class.get_data_classes(_make_request({}))
        assert resp["status"] == "success"
        assert resp["total"] == 3
        assert "Passwords" in resp["data_classes"]


# ---------------------------------------------------------------------------
# Error handling / cross-cutting
# ---------------------------------------------------------------------------
class TestErrorHandling:
    @patch("app.have_i_been_pwned.requests.get")
    def test_connection_error(self, mock_get):
        import requests as req
        mock_get.side_effect = req.exceptions.ConnectionError()
        with pytest.raises(Exception, match="Unable to connect"):
            integration_class.get_latest_breach(_make_request({}))

    @patch("app.have_i_been_pwned.requests.get")
    def test_timeout(self, mock_get):
        import requests as req
        mock_get.side_effect = req.exceptions.Timeout()
        with pytest.raises(Exception, match="timed out"):
            integration_class.get_latest_breach(_make_request({}))

    @patch("app.have_i_been_pwned.time.sleep")
    @patch("app.have_i_been_pwned.requests.get")
    def test_429_honors_retry_after_then_success(self, mock_get, mock_sleep):
        mock_get.side_effect = [
            _mock_response(429, headers={"Retry-After": "5"}),
            _mock_response(200, BREACH_TRUNCATED),
        ]
        resp = integration_class.check_breached_account(_make_request({"account": "test@example.com"}))
        assert resp["status"] == "success"
        # Retry-After value was honored.
        mock_sleep.assert_called_once_with(5)

    @patch("app.have_i_been_pwned.time.sleep")
    @patch("app.have_i_been_pwned.requests.get")
    def test_429_retry_exhausted(self, mock_get, mock_sleep):
        mock_get.return_value = _mock_response(429, headers={"Retry-After": "2"})
        with pytest.raises(Exception, match="Rate limit exceeded"):
            integration_class.check_breached_account(_make_request({"account": "test@example.com"}))

    @patch("app.have_i_been_pwned.time.sleep")
    @patch("app.have_i_been_pwned.requests.get")
    def test_503_retry_then_success(self, mock_get, mock_sleep):
        mock_get.side_effect = [
            _mock_response(503),
            _mock_response(200, LATEST_BREACH),
        ]
        resp = integration_class.get_latest_breach(_make_request({}))
        assert resp["status"] == "success"
        assert mock_sleep.call_count == 1

    @patch("app.have_i_been_pwned.requests.get")
    def test_400_bad_request(self, mock_get):
        mock_get.return_value = _mock_response(400)
        with pytest.raises(Exception, match="Bad request"):
            integration_class.check_breached_account(_make_request({"account": "not-an-account"}))

    @patch("app.have_i_been_pwned.requests.get")
    def test_missing_user_agent_403(self, mock_get):
        # HIBP returns 403 when the user-agent is missing/unacceptable.
        mock_get.return_value = _mock_response(403)
        with pytest.raises(Exception, match="Forbidden"):
            integration_class.get_latest_breach(_make_request({}))

    @patch("app.have_i_been_pwned.requests.get")
    def test_api_key_not_in_logs(self, mock_get, caplog):
        import logging
        mock_get.return_value = _mock_response(200, BREACH_TRUNCATED)
        with caplog.at_level(logging.DEBUG):
            integration_class.check_breached_account(_make_request({"account": "test@example.com"}))
        assert CONNECTION_PARAMS["api_key"] not in caplog.text

    @patch("app.have_i_been_pwned.requests.get")
    def test_request_uses_fixed_timeout(self, mock_get):
        mock_get.return_value = _mock_response(200, LATEST_BREACH)
        integration_class.get_latest_breach(_make_request({}))
        assert mock_get.call_args[1]["timeout"] == 30
