from unittest.mock import patch, MagicMock
from app.mxtoolbox import Mxtoolbox
from app.model.request_body import RequestBody
from pykson import Pykson
import json
import pytest

pykson = Pykson()
integration = Mxtoolbox()

CONNECTION_PARAMS = {
    "api_key": "<api_key>",
    "base_url": "https://mxtoolbox.com/api/v1",
    "timeout": 10,
    "max_retries": 3
}


def _make_request(params: dict) -> RequestBody:
    req = json.dumps({"connectionParameters": CONNECTION_PARAMS, "parameters": params})
    return pykson.from_json(req, RequestBody, True)


def _mock_response(status_code=200, json_data=None):
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_data or {}
    mock.text = json.dumps(json_data or {})
    return mock


# -------------------------------------------------------------------------
# test_connection
# -------------------------------------------------------------------------
class TestConnection:

    @patch("app.mxtoolbox.requests.get")
    def test_connection_success(self, mock_get):
        mock_get.return_value = _mock_response(200, {"Result": [], "Errors": []})
        result = integration.test_connection(CONNECTION_PARAMS)
        assert result["status"] == "success"
        assert "MXToolbox" in result["message"]
        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args
        assert call_kwargs[1]["params"] == {"argument": "example.com"}

    @patch("app.mxtoolbox.requests.get")
    def test_connection_invalid_api_key(self, mock_get):
        mock_get.return_value = _mock_response(401)
        with pytest.raises(Exception, match="Authentication failed"):
            integration.test_connection(CONNECTION_PARAMS)

    @patch("app.mxtoolbox.requests.get")
    def test_connection_forbidden(self, mock_get):
        mock_get.return_value = _mock_response(403)
        with pytest.raises(Exception, match="Access denied"):
            integration.test_connection(CONNECTION_PARAMS)

    @patch("app.mxtoolbox.requests.get")
    def test_connection_server_error(self, mock_get):
        mock_get.return_value = _mock_response(500)
        with pytest.raises(Exception, match="server error"):
            integration.test_connection(CONNECTION_PARAMS)


# -------------------------------------------------------------------------
# blacklist_ip_check
# -------------------------------------------------------------------------
class TestBlacklistIpCheck:

    @patch("app.mxtoolbox.requests.get")
    def test_clean_ip(self, mock_get):
        mock_get.return_value = _mock_response(200, {
            "Command": "blacklist",
            "Argument": "8.8.8.8",
            "Result": [
                {"Name": "Spamhaus ZEN", "Status": "Passed", "Info": "Not Listed"}
            ],
            "Errors": []
        })
        req = _make_request({"ip_address": "8.8.8.8"})
        result = integration.blacklist_ip_check(req)
        assert result["success"] is True
        assert result["indicator"] == "8.8.8.8"
        assert result["indicator_type"] == "ip"
        assert result["summary"]["verdict"] == "clean"
        assert result["summary"]["risk_level"] == "low"
        assert result["data"]["listed_count"] == 0
        assert result["data"]["total_checks"] == 1

    @patch("app.mxtoolbox.requests.get")
    def test_blacklisted_ip(self, mock_get):
        mock_get.return_value = _mock_response(200, {
            "Command": "blacklist",
            "Argument": "1.2.3.4",
            "Result": [
                {"Name": "Spamhaus", "Status": "Failed", "Info": "Listed"}
            ],
            "Errors": []
        })
        req = _make_request({"ip_address": "1.2.3.4"})
        result = integration.blacklist_ip_check(req)
        assert result["success"] is True
        assert result["summary"]["verdict"] == "listed"
        assert result["summary"]["risk_level"] == "critical"
        assert result["data"]["listed_count"] == 1


# -------------------------------------------------------------------------
# blacklist_domain_check
# -------------------------------------------------------------------------
class TestBlacklistDomainCheck:

    @patch("app.mxtoolbox.requests.get")
    def test_clean_domain(self, mock_get):
        mock_get.return_value = _mock_response(200, {
            "Command": "blacklist",
            "Argument": "example.com",
            "Result": [
                {"Name": "SURBL", "Status": "Passed", "Info": "Not Listed"}
            ],
            "Errors": []
        })
        req = _make_request({"domain": "example.com"})
        result = integration.blacklist_domain_check(req)
        assert result["success"] is True
        assert result["summary"]["verdict"] == "clean"
        assert result["data"]["listed_count"] == 0


# -------------------------------------------------------------------------
# mx_lookup
# -------------------------------------------------------------------------
class TestMxLookup:

    @patch("app.mxtoolbox.requests.get")
    def test_mx_records_found(self, mock_get):
        mock_get.return_value = _mock_response(200, {
            "Command": "mx",
            "Argument": "example.com",
            "Result": [
                {"Name": "mail.example.com", "Status": "Passed", "Info": "10 mail.example.com"}
            ],
            "Errors": []
        })
        req = _make_request({"domain": "example.com"})
        result = integration.mx_lookup(req)
        assert result["success"] is True
        assert result["lookup_type"] == "mx"
        assert result["summary"]["verdict"] == "found"
        assert result["summary"]["record_count"] == 1
        assert result["data"]["record_count"] == 1


# -------------------------------------------------------------------------
# dns_lookup
# -------------------------------------------------------------------------
class TestDnsLookup:

    @patch("app.mxtoolbox.requests.get")
    def test_dns_records_found(self, mock_get):
        mock_get.return_value = _mock_response(200, {
            "Command": "dns",
            "Argument": "example.com",
            "Result": [
                {"Name": "A Record", "Status": "Passed", "Info": "93.184.216.34"}
            ],
            "Errors": []
        })
        req = _make_request({"domain": "example.com"})
        result = integration.dns_lookup(req)
        assert result["success"] is True
        assert result["lookup_type"] == "dns"
        assert result["summary"]["verdict"] == "resolved"
        assert result["summary"]["record_count"] == 1
        assert result["data"]["record_count"] == 1


# -------------------------------------------------------------------------
# reverse_dns_lookup
# -------------------------------------------------------------------------
class TestReverseDnsLookup:

    @patch("app.mxtoolbox.requests.get")
    def test_ptr_record_found(self, mock_get):
        mock_get.return_value = _mock_response(200, {
            "Command": "ptr",
            "Argument": "8.8.8.8",
            "Result": [
                {"Name": "PTR Record", "Status": "Passed", "Info": "dns.google"}
            ],
            "Errors": []
        })
        req = _make_request({"ip_address": "8.8.8.8"})
        result = integration.reverse_dns_lookup(req)
        assert result["success"] is True
        assert result["indicator"] == "8.8.8.8"
        assert result["indicator_type"] == "ip"
        assert result["lookup_type"] == "ptr"
        assert result["summary"]["verdict"] == "resolved"
        assert result["summary"]["record_count"] == 1
        assert result["data"]["record_count"] == 1


# -------------------------------------------------------------------------
# spf_check
# -------------------------------------------------------------------------
class TestSpfCheck:

    @patch("app.mxtoolbox.requests.get")
    def test_spf_valid(self, mock_get):
        mock_get.return_value = _mock_response(200, {
            "Command": "spf",
            "Argument": "example.com",
            "Result": [
                {"Name": "SPF Record", "Status": "Passed", "Info": "v=spf1 include:_spf.google.com ~all"}
            ],
            "Errors": []
        })
        req = _make_request({"domain": "example.com"})
        result = integration.spf_check(req)
        assert result["success"] is True
        assert result["summary"]["verdict"] == "valid"
        assert result["data"]["spf_valid"] is True

    @patch("app.mxtoolbox.requests.get")
    def test_spf_invalid(self, mock_get):
        mock_get.return_value = _mock_response(200, {
            "Command": "spf",
            "Argument": "bad-domain.com",
            "Result": [
                {"Name": "SPF Record", "Status": "Failed", "Info": "No SPF record found"}
            ],
            "Errors": []
        })
        req = _make_request({"domain": "bad-domain.com"})
        result = integration.spf_check(req)
        assert result["success"] is True
        assert result["summary"]["verdict"] == "invalid"
        assert result["data"]["spf_valid"] is False
        assert len(result["data"]["failures"]) == 1


# -------------------------------------------------------------------------
# dkim_check
# -------------------------------------------------------------------------
class TestDkimCheck:

    @patch("app.mxtoolbox.requests.get")
    def test_dkim_with_explicit_selector(self, mock_get):
        mock_get.return_value = _mock_response(200, {
            "Command": "dkim",
            "Argument": "google._domainkey.example.com",
            "Result": [
                {"Name": "DKIM Record", "Status": "Passed", "Info": "DKIM record found"}
            ],
            "Errors": []
        })
        req = _make_request({"domain": "example.com", "selector": "google"})
        result = integration.dkim_check(req)
        assert result["success"] is True
        assert result["data"]["dkim_valid"] is True
        assert result["data"]["selector"] == "google"
        call_kwargs = mock_get.call_args
        assert call_kwargs[1]["params"]["argument"] == "google._domainkey.example.com"

    @patch("app.mxtoolbox.requests.get")
    def test_dkim_auto_detect_finds_selector(self, mock_get):
        """No selector provided — auto-tries common selectors, finds match on selector1"""
        no_match = _mock_response(200, {"Result": [{"Name": "DKIM", "Status": "Failed"}], "Errors": []})
        match = _mock_response(200, {"Result": [{"Name": "DKIM", "Status": "Passed", "Info": "Found"}], "Errors": []})
        mock_get.side_effect = [no_match, match]
        req = _make_request({"domain": "example.com"})
        result = integration.dkim_check(req)
        assert result["success"] is True
        assert result["data"]["dkim_valid"] is True
        assert result["data"]["selector"] == "selector1"

    @patch("app.mxtoolbox.requests.get")
    def test_dkim_auto_detect_no_match(self, mock_get):
        """No selector provided — none of the common selectors match"""
        no_match = _mock_response(200, {"Result": [{"Name": "DKIM", "Status": "Failed"}], "Errors": []})
        mock_get.return_value = no_match
        req = _make_request({"domain": "example.com"})
        result = integration.dkim_check(req)
        assert result["success"] is True
        assert result["data"]["dkim_valid"] is False
        assert result["data"]["selector"] == "not_found"


# -------------------------------------------------------------------------
# dmarc_check
# -------------------------------------------------------------------------
class TestDmarcCheck:

    @patch("app.mxtoolbox.requests.get")
    def test_dmarc_valid(self, mock_get):
        mock_get.return_value = _mock_response(200, {
            "Command": "dmarc",
            "Argument": "example.com",
            "Result": [
                {"Name": "DMARC Record", "Status": "Passed", "Info": "v=DMARC1; p=reject"}
            ],
            "Errors": []
        })
        req = _make_request({"domain": "example.com"})
        result = integration.dmarc_check(req)
        assert result["success"] is True
        assert result["summary"]["verdict"] == "valid"
        assert result["data"]["dmarc_valid"] is True

    @patch("app.mxtoolbox.requests.get")
    def test_dmarc_invalid(self, mock_get):
        mock_get.return_value = _mock_response(200, {
            "Command": "dmarc",
            "Argument": "bad-domain.com",
            "Result": [
                {"Name": "DMARC Record", "Status": "Failed", "Info": "No DMARC record"}
            ],
            "Errors": []
        })
        req = _make_request({"domain": "bad-domain.com"})
        result = integration.dmarc_check(req)
        assert result["data"]["dmarc_valid"] is False
        assert result["summary"]["risk_level"] == "critical"


# -------------------------------------------------------------------------
# API Error Handling (Errors array in response)
# -------------------------------------------------------------------------
class TestApiErrors:

    @patch("app.mxtoolbox.requests.get")
    def test_api_returns_error_in_response(self, mock_get):
        mock_get.return_value = _mock_response(200, {
            "Command": "blacklist",
            "Argument": "1.2.3.4",
            "Result": [],
            "Errors": [{"code": "INVALID_INPUT", "message": "Invalid request"}]
        })
        req = _make_request({"ip_address": "1.2.3.4"})
        with pytest.raises(Exception, match="Invalid request"):
            integration.blacklist_ip_check(req)


# -------------------------------------------------------------------------
# Retry Logic
# -------------------------------------------------------------------------
class TestRetryLogic:

    @patch("app.mxtoolbox.time.sleep")
    @patch("app.mxtoolbox.requests.get")
    def test_retry_on_429(self, mock_get, mock_sleep):
        rate_limited = _mock_response(429)
        success = _mock_response(200, {"Result": [], "Errors": []})
        mock_get.side_effect = [rate_limited, success]
        req = _make_request({"domain": "example.com"})
        result = integration.dns_lookup(req)
        assert result["success"] is True
        assert mock_get.call_count == 2
        mock_sleep.assert_called_once()

    @patch("app.mxtoolbox.time.sleep")
    @patch("app.mxtoolbox.requests.get")
    def test_retry_exhausted_on_429(self, mock_get, mock_sleep):
        rate_limited = _mock_response(429)
        mock_get.return_value = rate_limited
        req = _make_request({"domain": "example.com"})
        with pytest.raises(Exception, match="Rate limit exceeded"):
            integration.dns_lookup(req)

    @patch("app.mxtoolbox.time.sleep")
    @patch("app.mxtoolbox.requests.get")
    def test_retry_on_timeout(self, mock_get, mock_sleep):
        import requests as req_lib
        success = _mock_response(200, {"Result": [], "Errors": []})
        mock_get.side_effect = [req_lib.exceptions.Timeout(), success]
        req = _make_request({"domain": "example.com"})
        result = integration.dns_lookup(req)
        assert result["success"] is True
        assert mock_get.call_count == 2


# -------------------------------------------------------------------------
# HTTP Error Handling
# -------------------------------------------------------------------------
class TestErrorHandling:

    @patch("app.mxtoolbox.requests.get")
    def test_auth_failure_in_action(self, mock_get):
        mock_get.return_value = _mock_response(401)
        req = _make_request({"ip_address": "8.8.8.8"})
        with pytest.raises(Exception, match="Authentication failed"):
            integration.blacklist_ip_check(req)

    @patch("app.mxtoolbox.requests.get")
    def test_server_error_in_action(self, mock_get):
        mock_get.return_value = _mock_response(500)
        req = _make_request({"domain": "example.com"})
        with pytest.raises(Exception, match="server error"):
            integration.mx_lookup(req)

    @patch("app.mxtoolbox.requests.get")
    def test_connection_error(self, mock_get):
        import requests as req_lib
        mock_get.side_effect = req_lib.exceptions.ConnectionError()
        params = CONNECTION_PARAMS.copy()
        params["max_retries"] = 1
        req_json = json.dumps({"connectionParameters": params, "parameters": {"domain": "example.com"}})
        req = pykson.from_json(req_json, RequestBody, True)
        with pytest.raises(Exception, match="Failed to connect"):
            integration.dns_lookup(req)


# -------------------------------------------------------------------------
# URL Format Verification
# -------------------------------------------------------------------------
class TestUrlFormat:

    @patch("app.mxtoolbox.requests.get")
    def test_url_uses_query_param(self, mock_get):
        mock_get.return_value = _mock_response(200, {"Result": [], "Errors": []})
        req = _make_request({"ip_address": "8.8.8.8"})
        integration.blacklist_ip_check(req)
        call_args = mock_get.call_args
        assert "/lookup/blacklist/" in call_args[0][0]
        assert call_args[1]["params"] == {"argument": "8.8.8.8"}

    @patch("app.mxtoolbox.requests.get")
    def test_test_connection_url_format(self, mock_get):
        mock_get.return_value = _mock_response(200, {"Result": [], "Errors": []})
        integration.test_connection(CONNECTION_PARAMS)
        call_args = mock_get.call_args
        assert "/lookup/dns/" in call_args[0][0]
        assert call_args[1]["params"] == {"argument": "example.com"}


# -------------------------------------------------------------------------
# Input Validation
# -------------------------------------------------------------------------
class TestInputValidation:

    def test_invalid_ip_format(self):
        req = _make_request({"ip_address": "999.999.999.999"})
        with pytest.raises(Exception, match="Invalid IP address format"):
            integration.blacklist_ip_check(req)

    def test_empty_ip(self):
        req = _make_request({"ip_address": ""})
        with pytest.raises(Exception, match="IP address is required"):
            integration.blacklist_ip_check(req)

    def test_ip_not_numbers(self):
        req = _make_request({"ip_address": "abc.def.ghi.jkl"})
        with pytest.raises(Exception, match="Invalid IP address format"):
            integration.blacklist_ip_check(req)

    def test_ip_too_few_octets(self):
        req = _make_request({"ip_address": "1.2.3"})
        with pytest.raises(Exception, match="Invalid IP address format"):
            integration.blacklist_ip_check(req)

    def test_invalid_domain_format(self):
        req = _make_request({"domain": "not a domain!"})
        with pytest.raises(Exception, match="Invalid domain format"):
            integration.blacklist_domain_check(req)

    def test_empty_domain(self):
        req = _make_request({"domain": ""})
        with pytest.raises(Exception, match="Domain is required"):
            integration.blacklist_domain_check(req)

    def test_domain_no_tld(self):
        req = _make_request({"domain": "justahostname"})
        with pytest.raises(Exception, match="Invalid domain format"):
            integration.dns_lookup(req)

    def test_domain_with_spaces(self):
        req = _make_request({"domain": "bad domain.com"})
        with pytest.raises(Exception, match="Invalid domain format"):
            integration.dns_lookup(req)

    def test_domain_starts_with_dot(self):
        req = _make_request({"domain": ".example.com"})
        with pytest.raises(Exception, match="Invalid domain format"):
            integration.dns_lookup(req)

    def test_domain_double_dot(self):
        req = _make_request({"domain": "example..com"})
        with pytest.raises(Exception, match="Invalid domain format"):
            integration.dns_lookup(req)

    @patch("app.mxtoolbox.requests.get")
    def test_internal_domain_passes(self, mock_get):
        mock_get.return_value = _mock_response(200, {"Result": [], "Errors": []})
        req = _make_request({"domain": "server.local"})
        result = integration.dns_lookup(req)
        assert result["success"] is True

    @patch("app.mxtoolbox.requests.get")
    def test_valid_ip_passes(self, mock_get):
        mock_get.return_value = _mock_response(200, {"Result": [], "Errors": []})
        req = _make_request({"ip_address": "192.168.1.1"})
        result = integration.blacklist_ip_check(req)
        assert result["success"] is True

    @patch("app.mxtoolbox.requests.get")
    def test_valid_domain_passes(self, mock_get):
        mock_get.return_value = _mock_response(200, {"Result": [], "Errors": []})
        req = _make_request({"domain": "google.com"})
        result = integration.blacklist_domain_check(req)
        assert result["success"] is True

    @patch("app.mxtoolbox.requests.get")
    def test_ip_with_whitespace_trimmed(self, mock_get):
        mock_get.return_value = _mock_response(200, {"Result": [], "Errors": []})
        req = _make_request({"ip_address": "  8.8.8.8  "})
        result = integration.blacklist_ip_check(req)
        assert result["indicator"] == "8.8.8.8"


# -------------------------------------------------------------------------
# Connection Parameter Defaults
# -------------------------------------------------------------------------
class TestConnectionDefaults:

    def test_default_base_url(self):
        params = {"api_key": "<api_key>"}
        base_url, api_key, timeout, max_retries = integration._get_connection(params)
        assert base_url == "https://mxtoolbox.com/api/v1"
        assert timeout == 30
        assert max_retries == 3

    def test_custom_base_url(self):
        params = {"api_key": "<api_key>", "base_url": "https://proxy.example.com/mxtoolbox/"}
        base_url, _, _, _ = integration._get_connection(params)
        assert base_url == "https://proxy.example.com/mxtoolbox"

    def test_null_timeout_defaults(self):
        params = {"api_key": "<api_key>", "timeout": None, "max_retries": "None"}
        _, _, timeout, max_retries = integration._get_connection(params)
        assert timeout == 30
        assert max_retries == 3
