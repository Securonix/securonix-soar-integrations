import pytest
from unittest.mock import patch, MagicMock
from app.pulsedive import Pulsedive
from app.model.request_body import RequestBody
from pykson import Pykson
import json

pykson = Pykson()
integration_class = Pulsedive()

CONNECTION_PARAMS = {
    "api_key": "test_api_key_123",
    "base_url": "https://pulsedive.com/api",
}


def _make_request(params=None):
    body = {"connectionParameters": CONNECTION_PARAMS, "parameters": params or {}}
    return pykson.from_json(json.dumps(body), RequestBody, True)


def _mock_response(status_code=200, json_data=None):
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_data if json_data is not None else {}
    return mock


INDICATOR_RESPONSE = {
    "iid": 1,
    "indicator": "8.8.8.8",
    "type": "ip",
    "risk": "none",
    "risk_score": 0.0,
    "stamp_added": "2020-01-01",
    "stamp_updated": "2025-01-01",
    "attributes": {},
    "threats": [],
    "feeds": [],
}

SEARCH_RESPONSE = {
    "results": [
        {"iid": 1, "indicator": "8.8.8.8", "type": "ip", "risk": "none"},
        {"iid": 2, "indicator": "1.1.1.1", "type": "ip", "risk": "low"},
    ]
}

THREAT_SEARCH_RESPONSE = {
    "results": [
        {"tid": 10, "threat": "Emotet", "category": "malware", "risk": "high",
         "stamp_added": "2020-01-01", "stamp_updated": "2025-01-01"},
    ]
}


class TestTestConnection:
    @patch("app.pulsedive.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(200, INDICATOR_RESPONSE)
        result = integration_class.test_connection(CONNECTION_PARAMS)
        assert result["status"] == "success"
        assert "Connected" in result["message"]
        # Verify correct endpoint used
        call_url = mock_get.call_args[0][0]
        assert "/indicator.php" in call_url

    def test_missing_api_key(self):
        with pytest.raises(Exception, match="api_key is required"):
            integration_class.test_connection({"base_url": "https://pulsedive.com/api"})

    def test_empty_api_key(self):
        with pytest.raises(Exception, match="api_key is required"):
            integration_class.test_connection({"api_key": "   "})

    @patch("app.pulsedive.requests.get")
    def test_auth_failure(self, mock_get):
        mock_get.return_value = _mock_response(401)
        with pytest.raises(Exception, match="Authentication failed"):
            integration_class.test_connection(CONNECTION_PARAMS)

    @patch("app.pulsedive.requests.get")
    def test_api_error_in_response(self, mock_get):
        mock_get.return_value = _mock_response(200, {"error": "Invalid API key"})
        # test_connection does not parse body — 200 is treated as success
        result = integration_class.test_connection(CONNECTION_PARAMS)
        assert result["status"] == "success"


class TestGetIndicatorDetails:
    @patch("app.pulsedive.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(200, INDICATOR_RESPONSE)
        resp = integration_class.get_indicator_details(_make_request({"indicator": "8.8.8.8"}))
        assert resp["status"] == "success"
        assert resp["indicator"]["type"] == "ip"
        call_url = mock_get.call_args[0][0]
        assert "/indicator.php" in call_url

    def test_missing_indicator(self):
        with pytest.raises(Exception, match="indicator is required"):
            integration_class.get_indicator_details(_make_request({}))

    def test_empty_indicator(self):
        with pytest.raises(Exception, match="indicator is required"):
            integration_class.get_indicator_details(_make_request({"indicator": ""}))

    def test_indicator_too_long(self):
        with pytest.raises(Exception, match="exceeds maximum length"):
            integration_class.get_indicator_details(_make_request({"indicator": "a" * 2049}))

    @patch("app.pulsedive.requests.get")
    def test_not_found_returns_empty(self, mock_get):
        mock_get.return_value = _mock_response(404)
        resp = integration_class.get_indicator_details(_make_request({"indicator": "unknown.example"}))
        assert resp["status"] == "success"
        assert resp["indicator"] == {}


class TestEnrichIp:
    @patch("app.pulsedive.requests.get")
    def test_success_ipv4(self, mock_get):
        mock_get.return_value = _mock_response(200, INDICATOR_RESPONSE)
        resp = integration_class.enrich_ip(_make_request({"ip": "8.8.8.8"}))
        assert resp["status"] == "success"
        assert resp["indicator"]["type"] == "ip"

    @patch("app.pulsedive.requests.get")
    def test_success_ipv6(self, mock_get):
        mock_get.return_value = _mock_response(200, {**INDICATOR_RESPONSE, "type": "ip", "indicator": "::1"})
        resp = integration_class.enrich_ip(_make_request({"ip": "::1"}))
        assert resp["status"] == "success"

    def test_missing_ip(self):
        with pytest.raises(Exception, match="ip is required"):
            integration_class.enrich_ip(_make_request({}))

    def test_invalid_ip(self):
        with pytest.raises(Exception, match="Invalid IP address format"):
            integration_class.enrich_ip(_make_request({"ip": "not-an-ip"}))

    def test_invalid_ip_out_of_range(self):
        with pytest.raises(Exception, match="Invalid IP address format"):
            integration_class.enrich_ip(_make_request({"ip": "999.999.999.999"}))


class TestEnrichDomain:
    @patch("app.pulsedive.requests.get")
    def test_success(self, mock_get):
        domain_resp = {**INDICATOR_RESPONSE, "type": "domain", "indicator": "example.com"}
        mock_get.return_value = _mock_response(200, domain_resp)
        resp = integration_class.enrich_domain(_make_request({"domain": "example.com"}))
        assert resp["status"] == "success"
        assert resp["indicator"]["type"] == "domain"

    def test_missing_domain(self):
        with pytest.raises(Exception, match="domain is required"):
            integration_class.enrich_domain(_make_request({}))

    def test_invalid_domain(self):
        with pytest.raises(Exception, match="Invalid domain format"):
            integration_class.enrich_domain(_make_request({"domain": "not a domain!"}))

    def test_domain_too_long(self):
        with pytest.raises(Exception, match="Invalid domain format"):
            integration_class.enrich_domain(_make_request({"domain": "a" * 254 + ".com"}))


class TestEnrichUrl:
    @patch("app.pulsedive.requests.get")
    def test_success(self, mock_get):
        url_resp = {**INDICATOR_RESPONSE, "type": "url", "indicator": "https://example.com/path"}
        mock_get.return_value = _mock_response(200, url_resp)
        resp = integration_class.enrich_url(_make_request({"url": "https://example.com/path"}))
        assert resp["status"] == "success"
        assert resp["indicator"]["type"] == "url"

    def test_missing_url(self):
        with pytest.raises(Exception, match="url is required"):
            integration_class.enrich_url(_make_request({}))

    def test_invalid_url_no_scheme(self):
        with pytest.raises(Exception, match="Invalid URL format"):
            integration_class.enrich_url(_make_request({"url": "example.com/path"}))

    def test_invalid_url_ftp(self):
        with pytest.raises(Exception, match="Invalid URL format"):
            integration_class.enrich_url(_make_request({"url": "ftp://example.com"}))

    def test_url_too_long(self):
        with pytest.raises(Exception, match="Invalid URL format"):
            integration_class.enrich_url(_make_request({"url": "https://example.com/" + "a" * 2040}))


class TestEnrichHash:
    @patch("app.pulsedive.requests.get")
    def test_success_md5(self, mock_get):
        hash_resp = {**INDICATOR_RESPONSE, "type": "hash", "indicator": "d41d8cd98f00b204e9800998ecf8427e"}
        mock_get.return_value = _mock_response(200, hash_resp)
        resp = integration_class.enrich_hash(_make_request({"hash": "d41d8cd98f00b204e9800998ecf8427e"}))
        assert resp["status"] == "success"

    @patch("app.pulsedive.requests.get")
    def test_success_sha1(self, mock_get):
        mock_get.return_value = _mock_response(200, INDICATOR_RESPONSE)
        resp = integration_class.enrich_hash(_make_request({"hash": "da39a3ee5e6b4b0d3255bfef95601890afd80709"}))
        assert resp["status"] == "success"

    @patch("app.pulsedive.requests.get")
    def test_success_sha256(self, mock_get):
        mock_get.return_value = _mock_response(200, INDICATOR_RESPONSE)
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        resp = integration_class.enrich_hash(_make_request({"hash": sha256}))
        assert resp["status"] == "success"

    def test_missing_hash(self):
        with pytest.raises(Exception, match="hash is required"):
            integration_class.enrich_hash(_make_request({}))

    def test_invalid_hash_wrong_length(self):
        with pytest.raises(Exception, match="Invalid hash format"):
            integration_class.enrich_hash(_make_request({"hash": "abc123"}))

    def test_invalid_hash_non_hex(self):
        with pytest.raises(Exception, match="Invalid hash format"):
            integration_class.enrich_hash(_make_request({"hash": "z" * 32}))


class TestSearchIndicators:
    @patch("app.pulsedive.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(200, SEARCH_RESPONSE)
        resp = integration_class.search_indicators(_make_request({"query": "8.8.8.8"}))
        assert resp["status"] == "success"
        assert len(resp["results"]) == 2
        assert resp["total"] == 2

    @patch("app.pulsedive.requests.get")
    def test_with_type_filter(self, mock_get):
        mock_get.return_value = _mock_response(200, SEARCH_RESPONSE)
        resp = integration_class.search_indicators(_make_request({
            "query": "google", "indicator_type": "ip", "limit": "5"
        }))
        assert resp["status"] == "success"
        # Verify type param was passed correctly
        call_kwargs = mock_get.call_args
        assert call_kwargs[1]["params"]["type"] == "ip"
        assert call_kwargs[1]["params"]["limit"] == 5

    @patch("app.pulsedive.requests.get")
    def test_with_risk_filter(self, mock_get):
        mock_get.return_value = _mock_response(200, SEARCH_RESPONSE)
        resp = integration_class.search_indicators(_make_request({
            "query": "malware", "risk": "high"
        }))
        assert resp["status"] == "success"
        call_kwargs = mock_get.call_args
        assert call_kwargs[1]["params"]["risk"] == "high"

    def test_missing_query(self):
        with pytest.raises(Exception, match="query is required"):
            integration_class.search_indicators(_make_request({}))

    def test_invalid_indicator_type(self):
        with pytest.raises(Exception, match="indicator_type must be one of"):
            integration_class.search_indicators(_make_request({
                "query": "test", "indicator_type": "invalid_type"
            }))

    def test_invalid_risk(self):
        with pytest.raises(Exception, match="risk must be one of"):
            integration_class.search_indicators(_make_request({
                "query": "test", "risk": "extreme"
            }))

    def test_limit_out_of_range(self):
        with pytest.raises(Exception, match="limit must be between 1 and 100"):
            integration_class.search_indicators(_make_request({
                "query": "test", "limit": "200"
            }))

    def test_query_too_long(self):
        with pytest.raises(Exception, match="exceeds maximum length"):
            integration_class.search_indicators(_make_request({"query": "q" * 2049}))

    @patch("app.pulsedive.requests.get")
    def test_empty_results(self, mock_get):
        mock_get.return_value = _mock_response(200, {"results": []})
        resp = integration_class.search_indicators(_make_request({"query": "nonexistent"}))
        assert resp["results"] == []
        assert resp["total"] == 0


class TestSearchThreats:
    @patch("app.pulsedive.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(200, THREAT_SEARCH_RESPONSE["results"][0])
        resp = integration_class.search_threats(_make_request({"query": "Emotet"}))
        assert resp["status"] == "success"
        assert len(resp["results"]) == 1
        assert resp["results"][0]["threat"] == "Emotet"
        # Verify correct endpoint used
        call_url = mock_get.call_args[0][0]
        assert "/threat.php" in call_url
        assert mock_get.call_args[1]["params"]["threat"] == "Emotet"

    @patch("app.pulsedive.requests.get")
    def test_with_limit(self, mock_get):
        # limit param is not used by /threat.php (single lookup), but should not error
        mock_get.return_value = _mock_response(200, THREAT_SEARCH_RESPONSE["results"][0])
        resp = integration_class.search_threats(_make_request({"query": "ransomware", "limit": "20"}))
        assert resp["status"] == "success"

    def test_missing_query(self):
        with pytest.raises(Exception, match="query is required"):
            integration_class.search_threats(_make_request({}))

    def test_query_too_long(self):
        with pytest.raises(Exception, match="exceeds maximum length"):
            integration_class.search_threats(_make_request({"query": "t" * 2049}))

    @patch("app.pulsedive.requests.get")
    def test_empty_results(self, mock_get):
        mock_get.return_value = _mock_response(404)
        resp = integration_class.search_threats(_make_request({"query": "unknown_threat"}))
        assert resp["results"] == []
        assert resp["total"] == 0


class TestErrorHandling:
    @patch("app.pulsedive.requests.get")
    def test_connection_error(self, mock_get):
        import requests as req
        mock_get.side_effect = req.exceptions.ConnectionError()
        with pytest.raises(Exception, match="Unable to connect"):
            integration_class.test_connection(CONNECTION_PARAMS)

    @patch("app.pulsedive.requests.get")
    def test_timeout(self, mock_get):
        import requests as req
        mock_get.side_effect = req.exceptions.Timeout()
        with pytest.raises(Exception, match="timed out"):
            integration_class.test_connection(CONNECTION_PARAMS)

    @patch("app.pulsedive.requests.get")
    def test_403_forbidden(self, mock_get):
        mock_get.return_value = _mock_response(403)
        with pytest.raises(Exception, match="Authentication failed"):
            integration_class.enrich_ip(_make_request({"ip": "8.8.8.8"}))

    @patch("app.pulsedive.time.sleep")
    @patch("app.pulsedive.requests.get")
    def test_429_retry_then_success(self, mock_get, mock_sleep):
        mock_get.side_effect = [
            _mock_response(429),
            _mock_response(200, INDICATOR_RESPONSE),
        ]
        resp = integration_class.enrich_ip(_make_request({"ip": "8.8.8.8"}))
        assert resp["status"] == "success"
        assert mock_sleep.call_count == 1

    @patch("app.pulsedive.time.sleep")
    @patch("app.pulsedive.requests.get")
    def test_429_retry_exhausted(self, mock_get, mock_sleep):
        mock_get.return_value = _mock_response(429)
        with pytest.raises(Exception, match="Rate limit exceeded"):
            integration_class.enrich_ip(_make_request({"ip": "8.8.8.8"}))

    @patch("app.pulsedive.time.sleep")
    @patch("app.pulsedive.requests.get")
    def test_500_retry_then_success(self, mock_get, mock_sleep):
        mock_get.side_effect = [
            _mock_response(500),
            _mock_response(200, INDICATOR_RESPONSE),
        ]
        resp = integration_class.enrich_domain(_make_request({"domain": "example.com"}))
        assert resp["status"] == "success"
        assert mock_sleep.call_count == 1

    @patch("app.pulsedive.time.sleep")
    @patch("app.pulsedive.requests.get")
    def test_500_retry_exhausted(self, mock_get, mock_sleep):
        mock_get.return_value = _mock_response(500)
        with pytest.raises(Exception, match="server error"):
            integration_class.enrich_domain(_make_request({"domain": "example.com"}))

    @patch("app.pulsedive.requests.get")
    def test_api_key_not_in_logs(self, mock_get, caplog):
        import logging
        mock_get.return_value = _mock_response(200, INDICATOR_RESPONSE)
        with caplog.at_level(logging.DEBUG):
            integration_class.enrich_ip(_make_request({"ip": "8.8.8.8"}))
        assert "test_api_key_123" not in caplog.text

    @patch("app.pulsedive.requests.get")
    def test_custom_base_url(self, mock_get):
        mock_get.return_value = _mock_response(200, INDICATOR_RESPONSE)
        custom_params = {**CONNECTION_PARAMS, "base_url": "https://custom.pulsedive.com/api"}
        integration_class.test_connection(custom_params)
        call_url = mock_get.call_args[0][0]
        assert "custom.pulsedive.com" in call_url

    @patch("app.pulsedive.requests.get")
    def test_proxy_passed_to_request(self, mock_get):
        mock_get.return_value = _mock_response(200, INDICATOR_RESPONSE)
        proxy_params = {**CONNECTION_PARAMS, "proxy": "http://proxy.internal:8080"}
        integration_class.test_connection(proxy_params)
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs["proxies"] == {
            "http": "http://proxy.internal:8080",
            "https": "http://proxy.internal:8080",
        }

    @patch("app.pulsedive.requests.get")
    def test_verify_ssl_false(self, mock_get):
        mock_get.return_value = _mock_response(200, INDICATOR_RESPONSE)
        ssl_params = {**CONNECTION_PARAMS, "verify_ssl": "false"}
        integration_class.test_connection(ssl_params)
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs["verify"] is False
