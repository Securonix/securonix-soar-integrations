import pytest
from unittest.mock import patch, MagicMock
from app.shodan import Shodan
from app.model.request_body import RequestBody
from pykson import Pykson
import json

pykson = Pykson()
integration_class = Shodan()

CONNECTION_PARAMS = {"server_url": "https://api.shodan.io", "api_token": "test_token"}


def _make_request(params=None):
    body = {"connectionParameters": CONNECTION_PARAMS, "parameters": params or {}}
    return pykson.from_json(json.dumps(body), RequestBody, True)


def _mock_response(status_code=200, json_data=None, text=""):
    mock = MagicMock()
    mock.status_code = status_code
    mock.text = text
    mock.json.return_value = json_data if json_data is not None else {}
    return mock


class TestTestConnection:
    @patch("app.shodan.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(200, {"plan": "dev", "query_credits": 100})
        result = integration_class.test_connection(CONNECTION_PARAMS)
        assert result["status"] == "success"

    @patch("app.shodan.requests.get")
    def test_auth_failure(self, mock_get):
        mock_get.return_value = _mock_response(401, {"error": "Access denied"})
        with pytest.raises(Exception, match="Authentication failed"):
            integration_class.test_connection(CONNECTION_PARAMS)

    def test_missing_api_token(self):
        with pytest.raises(Exception, match="API Token is required"):
            integration_class.test_connection({"server_url": "https://api.shodan.io"})


class TestIpAddress:
    @patch("app.shodan.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(200, {
            "ip_str": "8.8.8.8", "org": "Google LLC", "isp": "Google LLC",
            "hostnames": ["dns.google"], "domains": ["google.com"],
            "country_name": "United States", "city": "Mountain View",
            "latitude": 37.386, "longitude": -122.0838,
            "ports": [53, 443], "os": None, "vulns": ["CVE-2021-1234"]
        })
        resp = integration_class.ip_address(_make_request({"ip_addr": "8.8.8.8"}))
        assert resp["ip"] == "8.8.8.8"
        assert resp["organization"] == "Google LLC"
        assert resp["ports"] == [53, 443]
        assert resp["vulnerabilities"] == ["CVE-2021-1234"]

    def test_invalid_ip(self):
        with pytest.raises(Exception, match="Invalid IP address format"):
            integration_class.ip_address(_make_request({"ip_addr": "999.999.999.999"}))

    def test_empty_ip(self):
        with pytest.raises(Exception, match="IP address is required"):
            integration_class.ip_address(_make_request({"ip_addr": ""}))

    @patch("app.shodan.requests.get")
    def test_ip_param_alias(self, mock_get):
        mock_get.return_value = _mock_response(200, {"ip_str": "1.1.1.1", "ports": [80]})
        resp = integration_class.ip_address(_make_request({"ip": "1.1.1.1"}))
        assert resp["ip"] == "1.1.1.1"


class TestDomainLookup:
    @patch("app.shodan.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(200, {
            "domain": "google.com",
            "subdomains": ["www", "mail", "dns"],
            "tags": ["ipv6"],
            "data": [{"subdomain": "www", "type": "A", "value": "142.250.80.46"}]
        })
        resp = integration_class.domain_lookup(_make_request({"domain": "google.com"}))
        assert resp["domain"] == "google.com"
        assert "www" in resp["subdomains"]
        assert len(resp["data"]) == 1

    def test_empty_domain(self):
        with pytest.raises(Exception, match="domain is required"):
            integration_class.domain_lookup(_make_request({"domain": ""}))


class TestHostSearch:
    @patch("app.shodan.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(200, {
            "total": 500,
            "matches": [{"ip_str": "1.2.3.4", "port": 80}]
        })
        resp = integration_class.host_search(_make_request({"query": "apache"}))
        assert resp["total"] == 500
        assert len(resp["matches"]) == 1

    @patch("app.shodan.requests.get")
    def test_with_page(self, mock_get):
        mock_get.return_value = _mock_response(200, {"total": 100, "matches": []})
        resp = integration_class.host_search(_make_request({"query": "nginx", "page": "2"}))
        assert resp["total"] == 100
        call_params = mock_get.call_args[1]["params"]
        assert call_params["page"] == 2

    def test_empty_query(self):
        with pytest.raises(Exception, match="query is required"):
            integration_class.host_search(_make_request({"query": ""}))


class TestHostCount:
    @patch("app.shodan.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(200, {"total": 12345, "facets": {}})
        resp = integration_class.host_count(_make_request({"query": "apache"}))
        assert resp["total"] == 12345

    @patch("app.shodan.requests.get")
    def test_with_facets(self, mock_get):
        mock_get.return_value = _mock_response(200, {
            "total": 100, "facets": {"country": [{"value": "US", "count": 50}]}
        })
        resp = integration_class.host_count(_make_request({"query": "nginx", "facets": "country"}))
        assert "country" in resp["facets"]


class TestListPorts:
    @patch("app.shodan.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(200, [21, 22, 23, 25, 80, 443])
        mock_get.return_value.json.return_value = [21, 22, 23, 25, 80, 443]
        resp = integration_class.list_ports(_make_request())
        assert 80 in resp["ports"]
        assert 443 in resp["ports"]


class TestListProtocols:
    @patch("app.shodan.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(200, {"http": "HTTP", "ssh": "SSH"})
        resp = integration_class.list_protocols(_make_request())
        assert "http" in resp["protocols"]


class TestListServices:
    @patch("app.shodan.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(200, {"80": "HTTP", "443": "HTTPS"})
        resp = integration_class.list_services(_make_request())
        assert "80" in resp["services"]


class TestHoneyscore:
    @patch("app.shodan.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(200, 0.5)
        mock_get.return_value.json.return_value = 0.5
        resp = integration_class.honeyscore(_make_request({"ip": "8.8.8.8"}))
        assert resp["ip"] == "8.8.8.8"
        assert resp["honeyscore"] == 0.5

    def test_invalid_ip(self):
        with pytest.raises(Exception, match="Invalid IP address format"):
            integration_class.honeyscore(_make_request({"ip": "not_an_ip"}))


class TestMyIp:
    @patch("app.shodan.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(200, "1.2.3.4")
        mock_get.return_value.json.return_value = "1.2.3.4"
        resp = integration_class.my_ip(_make_request())
        assert resp["ip"] == "1.2.3.4"


class TestApiInfo:
    @patch("app.shodan.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _mock_response(200, {
            "query_credits": 100, "scan_credits": 50,
            "monitored_ips": 5, "plan": "dev", "https": True, "unlocked": True
        })
        resp = integration_class.api_info(_make_request())
        assert resp["query_credits"] == 100
        assert resp["plan"] == "dev"
        assert resp["unlocked"] is True


class TestErrorHandling:
    @patch("app.shodan.requests.get")
    def test_connection_error(self, mock_get):
        mock_get.side_effect = Exception("Unable to connect to Shodan. Please verify the Server URL.")
        with pytest.raises(Exception, match="Unable to connect"):
            integration_class.ip_address(_make_request({"ip_addr": "8.8.8.8"}))

    @patch("app.shodan.requests.get")
    def test_timeout(self, mock_get):
        import requests as req
        mock_get.side_effect = req.exceptions.Timeout()
        with pytest.raises(Exception, match="timed out"):
            integration_class.ip_address(_make_request({"ip_addr": "8.8.8.8"}))

    @patch("app.shodan.requests.get")
    def test_auth_failure(self, mock_get):
        mock_get.return_value = _mock_response(403, {"error": "Access denied"})
        with pytest.raises(Exception, match="Authentication failed"):
            integration_class.ip_address(_make_request({"ip_addr": "8.8.8.8"}))

    @patch("app.shodan.requests.get")
    @patch("app.shodan.time.sleep")
    def test_rate_limit_retry(self, mock_sleep, mock_get):
        mock_get.side_effect = [
            _mock_response(429), _mock_response(429), _mock_response(429)
        ]
        with pytest.raises(Exception, match="Rate limit exceeded"):
            integration_class.ip_address(_make_request({"ip_addr": "8.8.8.8"}))
        assert mock_sleep.call_count == 2

    @patch("app.shodan.requests.get")
    @patch("app.shodan.time.sleep")
    def test_rate_limit_recovery(self, mock_sleep, mock_get):
        mock_get.side_effect = [
            _mock_response(429),
            _mock_response(200, {"ip_str": "8.8.8.8", "ports": [80]})
        ]
        resp = integration_class.ip_address(_make_request({"ip_addr": "8.8.8.8"}))
        assert resp["ip"] == "8.8.8.8"

    @patch("app.shodan.requests.get")
    @patch("app.shodan.time.sleep")
    def test_server_error_retry(self, mock_sleep, mock_get):
        mock_get.side_effect = [
            _mock_response(500),
            _mock_response(200, {"ip_str": "8.8.8.8", "ports": []})
        ]
        resp = integration_class.ip_address(_make_request({"ip_addr": "8.8.8.8"}))
        assert resp["ip"] == "8.8.8.8"


class TestDefaultBaseUrl:
    @patch("app.shodan.requests.get")
    def test_empty_server_url_uses_default(self, mock_get):
        mock_get.return_value = _mock_response(200, {"plan": "dev", "query_credits": 10})
        params = {"server_url": "", "api_token": "test_token"}
        result = integration_class.test_connection(params)
        assert result["status"] == "success"
        call_url = mock_get.call_args[0][0]
        assert call_url.startswith("https://api.shodan.io")
