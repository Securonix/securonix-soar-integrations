import pytest
from unittest.mock import patch, MagicMock
from app.netskope import Netskope


def _mock_request_body(connection_params=None, parameters=None):
    body = MagicMock()
    body.connectionParameters = connection_params or {
        "tenant_hostname": "mytenant.goskope.com",
        "api_token": "test-token-123",
    }
    body.parameters = parameters or {}
    return body


def _default_conn():
    return {
        "tenant_hostname": "mytenant.goskope.com",
        "api_token": "test-token-123",
    }


class TestGetConfig:

    def test_missing_tenant_hostname(self):
        ns = Netskope()
        with pytest.raises(Exception, match="tenant_hostname is required"):
            ns._get_config({"api_token": "tok"})

    def test_missing_api_token(self):
        ns = Netskope()
        with pytest.raises(Exception, match="api_token is required"):
            ns._get_config({"tenant_hostname": "t.goskope.com"})

    def test_invalid_timeout(self):
        ns = Netskope()
        with pytest.raises(Exception, match="timeout must be a positive integer"):
            ns._get_config({"tenant_hostname": "t.goskope.com", "api_token": "tok", "timeout": "-1"})

    def test_invalid_timeout_non_numeric(self):
        ns = Netskope()
        with pytest.raises(Exception, match="timeout must be a positive integer"):
            ns._get_config({"tenant_hostname": "t.goskope.com", "api_token": "tok", "timeout": "abc"})

    def test_valid_config(self):
        ns = Netskope()
        config = ns._get_config(_default_conn())
        assert config["base_url"] == "https://mytenant.goskope.com"
        assert config["headers"]["Netskope-API-Token"] == "test-token-123"
        assert config["headers"]["User-Agent"] == "SecuronixSOAR-Netskope/1.0"
        assert config["timeout"] == 30
        assert config["verify"] is True

    def test_verify_ssl_string_false(self):
        ns = Netskope()
        conn = _default_conn()
        conn["verify_ssl"] = "false"
        config = ns._get_config(conn)
        assert config["verify"] is False

    def test_proxy_config(self):
        ns = Netskope()
        conn = _default_conn()
        conn["proxy"] = "http://proxy:8080"
        config = ns._get_config(conn)
        assert config["proxies"] == {"http": "http://proxy:8080", "https": "http://proxy:8080"}


class TestTestConnection:

    @patch("app.netskope.requests.request")
    def test_success(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": []}
        mock_req.return_value = mock_resp

        ns = Netskope()
        result = ns.test_connection(_default_conn())
        assert result["status"] == "success"

    @patch("app.netskope.requests.request")
    def test_auth_failure(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_req.return_value = mock_resp

        ns = Netskope()
        with pytest.raises(Exception, match="Authentication failed"):
            ns.test_connection(_default_conn())


class TestGetAlerts:

    @patch("app.netskope.requests.request")
    def test_success_default(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": [{"alert_id": "1", "alert_type": "dlp"}]}
        mock_req.return_value = mock_resp

        ns = Netskope()
        result = ns.get_alerts(_mock_request_body())
        assert result["status"] == "success"
        assert len(result["alerts"]) == 1

    @patch("app.netskope.requests.request")
    def test_with_filters(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": []}
        mock_req.return_value = mock_resp

        ns = Netskope()
        params = {"alert_type": "malware", "time_period": "48", "user": "user@test.com", "severity": "high", "limit": "50"}
        result = ns.get_alerts(_mock_request_body(parameters=params))
        assert result["status"] == "success"

        call_kwargs = mock_req.call_args
        assert call_kwargs.kwargs["params"]["alert_type"] == "malware"
        assert call_kwargs.kwargs["params"]["timeperiod"] == 48
        assert call_kwargs.kwargs["params"]["user"] == "user@test.com"
        assert call_kwargs.kwargs["params"]["severity"] == "high"
        assert call_kwargs.kwargs["params"]["limit"] == 50

    @patch("app.netskope.requests.request")
    def test_with_raw_query(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": []}
        mock_req.return_value = mock_resp

        ns = Netskope()
        params = {"query": "app eq Slack"}
        result = ns.get_alerts(_mock_request_body(parameters=params))
        assert result["status"] == "success"
        assert mock_req.call_args.kwargs["params"]["query"] == "app eq Slack"

    def test_invalid_alert_type(self):
        ns = Netskope()
        params = {"alert_type": "invalid_type"}
        with pytest.raises(Exception, match="alert_type must be one of"):
            ns.get_alerts(_mock_request_body(parameters=params))

    def test_invalid_time_period(self):
        ns = Netskope()
        params = {"time_period": "abc"}
        with pytest.raises(Exception, match="time_period must be a positive integer"):
            ns.get_alerts(_mock_request_body(parameters=params))

    def test_invalid_limit(self):
        ns = Netskope()
        params = {"limit": "0"}
        with pytest.raises(Exception, match="limit must be a positive integer"):
            ns.get_alerts(_mock_request_body(parameters=params))


class TestGetEvents:

    @patch("app.netskope.requests.request")
    def test_success(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": [{"event_id": "1"}]}
        mock_req.return_value = mock_resp

        ns = Netskope()
        params = {"event_type": "page"}
        result = ns.get_events(_mock_request_body(parameters=params))
        assert result["status"] == "success"
        assert "events" in result
        assert "/api/v2/events/datasearch/page" in mock_req.call_args.kwargs["url"]

    def test_missing_event_type(self):
        ns = Netskope()
        with pytest.raises(Exception, match="event_type is required"):
            ns.get_events(_mock_request_body(parameters={}))

    def test_invalid_event_type(self):
        ns = Netskope()
        params = {"event_type": "invalid"}
        with pytest.raises(Exception, match="event_type must be one of"):
            ns.get_events(_mock_request_body(parameters=params))

    @patch("app.netskope.requests.request")
    def test_with_raw_query(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": []}
        mock_req.return_value = mock_resp

        ns = Netskope()
        params = {"event_type": "application", "query": "app eq Office365"}
        result = ns.get_events(_mock_request_body(parameters=params))
        assert result["status"] == "success"
        assert mock_req.call_args.kwargs["params"]["query"] == "app eq Office365"


class TestGetIncidents:

    @patch("app.netskope.requests.request")
    def test_success(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": [{"incident_id": "1"}]}
        mock_req.return_value = mock_resp

        ns = Netskope()
        result = ns.get_incidents(_mock_request_body())
        assert result["status"] == "success"
        assert "incidents" in result

    @patch("app.netskope.requests.request")
    def test_with_status_filter(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": []}
        mock_req.return_value = mock_resp

        ns = Netskope()
        params = {"status": "new", "time_period": "72"}
        result = ns.get_incidents(_mock_request_body(parameters=params))
        assert result["status"] == "success"
        assert mock_req.call_args.kwargs["params"]["status"] == "new"
        assert mock_req.call_args.kwargs["params"]["timeperiod"] == 72


class TestGetAlertDetails:

    @patch("app.netskope.requests.request")
    def test_success(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": [{"alert_id": "abc123", "alert_type": "dlp"}]}
        mock_req.return_value = mock_resp

        ns = Netskope()
        params = {"alert_id": "abc123"}
        result = ns.get_alert_details(_mock_request_body(parameters=params))
        assert result["status"] == "success"
        assert result["alert"]["alert_id"] == "abc123"

    def test_missing_alert_id(self):
        ns = Netskope()
        with pytest.raises(Exception, match="alert_id is required"):
            ns.get_alert_details(_mock_request_body(parameters={}))

    def test_alert_id_too_long(self):
        ns = Netskope()
        params = {"alert_id": "x" * 257}
        with pytest.raises(Exception, match="alert_id exceeds maximum length"):
            ns.get_alert_details(_mock_request_body(parameters=params))

    @patch("app.netskope.requests.request")
    def test_alert_not_found(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": []}
        mock_req.return_value = mock_resp

        ns = Netskope()
        params = {"alert_id": "nonexistent"}
        with pytest.raises(Exception, match="Alert not found"):
            ns.get_alert_details(_mock_request_body(parameters=params))


class TestUpdateUrlList:

    @patch("app.netskope.requests.request")
    def test_success_append(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "ok"}
        mock_req.return_value = mock_resp

        ns = Netskope()
        params = {"list_id": "42", "action": "append", "urls": "http://evil.com,http://bad.com"}
        result = ns.update_url_list(_mock_request_body(parameters=params))
        assert result["status"] == "success"
        assert "/api/v2/policy/urllist/42/append" in mock_req.call_args.kwargs["url"]
        assert mock_req.call_args.kwargs["json"] == {"urls": ["http://evil.com", "http://bad.com"]}

    @patch("app.netskope.requests.request")
    def test_success_replace(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "ok"}
        mock_req.return_value = mock_resp

        ns = Netskope()
        params = {"list_id": "10", "action": "replace", "urls": "http://only.com"}
        result = ns.update_url_list(_mock_request_body(parameters=params))
        assert result["status"] == "success"
        assert "/api/v2/policy/urllist/10/replace" in mock_req.call_args.kwargs["url"]

    def test_missing_list_id(self):
        ns = Netskope()
        params = {"action": "append", "urls": "http://test.com"}
        with pytest.raises(Exception, match="list_id is required"):
            ns.update_url_list(_mock_request_body(parameters=params))

    def test_missing_action(self):
        ns = Netskope()
        params = {"list_id": "1", "urls": "http://test.com"}
        with pytest.raises(Exception, match="action is required"):
            ns.update_url_list(_mock_request_body(parameters=params))

    def test_invalid_action(self):
        ns = Netskope()
        params = {"list_id": "1", "action": "delete", "urls": "http://test.com"}
        with pytest.raises(Exception, match="action must be one of"):
            ns.update_url_list(_mock_request_body(parameters=params))

    def test_missing_urls(self):
        ns = Netskope()
        params = {"list_id": "1", "action": "append"}
        with pytest.raises(Exception, match="urls is required"):
            ns.update_url_list(_mock_request_body(parameters=params))

    def test_empty_urls_after_split(self):
        ns = Netskope()
        params = {"list_id": "1", "action": "append", "urls": " , , "}
        with pytest.raises(Exception, match="urls must contain at least one valid URL"):
            ns.update_url_list(_mock_request_body(parameters=params))


class TestErrorHandling:

    @patch("app.netskope.requests.request")
    @patch("app.netskope.time.sleep")
    def test_429_retry_with_retry_after(self, mock_sleep, mock_req):
        mock_resp_429 = MagicMock()
        mock_resp_429.status_code = 429
        mock_resp_429.headers = {"Retry-After": "5"}

        mock_resp_200 = MagicMock()
        mock_resp_200.status_code = 200
        mock_resp_200.json.return_value = {"result": []}

        mock_req.side_effect = [mock_resp_429, mock_resp_200]

        ns = Netskope()
        result = ns.get_alerts(_mock_request_body())
        assert result["status"] == "success"
        mock_sleep.assert_called_once_with(5)

    @patch("app.netskope.requests.request")
    @patch("app.netskope.time.sleep")
    def test_429_exhausted(self, mock_sleep, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.headers = {}
        mock_req.return_value = mock_resp

        ns = Netskope()
        with pytest.raises(Exception, match="Rate limit exceeded"):
            ns.get_alerts(_mock_request_body())

    @patch("app.netskope.requests.request")
    @patch("app.netskope.time.sleep")
    def test_500_retry_then_success(self, mock_sleep, mock_req):
        mock_resp_500 = MagicMock()
        mock_resp_500.status_code = 500

        mock_resp_200 = MagicMock()
        mock_resp_200.status_code = 200
        mock_resp_200.json.return_value = {"result": []}

        mock_req.side_effect = [mock_resp_500, mock_resp_200]

        ns = Netskope()
        result = ns.get_alerts(_mock_request_body())
        assert result["status"] == "success"

    @patch("app.netskope.requests.request")
    @patch("app.netskope.time.sleep")
    def test_500_exhausted(self, mock_sleep, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_req.return_value = mock_resp

        ns = Netskope()
        with pytest.raises(Exception, match="Netskope server error"):
            ns.get_alerts(_mock_request_body())

    @patch("app.netskope.requests.request")
    def test_connection_error(self, mock_req):
        import requests as req_lib
        mock_req.side_effect = req_lib.exceptions.ConnectionError()

        ns = Netskope()
        with pytest.raises(Exception, match="Unable to connect to Netskope"):
            ns.get_alerts(_mock_request_body())

    @patch("app.netskope.requests.request")
    def test_timeout_error(self, mock_req):
        import requests as req_lib
        mock_req.side_effect = req_lib.exceptions.Timeout()

        ns = Netskope()
        with pytest.raises(Exception, match="Connection to Netskope timed out"):
            ns.get_alerts(_mock_request_body())

    @patch("app.netskope.requests.request")
    def test_404_error(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_req.return_value = mock_resp

        ns = Netskope()
        with pytest.raises(Exception, match="Resource not found"):
            ns.get_alerts(_mock_request_body())

    @patch("app.netskope.requests.request")
    def test_422_error(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 422
        mock_resp.json.return_value = {"error": "Invalid query syntax"}
        mock_req.return_value = mock_resp

        ns = Netskope()
        with pytest.raises(Exception, match="Validation error.*Invalid query syntax"):
            ns.get_alerts(_mock_request_body())
