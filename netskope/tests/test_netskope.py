import pytest
from unittest.mock import patch, MagicMock
from app.netskope import Netskope, _get_config, _parse_ioc_values, _confirm_deploy


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
        with pytest.raises(Exception, match="tenant_hostname is required"):
            _get_config({"api_token": "tok"})

    def test_missing_api_token(self):
        with pytest.raises(Exception, match="api_token is required"):
            _get_config({"tenant_hostname": "t.goskope.com"})

    def test_invalid_timeout(self):
        with pytest.raises(Exception, match="timeout must be a positive integer"):
            _get_config({"tenant_hostname": "t.goskope.com", "api_token": "tok", "timeout": "-1"})

    def test_invalid_timeout_non_numeric(self):
        with pytest.raises(Exception, match="timeout must be a positive integer"):
            _get_config({"tenant_hostname": "t.goskope.com", "api_token": "tok", "timeout": "abc"})

    def test_valid_config(self):
        config = _get_config(_default_conn())
        assert config["base_url"] == "https://mytenant.goskope.com"
        assert config["headers"]["Netskope-Api-Token"] == "test-token-123"
        assert config["headers"]["User-Agent"] == "SecuronixSOAR-Netskope/1.0"
        assert config["timeout"] == 30
        assert config["verify"] is True

    def test_verify_ssl_string_false(self):
        conn = _default_conn()
        conn["verify_ssl"] = "false"
        config = _get_config(conn)
        assert config["verify"] is False

    def test_proxy_config(self):
        conn = _default_conn()
        conn["proxy"] = "http://proxy:8080"
        config = _get_config(conn)
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

    @patch("app.netskope.requests.request")
    def test_400_error(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.json.return_value = {"message": "Bad request body"}
        mock_req.return_value = mock_resp

        ns = Netskope()
        with pytest.raises(Exception, match=r"Request failed \(HTTP 400\).*Bad request body"):
            ns.get_alerts(_mock_request_body())

    @patch("app.netskope.requests.request")
    def test_409_error_no_body(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 409
        mock_resp.json.side_effect = ValueError("no json")
        mock_req.return_value = mock_resp

        ns = Netskope()
        with pytest.raises(Exception, match=r"Request failed \(HTTP 409\)"):
            ns.get_alerts(_mock_request_body())


class TestParseIocValues:

    def test_comma_string(self):
        assert _parse_ioc_values("a.com,b.com", "values") == ["a.com", "b.com"]

    def test_list_input(self):
        assert _parse_ioc_values(["a.com", "b.com"], "values") == ["a.com", "b.com"]

    def test_strips_whitespace(self):
        assert _parse_ioc_values(" a.com , b.com ", "values") == ["a.com", "b.com"]

    def test_empty_raises(self):
        with pytest.raises(Exception, match="values must contain at least one value"):
            _parse_ioc_values("", "values")

    def test_none_raises(self):
        with pytest.raises(Exception, match="values must contain at least one value"):
            _parse_ioc_values(None, "values")


class TestConfirmDeploy:

    def test_passes_on_success_status(self):
        _confirm_deploy({"status": "success", "ids": ["p1"]}, "p1")  # no exception

    def test_passes_on_ok_status(self):
        _confirm_deploy({"status": "ok"}, "p1")  # no exception

    def test_passes_on_deployed_status(self):
        _confirm_deploy({"status": "deployed"}, "p1")  # no exception

    def test_passes_on_applied_status(self):
        _confirm_deploy({"status": "applied", "applied": ["p1"]}, "p1")  # no exception

    def test_checks_applied_field_for_profile_id(self):
        _confirm_deploy({"status": "applied", "applied": ["p1", "p2"]}, "p1")  # no exception

    def test_raises_when_profile_id_missing_from_applied(self):
        with pytest.raises(Exception, match="did not confirm profile p1"):
            _confirm_deploy({"status": "applied", "applied": ["p2"]}, "p1")

    def test_passes_when_no_status_field(self):
        _confirm_deploy({}, "p1")  # no exception

    def test_passes_when_ids_absent(self):
        _confirm_deploy({"status": "success"}, "p1")  # no exception

    def test_raises_on_failed_status(self):
        with pytest.raises(Exception, match="Deploy failed for profile p1"):
            _confirm_deploy({"status": "error", "message": "quota exceeded"}, "p1")

    def test_raises_when_profile_id_missing_from_ids(self):
        with pytest.raises(Exception, match="did not confirm profile p1"):
            _confirm_deploy({"status": "success", "ids": ["p2", "p3"]}, "p1")

    def test_passes_non_dict(self):
        _confirm_deploy(None, "p1")  # no exception


class TestGetDestinationProfiles:

    @patch("app.netskope.requests.request")
    def test_success(self, mock_req):
        mock_req.return_value = MagicMock(
            status_code=200,
            json=lambda: {"elements": [{"id": "p1", "name": "BlockProfile"}]},
        )
        ns = Netskope()
        result = ns.get_destination_profiles(_mock_request_body())
        assert result["status"] == "success"
        assert result["profiles"] == [{"id": "p1", "name": "BlockProfile"}]
        assert "/api/v2/profiles/destinations" in mock_req.call_args.kwargs["url"]

    @patch("app.netskope.requests.request")
    def test_falls_back_to_result_key(self, mock_req):
        mock_req.return_value = MagicMock(
            status_code=200,
            json=lambda: {"other": [{"id": "p2"}]},
        )
        ns = Netskope()
        result = ns.get_destination_profiles(_mock_request_body())
        assert result["profiles"] == {"other": [{"id": "p2"}]}

    @patch("app.netskope.requests.request")
    def test_auth_failure(self, mock_req):
        mock_req.return_value = MagicMock(status_code=401)
        ns = Netskope()
        with pytest.raises(Exception, match="Authentication failed"):
            ns.get_destination_profiles(_mock_request_body())


class TestAddDestinationProfileValues:

    @patch("app.netskope.requests.request")
    def test_success_comma_string(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, json=lambda: {"status": "ok"})
        ns = Netskope()
        params = {"profile_id": "prof-1", "values": "evil.com,1.2.3.4"}
        result = ns.add_destination_profile_values(_mock_request_body(parameters=params))
        assert result["status"] == "success"
        assert result["profile_id"] == "prof-1"
        assert result["values_added"] == ["evil.com", "1.2.3.4"]
        assert "readback" in result
        assert mock_req.call_count == 2
        append_call, deploy_call = mock_req.call_args_list
        assert "/api/v2/profiles/destinations/prof-1/values" in append_call.kwargs["url"]
        assert append_call.kwargs["json"] == {"operation": {"op": "append", "values": ["evil.com", "1.2.3.4"]}}
        assert "/api/v2/profiles/destinations/deploy" in deploy_call.kwargs["url"]
        assert deploy_call.kwargs["json"] == {"ids": ["prof-1"]}

    @patch("app.netskope.requests.request")
    def test_success_list_input(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, json=lambda: {})
        ns = Netskope()
        params = {"profile_id": "prof-2", "values": ["bad.net", "10.0.0.1"]}
        result = ns.add_destination_profile_values(_mock_request_body(parameters=params))
        assert result["status"] == "success"
        assert result["values_added"] == ["bad.net", "10.0.0.1"]

    @patch("app.netskope.requests.request")
    def test_success_applied_status(self, mock_req):
        append_resp = MagicMock(status_code=200, json=lambda: {"status": "applied"})
        deploy_resp = MagicMock(status_code=200, json=lambda: {"status": "applied", "applied": ["prof-1"]})
        mock_req.side_effect = [append_resp, deploy_resp]
        ns = Netskope()
        result = ns.add_destination_profile_values(_mock_request_body(parameters={"profile_id": "prof-1", "values": "evil.com"}))
        assert result["status"] == "success"

    def test_missing_profile_id(self):
        ns = Netskope()
        with pytest.raises(Exception, match="profile_id is required"):
            ns.add_destination_profile_values(_mock_request_body(parameters={"values": "evil.com"}))

    def test_empty_values(self):
        ns = Netskope()
        with pytest.raises(Exception, match="values must contain at least one value"):
            ns.add_destination_profile_values(_mock_request_body(parameters={"profile_id": "p1", "values": ""}))

    @patch("app.netskope.requests.request")
    def test_auth_failure(self, mock_req):
        mock_req.return_value = MagicMock(status_code=403)
        ns = Netskope()
        with pytest.raises(Exception, match="Authentication failed"):
            ns.add_destination_profile_values(_mock_request_body(parameters={"profile_id": "p1", "values": "evil.com"}))

    @patch("app.netskope.requests.request")
    def test_profile_not_found(self, mock_req):
        mock_req.return_value = MagicMock(status_code=404)
        ns = Netskope()
        with pytest.raises(Exception, match="Resource not found"):
            ns.add_destination_profile_values(_mock_request_body(parameters={"profile_id": "bad-id", "values": "evil.com"}))

    @patch("app.netskope.requests.request")
    @patch("app.netskope.time.sleep")
    def test_deploy_server_error(self, mock_sleep, mock_req):
        mock_200 = MagicMock(status_code=200, json=lambda: {})
        mock_500 = MagicMock(status_code=500)
        mock_req.side_effect = [mock_200, mock_500, mock_500, mock_500]
        ns = Netskope()
        with pytest.raises(Exception, match="Netskope server error"):
            ns.add_destination_profile_values(_mock_request_body(parameters={"profile_id": "p1", "values": "evil.com"}))

    @patch("app.netskope.requests.request")
    def test_api_level_error_on_append(self, mock_req):
        mock_req.return_value = MagicMock(
            status_code=200,
            json=lambda: {"status": "error", "message": "profile locked"},
        )
        ns = Netskope()
        with pytest.raises(Exception, match="Netskope rejected append.*profile locked"):
            ns.add_destination_profile_values(_mock_request_body(parameters={"profile_id": "p1", "values": "evil.com"}))

    @patch("app.netskope.requests.request")
    def test_deploy_confirmation_missing_profile(self, mock_req):
        append_resp = MagicMock(status_code=200, json=lambda: {"status": "success"})
        deploy_resp = MagicMock(status_code=200, json=lambda: {"status": "success", "ids": ["other-id"]})
        mock_req.side_effect = [append_resp, deploy_resp]
        ns = Netskope()
        with pytest.raises(Exception, match="did not confirm profile p1"):
            ns.add_destination_profile_values(_mock_request_body(parameters={"profile_id": "p1", "values": "evil.com"}))


class TestRemoveDestinationProfileValues:

    @patch("app.netskope.requests.request")
    def test_success(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, json=lambda: {"status": "ok"})
        ns = Netskope()
        params = {"profile_id": "prof-1", "values": "evil.com,1.2.3.4"}
        result = ns.remove_destination_profile_values(_mock_request_body(parameters=params))
        assert result["status"] == "success"
        assert result["profile_id"] == "prof-1"
        assert result["values_removed"] == ["evil.com", "1.2.3.4"]
        assert "readback" in result
        assert mock_req.call_count == 2
        remove_call, deploy_call = mock_req.call_args_list
        assert "/api/v2/profiles/destinations/prof-1/values" in remove_call.kwargs["url"]
        assert remove_call.kwargs["json"] == {"operation": {"op": "remove", "values": ["evil.com", "1.2.3.4"]}}
        assert "/api/v2/profiles/destinations/deploy" in deploy_call.kwargs["url"]
        assert deploy_call.kwargs["json"] == {"ids": ["prof-1"]}

    @patch("app.netskope.requests.request")
    def test_success_list_input(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, json=lambda: {})
        ns = Netskope()
        params = {"profile_id": "prof-3", "values": ["bad.net"]}
        result = ns.remove_destination_profile_values(_mock_request_body(parameters=params))
        assert result["status"] == "success"
        assert result["values_removed"] == ["bad.net"]

    @patch("app.netskope.requests.request")
    def test_success_applied_status(self, mock_req):
        remove_resp = MagicMock(status_code=200, json=lambda: {"status": "applied"})
        deploy_resp = MagicMock(status_code=200, json=lambda: {"status": "applied", "applied": ["prof-1"]})
        mock_req.side_effect = [remove_resp, deploy_resp]
        ns = Netskope()
        result = ns.remove_destination_profile_values(_mock_request_body(parameters={"profile_id": "prof-1", "values": "evil.com"}))
        assert result["status"] == "success"

    def test_missing_profile_id(self):
        ns = Netskope()
        with pytest.raises(Exception, match="profile_id is required"):
            ns.remove_destination_profile_values(_mock_request_body(parameters={"values": "evil.com"}))

    def test_empty_values(self):
        ns = Netskope()
        with pytest.raises(Exception, match="values must contain at least one value"):
            ns.remove_destination_profile_values(_mock_request_body(parameters={"profile_id": "p1", "values": ""}))

    @patch("app.netskope.requests.request")
    def test_auth_failure(self, mock_req):
        mock_req.return_value = MagicMock(status_code=401)
        ns = Netskope()
        with pytest.raises(Exception, match="Authentication failed"):
            ns.remove_destination_profile_values(_mock_request_body(parameters={"profile_id": "p1", "values": "evil.com"}))

    @patch("app.netskope.requests.request")
    @patch("app.netskope.time.sleep")
    def test_rate_limit_retry(self, mock_sleep, mock_req):
        mock_429 = MagicMock(status_code=429, headers={"Retry-After": "2"})
        mock_200 = MagicMock(status_code=200, json=lambda: {})
        mock_req.side_effect = [mock_429, mock_200, mock_200]
        ns = Netskope()
        result = ns.remove_destination_profile_values(_mock_request_body(parameters={"profile_id": "p1", "values": "evil.com"}))
        assert result["status"] == "success"
        mock_sleep.assert_called_once_with(2)

    @patch("app.netskope.requests.request")
    def test_api_level_error_on_remove(self, mock_req):
        mock_req.return_value = MagicMock(
            status_code=200,
            json=lambda: {"status": "error", "message": "value not found"},
        )
        ns = Netskope()
        with pytest.raises(Exception, match="Netskope rejected remove.*value not found"):
            ns.remove_destination_profile_values(_mock_request_body(parameters={"profile_id": "p1", "values": "evil.com"}))

    @patch("app.netskope.requests.request")
    def test_deploy_confirmation_missing_profile(self, mock_req):
        remove_resp = MagicMock(status_code=200, json=lambda: {"status": "success"})
        deploy_resp = MagicMock(status_code=200, json=lambda: {"status": "success", "ids": ["other-id"]})
        mock_req.side_effect = [remove_resp, deploy_resp]
        ns = Netskope()
        with pytest.raises(Exception, match="did not confirm profile p1"):
            ns.remove_destination_profile_values(_mock_request_body(parameters={"profile_id": "p1", "values": "evil.com"}))


class TestDeployDestinationProfile:

    @patch("app.netskope.requests.request")
    def test_success(self, mock_req):
        mock_req.return_value = MagicMock(
            status_code=200,
            json=lambda: {"status": "deployed"},
        )
        ns = Netskope()
        params = {"profile_id": "prof-1"}
        result = ns.deploy_destination_profile(_mock_request_body(parameters=params))
        assert result["status"] == "success"
        assert result["profile_id"] == "prof-1"
        assert result["deploy_result"] == {"status": "deployed"}
        assert "/api/v2/profiles/destinations/deploy" in mock_req.call_args.kwargs["url"]
        assert mock_req.call_args.kwargs["json"] == {"ids": ["prof-1"]}

    def test_missing_profile_id(self):
        ns = Netskope()
        with pytest.raises(Exception, match="profile_id is required"):
            ns.deploy_destination_profile(_mock_request_body(parameters={}))

    @patch("app.netskope.requests.request")
    def test_auth_failure(self, mock_req):
        mock_req.return_value = MagicMock(status_code=401)
        ns = Netskope()
        with pytest.raises(Exception, match="Authentication failed"):
            ns.deploy_destination_profile(_mock_request_body(parameters={"profile_id": "p1"}))

    @patch("app.netskope.requests.request")
    @patch("app.netskope.time.sleep")
    def test_server_error(self, mock_sleep, mock_req):
        mock_req.return_value = MagicMock(status_code=503)
        ns = Netskope()
        with pytest.raises(Exception, match="Netskope server error"):
            ns.deploy_destination_profile(_mock_request_body(parameters={"profile_id": "p1"}))

    @patch("app.netskope.requests.request")
    def test_profile_not_found(self, mock_req):
        mock_req.return_value = MagicMock(status_code=404)
        ns = Netskope()
        with pytest.raises(Exception, match="Resource not found"):
            ns.deploy_destination_profile(_mock_request_body(parameters={"profile_id": "bad-id"}))

    @patch("app.netskope.requests.request")
    def test_deploy_api_level_failure(self, mock_req):
        mock_req.return_value = MagicMock(
            status_code=200,
            json=lambda: {"status": "error", "message": "no pending changes"},
        )
        ns = Netskope()
        with pytest.raises(Exception, match="Deploy failed for profile p1.*no pending changes"):
            ns.deploy_destination_profile(_mock_request_body(parameters={"profile_id": "p1"}))

    @patch("app.netskope.requests.request")
    def test_deploy_confirmation_missing_profile(self, mock_req):
        mock_req.return_value = MagicMock(
            status_code=200,
            json=lambda: {"status": "success", "ids": ["other-id"]},
        )
        ns = Netskope()
        with pytest.raises(Exception, match="did not confirm profile p1"):
            ns.deploy_destination_profile(_mock_request_body(parameters={"profile_id": "p1"}))


class TestBlockUrl:

    @patch("app.netskope.requests.request")
    def test_success(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, json=lambda: {"status": "ok"})
        ns = Netskope()
        params = {"list_id": "5", "urls": "http://evil.com,http://bad.org"}
        result = ns.block_url(_mock_request_body(parameters=params))
        assert result["status"] == "success"
        assert result["list_id"] == 5
        assert mock_req.call_count == 2
        patch_call, deploy_call = mock_req.call_args_list
        assert "/api/v2/policy/urllist/5/append" in patch_call.kwargs["url"]
        assert patch_call.kwargs["json"] == {"data": {"urls": ["http://evil.com", "http://bad.org"], "type": "exact"}}
        assert "/api/v2/policy/urllist/deploy" in deploy_call.kwargs["url"]

    @patch("app.netskope.requests.request")
    def test_success_regex_type(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, json=lambda: {})
        ns = Netskope()
        params = {"list_id": "1", "urls": ".*evil\\.com", "type": "regex"}
        result = ns.block_url(_mock_request_body(parameters=params))
        assert result["status"] == "success"
        assert mock_req.call_args_list[0].kwargs["json"]["data"]["type"] == "regex"

    @patch("app.netskope.requests.request")
    def test_success_list_input(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, json=lambda: {})
        ns = Netskope()
        params = {"list_id": "3", "urls": ["http://a.com", "http://b.com"]}
        result = ns.block_url(_mock_request_body(parameters=params))
        assert result["status"] == "success"
        assert result["items_added"] == ["http://a.com", "http://b.com"]

    def test_missing_list_id(self):
        ns = Netskope()
        with pytest.raises(Exception, match="list_id must be a positive integer"):
            ns.block_url(_mock_request_body(parameters={"urls": "http://x.com"}))

    def test_invalid_list_id_zero(self):
        ns = Netskope()
        with pytest.raises(Exception, match="list_id must be a positive integer"):
            ns.block_url(_mock_request_body(parameters={"list_id": "0", "urls": "http://x.com"}))

    def test_empty_urls(self):
        ns = Netskope()
        with pytest.raises(Exception, match="urls must contain at least one value"):
            ns.block_url(_mock_request_body(parameters={"list_id": "1", "urls": " , "}))

    def test_invalid_type(self):
        ns = Netskope()
        with pytest.raises(Exception, match="type must be one of"):
            ns.block_url(_mock_request_body(parameters={"list_id": "1", "urls": "http://x.com", "type": "wildcard"}))

    @patch("app.netskope.requests.request")
    def test_auth_failure(self, mock_req):
        mock_req.return_value = MagicMock(status_code=401)
        ns = Netskope()
        with pytest.raises(Exception, match="Authentication failed"):
            ns.block_url(_mock_request_body(parameters={"list_id": "1", "urls": "http://x.com"}))

    @patch("app.netskope.requests.request")
    @patch("app.netskope.time.sleep")
    def test_rate_limit_retry(self, mock_sleep, mock_req):
        mock_429 = MagicMock(status_code=429, headers={"Retry-After": "2"})
        mock_200 = MagicMock(status_code=200, json=lambda: {})
        mock_req.side_effect = [mock_429, mock_200, mock_200]
        ns = Netskope()
        result = ns.block_url(_mock_request_body(parameters={"list_id": "1", "urls": "http://x.com"}))
        assert result["status"] == "success"
        mock_sleep.assert_called_once_with(2)

    @patch("app.netskope.requests.request")
    @patch("app.netskope.time.sleep")
    def test_deploy_fails_on_server_error(self, mock_sleep, mock_req):
        mock_200 = MagicMock(status_code=200, json=lambda: {})
        mock_503 = MagicMock(status_code=503)
        mock_req.side_effect = [mock_200, mock_503, mock_503, mock_503]
        ns = Netskope()
        with pytest.raises(Exception, match="Netskope server error"):
            ns.block_url(_mock_request_body(parameters={"list_id": "1", "urls": "http://x.com"}))


class TestBlockDomain:

    @patch("app.netskope.requests.request")
    def test_success(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, json=lambda: {})
        ns = Netskope()
        params = {"list_id": "7", "domains": "evil.com,malicious.org"}
        result = ns.block_domain(_mock_request_body(parameters=params))
        assert result["status"] == "success"
        assert result["list_id"] == 7
        assert mock_req.call_count == 2
        assert mock_req.call_args_list[0].kwargs["json"]["data"]["urls"] == ["evil.com", "malicious.org"]

    @patch("app.netskope.requests.request")
    def test_success_list_input(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, json=lambda: {})
        ns = Netskope()
        params = {"list_id": "2", "domains": ["bad.net", "threat.io"]}
        result = ns.block_domain(_mock_request_body(parameters=params))
        assert result["status"] == "success"

    def test_missing_list_id(self):
        ns = Netskope()
        with pytest.raises(Exception, match="list_id must be a positive integer"):
            ns.block_domain(_mock_request_body(parameters={"domains": "evil.com"}))

    def test_empty_domains(self):
        ns = Netskope()
        with pytest.raises(Exception, match="domains must contain at least one value"):
            ns.block_domain(_mock_request_body(parameters={"list_id": "1", "domains": ""}))

    def test_invalid_domain(self):
        ns = Netskope()
        with pytest.raises(Exception, match="Invalid domain"):
            ns.block_domain(_mock_request_body(parameters={"list_id": "1", "domains": "not_a_domain,evil.com"}))

    def test_ip_address_rejected_as_domain(self):
        ns = Netskope()
        with pytest.raises(Exception, match="Invalid domain"):
            ns.block_domain(_mock_request_body(parameters={"list_id": "1", "domains": "1.2.3.4"}))

    def test_invalid_type(self):
        ns = Netskope()
        with pytest.raises(Exception, match="type must be one of"):
            ns.block_domain(_mock_request_body(parameters={"list_id": "1", "domains": "evil.com", "type": "glob"}))

    @patch("app.netskope.requests.request")
    def test_auth_failure(self, mock_req):
        mock_req.return_value = MagicMock(status_code=403)
        ns = Netskope()
        with pytest.raises(Exception, match="Authentication failed"):
            ns.block_domain(_mock_request_body(parameters={"list_id": "1", "domains": "evil.com"}))

    @patch("app.netskope.requests.request")
    @patch("app.netskope.time.sleep")
    def test_rate_limit_exhausted(self, mock_sleep, mock_req):
        mock_req.return_value = MagicMock(status_code=429, headers={})
        ns = Netskope()
        with pytest.raises(Exception, match="Rate limit exceeded"):
            ns.block_domain(_mock_request_body(parameters={"list_id": "1", "domains": "evil.com"}))


class TestBlockIp:

    @patch("app.netskope.requests.request")
    def test_success_ipv4(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, json=lambda: {})
        ns = Netskope()
        params = {"list_id": "3", "ips": "1.2.3.4,5.6.7.8"}
        result = ns.block_ip(_mock_request_body(parameters=params))
        assert result["status"] == "success"
        assert result["items_added"] == ["1.2.3.4", "5.6.7.8"]
        assert mock_req.call_count == 2

    @patch("app.netskope.requests.request")
    def test_success_ipv6(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, json=lambda: {})
        ns = Netskope()
        params = {"list_id": "3", "ips": "2001:db8::1"}
        result = ns.block_ip(_mock_request_body(parameters=params))
        assert result["status"] == "success"

    @patch("app.netskope.requests.request")
    def test_success_cidr(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, json=lambda: {})
        ns = Netskope()
        params = {"list_id": "3", "ips": "10.0.0.0/24,192.168.1.0/16"}
        result = ns.block_ip(_mock_request_body(parameters=params))
        assert result["status"] == "success"

    @patch("app.netskope.requests.request")
    def test_success_list_input(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, json=lambda: {})
        ns = Netskope()
        params = {"list_id": "4", "ips": ["1.1.1.1", "8.8.8.8"]}
        result = ns.block_ip(_mock_request_body(parameters=params))
        assert result["status"] == "success"

    def test_missing_list_id(self):
        ns = Netskope()
        with pytest.raises(Exception, match="list_id must be a positive integer"):
            ns.block_ip(_mock_request_body(parameters={"ips": "1.2.3.4"}))

    def test_empty_ips(self):
        ns = Netskope()
        with pytest.raises(Exception, match="ips must contain at least one value"):
            ns.block_ip(_mock_request_body(parameters={"list_id": "1", "ips": ""}))

    def test_invalid_ip(self):
        ns = Netskope()
        with pytest.raises(Exception, match="Invalid IP/CIDR"):
            ns.block_ip(_mock_request_body(parameters={"list_id": "1", "ips": "999.999.999.999,1.2.3.4"}))

    def test_domain_rejected_as_ip(self):
        ns = Netskope()
        with pytest.raises(Exception, match="Invalid IP/CIDR"):
            ns.block_ip(_mock_request_body(parameters={"list_id": "1", "ips": "evil.com"}))

    @patch("app.netskope.requests.request")
    def test_auth_failure(self, mock_req):
        mock_req.return_value = MagicMock(status_code=401)
        ns = Netskope()
        with pytest.raises(Exception, match="Authentication failed"):
            ns.block_ip(_mock_request_body(parameters={"list_id": "1", "ips": "1.2.3.4"}))

    @patch("app.netskope.requests.request")
    @patch("app.netskope.time.sleep")
    def test_rate_limit_retry(self, mock_sleep, mock_req):
        mock_429 = MagicMock(status_code=429, headers={"Retry-After": "3"})
        mock_200 = MagicMock(status_code=200, json=lambda: {})
        mock_req.side_effect = [mock_429, mock_200, mock_200]
        ns = Netskope()
        result = ns.block_ip(_mock_request_body(parameters={"list_id": "1", "ips": "1.2.3.4"}))
        assert result["status"] == "success"
        mock_sleep.assert_called_once_with(3)

    @patch("app.netskope.requests.request")
    @patch("app.netskope.time.sleep")
    def test_server_error(self, mock_sleep, mock_req):
        mock_req.return_value = MagicMock(status_code=500)
        ns = Netskope()
        with pytest.raises(Exception, match="Netskope server error"):
            ns.block_ip(_mock_request_body(parameters={"list_id": "1", "ips": "1.2.3.4"}))


class TestBlockFileHash:

    @patch("app.netskope.requests.request")
    def test_success_md5(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, json=lambda: {"status": "success"})
        ns = Netskope()
        params = {
            "file_hash_list_name": "malware-hashes",
            "hashes": "d41d8cd98f00b204e9800998ecf8427e",
            "hash_type": "md5",
        }
        result = ns.block_file_hash(_mock_request_body(parameters=params))
        assert result["status"] == "success"
        assert result["file_hash_list"] == "malware-hashes"
        assert result["hashes_added"] == ["d41d8cd98f00b204e9800998ecf8427e"]
        call = mock_req.call_args
        assert "/api/v1/updateFileHashList" in call.kwargs["url"]
        assert call.kwargs["params"]["name"] == "malware-hashes"
        assert call.kwargs["json"]["list"] == "d41d8cd98f00b204e9800998ecf8427e"
        assert call.kwargs["json"].get("hash_type") is None  # hash_type not in body

    @patch("app.netskope.requests.request")
    def test_success_sha256(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, json=lambda: {})
        ns = Netskope()
        params = {
            "file_hash_list_name": "threat-hashes",
            "hashes": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "hash_type": "sha256",
        }
        result = ns.block_file_hash(_mock_request_body(parameters=params))
        assert result["status"] == "success"

    @patch("app.netskope.requests.request")
    def test_success_no_hash_type(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, json=lambda: {})
        ns = Netskope()
        params = {
            "file_hash_list_name": "mixed-hashes",
            "hashes": "d41d8cd98f00b204e9800998ecf8427e",
        }
        result = ns.block_file_hash(_mock_request_body(parameters=params))
        assert result["status"] == "success"
        assert result["file_hash_list"] == "mixed-hashes"
        assert "hash_type" not in mock_req.call_args.kwargs["json"]

    @patch("app.netskope.requests.request")
    def test_success_list_input(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, json=lambda: {})
        ns = Netskope()
        params = {
            "file_hash_list_name": "list1",
            "hashes": ["d41d8cd98f00b204e9800998ecf8427e", "d41d8cd98f00b204e9800998ecf8427e"],
        }
        result = ns.block_file_hash(_mock_request_body(parameters=params))
        assert result["status"] == "success"

    def test_missing_file_hash_list_name(self):
        ns = Netskope()
        with pytest.raises(Exception, match="file_hash_list_name is required"):
            ns.block_file_hash(_mock_request_body(parameters={"hashes": "d41d8cd98f00b204e9800998ecf8427e"}))

    def test_empty_hashes(self):
        ns = Netskope()
        with pytest.raises(Exception, match="hashes must contain at least one value"):
            ns.block_file_hash(_mock_request_body(parameters={"file_hash_list_name": "list1", "hashes": ""}))

    def test_invalid_hash_type(self):
        ns = Netskope()
        with pytest.raises(Exception, match="hash_type must be one of"):
            ns.block_file_hash(_mock_request_body(parameters={
                "file_hash_list_name": "list1",
                "hashes": "d41d8cd98f00b204e9800998ecf8427e",
                "hash_type": "sha1",
            }))

    def test_invalid_hash_format(self):
        ns = Netskope()
        with pytest.raises(Exception, match="Invalid hash value"):
            ns.block_file_hash(_mock_request_body(parameters={
                "file_hash_list_name": "list1",
                "hashes": "not-a-hash",
            }))

    def test_md5_hash_rejected_when_sha256_type(self):
        ns = Netskope()
        with pytest.raises(Exception, match="Invalid hash value"):
            ns.block_file_hash(_mock_request_body(parameters={
                "file_hash_list_name": "list1",
                "hashes": "d41d8cd98f00b204e9800998ecf8427e",
                "hash_type": "sha256",
            }))

    def test_sha256_hash_rejected_when_md5_type(self):
        ns = Netskope()
        with pytest.raises(Exception, match="Invalid hash value"):
            ns.block_file_hash(_mock_request_body(parameters={
                "file_hash_list_name": "list1",
                "hashes": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "hash_type": "md5",
            }))

    @patch("app.netskope.requests.request")
    def test_auth_failure(self, mock_req):
        mock_req.return_value = MagicMock(status_code=401)
        ns = Netskope()
        with pytest.raises(Exception, match="Authentication failed"):
            ns.block_file_hash(_mock_request_body(parameters={
                "file_hash_list_name": "list1",
                "hashes": "d41d8cd98f00b204e9800998ecf8427e",
            }))

    @patch("app.netskope.requests.request")
    @patch("app.netskope.time.sleep")
    def test_rate_limit_retry(self, mock_sleep, mock_req):
        mock_429 = MagicMock(status_code=429, headers={"Retry-After": "1"})
        mock_200 = MagicMock(status_code=200, json=lambda: {})
        mock_req.side_effect = [mock_429, mock_200]
        ns = Netskope()
        result = ns.block_file_hash(_mock_request_body(parameters={
            "file_hash_list_name": "list1",
            "hashes": "d41d8cd98f00b204e9800998ecf8427e",
        }))
        assert result["status"] == "success"
        mock_sleep.assert_called_once_with(1)

    @patch("app.netskope.requests.request")
    @patch("app.netskope.time.sleep")
    def test_server_error(self, mock_sleep, mock_req):
        mock_req.return_value = MagicMock(status_code=500)
        ns = Netskope()
        with pytest.raises(Exception, match="Netskope server error"):
            ns.block_file_hash(_mock_request_body(parameters={
                "file_hash_list_name": "list1",
                "hashes": "d41d8cd98f00b204e9800998ecf8427e",
            }))
