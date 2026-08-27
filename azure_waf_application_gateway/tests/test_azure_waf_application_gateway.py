import pytest
import time
from unittest.mock import patch, MagicMock
import app.azure_waf_application_gateway as _mod
from app.azure_waf_application_gateway import (
    AzureWaf, _validate_ip, _validate_required, _find_soar_rule,
    _find_ip_match_condition, _build_soar_rule, _is_soar_ip_block_rule,
    _next_available_priority, _TokenExpiredError, DEFAULT_RULE_NAME, DEFAULT_URL_RULE_NAME,
    MAX_RETRIES, _normalize_url, _find_url_match_condition, _build_soar_url_rule,
)
from app.model.request_body import RequestBody

CONN = {
    "tenant_id": "tenant-123",
    "client_id": "client-abc",
    "client_secret": "secret-xyz",
    "subscription_id": "sub-001",
    "resource_group": "rg-test",
}
CONN_NO_RG = {**CONN, "resource_group": ""}

TOKEN_RESP = {"access_token": "test-token", "expires_in": 3600}


def _fresh_policy():
    return {
        "name": "Policy1",
        "location": "eastus",
        "properties": {
            "customRules": [],
            "policySettings": {"state": "Enabled"},
        },
    }


def _policy_with_rule(ips=None, state="Enabled", action="Block"):
    p = _fresh_policy()
    if ips is not None:
        rule = _build_soar_rule(DEFAULT_RULE_NAME, list(ips))
        rule["state"] = state
        rule["action"] = action
        p["properties"]["customRules"] = [rule]
    return p


def _make_resp(status_code, json_data=None):
    m = MagicMock()
    m.status_code = status_code
    m.content = b"x"
    m.json.return_value = json_data or {}
    m.headers = {}
    m.text = str(json_data)
    return m


def _make_request(conn=None, params=None):
    rb = RequestBody()
    rb.connectionParameters = conn or CONN
    rb.parameters = params or {}
    return rb


# ── Helpers ───────────────────────────────────────────────────────────────────

class TestValidateIp:
    def test_valid_ipv4(self):
        assert _validate_ip("192.168.1.1") == "192.168.1.1"

    def test_valid_cidr(self):
        assert _validate_ip("10.0.0.0/24") == "10.0.0.0/24"

    def test_invalid_octet(self):
        with pytest.raises(Exception, match="Invalid IPv4"):
            _validate_ip("999.999.999.999")

    def test_invalid_cidr_prefix(self):
        with pytest.raises(Exception, match="Invalid IPv4"):
            _validate_ip("10.0.0.0/99")

    def test_ipv6_raises(self):
        with pytest.raises(Exception, match="Invalid IPv4"):
            _validate_ip("::1")

    def test_garbage_raises(self):
        with pytest.raises(Exception, match="Invalid IPv4"):
            _validate_ip("not-an-ip")


class TestValidateRequired:
    def test_valid(self):
        assert _validate_required("value", "field") == "value"

    def test_empty_raises(self):
        with pytest.raises(Exception, match="field is required"):
            _validate_required("", "field")

    def test_none_raises(self):
        with pytest.raises(Exception, match="field is required"):
            _validate_required(None, "field")


class TestFindSoarRule:
    def test_found(self):
        rules = [{"name": "Other"}, {"name": DEFAULT_RULE_NAME}]
        assert _find_soar_rule(rules, DEFAULT_RULE_NAME)["name"] == DEFAULT_RULE_NAME

    def test_not_found(self):
        assert _find_soar_rule([{"name": "Other"}], DEFAULT_RULE_NAME) is None


class TestFindIpMatchCondition:
    def test_found(self):
        rule = _build_soar_rule(DEFAULT_RULE_NAME, ["10.0.0.1"])
        assert _find_ip_match_condition(rule)["operator"] == "IPMatch"

    def test_not_found(self):
        rule = {"matchConditions": [{"matchVariables": [{"variableName": "RequestUri"}], "operator": "Contains"}]}
        assert _find_ip_match_condition(rule) is None


class TestIsSoarIpBlockRule:
    def test_valid_rule(self):
        rule = _build_soar_rule(DEFAULT_RULE_NAME, ["1.2.3.4"])
        assert _is_soar_ip_block_rule(rule) is True

    def test_wrong_action(self):
        rule = _build_soar_rule(DEFAULT_RULE_NAME, ["1.2.3.4"])
        rule["action"] = "Allow"
        assert _is_soar_ip_block_rule(rule) is False

    def test_wrong_rule_type(self):
        rule = _build_soar_rule(DEFAULT_RULE_NAME, ["1.2.3.4"])
        rule["ruleType"] = "RateLimitRule"
        assert _is_soar_ip_block_rule(rule) is False

    def test_no_ip_match_condition(self):
        rule = _build_soar_rule(DEFAULT_RULE_NAME, ["1.2.3.4"])
        rule["matchConditions"] = []
        assert _is_soar_ip_block_rule(rule) is False


class TestNextAvailablePriority:
    def test_empty_rules(self):
        assert _next_available_priority([]) == 1

    def test_skips_used(self):
        rules = [{"priority": 1}, {"priority": 2}]
        assert _next_available_priority(rules) == 3

    def test_gap_in_middle(self):
        rules = [{"priority": 1}, {"priority": 3}]
        assert _next_available_priority(rules) == 2


# ── Token ─────────────────────────────────────────────────────────────────────

class TestGetToken:
    def setup_method(self):
        _mod._token_cache.clear()

    def test_success(self):
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)):
            assert _mod._get_token("t", "c", "s", 30, True, None) == "test-token"

    def test_cached(self):
        _mod._token_cache["t:c"] = {"token": "cached", "expires_at": time.time() + 3600}
        with patch("app.azure_waf_application_gateway.requests.post") as mock_post:
            token = _mod._get_token("t", "c", "s", 30, True, None)
        mock_post.assert_not_called()
        assert token == "cached"

    def test_expired_cache_refreshes(self):
        _mod._token_cache["t:c"] = {"token": "old", "expires_at": time.time() - 1}
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)):
            assert _mod._get_token("t", "c", "s", 30, True, None) == "test-token"

    def test_401_raises(self):
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(401)):
            with pytest.raises(Exception, match="Authentication failed"):
                _mod._get_token("t", "c", "s", 30, True, None)

    def test_missing_token_raises(self):
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, {})):
            with pytest.raises(Exception, match="missing access_token"):
                _mod._get_token("t", "c", "s", 30, True, None)

    def test_connection_error(self):
        import requests as req_lib
        with patch("app.azure_waf_application_gateway.requests.post", side_effect=req_lib.exceptions.ConnectionError):
            with pytest.raises(Exception, match="Unable to connect"):
                _mod._get_token("t", "c", "s", 30, True, None)

    def test_cache_shared_across_instances(self):
        _mod._token_cache["t:c"] = {"token": "token1", "expires_at": time.time() + 3600}
        with patch("app.azure_waf_application_gateway.requests.post") as mock_post:
            token = _mod._get_token("t", "c", "s", 30, True, None)
        mock_post.assert_not_called()
        assert token == "token1"


# ── _request ──────────────────────────────────────────────────────────────────

class TestRequest:
    def test_200(self):
        with patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, {"value": []})):
            assert _mod._request("GET", "http://x", "tok", 30, True, None) == {"value": []}

    def test_404_raises(self):
        with patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(404)):
            with pytest.raises(Exception, match="Resource not found"):
                _mod._request("GET", "http://x", "tok", 30, True, None)

    def test_403_raises(self):
        with patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(403)):
            with pytest.raises(Exception, match="Authorization failed"):
                _mod._request("GET", "http://x", "tok", 30, True, None)

    def test_401_raises_token_expired(self):
        with patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(401)):
            with pytest.raises(_TokenExpiredError):
                _mod._request("GET", "http://x", "tok", 30, True, None)

    def test_429_retries(self):
        r = _make_resp(429)
        r.headers = {"Retry-After": "1"}
        with patch("app.azure_waf_application_gateway.requests.request", return_value=r), \
             patch("app.azure_waf_application_gateway.time.sleep") as mock_sleep:
            with pytest.raises(Exception, match="rate limit"):
                _mod._request("GET", "http://x", "tok", 30, True, None)
        assert mock_sleep.call_count == MAX_RETRIES - 1

    def test_500_retries(self):
        with patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(500)), \
             patch("app.azure_waf_application_gateway.time.sleep") as mock_sleep:
            with pytest.raises(Exception, match="server error"):
                _mod._request("GET", "http://x", "tok", 30, True, None)
        assert mock_sleep.call_count == MAX_RETRIES - 1


# ── _request_with_refresh ─────────────────────────────────────────────────────

class TestRequestWithRefresh:
    def setup_method(self):
        _mod._token_cache.clear()

    def test_refreshes_on_401(self):
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)) as mock_post, \
             patch("app.azure_waf_application_gateway.requests.request", side_effect=[_make_resp(401), _make_resp(200, {"ok": True})]):
            result = _mod._request_with_refresh("GET", "http://x", "t", "c", "s", 30, True, None)
        assert result == {"ok": True}
        assert mock_post.call_count == 2

    def test_raises_after_double_401(self):
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(401)):
            with pytest.raises(Exception, match="Authorization failed after token refresh"):
                _mod._request_with_refresh("GET", "http://x", "t", "c", "s", 30, True, None)


# ── test_connection ───────────────────────────────────────────────────────────

class TestTestConnection:
    def setup_method(self):
        _mod._token_cache.clear()

    def test_success_with_rg(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, {"value": []})) as mock_req:
            result = connector.test_connection(CONN)
        assert result["status"] == "success"
        assert "resourceGroups" in mock_req.call_args[0][1]

    def test_success_without_rg(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, {"value": []})) as mock_req:
            result = connector.test_connection(CONN_NO_RG)
        assert result["status"] == "success"
        assert "resourceGroups" not in mock_req.call_args[0][1]

    def test_auth_failure(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(401)):
            with pytest.raises(Exception, match="Authentication failed"):
                connector.test_connection(CONN)


# ── list_waf_policies ─────────────────────────────────────────────────────────

class TestListWafPolicies:
    def setup_method(self):
        _mod._token_cache.clear()

    def test_success(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, {"value": [{"name": "P1"}]})):
            result = connector.list_waf_policies(_make_request())
        assert result["total_count"] == 1

    def test_pagination(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", side_effect=[
                 _make_resp(200, {"value": [{"name": "P1"}], "nextLink": "http://next"}),
                 _make_resp(200, {"value": [{"name": "P2"}]}),
             ]):
            result = connector.list_waf_policies(_make_request())
        assert result["total_count"] == 2

    def test_subscription_scope_when_no_rg(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, {"value": []})) as mock_req:
            connector.list_waf_policies(_make_request(conn=CONN_NO_RG))
        assert "resourceGroups" not in mock_req.call_args[0][1]


# ── get_waf_policy / get_custom_rules ─────────────────────────────────────────

class TestGetWafPolicy:
    def setup_method(self):
        _mod._token_cache.clear()

    def test_success(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, _fresh_policy())):
            result = connector.get_waf_policy(_make_request(params={"policy_name": "Policy1"}))
        assert result["policy"]["name"] == "Policy1"

    def test_missing_policy_name(self):
        connector = AzureWaf()
        with pytest.raises(Exception, match="policy_name is required"):
            connector.get_waf_policy(_make_request())


class TestGetCustomRules:
    def setup_method(self):
        _mod._token_cache.clear()

    def test_returns_rules(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, _policy_with_rule(["1.2.3.4"]))):
            result = connector.get_custom_rules(_make_request(params={"policy_name": "Policy1"}))
        assert result["total_count"] == 1

    def test_empty(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, _fresh_policy())):
            result = connector.get_custom_rules(_make_request(params={"policy_name": "Policy1"}))
        assert result["custom_rules"] == []


# ── add_ip_to_block_list ──────────────────────────────────────────────────────

class TestAddIpToBlockList:
    def setup_method(self):
        _mod._token_cache.clear()

    def test_creates_new_rule(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", side_effect=[
                 _make_resp(200, _fresh_policy()),
                 _make_resp(200, _policy_with_rule(["10.0.0.1"])),
             ]):
            result = connector.add_ip_to_block_list(
                _make_request(params={"policy_name": "Policy1", "ip_address": "10.0.0.1"})
            )
        assert result["status"] == "success"

    def test_new_rule_uses_available_priority(self):
        connector = AzureWaf()
        policy = _fresh_policy()
        policy["properties"]["customRules"] = [{"name": "Existing", "priority": 1}]
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", side_effect=[_make_resp(200, policy), _make_resp(200, {})]) as mock_req:
            connector.add_ip_to_block_list(
                _make_request(params={"policy_name": "Policy1", "ip_address": "10.0.0.1"})
            )
        put_body = mock_req.call_args[1]["json"]
        soar = next(r for r in put_body["properties"]["customRules"] if r["name"] == DEFAULT_RULE_NAME)
        assert soar["priority"] != 1

    def test_adds_to_existing_rule(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", side_effect=[
                 _make_resp(200, _policy_with_rule(["10.0.0.1"])),
                 _make_resp(200, {}),
             ]):
            result = connector.add_ip_to_block_list(
                _make_request(params={"policy_name": "Policy1", "ip_address": "10.0.0.2"})
            )
        assert result["status"] == "success"

    def test_deduplicates_ip(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", side_effect=[
                 _make_resp(200, _policy_with_rule(["10.0.0.1"])),
                 _make_resp(200, {}),
             ]) as mock_req:
            connector.add_ip_to_block_list(
                _make_request(params={"policy_name": "Policy1", "ip_address": "10.0.0.1"})
            )
        put_body = mock_req.call_args[1]["json"]
        ips = put_body["properties"]["customRules"][0]["matchConditions"][0]["matchValues"]
        assert ips.count("10.0.0.1") == 1

    def test_re_enables_disabled_rule(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", side_effect=[
                 _make_resp(200, _policy_with_rule([], state="Disabled")),
                 _make_resp(200, {}),
             ]) as mock_req:
            connector.add_ip_to_block_list(
                _make_request(params={"policy_name": "Policy1", "ip_address": "10.0.0.1"})
            )
        put_body = mock_req.call_args[1]["json"]
        assert put_body["properties"]["customRules"][0]["state"] == "Enabled"

    def test_incompatible_rule_raises(self):
        connector = AzureWaf()
        policy = _fresh_policy()
        policy["properties"]["customRules"] = [{
            "name": DEFAULT_RULE_NAME, "priority": 5,
            "ruleType": "MatchRule", "action": "Allow",
            "state": "Enabled", "matchConditions": [],
        }]
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, policy)):
            with pytest.raises(Exception, match="not a compatible IP block rule"):
                connector.add_ip_to_block_list(
                    _make_request(params={"policy_name": "Policy1", "ip_address": "10.0.0.1"})
                )

    def test_invalid_ip_raises(self):
        connector = AzureWaf()
        with pytest.raises(Exception, match="Invalid IPv4"):
            connector.add_ip_to_block_list(
                _make_request(params={"policy_name": "P1", "ip_address": "256.0.0.1"})
            )


# ── remove_ip_from_block_list ─────────────────────────────────────────────────

class TestRemoveIpFromBlockList:
    def setup_method(self):
        _mod._token_cache.clear()

    def test_removes_ip(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", side_effect=[
                 _make_resp(200, _policy_with_rule(["10.0.0.1", "10.0.0.2"])),
                 _make_resp(200, {}),
             ]):
            result = connector.remove_ip_from_block_list(
                _make_request(params={"policy_name": "Policy1", "ip_address": "10.0.0.1"})
            )
        assert result["removed_ip"] == "10.0.0.1"

    def test_last_ip_disables_rule(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", side_effect=[
                 _make_resp(200, _policy_with_rule(["10.0.0.1"])),
                 _make_resp(200, {}),
             ]):
            result = connector.remove_ip_from_block_list(
                _make_request(params={"policy_name": "Policy1", "ip_address": "10.0.0.1"})
            )
        assert result["rule"]["state"] == "Disabled"

    def test_rule_not_found_raises(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, _fresh_policy())):
            with pytest.raises(Exception, match="not found in policy"):
                connector.remove_ip_from_block_list(
                    _make_request(params={"policy_name": "Policy1", "ip_address": "10.0.0.1"})
                )

    def test_ip_not_in_rule_raises(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, _policy_with_rule(["10.0.0.1"]))):
            with pytest.raises(Exception, match="not found in rule"):
                connector.remove_ip_from_block_list(
                    _make_request(params={"policy_name": "Policy1", "ip_address": "9.9.9.9"})
                )


# ── check_ip_in_block_list ────────────────────────────────────────────────────

class TestCheckIpInBlockList:
    def setup_method(self):
        _mod._token_cache.clear()

    def test_ip_blocked(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, _policy_with_rule(["10.0.0.1"]))):
            result = connector.check_ip_in_block_list(
                _make_request(params={"policy_name": "Policy1", "ip_address": "10.0.0.1"})
            )
        assert result["blocked"] is True

    def test_ip_not_in_list(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, _policy_with_rule(["10.0.0.1"]))):
            result = connector.check_ip_in_block_list(
                _make_request(params={"policy_name": "Policy1", "ip_address": "9.9.9.9"})
            )
        assert result["blocked"] is False

    def test_disabled_rule_returns_not_blocked(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, _policy_with_rule(["10.0.0.1"], state="Disabled"))):
            result = connector.check_ip_in_block_list(
                _make_request(params={"policy_name": "Policy1", "ip_address": "10.0.0.1"})
            )
        assert result["blocked"] is False

    def test_allow_action_returns_not_blocked(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, _policy_with_rule(["10.0.0.1"], action="Allow"))):
            result = connector.check_ip_in_block_list(
                _make_request(params={"policy_name": "Policy1", "ip_address": "10.0.0.1"})
            )
        assert result["blocked"] is False

    def test_no_rule_returns_not_blocked(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, _fresh_policy())):
            result = connector.check_ip_in_block_list(
                _make_request(params={"policy_name": "Policy1", "ip_address": "10.0.0.1"})
            )
        assert result["blocked"] is False


# ── get_blocked_ips ───────────────────────────────────────────────────────────

class TestGetBlockedIps:
    def setup_method(self):
        _mod._token_cache.clear()

    def test_returns_ips(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, _policy_with_rule(["1.1.1.1", "2.2.2.2"]))):
            result = connector.get_blocked_ips(_make_request(params={"policy_name": "Policy1"}))
        assert result["total_count"] == 2
        assert "1.1.1.1" in result["blocked_ips"]

    def test_disabled_rule_returns_empty(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, _policy_with_rule(["1.1.1.1"], state="Disabled"))):
            result = connector.get_blocked_ips(_make_request(params={"policy_name": "Policy1"}))
        assert result["blocked_ips"] == []

    def test_no_rule_returns_empty(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, _fresh_policy())):
            result = connector.get_blocked_ips(_make_request(params={"policy_name": "Policy1"}))
        assert result["blocked_ips"] == []


# ── enable / disable custom rule ──────────────────────────────────────────────

class TestEnableCustomRule:
    def setup_method(self):
        _mod._token_cache.clear()

    def test_enables_rule(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", side_effect=[
                 _make_resp(200, _policy_with_rule(["1.1.1.1"], state="Disabled")),
                 _make_resp(200, {}),
             ]):
            result = connector.enable_custom_rule(
                _make_request(params={"policy_name": "Policy1", "rule_name": DEFAULT_RULE_NAME})
            )
        assert result["rule"]["state"] == "Enabled"

    def test_rule_not_found_raises(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, _fresh_policy())):
            with pytest.raises(Exception, match="not found in policy"):
                connector.enable_custom_rule(
                    _make_request(params={"policy_name": "Policy1", "rule_name": "Ghost"})
                )


class TestDisableCustomRule:
    def setup_method(self):
        _mod._token_cache.clear()

    def test_disables_rule(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", side_effect=[
                 _make_resp(200, _policy_with_rule(["1.1.1.1"])),
                 _make_resp(200, {}),
             ]):
            result = connector.disable_custom_rule(
                _make_request(params={"policy_name": "Policy1", "rule_name": DEFAULT_RULE_NAME})
            )
        assert result["rule"]["state"] == "Disabled"

    def test_rule_not_found_raises(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, _fresh_policy())):
            with pytest.raises(Exception, match="not found in policy"):
                connector.disable_custom_rule(
                    _make_request(params={"policy_name": "Policy1", "rule_name": "Ghost"})
                )


# ── _normalize_url ────────────────────────────────────────────────────────────

class TestNormalizeUrl:
    def test_full_url_extracts_path(self):
        assert _normalize_url("https://example.com/admin/login") == "/admin/login"

    def test_path_only_unchanged(self):
        assert _normalize_url("/admin/login") == "/admin/login"

    def test_path_without_leading_slash(self):
        assert _normalize_url("admin/login") == "/admin/login"

    def test_full_url_with_query(self):
        assert _normalize_url("https://example.com/search?q=test") == "/search?q=test"

    def test_strips_whitespace(self):
        assert _normalize_url("  /admin/login  ") == "/admin/login"

    def test_empty_raises(self):
        with pytest.raises(Exception, match="url is required"):
            _normalize_url("")


# ── _find_url_match_condition / _build_soar_url_rule ─────────────────────────

class TestUrlRuleHelpers:
    def test_find_url_match_condition_found(self):
        rule = _build_soar_url_rule(DEFAULT_URL_RULE_NAME, ["/admin"])
        assert _find_url_match_condition(rule)["operator"] == "BeginsWith"

    def test_find_url_match_condition_not_found(self):
        rule = {"matchConditions": [{"matchVariables": [{"variableName": "RemoteAddr"}], "operator": "IPMatch"}]}
        assert _find_url_match_condition(rule) is None

    def test_build_soar_url_rule_structure(self):
        rule = _build_soar_url_rule(DEFAULT_URL_RULE_NAME, ["/admin"], priority=5)
        assert rule["name"] == DEFAULT_URL_RULE_NAME
        assert rule["action"] == "Block"
        assert rule["priority"] == 5
        cond = rule["matchConditions"][0]
        assert cond["matchVariables"][0]["variableName"] == "RequestUri"
        assert cond["operator"] == "BeginsWith"
        assert "/admin" in cond["matchValues"]


# ── block_url ─────────────────────────────────────────────────────────────────

def _policy_with_url_rule(paths=None, state="Enabled", action="Block"):
    p = _fresh_policy()
    if paths is not None:
        rule = _build_soar_url_rule(DEFAULT_URL_RULE_NAME, list(paths))
        rule["state"] = state
        rule["action"] = action
        p["properties"]["customRules"] = [rule]
    return p


class TestBlockUrl:
    def setup_method(self):
        _mod._token_cache.clear()

    def test_creates_new_rule(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", side_effect=[
                 _make_resp(200, _fresh_policy()),
                 _make_resp(200, {}),
             ]):
            result = connector.block_url(
                _make_request(params={"policy_name": "Policy1", "url": "https://example.com/admin/login"})
            )
        assert result["status"] == "success"
        assert result["blocked_url"] == "/admin/login"

    def test_normalizes_full_url(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", side_effect=[
                 _make_resp(200, _fresh_policy()),
                 _make_resp(200, {}),
             ]) as mock_req:
            connector.block_url(
                _make_request(params={"policy_name": "Policy1", "url": "https://example.com/admin"})
            )
        put_body = mock_req.call_args[1]["json"]
        values = put_body["properties"]["customRules"][0]["matchConditions"][0]["matchValues"]
        assert "/admin" in values

    def test_adds_to_existing_rule(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", side_effect=[
                 _make_resp(200, _policy_with_url_rule(["/admin"])),
                 _make_resp(200, {}),
             ]):
            result = connector.block_url(
                _make_request(params={"policy_name": "Policy1", "url": "/login"})
            )
        assert result["status"] == "success"

    def test_deduplicates_url(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", side_effect=[
                 _make_resp(200, _policy_with_url_rule(["/admin"])),
                 _make_resp(200, {}),
             ]) as mock_req:
            connector.block_url(
                _make_request(params={"policy_name": "Policy1", "url": "/admin"})
            )
        put_body = mock_req.call_args[1]["json"]
        values = put_body["properties"]["customRules"][0]["matchConditions"][0]["matchValues"]
        assert values.count("/admin") == 1

    def test_re_enables_disabled_rule(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", side_effect=[
                 _make_resp(200, _policy_with_url_rule([], state="Disabled")),
                 _make_resp(200, {}),
             ]) as mock_req:
            connector.block_url(
                _make_request(params={"policy_name": "Policy1", "url": "/admin"})
            )
        put_body = mock_req.call_args[1]["json"]
        assert put_body["properties"]["customRules"][0]["state"] == "Enabled"

    def test_incompatible_rule_raises(self):
        connector = AzureWaf()
        policy = _fresh_policy()
        policy["properties"]["customRules"] = [{
            "name": DEFAULT_URL_RULE_NAME, "priority": 5,
            "ruleType": "MatchRule", "action": "Allow",
            "state": "Enabled", "matchConditions": [],
        }]
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, policy)):
            with pytest.raises(Exception, match="not a compatible URL block rule"):
                connector.block_url(
                    _make_request(params={"policy_name": "Policy1", "url": "/admin"})
                )

    def test_missing_url_raises(self):
        connector = AzureWaf()
        with pytest.raises(Exception, match="url is required"):
            connector.block_url(_make_request(params={"policy_name": "Policy1"}))


# ── unblock_url ───────────────────────────────────────────────────────────────

class TestUnblockUrl:
    def setup_method(self):
        _mod._token_cache.clear()

    def test_removes_url(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", side_effect=[
                 _make_resp(200, _policy_with_url_rule(["/admin", "/login"])),
                 _make_resp(200, {}),
             ]):
            result = connector.unblock_url(
                _make_request(params={"policy_name": "Policy1", "url": "/admin"})
            )
        assert result["unblocked_url"] == "/admin"

    def test_last_url_disables_rule(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", side_effect=[
                 _make_resp(200, _policy_with_url_rule(["/admin"])),
                 _make_resp(200, {}),
             ]):
            result = connector.unblock_url(
                _make_request(params={"policy_name": "Policy1", "url": "/admin"})
            )
        assert result["rule"]["state"] == "Disabled"

    def test_rule_not_found_raises(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, _fresh_policy())):
            with pytest.raises(Exception, match="not found in policy"):
                connector.unblock_url(
                    _make_request(params={"policy_name": "Policy1", "url": "/admin"})
                )

    def test_url_not_in_rule_raises(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", return_value=_make_resp(200, _policy_with_url_rule(["/admin"]))):
            with pytest.raises(Exception, match="not found in rule"):
                connector.unblock_url(
                    _make_request(params={"policy_name": "Policy1", "url": "/other"})
                )

    def test_accepts_full_url_input(self):
        connector = AzureWaf()
        with patch("app.azure_waf_application_gateway.requests.post", return_value=_make_resp(200, TOKEN_RESP)), \
             patch("app.azure_waf_application_gateway.requests.request", side_effect=[
                 _make_resp(200, _policy_with_url_rule(["/admin"])),
                 _make_resp(200, {}),
             ]):
            result = connector.unblock_url(
                _make_request(params={"policy_name": "Policy1", "url": "https://example.com/admin"})
            )
        assert result["unblocked_url"] == "/admin"

