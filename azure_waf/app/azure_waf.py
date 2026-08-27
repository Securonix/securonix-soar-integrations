from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import ipaddress
import logging
import time
from typing import Optional
import requests

MANAGEMENT_BASE = "https://management.azure.com"
TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
TOKEN_SCOPE = "https://management.azure.com/.default"
API_VERSION = "2025-05-01"
WAF_POLICY_PATH = (
    "/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
    "/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies"
)
DEFAULT_RULE_NAME = "SecuronixSOAR-IP-Block"
DEFAULT_URL_RULE_NAME = "SecuronixSOAR-URL-Block"
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3
BACKOFF_FACTOR = 2

_token_cache: dict = {}
_logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Validation helpers
# ------------------------------------------------------------------

def _validate_ip(value: str) -> str:
    value = value.strip()
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            if network.version != 4:
                raise ValueError()
        else:
            address = ipaddress.ip_address(value)
            if address.version != 4:
                raise ValueError()
    except ValueError:
        raise Exception(f"Invalid IPv4/CIDR value: '{value}'")
    return value


def _validate_required(value, field_name: str) -> str:
    if not value or (isinstance(value, str) and not value.strip()):
        raise Exception(f"{field_name} is required and cannot be empty.")
    return value.strip() if isinstance(value, str) else value


def _get_connection(connection_params: dict):
    tenant_id = _validate_required(connection_params.get("tenant_id"), "tenant_id")
    client_id = _validate_required(connection_params.get("client_id"), "client_id")
    client_secret = _validate_required(connection_params.get("client_secret"), "client_secret")
    subscription_id = _validate_required(connection_params.get("subscription_id"), "subscription_id")

    resource_group = (connection_params.get("resource_group") or "").strip() or None
    base_url = (connection_params.get("base_url") or MANAGEMENT_BASE).rstrip("/")

    timeout = DEFAULT_TIMEOUT
    try:
        t = connection_params.get("timeout")
        if t:
            timeout = max(1, int(t))
    except (ValueError, TypeError):
        pass

    verify_ssl = connection_params.get("verify_ssl", True)
    if isinstance(verify_ssl, str):
        verify_ssl = verify_ssl.lower() in ("true", "1", "yes")

    proxy = connection_params.get("proxy")
    proxies = {"https": proxy, "http": proxy} if proxy else None

    return tenant_id, client_id, client_secret, subscription_id, resource_group, base_url, timeout, verify_ssl, proxies


# ------------------------------------------------------------------
# URL builders
# ------------------------------------------------------------------

def _policy_url(base_url: str, subscription_id: str, resource_group: str, policy_name: str = None) -> str:
    path = WAF_POLICY_PATH.format(
        subscription_id=subscription_id,
        resource_group=resource_group,
    )
    url = f"{base_url}{path}"
    if policy_name:
        url = f"{url}/{policy_name}"
    return f"{url}?api-version={API_VERSION}"


def _subscription_list_url(base_url: str, subscription_id: str) -> str:
    return (
        f"{base_url}/subscriptions/{subscription_id}/providers"
        f"/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies"
        f"?api-version={API_VERSION}"
    )


# ------------------------------------------------------------------
# Policy rule helpers
# ------------------------------------------------------------------

def _find_soar_rule(custom_rules: list, rule_name: str) -> Optional[dict]:
    for rule in custom_rules:
        if rule.get("name") == rule_name:
            return rule
    return None


def _find_ip_match_condition(rule: dict) -> Optional[dict]:
    for cond in rule.get("matchConditions", []):
        variables = cond.get("matchVariables", [])
        if (
            any(v.get("variableName") == "RemoteAddr" for v in variables)
            and cond.get("operator") == "IPMatch"
        ):
            return cond
    return None


def _is_soar_ip_block_rule(rule: dict) -> bool:
    return (
        rule.get("ruleType") == "MatchRule"
        and rule.get("action") == "Block"
        and _find_ip_match_condition(rule) is not None
    )


def _next_available_priority(custom_rules: list) -> int:
    used = {rule.get("priority") for rule in custom_rules if rule.get("priority") is not None}
    return next(p for p in range(1, 1001) if p not in used)


def _build_soar_rule(rule_name: str, match_values: list, priority: int = 10) -> dict:
    return {
        "name": rule_name,
        "priority": priority,
        "ruleType": "MatchRule",
        "action": "Block",
        "state": "Enabled",
        "matchConditions": [
            {
                "matchVariables": [{"variableName": "RemoteAddr"}],
                "operator": "IPMatch",
                "negationCondition": False,
                "matchValues": match_values,
                "transforms": [],
            }
        ],
    }


def _normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise Exception("url is required and cannot be empty.")
    # Strip scheme+host if present, keep path+query
    if "://" in value:
        from urllib.parse import urlparse
        parsed = urlparse(value)
        path = parsed.path or "/"
        value = path + ("?" + parsed.query if parsed.query else "")
    if not value.startswith("/"):
        value = "/" + value
    return value


def _find_url_match_condition(rule: dict) -> Optional[dict]:
    for cond in rule.get("matchConditions", []):
        variables = cond.get("matchVariables", [])
        if (
            any(v.get("variableName") == "RequestUri" for v in variables)
            and cond.get("operator") == "BeginsWith"
        ):
            return cond
    return None


def _is_soar_url_block_rule(rule: dict) -> bool:
    return (
        rule.get("ruleType") == "MatchRule"
        and rule.get("action") == "Block"
        and _find_url_match_condition(rule) is not None
    )


def _build_soar_url_rule(rule_name: str, match_values: list, priority: int = 10) -> dict:
    return {
        "name": rule_name,
        "priority": priority,
        "ruleType": "MatchRule",
        "action": "Block",
        "state": "Enabled",
        "matchConditions": [
            {
                "matchVariables": [{"variableName": "RequestUri"}],
                "operator": "BeginsWith",
                "negationCondition": False,
                "matchValues": match_values,
                "transforms": [],
            }
        ],
    }


# ------------------------------------------------------------------
# Auth helpers
# ------------------------------------------------------------------

def _get_token(tenant_id: str, client_id: str, client_secret: str,
               timeout: int, verify_ssl: bool, proxies) -> str:
    cache_key = f"{tenant_id}:{client_id}"
    cached = _token_cache.get(cache_key)
    if cached and cached["expires_at"] > time.time() + 60:
        return cached["token"]

    try:
        resp = requests.post(
            TOKEN_URL_TEMPLATE.format(tenant_id=tenant_id),
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": TOKEN_SCOPE,
            },
            timeout=timeout,
            verify=verify_ssl,
            proxies=proxies,
        )
    except requests.exceptions.ConnectionError:
        raise Exception("Unable to connect to Azure AD token endpoint.")
    except requests.exceptions.Timeout:
        raise Exception("Connection to Azure AD token endpoint timed out.")

    if resp.status_code in (401, 403):
        raise Exception("Authentication failed. Verify tenant_id, client_id, and client_secret.")
    if resp.status_code != 200:
        raise Exception(f"Token request failed (HTTP {resp.status_code}).")

    data = resp.json()
    token = data.get("access_token")
    if not token:
        raise Exception("Token response missing access_token.")

    expires_in = int(data.get("expires_in", 3600))
    _token_cache[cache_key] = {"token": token, "expires_at": time.time() + expires_in}
    return token


def _invalidate_token(tenant_id: str, client_id: str) -> None:
    _token_cache.pop(f"{tenant_id}:{client_id}", None)


# ------------------------------------------------------------------
# HTTP helpers
# ------------------------------------------------------------------

class _TokenExpiredError(Exception):
    pass


def _request(method: str, url: str, token: str, timeout: int,
             verify_ssl: bool, proxies, **kwargs) -> dict:
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    last_exc = None

    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.request(
                method, url, headers=headers,
                timeout=timeout, verify=verify_ssl, proxies=proxies, **kwargs
            )
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Azure Management API.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Azure Management API timed out.")

        if resp.status_code in (200, 201):
            return resp.json() if resp.content else {}

        if resp.status_code == 401:
            raise _TokenExpiredError()

        if resp.status_code == 403:
            raise Exception("Authorization failed (HTTP 403). Verify service principal permissions.")

        if resp.status_code == 404:
            raise Exception("Resource not found. Verify subscription_id, resource_group, and policy_name.")

        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", BACKOFF_FACTOR ** (attempt + 1)))
            if attempt < MAX_RETRIES - 1:
                _logger.warning("Rate limited (429). Retrying in %ds...", retry_after)
                time.sleep(retry_after)
                last_exc = Exception("Azure API rate limit exceeded. Please try again later.")
                continue
            raise Exception("Azure API rate limit exceeded. Please try again later.")

        if resp.status_code >= 500:
            wait = BACKOFF_FACTOR ** (attempt + 1)
            if attempt < MAX_RETRIES - 1:
                _logger.warning("Server error (%d). Retrying in %ds...", resp.status_code, wait)
                time.sleep(wait)
                last_exc = Exception(f"Azure server error (HTTP {resp.status_code}).")
                continue
            raise Exception(f"Azure server error (HTTP {resp.status_code}).")

        try:
            error_detail = resp.json().get("error", {}).get("message", resp.text)
        except Exception:
            error_detail = resp.text
        raise Exception(f"Azure API error (HTTP {resp.status_code}): {error_detail}")

    if last_exc:
        raise last_exc


def _request_with_refresh(method: str, url: str, tenant_id: str, client_id: str,
                           client_secret: str, timeout: int, verify_ssl: bool,
                           proxies, **kwargs) -> dict:
    token = _get_token(tenant_id, client_id, client_secret, timeout, verify_ssl, proxies)
    try:
        return _request(method, url, token, timeout, verify_ssl, proxies, **kwargs)
    except _TokenExpiredError:
        _invalidate_token(tenant_id, client_id)
        token = _get_token(tenant_id, client_id, client_secret, timeout, verify_ssl, proxies)
        try:
            return _request(method, url, token, timeout, verify_ssl, proxies, **kwargs)
        except _TokenExpiredError:
            raise Exception("Authorization failed after token refresh. Verify service principal permissions.")


class AzureWaf:

    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Test Connection
    # ------------------------------------------------------------------
    def test_connection(self, connectionParameters: dict):
        try:
            tenant_id, client_id, client_secret, subscription_id, resource_group, base_url, timeout, verify_ssl, proxies = _get_connection(connectionParameters)
            if resource_group:
                url = _policy_url(base_url, subscription_id, resource_group)
            else:
                url = _subscription_list_url(base_url, subscription_id)
            _request_with_refresh("GET", url, tenant_id, client_id, client_secret, timeout, verify_ssl, proxies)
            return {"status": "success", "message": "Connected to Azure WAF successfully."}
        except Exception:
            _logger.error("Exception while testing connection", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def list_waf_policies(self, request: RequestBody) -> dict:
        try:
            tenant_id, client_id, client_secret, subscription_id, conn_rg, base_url, timeout, verify_ssl, proxies = _get_connection(request.connectionParameters)
            params = request.parameters or {}
            sub_id = params.get("subscription_id") or subscription_id
            rg = (params.get("resource_group") or conn_rg or "").strip()

            url = _policy_url(base_url, sub_id, rg) if rg else _subscription_list_url(base_url, sub_id)

            policies = []
            while url:
                data = _request_with_refresh("GET", url, tenant_id, client_id, client_secret, timeout, verify_ssl, proxies)
                policies.extend(data.get("value", []))
                url = data.get("nextLink")

            return {"status": "success", "policies": policies, "total_count": len(policies)}
        except Exception:
            _logger.error("Error in list_waf_policies", exc_info=True)
            raise

    def get_waf_policy(self, request: RequestBody) -> dict:
        try:
            tenant_id, client_id, client_secret, subscription_id, conn_rg, base_url, timeout, verify_ssl, proxies = _get_connection(request.connectionParameters)
            params = request.parameters or {}
            sub_id = params.get("subscription_id") or subscription_id
            rg = _validate_required(params.get("resource_group") or conn_rg, "resource_group")
            policy_name = _validate_required(params.get("policy_name"), "policy_name")

            policy = _request_with_refresh("GET", _policy_url(base_url, sub_id, rg, policy_name), tenant_id, client_id, client_secret, timeout, verify_ssl, proxies)
            return {"status": "success", "policy": policy}
        except Exception:
            _logger.error("Error in get_waf_policy", exc_info=True)
            raise

    def get_custom_rules(self, request: RequestBody) -> dict:
        try:
            tenant_id, client_id, client_secret, subscription_id, conn_rg, base_url, timeout, verify_ssl, proxies = _get_connection(request.connectionParameters)
            params = request.parameters or {}
            sub_id = params.get("subscription_id") or subscription_id
            rg = _validate_required(params.get("resource_group") or conn_rg, "resource_group")
            policy_name = _validate_required(params.get("policy_name"), "policy_name")

            policy = _request_with_refresh("GET", _policy_url(base_url, sub_id, rg, policy_name), tenant_id, client_id, client_secret, timeout, verify_ssl, proxies)
            custom_rules = policy.get("properties", {}).get("customRules", [])
            return {"status": "success", "custom_rules": custom_rules, "total_count": len(custom_rules)}
        except Exception:
            _logger.error("Error in get_custom_rules", exc_info=True)
            raise

    def add_ip_to_block_list(self, request: RequestBody) -> dict:
        try:
            tenant_id, client_id, client_secret, subscription_id, conn_rg, base_url, timeout, verify_ssl, proxies = _get_connection(request.connectionParameters)
            params = request.parameters or {}
            sub_id = params.get("subscription_id") or subscription_id
            rg = _validate_required(params.get("resource_group") or conn_rg, "resource_group")
            policy_name = _validate_required(params.get("policy_name"), "policy_name")
            ip_address = _validate_ip(_validate_required(params.get("ip_address"), "ip_address"))
            rule_name = (params.get("rule_name") or DEFAULT_RULE_NAME).strip()

            policy = _request_with_refresh("GET", _policy_url(base_url, sub_id, rg, policy_name), tenant_id, client_id, client_secret, timeout, verify_ssl, proxies)
            custom_rules = policy.setdefault("properties", {}).setdefault("customRules", [])

            soar_rule = _find_soar_rule(custom_rules, rule_name)
            if soar_rule is None:
                priority = _next_available_priority(custom_rules)
                soar_rule = _build_soar_rule(rule_name, [ip_address], priority)
                custom_rules.append(soar_rule)
            else:
                if not _is_soar_ip_block_rule(soar_rule):
                    raise Exception(
                        f"Rule '{rule_name}' exists but is not a compatible IP block rule "
                        "(expected ruleType=MatchRule, action=Block, RemoteAddr+IPMatch condition). "
                        "Use a different rule_name to avoid modifying customer-created rules."
                    )
                soar_rule["state"] = "Enabled"
                cond = _find_ip_match_condition(soar_rule)
                if ip_address not in cond["matchValues"]:
                    cond["matchValues"].append(ip_address)

            _request_with_refresh("PUT", _policy_url(base_url, sub_id, rg, policy_name), tenant_id, client_id, client_secret, timeout, verify_ssl, proxies, json=policy)
            updated_rule = _find_soar_rule(policy["properties"]["customRules"], rule_name)
            return {"status": "success", "rule": updated_rule}
        except Exception:
            _logger.error("Error in add_ip_to_block_list", exc_info=True)
            raise

    def remove_ip_from_block_list(self, request: RequestBody) -> dict:
        try:
            tenant_id, client_id, client_secret, subscription_id, conn_rg, base_url, timeout, verify_ssl, proxies = _get_connection(request.connectionParameters)
            params = request.parameters or {}
            sub_id = params.get("subscription_id") or subscription_id
            rg = _validate_required(params.get("resource_group") or conn_rg, "resource_group")
            policy_name = _validate_required(params.get("policy_name"), "policy_name")
            ip_address = _validate_ip(_validate_required(params.get("ip_address"), "ip_address"))
            rule_name = (params.get("rule_name") or DEFAULT_RULE_NAME).strip()

            policy = _request_with_refresh("GET", _policy_url(base_url, sub_id, rg, policy_name), tenant_id, client_id, client_secret, timeout, verify_ssl, proxies)
            custom_rules = policy.get("properties", {}).get("customRules", [])
            soar_rule = _find_soar_rule(custom_rules, rule_name)

            if soar_rule is None:
                raise Exception(f"Rule '{rule_name}' not found in policy '{policy_name}'.")

            cond = _find_ip_match_condition(soar_rule)
            if cond is None or ip_address not in cond["matchValues"]:
                raise Exception(f"IP '{ip_address}' not found in rule '{rule_name}'.")

            cond["matchValues"].remove(ip_address)
            if not cond["matchValues"]:
                soar_rule["state"] = "Disabled"

            _request_with_refresh("PUT", _policy_url(base_url, sub_id, rg, policy_name), tenant_id, client_id, client_secret, timeout, verify_ssl, proxies, json=policy)
            return {"status": "success", "rule": soar_rule, "removed_ip": ip_address}
        except Exception:
            _logger.error("Error in remove_ip_from_block_list", exc_info=True)
            raise

    def check_ip_in_block_list(self, request: RequestBody) -> dict:
        try:
            tenant_id, client_id, client_secret, subscription_id, conn_rg, base_url, timeout, verify_ssl, proxies = _get_connection(request.connectionParameters)
            params = request.parameters or {}
            sub_id = params.get("subscription_id") or subscription_id
            rg = _validate_required(params.get("resource_group") or conn_rg, "resource_group")
            policy_name = _validate_required(params.get("policy_name"), "policy_name")
            ip_address = _validate_ip(_validate_required(params.get("ip_address"), "ip_address"))
            rule_name = (params.get("rule_name") or DEFAULT_RULE_NAME).strip()

            policy = _request_with_refresh("GET", _policy_url(base_url, sub_id, rg, policy_name), tenant_id, client_id, client_secret, timeout, verify_ssl, proxies)
            custom_rules = policy.get("properties", {}).get("customRules", [])
            soar_rule = _find_soar_rule(custom_rules, rule_name)

            if (
                soar_rule is None
                or soar_rule.get("state") != "Enabled"
                or soar_rule.get("action") != "Block"
            ):
                return {"status": "success", "ip": ip_address, "blocked": False, "rule_name": rule_name}

            cond = _find_ip_match_condition(soar_rule)
            blocked = cond is not None and ip_address in cond.get("matchValues", [])
            return {"status": "success", "ip": ip_address, "blocked": blocked, "rule_name": rule_name}
        except Exception:
            _logger.error("Error in check_ip_in_block_list", exc_info=True)
            raise

    def get_blocked_ips(self, request: RequestBody) -> dict:
        try:
            tenant_id, client_id, client_secret, subscription_id, conn_rg, base_url, timeout, verify_ssl, proxies = _get_connection(request.connectionParameters)
            params = request.parameters or {}
            sub_id = params.get("subscription_id") or subscription_id
            rg = _validate_required(params.get("resource_group") or conn_rg, "resource_group")
            policy_name = _validate_required(params.get("policy_name"), "policy_name")
            rule_name = (params.get("rule_name") or DEFAULT_RULE_NAME).strip()

            policy = _request_with_refresh("GET", _policy_url(base_url, sub_id, rg, policy_name), tenant_id, client_id, client_secret, timeout, verify_ssl, proxies)
            custom_rules = policy.get("properties", {}).get("customRules", [])
            soar_rule = _find_soar_rule(custom_rules, rule_name)

            if soar_rule is None or soar_rule.get("state") != "Enabled":
                return {"status": "success", "rule_name": rule_name, "blocked_ips": [], "total_count": 0}

            cond = _find_ip_match_condition(soar_rule)
            blocked_ips = list(cond.get("matchValues", [])) if cond else []
            return {"status": "success", "rule_name": rule_name, "blocked_ips": blocked_ips, "total_count": len(blocked_ips)}
        except Exception:
            _logger.error("Error in get_blocked_ips", exc_info=True)
            raise

    def enable_custom_rule(self, request: RequestBody) -> dict:
        try:
            tenant_id, client_id, client_secret, subscription_id, conn_rg, base_url, timeout, verify_ssl, proxies = _get_connection(request.connectionParameters)
            params = request.parameters or {}
            sub_id = params.get("subscription_id") or subscription_id
            rg = _validate_required(params.get("resource_group") or conn_rg, "resource_group")
            policy_name = _validate_required(params.get("policy_name"), "policy_name")
            rule_name = _validate_required(params.get("rule_name"), "rule_name")

            policy = _request_with_refresh("GET", _policy_url(base_url, sub_id, rg, policy_name), tenant_id, client_id, client_secret, timeout, verify_ssl, proxies)
            custom_rules = policy.get("properties", {}).get("customRules", [])
            rule = _find_soar_rule(custom_rules, rule_name)

            if rule is None:
                raise Exception(f"Custom rule '{rule_name}' not found in policy '{policy_name}'.")

            rule["state"] = "Enabled"
            _request_with_refresh("PUT", _policy_url(base_url, sub_id, rg, policy_name), tenant_id, client_id, client_secret, timeout, verify_ssl, proxies, json=policy)
            return {"status": "success", "rule": rule}
        except Exception:
            _logger.error("Error in enable_custom_rule", exc_info=True)
            raise

    def disable_custom_rule(self, request: RequestBody) -> dict:
        try:
            tenant_id, client_id, client_secret, subscription_id, conn_rg, base_url, timeout, verify_ssl, proxies = _get_connection(request.connectionParameters)
            params = request.parameters or {}
            sub_id = params.get("subscription_id") or subscription_id
            rg = _validate_required(params.get("resource_group") or conn_rg, "resource_group")
            policy_name = _validate_required(params.get("policy_name"), "policy_name")
            rule_name = _validate_required(params.get("rule_name"), "rule_name")

            policy = _request_with_refresh("GET", _policy_url(base_url, sub_id, rg, policy_name), tenant_id, client_id, client_secret, timeout, verify_ssl, proxies)
            custom_rules = policy.get("properties", {}).get("customRules", [])
            rule = _find_soar_rule(custom_rules, rule_name)

            if rule is None:
                raise Exception(f"Custom rule '{rule_name}' not found in policy '{policy_name}'.")

            rule["state"] = "Disabled"
            _request_with_refresh("PUT", _policy_url(base_url, sub_id, rg, policy_name), tenant_id, client_id, client_secret, timeout, verify_ssl, proxies, json=policy)
            return {"status": "success", "rule": rule}
        except Exception:
            _logger.error("Error in disable_custom_rule", exc_info=True)
            raise

    def block_url(self, request: RequestBody) -> dict:
        try:
            tenant_id, client_id, client_secret, subscription_id, conn_rg, base_url, timeout, verify_ssl, proxies = _get_connection(request.connectionParameters)
            params = request.parameters or {}
            sub_id = params.get("subscription_id") or subscription_id
            rg = _validate_required(params.get("resource_group") or conn_rg, "resource_group")
            policy_name = _validate_required(params.get("policy_name"), "policy_name")
            url_path = _normalize_url(_validate_required(params.get("url"), "url"))
            rule_name = (params.get("rule_name") or DEFAULT_URL_RULE_NAME).strip()

            policy = _request_with_refresh("GET", _policy_url(base_url, sub_id, rg, policy_name), tenant_id, client_id, client_secret, timeout, verify_ssl, proxies)
            custom_rules = policy.setdefault("properties", {}).setdefault("customRules", [])

            soar_rule = _find_soar_rule(custom_rules, rule_name)
            if soar_rule is None:
                priority = _next_available_priority(custom_rules)
                soar_rule = _build_soar_url_rule(rule_name, [url_path], priority)
                custom_rules.append(soar_rule)
            else:
                if not _is_soar_url_block_rule(soar_rule):
                    raise Exception(
                        f"Rule '{rule_name}' exists but is not a compatible URL block rule "
                        "(expected ruleType=MatchRule, action=Block, RequestUri+BeginsWith condition). "
                        "Use a different rule_name to avoid modifying customer-created rules."
                    )
                soar_rule["state"] = "Enabled"
                cond = _find_url_match_condition(soar_rule)
                if url_path not in cond["matchValues"]:
                    cond["matchValues"].append(url_path)

            _request_with_refresh("PUT", _policy_url(base_url, sub_id, rg, policy_name), tenant_id, client_id, client_secret, timeout, verify_ssl, proxies, json=policy)
            updated_rule = _find_soar_rule(policy["properties"]["customRules"], rule_name)
            return {"status": "success", "rule": updated_rule, "blocked_url": url_path}
        except Exception:
            _logger.error("Error in block_url", exc_info=True)
            raise

    def unblock_url(self, request: RequestBody) -> dict:
        try:
            tenant_id, client_id, client_secret, subscription_id, conn_rg, base_url, timeout, verify_ssl, proxies = _get_connection(request.connectionParameters)
            params = request.parameters or {}
            sub_id = params.get("subscription_id") or subscription_id
            rg = _validate_required(params.get("resource_group") or conn_rg, "resource_group")
            policy_name = _validate_required(params.get("policy_name"), "policy_name")
            url_path = _normalize_url(_validate_required(params.get("url"), "url"))
            rule_name = (params.get("rule_name") or DEFAULT_URL_RULE_NAME).strip()

            policy = _request_with_refresh("GET", _policy_url(base_url, sub_id, rg, policy_name), tenant_id, client_id, client_secret, timeout, verify_ssl, proxies)
            custom_rules = policy.get("properties", {}).get("customRules", [])
            soar_rule = _find_soar_rule(custom_rules, rule_name)

            if soar_rule is None:
                raise Exception(f"Rule '{rule_name}' not found in policy '{policy_name}'.")

            cond = _find_url_match_condition(soar_rule)
            if cond is None or url_path not in cond["matchValues"]:
                raise Exception(f"URL '{url_path}' not found in rule '{rule_name}'.")

            cond["matchValues"].remove(url_path)
            if not cond["matchValues"]:
                soar_rule["state"] = "Disabled"

            _request_with_refresh("PUT", _policy_url(base_url, sub_id, rg, policy_name), tenant_id, client_id, client_secret, timeout, verify_ssl, proxies, json=policy)
            return {"status": "success", "rule": soar_rule, "unblocked_url": url_path}
        except Exception:
            _logger.error("Error in unblock_url", exc_info=True)
            raise

