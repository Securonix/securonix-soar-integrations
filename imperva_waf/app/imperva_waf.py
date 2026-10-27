from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import requests


DEFAULT_BASE_URL = "https://my.imperva.com/api/prov/v1"
AUDIT_EVENTS_URL = "https://api.imperva.com/audit-trail/v2/events"
DEFAULT_TIMEOUT = 30

# ACL rule_id values (confirmed from the Imperva Incapsula API reference).
ACL_BLACKLISTED_IPS = "api.acl.blacklisted_ips"
ACL_WHITELISTED_IPS = "api.acl.whitelisted_ips"
ACL_BLACKLISTED_COUNTRIES = "api.acl.blacklisted_countries"


def _require_conn(connection_params: dict, name: str) -> str:
    value = connection_params.get(name)
    if not value or (isinstance(value, str) and not value.strip()):
        raise Exception(f"Missing required connection parameter: {name}")
    return value.strip() if isinstance(value, str) else value


def _get_base_url(connection_params: dict) -> str:
    base = (connection_params.get("base_url") or "").strip()
    if not base:
        base = DEFAULT_BASE_URL
    return base.rstrip("/")


def _get_verify_ssl(connection_params: dict):
    v = connection_params.get("verify_ssl", True)
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes")
    return bool(v)


def _get_timeout(connection_params: dict) -> int:
    t = connection_params.get("timeout", "")
    if not t or str(t) in ("None", "null"):
        return DEFAULT_TIMEOUT
    try:
        n = int(t)
    except (ValueError, TypeError):
        raise Exception(f"timeout must be a positive integer (seconds), got: {t!r}")
    if n <= 0:
        raise Exception(f"timeout must be a positive integer (seconds), got: {n}")
    return n


def _param(parameters: dict, name: str):
    """Required action parameter (raises if missing)."""
    value = parameters.get(name)
    if value is None or (isinstance(value, str) and not value.strip()):
        raise Exception(f"Missing required parameter: {name}")
    return value.strip() if isinstance(value, str) else value


class ImpervaWaf:
    """
    Imperva Cloud WAF (Incapsula) SOAR connector.

    Uses the Imperva provisioning API (https://my.imperva.com/api/prov/v1,
    RPC-style, form-encoded POSTs) and the audit-trail API
    (https://api.imperva.com/audit-trail/v2). Authentication is via the
    x-API-Id / x-API-Key header key pair.

    Actions:
      Remediate  - block_ip, unblock_ip, allowlist_ip, block_country,
                   add_security_rule
      Investigate - list_sites, get_site_status, get_audit_events
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    # ------------------------------------------------------------------
    # HTTP plumbing
    # ------------------------------------------------------------------
    def _headers(self, connection_params: dict, form=True):
        api_id = _require_conn(connection_params, "api_id")
        api_key = _require_conn(connection_params, "api_key")
        headers = {
            "x-API-Id": api_id,
            "x-API-Key": api_key,
            "Accept": "application/json",
        }
        if form:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        return headers

    def _prov_post(self, connection_params: dict, path: str, params: dict) -> dict:
        """
        POST to the provisioning API (form-encoded). The prov/v1 API signals
        success/failure via a `res` field in the JSON body (res == 0 is success).
        """
        verify = _get_verify_ssl(connection_params)
        timeout = _get_timeout(connection_params)
        url = f"{_get_base_url(connection_params)}/{path}"
        try:
            resp = requests.post(
                url,
                headers=self._headers(connection_params, form=True),
                data=params,
                verify=verify,
                timeout=timeout,
            )
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Imperva. Please verify base_url and network connectivity.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Imperva timed out.")

        if resp.status_code == 401:
            raise Exception("Authentication failed. Please verify your Imperva api_id and api_key.")
        if resp.status_code != 200:
            raise Exception(f"Imperva API returned HTTP {resp.status_code} for {path}.")

        data = resp.json() if resp.content else {}
        # prov/v1 returns a `res` code; non-zero means the operation failed.
        res = data.get("res")
        if res is not None and str(res) != "0":
            message = data.get("res_message") or data.get("debug_info") or "Imperva API request failed"
            raise Exception(f"Imperva API error (res={res}): {message}")
        return data

    def _audit_get(self, connection_params: dict, params: dict) -> dict:
        """GET the audit-trail events API (query params, JSON response)."""
        verify = _get_verify_ssl(connection_params)
        timeout = _get_timeout(connection_params)
        try:
            resp = requests.get(
                AUDIT_EVENTS_URL,
                headers=self._headers(connection_params, form=False),
                params=params,
                verify=verify,
                timeout=timeout,
            )
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Imperva. Please verify network connectivity.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Imperva timed out.")

        if resp.status_code == 401:
            raise Exception("Authentication failed. Please verify your Imperva api_id and api_key.")
        if resp.status_code != 200:
            raise Exception(f"Imperva audit-trail API returned HTTP {resp.status_code}.")
        return resp.json() if resp.content else {}

    # ------------------------------------------------------------------
    # Test Connection
    # ------------------------------------------------------------------
    def test_connection(self, connectionParameters: dict):
        try:
            # Listing sites is a lightweight authenticated call.
            self._prov_post(connectionParameters, "sites/list", {"page_size": 1})
            return {"status": "success", "message": "Connected to Imperva Cloud WAF successfully."}
        except Exception as e:
            self.logger.error("Exception while testing Imperva connection", exc_info=e)
            raise Exception(str(e))

    # ------------------------------------------------------------------
    # Remediate — ACL (block/unblock/allowlist/country)
    # ------------------------------------------------------------------
    def block_ip(self, request: RequestBody) -> ResponseBody:
        """
        Add IP(s) to a site's blacklisted_ips ACL.
        Required: site_id, ips (comma-separated).
        """
        p = request.parameters
        try:
            params = {
                "site_id": _param(p, "site_id"),
                "rule_id": ACL_BLACKLISTED_IPS,
                "ips": _param(p, "ips"),
            }
            data = self._prov_post(request.connectionParameters, "sites/configure/acl", params)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in block_ip", exc_info=e)
            raise Exception(str(e))

    def unblock_ip(self, request: RequestBody) -> ResponseBody:
        """
        Set the site's blacklisted_ips ACL to the provided list (to remove an IP,
        pass the remaining list; an empty list clears all blacklisted IPs).
        Required: site_id. Optional: ips (comma-separated; empty clears the list).
        """
        p = request.parameters
        try:
            params = {
                "site_id": _param(p, "site_id"),
                "rule_id": ACL_BLACKLISTED_IPS,
                "ips": p.get("ips", ""),
            }
            data = self._prov_post(request.connectionParameters, "sites/configure/acl", params)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in unblock_ip", exc_info=e)
            raise Exception(str(e))

    def allowlist_ip(self, request: RequestBody) -> ResponseBody:
        """
        Set a site's whitelisted_ips ACL.
        Required: site_id, ips (comma-separated).
        """
        p = request.parameters
        try:
            params = {
                "site_id": _param(p, "site_id"),
                "rule_id": ACL_WHITELISTED_IPS,
                "ips": _param(p, "ips"),
            }
            data = self._prov_post(request.connectionParameters, "sites/configure/acl", params)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in allowlist_ip", exc_info=e)
            raise Exception(str(e))

    def block_country(self, request: RequestBody) -> ResponseBody:
        """
        Set a site's blacklisted_countries ACL.
        Required: site_id, countries (comma-separated ISO country/continent codes).
        """
        p = request.parameters
        try:
            params = {
                "site_id": _param(p, "site_id"),
                "rule_id": ACL_BLACKLISTED_COUNTRIES,
                "countries": _param(p, "countries"),
            }
            data = self._prov_post(request.connectionParameters, "sites/configure/acl", params)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in block_country", exc_info=e)
            raise Exception(str(e))

    # ------------------------------------------------------------------
    # Remediate — IncapRule
    # ------------------------------------------------------------------
    def add_security_rule(self, request: RequestBody) -> ResponseBody:
        """
        Add a security rule (IncapRule) to a site.
        Required: site_id, name, action (e.g. RULE_ACTION_BLOCK_IP), filter.
        """
        p = request.parameters
        try:
            params = {
                "site_id": _param(p, "site_id"),
                "name": _param(p, "name"),
                "action": _param(p, "action"),
                "filter": _param(p, "filter"),
            }
            data = self._prov_post(request.connectionParameters, "sites/incapRules/add", params)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in add_security_rule", exc_info=e)
            raise Exception(str(e))

    # ------------------------------------------------------------------
    # Investigate
    # ------------------------------------------------------------------
    def list_sites(self, request: RequestBody) -> ResponseBody:
        """
        List sites for the account.
        Optional: account_id, page_size, page_num.
        """
        p = request.parameters
        try:
            params = {}
            if p.get("account_id"):
                params["account_id"] = p["account_id"]
            if p.get("page_size") not in (None, ""):
                params["page_size"] = p["page_size"]
            if p.get("page_num") not in (None, ""):
                params["page_num"] = p["page_num"]
            data = self._prov_post(request.connectionParameters, "sites/list", params)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in list_sites", exc_info=e)
            raise Exception(str(e))

    def get_site_status(self, request: RequestBody) -> ResponseBody:
        """
        Get the status of a site.
        Required: site_id. Optional: tests (comma-separated: domain_validation, services, dns).
        """
        p = request.parameters
        try:
            params = {"site_id": _param(p, "site_id")}
            if p.get("tests"):
                params["tests"] = p["tests"]
            data = self._prov_post(request.connectionParameters, "sites/status", params)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_site_status", exc_info=e)
            raise Exception(str(e))

    def get_audit_events(self, request: RequestBody) -> ResponseBody:
        """
        Get account audit-trail events.
        Optional: account_id, start (ms epoch), end (ms epoch), page_size, page_num.
        """
        p = request.parameters
        try:
            params = {}
            for key in ("account_id", "start", "end", "page_size", "page_num"):
                if p.get(key) not in (None, ""):
                    params[key] = p[key]
            data = self._audit_get(request.connectionParameters, params)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_audit_events", exc_info=e)
            raise Exception(str(e))
