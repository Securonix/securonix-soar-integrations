from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import datetime
import logging
import re
import uuid
from urllib.parse import quote
import requests


DEFAULT_BASE_URL = "https://s-platform.api.opendns.com/1.0"
DEFAULT_TIMEOUT = 30
# Per Cisco docs, providerName must be set to the fixed value "Security Platform".
DEFAULT_PROVIDER_NAME = "Security Platform"
DEFAULT_DEVICE_VERSION = "1.0"
PROTOCOL_VERSION = "1.0a"
MAX_DOMAIN_LENGTH = 255

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


# ----------------------------------------------------------------------
# Connection-parameter helpers
# ----------------------------------------------------------------------
def _get_base_url(connection_params: dict) -> str:
    base = (connection_params.get("base_url") or "").strip()
    if not base:
        base = DEFAULT_BASE_URL
    return base.rstrip("/")


def _get_customer_key(connection_params: dict) -> str:
    key = (connection_params.get("customer_key") or "").strip()
    if not key:
        raise Exception("customer_key is required for the Umbrella Enforcement API.")
    return key


def _get_timeout(connection_params: dict) -> int:
    t = connection_params.get("timeout", "")
    if not t or t in (None, "None", "null"):
        return DEFAULT_TIMEOUT
    try:
        n = int(t)
    except (ValueError, TypeError):
        raise Exception(f"timeout must be a positive integer (seconds), got: {t!r}")
    if n <= 0:
        raise Exception(f"timeout must be a positive integer (seconds), got: {n}")
    return n


def _get_verify_ssl(connection_params: dict) -> bool:
    v = connection_params.get("verify_ssl", True)
    if isinstance(v, str):
        return v.lower() in ("true", "1", "yes")
    return bool(v)


def _get_proxies(connection_params: dict):
    proxy = connection_params.get("proxy")
    return {"http": proxy, "https": proxy} if proxy else None


def _to_bool(value, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in ("true", "1", "yes"):
        return True
    if s in ("false", "0", "no", ""):
        return False
    raise Exception(f"{field_name} must be a boolean (true/false), got: {value!r}")


def _to_positive_int(value, field_name: str) -> int:
    try:
        n = int(str(value).strip())
        if n <= 0:
            raise ValueError
        return n
    except (ValueError, TypeError):
        raise Exception(f"{field_name} must be a positive integer, got: {value!r}")


def _is_valid_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value))


def _now_iso() -> str:
    """Current UTC time in the ISO 8601 form Umbrella expects (e.g. 2021-02-08T09:30:26.0Z)."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.0Z")


def _handle_response_errors(resp):
    if resp.status_code == 403:
        raise Exception(
            "Authentication/authorization failed. Please verify your Umbrella Enforcement customer_key."
        )
    if resp.status_code == 404:
        raise Exception("Resource not found.")
    if resp.status_code == 429:
        raise Exception("Cisco Umbrella rate limit exceeded (HTTP 429). Please retry later.")
    if resp.status_code >= 500:
        raise Exception(f"Cisco Umbrella server error: HTTP {resp.status_code}")
    if resp.status_code >= 400:
        logging.getLogger().error("Cisco Umbrella Enforcement rejected request: HTTP %s", resp.status_code)
        raise Exception(
            "Cisco Umbrella rejected the request. Please verify the request parameters."
        )


class CiscoUmbrellaEnforcement:
    """
    Cisco Umbrella Enforcement API connector (response actions).

    Base URL: https://s-platform.api.opendns.com/1.0
    Auth: a single `customerKey` passed as a query parameter on every request.

    Actions:
      - add_domain_event      -> POST /events  (block a domain / submit threat event)
      - list_blocked_domains  -> GET  /domains (list enforced/blocked domains)
      - delete_blocked_domain -> DELETE /domains/{id} (remove a blocked domain)
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    # ------------------------------------------------------------------
    # HTTP helper
    # ------------------------------------------------------------------
    def _request(self, connection_params: dict, method: str, path: str,
                 params=None, body=None) -> dict:
        base_url = _get_base_url(connection_params)
        customer_key = _get_customer_key(connection_params)
        timeout = _get_timeout(connection_params)
        verify_ssl = _get_verify_ssl(connection_params)
        proxies = _get_proxies(connection_params)

        query = {"customerKey": customer_key}
        if params:
            query.update(params)

        url = f"{base_url}{path}"
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        try:
            resp = requests.request(
                method, url,
                headers=headers,
                params=query,
                json=body,
                timeout=timeout,
                verify=verify_ssl,
                proxies=proxies,
            )
        except requests.exceptions.ConnectionError:
            raise Exception(
                "Unable to connect to Cisco Umbrella. Please verify base_url and network connectivity."
            )
        except requests.exceptions.Timeout:
            raise Exception("Connection to Cisco Umbrella timed out.")

        _handle_response_errors(resp)

        if resp.status_code == 204 or not resp.content:
            return {}
        return resp.json()

    # ------------------------------------------------------------------
    # Test Connection
    # ------------------------------------------------------------------
    def test_connection(self, connectionParameters: dict):
        try:
            # Listing blocked domains is a lightweight authenticated GET.
            self._request(connectionParameters, "GET", "/domains", params={"limit": 1})
            return {"status": "success", "message": "Connected to Cisco Umbrella Enforcement successfully."}
        except Exception as e:
            self.logger.error("Exception while testing Cisco Umbrella Enforcement connection", exc_info=e)
            raise Exception(str(e))

    # ------------------------------------------------------------------
    # Action: Block Domain / Submit Threat Event
    # ------------------------------------------------------------------
    def add_domain_event(self, request: RequestBody) -> ResponseBody:
        """
        Submit a threat event to the Umbrella Enforcement API to block a domain.
        Required parameters: dst_domain, dst_url.
        Optional parameters: event_severity, event_type, event_description,
            dst_ip, src, disable_dst_safeguards, device_id, device_version,
            alert_time, event_time.
        Note: protocolVersion ("1.0a") and providerName ("Security Platform")
        are fixed values required by the Cisco Enforcement API and are set
        automatically; they are not accepted as inputs.
        """
        cp = request.connectionParameters
        params = request.parameters

        dst_domain = (params["dst_domain"] or "").strip()
        dst_url = (params["dst_url"] or "").strip()
        if not dst_domain:
            raise Exception("dst_domain cannot be empty.")
        if len(dst_domain) > MAX_DOMAIN_LENGTH:
            raise Exception(f"dst_domain exceeds the maximum length of {MAX_DOMAIN_LENGTH} characters.")
        if not _is_valid_domain(dst_domain):
            raise Exception(f"dst_domain is not a valid domain: {dst_domain!r}")
        if not dst_url:
            raise Exception("dst_url cannot be empty.")

        now = _now_iso()
        event = {
            "alertTime": (params.get("alert_time") or now),
            "deviceId": (params.get("device_id") or str(uuid.uuid4())),
            "deviceVersion": (params.get("device_version") or DEFAULT_DEVICE_VERSION),
            "dstDomain": dst_domain,
            "dstUrl": dst_url,
            "eventTime": (params.get("event_time") or now),
            # Both of these are fixed required values per the Cisco Enforcement API docs.
            "protocolVersion": PROTOCOL_VERSION,
            "providerName": DEFAULT_PROVIDER_NAME,
        }

        # Optional, SOAR-relevant threat metadata
        if params.get("dst_ip"):
            event["dstIP"] = params["dst_ip"]
        if params.get("src"):
            event["src"] = params["src"]
        if params.get("event_severity"):
            event["eventSeverity"] = params["event_severity"]
        if params.get("event_type"):
            event["eventType"] = params["event_type"]
        if params.get("event_description"):
            event["eventDescription"] = params["event_description"]
        if params.get("disable_dst_safeguards") is not None and str(params.get("disable_dst_safeguards")) != "":
            event["disableDstSafeguards"] = _to_bool(params["disable_dst_safeguards"], "disable_dst_safeguards")

        try:
            # The Enforcement API expects an array of event objects.
            data = self._request(cp, "POST", "/events", body=[event])
            self.logger.debug("Umbrella add_domain_event response: %s", data)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in add_domain_event", exc_info=e)
            raise Exception(str(e))

    # ------------------------------------------------------------------
    # Action: List Blocked Domains
    # ------------------------------------------------------------------
    def list_blocked_domains(self, request: RequestBody) -> ResponseBody:
        """
        List the domains currently in the Umbrella Enforcement block list.
        Optional parameters: limit (default/max 200), page.
        """
        cp = request.connectionParameters
        params = request.parameters

        query = {}
        if params.get("limit") not in (None, ""):
            query["limit"] = _to_positive_int(params["limit"], "limit")
        if params.get("page") not in (None, ""):
            query["page"] = _to_positive_int(params["page"], "page")

        try:
            data = self._request(cp, "GET", "/domains", params=query or None)
            self.logger.debug("Umbrella list_blocked_domains response: %s", data)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in list_blocked_domains", exc_info=e)
            raise Exception(str(e))

    # ------------------------------------------------------------------
    # Action: Remove Blocked Domain
    # ------------------------------------------------------------------
    def delete_blocked_domain(self, request: RequestBody) -> ResponseBody:
        """
        Remove a domain from the Umbrella Enforcement block list.
        Required parameter: domain (a numeric domain ID or a domain name).
        """
        cp = request.connectionParameters
        params = request.parameters

        domain = str(params["domain"]).strip()
        if not domain:
            raise Exception("domain cannot be empty.")

        # The {id} path segment accepts a numeric ID or a URL-encoded domain name.
        if domain.isdigit():
            path_id = domain
        else:
            path_id = quote(domain, safe="")

        try:
            data = self._request(cp, "DELETE", f"/domains/{path_id}")
            self.logger.debug("Umbrella delete_blocked_domain response: %s", data)
            return {"status": "success", "results": {"domain": domain, "message": "Domain removed from enforcement block list"}}
        except Exception as e:
            self.logger.error("Exception in delete_blocked_domain", exc_info=e)
            raise Exception(str(e))
