from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import base64
import ipaddress
import logging
import re
import time
import requests
from urllib.parse import urlparse


DEFAULT_TIMEOUT = 30
MAX_BATCH = 500
VALID_DEST_TYPES = {"URL", "IPV4", "DOMAIN"}
VALID_BUNDLE_TYPE_IDS = {1, 2, 4}
VALID_BOOL_TRUE = {"true", "1", "yes"}
VALID_BOOL_FALSE = {"false", "0", "no"}

_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
  

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


def _normalize_list(value) -> list:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    raise Exception(f"Invalid input format: expected string or list, got {type(value).__name__}")


def _to_positive_int(value, field_name: str) -> int:
    try:
        n = int(str(value).strip())
        if n <= 0:
            raise ValueError
        return n
    except (ValueError, TypeError):
        raise Exception(f"{field_name} must be a positive integer, got: {value!r}")


def _to_positive_int_list(values: list, field_name: str) -> list:
    return [_to_positive_int(v, field_name) for v in values]


def _is_valid_ipv4(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
        return addr.version == 4
    except ValueError:
        return False


def _is_valid_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.hostname)
    except Exception:
        return False


def _is_valid_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value))


def _detect_type(destination: str) -> str:
    if _is_valid_url(destination):
        return "URL"
    if _is_valid_ipv4(destination):
        return "IPV4"
    if _is_valid_domain(destination):
        return "DOMAIN"
    raise Exception(
        f"Cannot auto-detect destination type for {destination!r}. "
        "Please provide destination_type explicitly (URL, IPV4, or DOMAIN)."
    )


def _handle_response_errors(resp, resource_hint: str = ""):
    if resp.status_code == 401:
        raise Exception("Authentication failed. Please verify your Cisco Umbrella API credentials.")
    if resp.status_code == 403:
        raise Exception(
            "Authorization failed. Please verify that the API credentials have the required Cisco Umbrella policy scopes."
        )
    if resp.status_code == 404:
        hint = f": {resource_hint} does not exist." if resource_hint else "."
        raise Exception(f"Resource not found{hint}")
    if resp.status_code >= 500:
        raise Exception(f"Cisco Umbrella server error: HTTP {resp.status_code}")
    if resp.status_code >= 400:
        logging.getLogger().error("Cisco Umbrella rejected request: HTTP %s", resp.status_code)
        raise Exception(
            "Cisco Umbrella rejected the request. Please verify the destination type and destination list configuration."
        )


class CiscoUmbrellaCloudSecurity:

    def __init__(self) -> None:
        self.logger = logging.getLogger()
        self._token_cache: dict = {}

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------
    def _get_token(self, base_url: str, client_id: str, client_secret: str,
                   timeout: int, verify_ssl: bool, proxies) -> str:
        cache_key = (base_url, client_id)
        cached = self._token_cache.get(cache_key)
        if cached and time.time() < cached["expiry"] - 30:
            return cached["token"]

        credentials = base64.b64encode(
            f"{client_id}:{client_secret}".encode()
        ).decode()

        token_url = f"{base_url}/auth/v2/token"

        try:
            resp = requests.post(
                token_url,
                headers={
                    "Authorization": f"Basic {credentials}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                data="grant_type=client_credentials",
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

        if resp.status_code == 401:
            raise Exception("Authentication failed. Please verify your Cisco Umbrella API credentials.")
        if resp.status_code == 403:
            raise Exception(
                "Authorization failed. Please verify that the API credentials have the required Cisco Umbrella policy scopes."
            )
        if resp.status_code != 200:
            raise Exception(f"Authentication failed: HTTP {resp.status_code}")

        data = resp.json()
        token = data.get("access_token")
        if not token:
            raise Exception("Authentication response missing access_token.")

        expires_in = data.get("expires_in", 3600)
        self._token_cache[(base_url, client_id)] = {
            "token": token,
            "expiry": time.time() + expires_in,
        }
        return token

    def _invalidate_token(self, base_url: str, client_id: str):
        self._token_cache.pop((base_url, client_id), None)

    # ------------------------------------------------------------------
    # HTTP helper — with 401 retry once
    # ------------------------------------------------------------------
    def _request(self, base_url: str, client_id: str, client_secret: str,
                 method: str, url: str, timeout: int, verify_ssl: bool,
                 proxies, **kwargs) -> dict:
        resource_hint = kwargs.pop("resource_hint", "")

        def _do_request(token):
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            try:
                return requests.request(
                    method, url,
                    headers=headers,
                    timeout=timeout,
                    verify=verify_ssl,
                    proxies=proxies,
                    **kwargs,
                )
            except requests.exceptions.ConnectionError:
                raise Exception(
                    "Unable to connect to Cisco Umbrella. Please verify base_url and network connectivity."
                )
            except requests.exceptions.Timeout:
                raise Exception("Connection to Cisco Umbrella timed out.")

        token = self._get_token(base_url, client_id, client_secret, timeout, verify_ssl, proxies)
        resp = _do_request(token)

        if resp.status_code == 401:
            self._invalidate_token(base_url, client_id)
            token = self._get_token(base_url, client_id, client_secret, timeout, verify_ssl, proxies)
            resp = _do_request(token)

        _handle_response_errors(resp, resource_hint)

        if resp.status_code == 204 or not resp.content:
            return {}
        return resp.json()

    # ------------------------------------------------------------------
    # Test Connection
    # ------------------------------------------------------------------
    def test_connection(self, connectionParameters: dict):
        client_id = connectionParameters["client_id"]
        client_secret = connectionParameters["client_secret"]
        base_url = connectionParameters["base_url"].rstrip("/")
        timeout = _get_timeout(connectionParameters)
        verify_ssl = _get_verify_ssl(connectionParameters)
        proxies = _get_proxies(connectionParameters)

        try:
            self._request(
                base_url, client_id, client_secret,
                "GET", f"{base_url}/policies/v2/destinationlists",
                timeout, verify_ssl, proxies,
                params={"page": 1, "limit": 1},
            )
            return {"status": "success", "message": "Connected to Cisco Umbrella successfully."}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Cisco Umbrella. Please verify base_url and network connectivity.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Cisco Umbrella timed out.")
        except Exception:
            self.logger.error("Exception while testing Cisco Umbrella connection parameters", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def add_destination(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        client_id = cp["client_id"]
        client_secret = cp["client_secret"]
        base_url = cp["base_url"].rstrip("/")
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)

        params = request.parameters
        dl_id = _to_positive_int(params["destination_list_id"], "destination_list_id")
        destinations_raw = _normalize_list(params["destinations"])
        if not destinations_raw:
            raise Exception("destinations cannot be empty.")

        dest_type_input = (params.get("destination_type") or "").strip().upper() or None
        if dest_type_input and dest_type_input not in VALID_DEST_TYPES:
            raise Exception(f"destination_type must be one of {sorted(VALID_DEST_TYPES)}, got: {dest_type_input!r}")

        comment = (params.get("comment") or "").strip()

        dest_objects = [
            {k: v for k, v in {
                "destination": d,
                "type": dest_type_input or _detect_type(d),
                "comment": comment or None,
            }.items() if v is not None}
            for d in destinations_raw
        ]

        url = f"{base_url}/policies/v2/destinationlists/{dl_id}/destinations"
        added = []

        try:
            for i in range(0, len(dest_objects), MAX_BATCH):
                batch = dest_objects[i:i + MAX_BATCH]
                data = self._request(
                    base_url, client_id, client_secret,
                    "POST", url, timeout, verify_ssl, proxies,
                    resource_hint=f"destination list ID {dl_id}",
                    json=batch,
                )
                added.extend(data.get("data", batch))
            return {"status": "success", "added": added}
        except requests.exceptions.ConnectionError:
            raise Exception(
                "Unable to connect to Cisco Umbrella. Please verify base_url and network connectivity."
            )
        except requests.exceptions.Timeout:
            raise Exception("Connection to Cisco Umbrella timed out.")
        except Exception:
            self.logger.error("error while running action 'add_destination'", exc_info=True)
            raise

    def get_destinations(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        client_id = cp["client_id"]
        client_secret = cp["client_secret"]
        base_url = cp["base_url"].rstrip("/")
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)

        params = request.parameters
        dl_id = _to_positive_int(params["destination_list_id"], "destination_list_id")

        page = 1
        limit = 100
        if params.get("page"):
            try:
                page = int(params["page"])
            except (ValueError, TypeError):
                raise Exception("page must be a positive integer.")
            if page < 1:
                raise Exception("page must be a positive integer.")
        if params.get("limit"):
            try:
                limit = int(params["limit"])
            except (ValueError, TypeError):
                raise Exception("limit must be an integer between 1 and 100.")
            if not 1 <= limit <= 100:
                raise Exception("limit must be an integer between 1 and 100.")

        url = f"{base_url}/policies/v2/destinationlists/{dl_id}/destinations"

        try:
            data = self._request(
                base_url, client_id, client_secret,
                "GET", url, timeout, verify_ssl, proxies,
                resource_hint=f"destination list ID {dl_id}",
                params={"page": page, "limit": limit},
            )
            return {
                "status": "success",
                "destinations": data.get("data", []),
                "total": data.get("meta", {}).get("total", len(data.get("data", []))),
            }
        except requests.exceptions.ConnectionError:
            raise Exception(
                "Unable to connect to Cisco Umbrella. Please verify base_url and network connectivity."
            )
        except requests.exceptions.Timeout:
            raise Exception("Connection to Cisco Umbrella timed out.")
        except Exception:
            self.logger.error("error while running action 'get_destinations'", exc_info=True)
            raise

    def delete_destination(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        client_id = cp["client_id"]
        client_secret = cp["client_secret"]
        base_url = cp["base_url"].rstrip("/")
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)

        params = request.parameters
        dl_id = _to_positive_int(params["destination_list_id"], "destination_list_id")
        ids_raw = _normalize_list(params["destination_ids"])
        if not ids_raw:
            raise Exception("destination_ids cannot be empty.")
        if len(ids_raw) > MAX_BATCH:
            raise Exception(f"Maximum {MAX_BATCH} destination IDs per request, got {len(ids_raw)}.")

        dest_ids = _to_positive_int_list(ids_raw, "destination_ids")
        url = f"{base_url}/policies/v2/destinationlists/{dl_id}/destinations/remove"

        try:
            self._request(
                base_url, client_id, client_secret,
                "DELETE", url, timeout, verify_ssl, proxies,
                resource_hint=f"destination list ID {dl_id}",
                json=dest_ids,
            )
            return {"status": "success", "deleted_count": len(dest_ids)}
        except requests.exceptions.ConnectionError:
            raise Exception(
                "Unable to connect to Cisco Umbrella. Please verify base_url and network connectivity."
            )
        except requests.exceptions.Timeout:
            raise Exception("Connection to Cisco Umbrella timed out.")
        except Exception:
            self.logger.error("error while running action 'delete_destination'", exc_info=True)
            raise

    def create_destination_list(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        client_id = cp["client_id"]
        client_secret = cp["client_secret"]
        base_url = cp["base_url"].rstrip("/")
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)

        params = request.parameters
        name = (params.get("name") or "").strip()
        if not name:
            raise Exception("name is required.")
        access = (params.get("access") or "").strip().lower()
        if access not in ("allow", "block"):
            raise Exception("access must be 'allow' or 'block'.")

        body = {"name": name, "access": access}

        is_global = params.get("is_global")
        if is_global is not None:
            val = str(is_global).lower().strip()
            if val in VALID_BOOL_TRUE:
                body["isGlobal"] = True
            elif val in VALID_BOOL_FALSE:
                body["isGlobal"] = False
            else:
                raise Exception("is_global must be 'true' or 'false'.")

        bundle_type_id = params.get("bundle_type_id")
        if bundle_type_id is not None:
            try:
                btid = int(bundle_type_id)
            except (ValueError, TypeError):
                raise Exception(f"bundle_type_id must be one of {sorted(VALID_BUNDLE_TYPE_IDS)}.")
            if btid not in VALID_BUNDLE_TYPE_IDS:
                raise Exception(f"bundle_type_id must be one of {sorted(VALID_BUNDLE_TYPE_IDS)}, got: {btid}.")
            body["bundleTypeId"] = btid

        url = f"{base_url}/policies/v2/destinationlists"

        try:
            data = self._request(
                base_url, client_id, client_secret,
                "POST", url, timeout, verify_ssl, proxies,
                json=body,
            )
            dl = data.get("data", data)
            return {
                "status": "success",
                "destination_list": {
                    "id": dl.get("id"),
                    "name": dl.get("name"),
                    "access": dl.get("access"),
                },
            }
        except requests.exceptions.ConnectionError:
            raise Exception(
                "Unable to connect to Cisco Umbrella. Please verify base_url and network connectivity."
            )
        except requests.exceptions.Timeout:
            raise Exception("Connection to Cisco Umbrella timed out.")
        except Exception:
            self.logger.error("error while running action 'create_destination_list'", exc_info=True)
            raise

    def update_destination_list(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        client_id = cp["client_id"]
        client_secret = cp["client_secret"]
        base_url = cp["base_url"].rstrip("/")
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)

        params = request.parameters
        dl_id = _to_positive_int(params["destination_list_id"], "destination_list_id")
        name = (params.get("name") or "").strip()
        if not name:
            raise Exception("name is required.")

        url = f"{base_url}/policies/v2/destinationlists/{dl_id}"

        try:
            data = self._request(
                base_url, client_id, client_secret,
                "PATCH", url, timeout, verify_ssl, proxies,
                resource_hint=f"destination list ID {dl_id}",
                json={"name": name},
            )
            dl = data.get("data", data)
            return {
                "status": "success",
                "destination_list": {
                    "id": dl.get("id"),
                    "name": dl.get("name"),
                },
            }
        except requests.exceptions.ConnectionError:
            raise Exception(
                "Unable to connect to Cisco Umbrella. Please verify base_url and network connectivity."
            )
        except requests.exceptions.Timeout:
            raise Exception("Connection to Cisco Umbrella timed out.")
        except Exception:
            self.logger.error("error while running action 'update_destination_list'", exc_info=True)
            raise
