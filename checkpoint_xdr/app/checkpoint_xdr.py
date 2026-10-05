from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import time
import requests

try:
    import base64 as _base64
    import json as _json
except ImportError:
    pass

DEFAULT_TIMEOUT = 30
API_PATH = "/app/xdr/api/xdr/v1"
_token_cache = {}


def _get_timeout(cp: dict) -> int:
    t = cp.get("timeout", "")
    if not t or t in (None, "None", "null"):
        return DEFAULT_TIMEOUT
    try:
        n = int(t)
    except (ValueError, TypeError):
        raise Exception(f"timeout must be a positive integer (seconds), got: {t!r}")
    if n <= 0:
        raise Exception(f"timeout must be a positive integer (seconds), got: {n}")
    return n


def _get_verify_ssl(cp: dict) -> bool:
    v = cp.get("verify_ssl", True)
    if isinstance(v, str):
        return v.lower() in ("true", "1", "yes")
    return bool(v)


def _get_proxies(cp: dict):
    proxy = cp.get("proxy")
    return {"http": proxy, "https": proxy} if proxy else None


def _api_error_detail(resp) -> str:
    try:
        body = resp.json()
        return body.get("message") or body.get("detail") or body.get("error") or str(body)
    except Exception:
        return resp.text or f"HTTP {resp.status_code}"


def _handle_response_errors(resp, resource_hint: str = ""):
    if resp.status_code == 401:
        raise Exception("Authentication failed. Please verify client_id and access_key.")
    if resp.status_code == 403:
        raise Exception(
            f"Authorization failed. Please verify the API client has required XDR permissions. "
            f"Detail: {_api_error_detail(resp)}"
        )
    if resp.status_code == 404:
        hint = f": {resource_hint} does not exist." if resource_hint else "."
        raise Exception(f"Resource not found{hint}")
    if resp.status_code >= 500:
        raise Exception(f"CheckPoint XDR server error: HTTP {resp.status_code}. Detail: {_api_error_detail(resp)}")
    if resp.status_code >= 400:
        raise Exception(f"CheckPoint XDR rejected the request: HTTP {resp.status_code}. Detail: {_api_error_detail(resp)}")


def _decode_jwt_exp(token: str):
    try:
        payload_b64 = token.split(".")[1]
        padding = 4 - len(payload_b64) % 4
        payload_b64 += "=" * (padding % 4)
        payload = _json.loads(_base64.urlsafe_b64decode(payload_b64))
        return payload.get("exp")
    except Exception:
        return None


def _get_token(gateway_url: str, client_id: str, access_key: str,
               timeout: int, verify_ssl: bool, proxies) -> str:
    cache_key = (gateway_url, client_id)
    cached = _token_cache.get(cache_key)
    if cached and time.time() < cached["expiry"] - 30:
        return cached["token"]

    token_url = f"{gateway_url}/auth/external"
    try:
        resp = requests.post(
            token_url,
            json={"clientId": client_id, "accessKey": access_key},
            timeout=timeout,
            verify=verify_ssl,
            proxies=proxies,
        )
    except requests.exceptions.ConnectionError:
        raise Exception(
            "Unable to connect to CheckPoint XDR. Please verify gateway_url and network connectivity."
        )
    except requests.exceptions.Timeout:
        raise Exception("Connection to CheckPoint XDR timed out.")

    if resp.status_code == 401:
        raise Exception("Authentication failed. Please verify client_id and access_key.")
    if resp.status_code != 200:
        raise Exception(f"Authentication failed: HTTP {resp.status_code}")

    data = resp.json()
    token = (data.get("data") or {}).get("token") or data.get("token")
    if not token:
        raise Exception("Authentication response missing token.")

    exp = _decode_jwt_exp(token)
    expires_in = (exp - time.time()) if exp else 3600
    _token_cache[cache_key] = {"token": token, "expiry": time.time() + expires_in}
    return token


def _invalidate_token(gateway_url: str, client_id: str):
    _token_cache.pop((gateway_url, client_id), None)


def _do_request(gateway_url: str, client_id: str, access_key: str,
                method: str, path: str, timeout: int, verify_ssl: bool, proxies,
                resource_hint: str = "", **kwargs):
    url = f"{gateway_url}{API_PATH}{path}"

    def _do(token):
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
                "Unable to connect to CheckPoint XDR. Please verify gateway_url and network connectivity."
            )
        except requests.exceptions.Timeout:
            raise Exception("Connection to CheckPoint XDR timed out.")

    token = _get_token(gateway_url, client_id, access_key, timeout, verify_ssl, proxies)
    resp = _do(token)

    if resp.status_code == 401:
        _invalidate_token(gateway_url, client_id)
        token = _get_token(gateway_url, client_id, access_key, timeout, verify_ssl, proxies)
        resp = _do(token)

    _handle_response_errors(resp, resource_hint)

    if resp.status_code == 204 or not resp.content:
        return {}
    return resp.json()


class CheckpointXdr:

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    # ------------------------------------------------------------------
    # FR-1: test_connection (hidden from UI)
    # ------------------------------------------------------------------
    def test_connection(self, connectionParameters: dict):
        cp = connectionParameters
        gateway_url = cp["gateway_url"].rstrip("/")
        client_id = cp["client_id"]
        access_key = cp["access_key"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        try:
            _do_request(gateway_url, client_id, access_key, "GET", "/version",
                        timeout, verify_ssl, proxies)
            return {"status": "success", "message": "Connected to CheckPoint XDR successfully."}
        except Exception:
            logging.getLogger().error("Exception while testing CheckPoint XDR connection", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-2: get_incidents
    # ------------------------------------------------------------------
    def get_incidents(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        gateway_url = cp["gateway_url"].rstrip("/")
        client_id = cp["client_id"]
        access_key = cp["access_key"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        p = request.parameters
        params = {}
        if p.get("from_date"):
            params["from"] = p["from_date"]
        if p.get("to_date"):
            params["to"] = p["to_date"]
        if p.get("filter_by"):
            params["filterBy"] = p["filter_by"]
        if p.get("limit") is not None:
            params["limit"] = int(p["limit"])
        if p.get("offset") is not None:
            params["offset"] = int(p["offset"])
        try:
            data = _do_request(gateway_url, client_id, access_key, "GET", "/incidents",
                               timeout, verify_ssl, proxies, params=params)
            return {"status": "success", "incidents": data}
        except Exception:
            logging.getLogger().error("error while running action 'get_incidents'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-3: get_incident_by_id
    # ------------------------------------------------------------------
    def get_incident_by_id(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        gateway_url = cp["gateway_url"].rstrip("/")
        client_id = cp["client_id"]
        access_key = cp["access_key"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        incident_id = request.parameters["incident_id"]
        try:
            data = _do_request(gateway_url, client_id, access_key, "GET",
                               f"/incidents/{incident_id}", timeout, verify_ssl, proxies,
                               resource_hint=f"incident {incident_id}")
            return {"status": "success", "incident": data}
        except Exception:
            logging.getLogger().error("error while running action 'get_incident_by_id'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-4: update_incident
    # ------------------------------------------------------------------
    def update_incident(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        gateway_url = cp["gateway_url"].rstrip("/")
        client_id = cp["client_id"]
        access_key = cp["access_key"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        p = request.parameters
        incident_id = p["incident_id"]
        body = {"status": p["status"]}
        if p.get("assignee"):
            body["assignee"] = p["assignee"]
        if p.get("assignee_name"):
            body["assigneeName"] = p["assignee_name"]
        if p.get("assignee_email"):
            body["assigneeEmail"] = p["assignee_email"]
        if p.get("is_prevented") is not None:
            body["isPrevented"] = bool(p["is_prevented"])
        if p.get("follow_up") is not None:
            body["followUp"] = bool(p["follow_up"])
        try:
            data = _do_request(gateway_url, client_id, access_key, "PUT",
                               f"/incidents/{incident_id}", timeout, verify_ssl, proxies,
                               resource_hint=f"incident {incident_id}", json=body)
            return {"status": "success", "incident": data}
        except Exception:
            logging.getLogger().error("error while running action 'update_incident'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-5: get_incident_comments
    # ------------------------------------------------------------------
    def get_incident_comments(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        gateway_url = cp["gateway_url"].rstrip("/")
        client_id = cp["client_id"]
        access_key = cp["access_key"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        incident_id = request.parameters["incident_id"]
        try:
            data = _do_request(gateway_url, client_id, access_key, "GET",
                               f"/incidents/{incident_id}/comments", timeout, verify_ssl, proxies,
                               resource_hint=f"incident {incident_id}")
            return {"status": "success", "comments": data}
        except Exception:
            logging.getLogger().error("error while running action 'get_incident_comments'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-6: add_incident_comment
    # ------------------------------------------------------------------
    def add_incident_comment(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        gateway_url = cp["gateway_url"].rstrip("/")
        client_id = cp["client_id"]
        access_key = cp["access_key"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        p = request.parameters
        incident_id = p["incident_id"]
        try:
            _do_request(gateway_url, client_id, access_key, "POST",
                        f"/incidents/{incident_id}/comments", timeout, verify_ssl, proxies,
                        resource_hint=f"incident {incident_id}",
                        json={"comment": p["comment"]})
            return {"status": "success", "message": "Comment added successfully."}
        except Exception:
            logging.getLogger().error("error while running action 'add_incident_comment'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-7: get_audit_logs
    # ------------------------------------------------------------------
    def get_audit_logs(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        gateway_url = cp["gateway_url"].rstrip("/")
        client_id = cp["client_id"]
        access_key = cp["access_key"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        p = request.parameters
        params = {}
        if p.get("limit") is not None:
            params["limit"] = int(p["limit"])
        if p.get("page") is not None:
            params["page"] = int(p["page"])
        if p.get("from_date"):
            params["fromDate"] = p["from_date"]
        if p.get("to_date"):
            params["toDate"] = p["to_date"]
        if p.get("search"):
            params["search"] = p["search"]
        for key, param_name in [("user", "user"), ("status", "status"),
                                 ("type", "type"), ("detail", "detail")]:
            val = p.get(key)
            if val:
                params[param_name] = val if isinstance(val, list) else [val]
        try:
            data = _do_request(gateway_url, client_id, access_key, "GET", "/auditlogs",
                               timeout, verify_ssl, proxies, params=params)
            return {
                "status": "success",
                "limit": data.get("limit"),
                "offset": data.get("offset"),
                "total": data.get("total"),
                "hasNext": data.get("hasNext"),
                "results": data.get("results", data),
            }
        except Exception:
            logging.getLogger().error("error while running action 'get_audit_logs'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-8: create_exclusion
    # ------------------------------------------------------------------
    def create_exclusion(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        gateway_url = cp["gateway_url"].rstrip("/")
        client_id = cp["client_id"]
        access_key = cp["access_key"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        p = request.parameters
        body = {"type": p["exclusion_type"], "value": p["value"]}
        if p.get("comment"):
            body["comment"] = p["comment"]
        if p.get("expiration_date"):
            body["expirationDate"] = p["expiration_date"]
        try:
            data = _do_request(gateway_url, client_id, access_key, "POST", "/exclusions",
                               timeout, verify_ssl, proxies, json=body)
            return {"status": "success", "exclusion": data}
        except Exception:
            logging.getLogger().error("error while running action 'create_exclusion'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-9: get_exclusions
    # ------------------------------------------------------------------
    def get_exclusions(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        gateway_url = cp["gateway_url"].rstrip("/")
        client_id = cp["client_id"]
        access_key = cp["access_key"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        p = request.parameters
        params = {}
        if p.get("limit") is not None:
            params["limit"] = int(p["limit"])
        if p.get("page") is not None:
            params["page"] = int(p["page"])
        if p.get("from_date"):
            params["fromDate"] = p["from_date"]
        if p.get("to_date"):
            params["toDate"] = p["to_date"]
        try:
            data = _do_request(gateway_url, client_id, access_key, "GET", "/exclusions",
                               timeout, verify_ssl, proxies, params=params)
            return {"status": "success", "exclusions": data}
        except Exception:
            logging.getLogger().error("error while running action 'get_exclusions'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-10: get_exclusion_by_id
    # ------------------------------------------------------------------
    def get_exclusion_by_id(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        gateway_url = cp["gateway_url"].rstrip("/")
        client_id = cp["client_id"]
        access_key = cp["access_key"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        exclusion_id = request.parameters["exclusion_id"]
        try:
            data = _do_request(gateway_url, client_id, access_key, "GET",
                               f"/exclusions/{exclusion_id}", timeout, verify_ssl, proxies,
                               resource_hint=f"exclusion {exclusion_id}")
            return {"status": "success", "exclusion": data}
        except Exception:
            logging.getLogger().error("error while running action 'get_exclusion_by_id'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-11: update_exclusion
    # ------------------------------------------------------------------
    def update_exclusion(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        gateway_url = cp["gateway_url"].rstrip("/")
        client_id = cp["client_id"]
        access_key = cp["access_key"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        p = request.parameters
        exclusion_id = p["exclusion_id"]
        body = {}
        if p.get("comment"):
            body["comment"] = p["comment"]
        if p.get("expiration_date"):
            body["expirationDate"] = p["expiration_date"]
        try:
            data = _do_request(gateway_url, client_id, access_key, "PUT",
                               f"/exclusions/{exclusion_id}", timeout, verify_ssl, proxies,
                               resource_hint=f"exclusion {exclusion_id}", json=body)
            return {"status": "success", "exclusion": data}
        except Exception:
            logging.getLogger().error("error while running action 'update_exclusion'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-12: delete_exclusion
    # ------------------------------------------------------------------
    def delete_exclusion(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        gateway_url = cp["gateway_url"].rstrip("/")
        client_id = cp["client_id"]
        access_key = cp["access_key"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        exclusion_id = request.parameters["exclusion_id"]
        try:
            _do_request(gateway_url, client_id, access_key, "DELETE",
                        f"/exclusions/{exclusion_id}", timeout, verify_ssl, proxies,
                        resource_hint=f"exclusion {exclusion_id}")
            return {"status": "success", "message": "Exclusion deleted successfully."}
        except Exception:
            logging.getLogger().error("error while running action 'delete_exclusion'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-13: get_responses_by_incident
    # ------------------------------------------------------------------
    def get_responses_by_incident(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        gateway_url = cp["gateway_url"].rstrip("/")
        client_id = cp["client_id"]
        access_key = cp["access_key"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        incident_id = request.parameters["incident_id"]
        try:
            data = _do_request(gateway_url, client_id, access_key, "GET",
                               f"/responses/{incident_id}", timeout, verify_ssl, proxies,
                               resource_hint=f"incident {incident_id}")
            return {"status": "success", "responses": data}
        except Exception:
            logging.getLogger().error("error while running action 'get_responses_by_incident'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-14: execute_response_action
    # ------------------------------------------------------------------
    def execute_response_action(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        gateway_url = cp["gateway_url"].rstrip("/")
        client_id = cp["client_id"]
        access_key = cp["access_key"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        p = request.parameters
        action = p["action"]
        response_ids = p["response_ids"]
        if isinstance(response_ids, str):
            response_ids = [response_ids]
        try:
            data = _do_request(gateway_url, client_id, access_key, "POST",
                               f"/responses/action/{action}", timeout, verify_ssl, proxies,
                               json={"responsesIds": response_ids})
            return {"status": "success", "result": data}
        except Exception:
            logging.getLogger().error("error while running action 'execute_response_action'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-15: get_data_sources
    # ------------------------------------------------------------------
    def get_data_sources(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        gateway_url = cp["gateway_url"].rstrip("/")
        client_id = cp["client_id"]
        access_key = cp["access_key"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        try:
            data = _do_request(gateway_url, client_id, access_key, "GET", "/datasources",
                               timeout, verify_ssl, proxies)
            return {"status": "success", "data_sources": data}
        except Exception:
            logging.getLogger().error("error while running action 'get_data_sources'", exc_info=True)
            raise
