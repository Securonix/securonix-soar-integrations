from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import base64
import logging
import time
import requests


DEFAULT_TIMEOUT = 30

_REGION_TLD = {
    "northamerica": "com",
    "europe": "eu",
    "asiapacific": "asia",
    "canada": "ca",
}


def _region_to_tld(region: str) -> str:
    tld = _REGION_TLD.get(region.lower().replace(" ", ""))
    if not tld:
        raise Exception(
            f"Unknown region {region!r}. Valid values: NorthAmerica, Europe, AsiaPacific, Canada."
        )
    return tld


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
        raise Exception("Authentication failed. Please verify client_id and client_secret.")
    if resp.status_code == 403:
        raise Exception(
            f"Authorization failed. Please verify the application has required PingOne scopes. "
            f"Detail: {_api_error_detail(resp)}"
        )
    if resp.status_code == 404:
        hint = f": {resource_hint} does not exist." if resource_hint else "."
        raise Exception(f"Resource not found{hint}")
    if resp.status_code >= 500:
        raise Exception(f"PingOne server error: HTTP {resp.status_code}. Detail: {_api_error_detail(resp)}")
    if resp.status_code >= 400:
        raise Exception(f"PingOne rejected the request: HTTP {resp.status_code}. Detail: {_api_error_detail(resp)}")


class PingOne:

    def __init__(self) -> None:
        self.logger = logging.getLogger()
        self._token_cache: dict = {}

    # ------------------------------------------------------------------
    # Auth helpers
    # ------------------------------------------------------------------
    def _get_token(self, auth_base: str, env_id: str, client_id: str,
                   client_secret: str, timeout: int, verify_ssl: bool, proxies) -> str:
        cache_key = (auth_base, client_id)
        cached = self._token_cache.get(cache_key)
        if cached and time.time() < cached["expiry"] - 30:
            return cached["token"]

        credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        token_url = f"{auth_base}/{env_id}/as/token"

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
                "Unable to connect to PingOne. Please verify region, environment_id, and network connectivity."
            )
        except requests.exceptions.Timeout:
            raise Exception("Connection to PingOne timed out.")

        if resp.status_code == 401:
            raise Exception("Authentication failed. Please verify client_id and client_secret.")
        if resp.status_code != 200:
            raise Exception(f"Authentication failed: HTTP {resp.status_code}")

        data = resp.json()
        token = data.get("access_token")
        if not token:
            raise Exception("Authentication response missing access_token.")

        expires_in = data.get("expires_in", 3600)
        self._token_cache[cache_key] = {"token": token, "expiry": time.time() + expires_in}
        return token

    def _invalidate_token(self, auth_base: str, client_id: str):
        self._token_cache.pop((auth_base, client_id), None)

    def _request(self, auth_base: str, api_base: str, env_id: str, client_id: str,
                 client_secret: str, method: str, path: str, timeout: int,
                 verify_ssl: bool, proxies, resource_hint: str = "", **kwargs):
        url = f"{api_base}/v1/environments/{env_id}{path}"
        content_type = kwargs.pop("content_type", "application/json")

        def _do(token):
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": content_type,
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
                    "Unable to connect to PingOne. Please verify region, environment_id, and network connectivity."
                )
            except requests.exceptions.Timeout:
                raise Exception("Connection to PingOne timed out.")

        token = self._get_token(auth_base, env_id, client_id, client_secret, timeout, verify_ssl, proxies)
        resp = _do(token)

        if resp.status_code == 401:
            self._invalidate_token(auth_base, client_id)
            token = self._get_token(auth_base, env_id, client_id, client_secret, timeout, verify_ssl, proxies)
            resp = _do(token)

        _handle_response_errors(resp, resource_hint)

        if resp.status_code in (204, 200) and not resp.content:
            return {}
        if resp.status_code == 204:
            return {}
        return resp.json()

    # ------------------------------------------------------------------
    # Test connection (Python-only — not in integration_definition.json)
    # ------------------------------------------------------------------
    def test_connection(self, connectionParameters: dict):
        cp = connectionParameters
        tld = _region_to_tld(cp["region"])
        auth_base = f"https://auth.pingone.{tld}"
        api_base = f"https://api.pingone.{tld}"
        env_id = cp["environment_id"]
        client_id = cp["client_id"]
        client_secret = cp["client_secret"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        try:
            self._request(
                auth_base, api_base, env_id, client_id, client_secret,
                "GET", "/users", timeout, verify_ssl, proxies,
                params={"limit": 1},
            )
            return {"status": "success", "message": "Connected to PingOne successfully."}
        except Exception:
            self.logger.error("Exception while testing PingOne connection", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-2: unlock_user
    # ------------------------------------------------------------------
    def unlock_user(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        tld = _region_to_tld(cp["region"])
        auth_base = f"https://auth.pingone.{tld}"
        api_base = f"https://api.pingone.{tld}"
        env_id = cp["environment_id"]
        client_id = cp["client_id"]
        client_secret = cp["client_secret"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        user_id = request.parameters["user_id"]
        try:
            self._request(
                auth_base, api_base, env_id, client_id, client_secret,
                "POST", f"/users/{user_id}/password",
                timeout, verify_ssl, proxies,
                resource_hint=f"user {user_id}",
                content_type="application/vnd.pingidentity.password.unlock+json",
            )
            return {"status": "success", "message": "User unlocked successfully."}
        except Exception:
            self.logger.error("error while running action 'unlock_user'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-3: deactivate_user
    # ------------------------------------------------------------------
    def deactivate_user(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        tld = _region_to_tld(cp["region"])
        auth_base = f"https://auth.pingone.{tld}"
        api_base = f"https://api.pingone.{tld}"
        env_id = cp["environment_id"]
        client_id = cp["client_id"]
        client_secret = cp["client_secret"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        user_id = request.parameters["user_id"]
        try:
            self._request(
                auth_base, api_base, env_id, client_id, client_secret,
                "PUT", f"/users/{user_id}/enabled",
                timeout, verify_ssl, proxies,
                resource_hint=f"user {user_id}",
                json={"enabled": False},
            )
            return {"status": "success", "message": "User deactivated successfully."}
        except Exception:
            self.logger.error("error while running action 'deactivate_user'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-4: activate_user
    # ------------------------------------------------------------------
    def activate_user(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        tld = _region_to_tld(cp["region"])
        auth_base = f"https://auth.pingone.{tld}"
        api_base = f"https://api.pingone.{tld}"
        env_id = cp["environment_id"]
        client_id = cp["client_id"]
        client_secret = cp["client_secret"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        user_id = request.parameters["user_id"]
        try:
            self._request(
                auth_base, api_base, env_id, client_id, client_secret,
                "PUT", f"/users/{user_id}/enabled",
                timeout, verify_ssl, proxies,
                resource_hint=f"user {user_id}",
                json={"enabled": True},
            )
            return {"status": "success", "message": "User activated successfully."}
        except Exception:
            self.logger.error("error while running action 'activate_user'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-5: set_password
    # ------------------------------------------------------------------
    def set_password(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        tld = _region_to_tld(cp["region"])
        auth_base = f"https://auth.pingone.{tld}"
        api_base = f"https://api.pingone.{tld}"
        env_id = cp["environment_id"]
        client_id = cp["client_id"]
        client_secret = cp["client_secret"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        user_id = request.parameters["user_id"]
        new_password = request.parameters["new_password"]
        try:
            self._request(
                auth_base, api_base, env_id, client_id, client_secret,
                "PUT", f"/users/{user_id}/password",
                timeout, verify_ssl, proxies,
                resource_hint=f"user {user_id}",
                json={"newPassword": new_password},
            )
            return {"status": "success", "message": "Password set successfully."}
        except Exception:
            self.logger.error("error while running action 'set_password'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-6: force_password_change
    # ------------------------------------------------------------------
    def force_password_change(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        tld = _region_to_tld(cp["region"])
        auth_base = f"https://auth.pingone.{tld}"
        api_base = f"https://api.pingone.{tld}"
        env_id = cp["environment_id"]
        client_id = cp["client_id"]
        client_secret = cp["client_secret"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        user_id = request.parameters["user_id"]
        try:
            self._request(
                auth_base, api_base, env_id, client_id, client_secret,
                "POST", f"/users/{user_id}/password",
                timeout, verify_ssl, proxies,
                resource_hint=f"user {user_id}",
                content_type="application/vnd.pingidentity.password.forceChange",
            )
            return {"status": "success", "message": "Password change required at next sign-in."}
        except Exception:
            self.logger.error("error while running action 'force_password_change'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-7: get_password_state
    # ------------------------------------------------------------------
    def get_password_state(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        tld = _region_to_tld(cp["region"])
        auth_base = f"https://auth.pingone.{tld}"
        api_base = f"https://api.pingone.{tld}"
        env_id = cp["environment_id"]
        client_id = cp["client_id"]
        client_secret = cp["client_secret"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        user_id = request.parameters["user_id"]
        try:
            data = self._request(
                auth_base, api_base, env_id, client_id, client_secret,
                "GET", f"/users/{user_id}/password",
                timeout, verify_ssl, proxies,
                resource_hint=f"user {user_id}",
            )
            return {"status": "success", "password_state": data}
        except Exception:
            self.logger.error("error while running action 'get_password_state'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-8: add_user_to_group
    # ------------------------------------------------------------------
    def add_user_to_group(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        tld = _region_to_tld(cp["region"])
        auth_base = f"https://auth.pingone.{tld}"
        api_base = f"https://api.pingone.{tld}"
        env_id = cp["environment_id"]
        client_id = cp["client_id"]
        client_secret = cp["client_secret"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        user_id = request.parameters["user_id"]
        group_id = request.parameters["group_id"]
        try:
            self._request(
                auth_base, api_base, env_id, client_id, client_secret,
                "POST", f"/users/{user_id}/memberOfGroups",
                timeout, verify_ssl, proxies,
                resource_hint=f"user {user_id} or group {group_id}",
                json={"id": group_id},
            )
            return {"status": "success", "message": "User added to group successfully."}
        except Exception:
            self.logger.error("error while running action 'add_user_to_group'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-9: remove_user_from_group
    # ------------------------------------------------------------------
    def remove_user_from_group(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        tld = _region_to_tld(cp["region"])
        auth_base = f"https://auth.pingone.{tld}"
        api_base = f"https://api.pingone.{tld}"
        env_id = cp["environment_id"]
        client_id = cp["client_id"]
        client_secret = cp["client_secret"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        user_id = request.parameters["user_id"]
        group_id = request.parameters["group_id"]
        try:
            self._request(
                auth_base, api_base, env_id, client_id, client_secret,
                "DELETE", f"/users/{user_id}/memberOfGroups/{group_id}",
                timeout, verify_ssl, proxies,
                resource_hint=f"membership of user {user_id} in group {group_id}",
            )
            return {"status": "success", "message": "User removed from group successfully."}
        except Exception:
            self.logger.error("error while running action 'remove_user_from_group'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-10: get_user_groups
    # ------------------------------------------------------------------
    def get_user_groups(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        tld = _region_to_tld(cp["region"])
        auth_base = f"https://auth.pingone.{tld}"
        api_base = f"https://api.pingone.{tld}"
        env_id = cp["environment_id"]
        client_id = cp["client_id"]
        client_secret = cp["client_secret"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        user_id = request.parameters["user_id"]
        params = {}
        if request.parameters.get("cursor"):
            params["cursor"] = request.parameters["cursor"]
        if request.parameters.get("limit"):
            params["limit"] = request.parameters["limit"]
        try:
            data = self._request(
                auth_base, api_base, env_id, client_id, client_secret,
                "GET", f"/users/{user_id}/memberOfGroups",
                timeout, verify_ssl, proxies,
                resource_hint=f"user {user_id}",
                params=params,
            )
            next_href = data.get("_links", {}).get("next", {}).get("href")
            next_cursor = None
            if next_href:
                from urllib.parse import urlparse, parse_qs
                qs = parse_qs(urlparse(next_href).query)
                next_cursor = qs.get("cursor", [None])[0]
            return {
                "status": "success",
                "groups": data.get("_embedded", {}).get("groupMemberships", []),
                "next_cursor": next_cursor,
            }
        except Exception:
            self.logger.error("error while running action 'get_user_groups'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-11: get_user
    # ------------------------------------------------------------------
    def get_user(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        tld = _region_to_tld(cp["region"])
        auth_base = f"https://auth.pingone.{tld}"
        api_base = f"https://api.pingone.{tld}"
        env_id = cp["environment_id"]
        client_id = cp["client_id"]
        client_secret = cp["client_secret"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        user_id = request.parameters.get("user_id", "").strip()
        username = request.parameters.get("username", "").strip()
        if not user_id and not username:
            raise Exception("Either user_id or username must be provided.")
        try:
            if user_id:
                data = self._request(
                    auth_base, api_base, env_id, client_id, client_secret,
                    "GET", f"/users/{user_id}",
                    timeout, verify_ssl, proxies,
                    resource_hint=f"user {user_id}",
                )
                return {"status": "success", "user": data}
            else:
                data = self._request(
                    auth_base, api_base, env_id, client_id, client_secret,
                    "GET", "/users",
                    timeout, verify_ssl, proxies,
                    params={"filter": f'username eq "{username}"'},
                )
                users = data.get("_embedded", {}).get("users", [])
                if not users:
                    raise Exception("User not found.")
                return {"status": "success", "user": users[0]}
        except Exception:
            self.logger.error("error while running action 'get_user'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-12: create_user
    # ------------------------------------------------------------------
    def create_user(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        tld = _region_to_tld(cp["region"])
        auth_base = f"https://auth.pingone.{tld}"
        api_base = f"https://api.pingone.{tld}"
        env_id = cp["environment_id"]
        client_id = cp["client_id"]
        client_secret = cp["client_secret"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        p = request.parameters
        body = {
            "username": p["username"],
            "email": {"address": p["email"]},
            "population": {"id": p["population_id"]},
        }
        given = p.get("given_name", "").strip()
        family = p.get("family_name", "").strip()
        if given or family:
            body["name"] = {}
            if given:
                body["name"]["given"] = given
            if family:
                body["name"]["family"] = family
        try:
            data = self._request(
                auth_base, api_base, env_id, client_id, client_secret,
                "POST", "/users",
                timeout, verify_ssl, proxies,
                json=body,
            )
            return {
                "status": "success",
                "user": {
                    "id": data.get("id"),
                    "username": data.get("username"),
                    "email": data.get("email", {}).get("address"),
                },
            }
        except Exception:
            self.logger.error("error while running action 'create_user'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-13: update_user
    # ------------------------------------------------------------------
    def update_user(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        tld = _region_to_tld(cp["region"])
        auth_base = f"https://auth.pingone.{tld}"
        api_base = f"https://api.pingone.{tld}"
        env_id = cp["environment_id"]
        client_id = cp["client_id"]
        client_secret = cp["client_secret"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        user_id = request.parameters["user_id"]
        p = request.parameters
        body = {}
        given = p.get("given_name", "").strip()
        family = p.get("family_name", "").strip()
        if given or family:
            body["name"] = {}
            if given:
                body["name"]["given"] = given
            if family:
                body["name"]["family"] = family
        email = p.get("email", "").strip()
        if email:
            body["email"] = {"address": email}
        if not body:
            raise Exception("At least one field (given_name, family_name, email) must be provided.")
        try:
            data = self._request(
                auth_base, api_base, env_id, client_id, client_secret,
                "PATCH", f"/users/{user_id}",
                timeout, verify_ssl, proxies,
                resource_hint=f"user {user_id}",
                json=body,
            )
            return {"status": "success", "user": data}
        except Exception:
            self.logger.error("error while running action 'update_user'", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # FR-14: delete_user
    # ------------------------------------------------------------------
    def delete_user(self, request: RequestBody) -> ResponseBody:
        cp = request.connectionParameters
        tld = _region_to_tld(cp["region"])
        auth_base = f"https://auth.pingone.{tld}"
        api_base = f"https://api.pingone.{tld}"
        env_id = cp["environment_id"]
        client_id = cp["client_id"]
        client_secret = cp["client_secret"]
        timeout = _get_timeout(cp)
        verify_ssl = _get_verify_ssl(cp)
        proxies = _get_proxies(cp)
        user_id = request.parameters.get("user_id", "").strip()
        username = request.parameters.get("username", "").strip()
        if not user_id and not username:
            raise Exception("Either user_id or username must be provided.")
        try:
            if not user_id:
                data = self._request(
                    auth_base, api_base, env_id, client_id, client_secret,
                    "GET", "/users",
                    timeout, verify_ssl, proxies,
                    params={"filter": f'username eq "{username}"'},
                )
                users = data.get("_embedded", {}).get("users", [])
                if not users:
                    raise Exception("User not found.")
                user_id = users[0]["id"]
            self._request(
                auth_base, api_base, env_id, client_id, client_secret,
                "DELETE", f"/users/{user_id}",
                timeout, verify_ssl, proxies,
                resource_hint=f"user {user_id}",
            )
            return {"status": "success", "message": "User deleted successfully."}
        except Exception:
            self.logger.error("error while running action 'delete_user'", exc_info=True)
            raise
