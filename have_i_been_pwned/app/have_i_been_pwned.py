from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import re
import time
from urllib.parse import quote

import requests


MAX_RETRIES = 3
BACKOFF_FACTOR = 2
DEFAULT_RETRY_AFTER = 2
REQUEST_TIMEOUT = 30

_RE_HASH_PREFIX_5 = re.compile(r"^[0-9a-fA-F]{5}$")
_RE_HASH_PREFIX_6 = re.compile(r"^[0-9a-fA-F]{6}$")


class HaveIBeenPwned():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    # -------------------------------
    # Internal helpers
    # -------------------------------
    @staticmethod
    def _to_bool(value, default=False):
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("true", "1", "yes")

    def _get_config(self, source: dict) -> dict:
        """Read the connection parameters. All are required (see integration_definition.json)."""
        return {
            "base_url": source['base_url'].rstrip('/'),
            "passwords_base_url": source['passwords_base_url'].rstrip('/'),
            "api_key": source['api_key'],
            "user_agent": source['user_agent'],
        }

    @staticmethod
    def _parse_retry_after(resp, default=DEFAULT_RETRY_AFTER):
        value = resp.headers.get("Retry-After") or resp.headers.get("retry-after")
        if value is None:
            return default
        try:
            return max(0, int(float(value)))
        except (ValueError, TypeError):
            return default

    def _request(self, url, cfg, authenticated, params=None, extra_headers=None, allow_404=True):
        """
        Perform a GET against HIBP with the repo-standard error normalization.

        - user-agent is sent on every request (missing one yields HTTP 403 from HIBP).
        - hibp-api-key is only attached on authenticated endpoints.
        - 429 responses honor the Retry-After header and are retried.
        - 5xx/503 responses are retried with exponential backoff.
        Returns the raw ``requests.Response`` so callers can decide how to parse
        the body (JSON vs. plain text) and how to treat 404.
        """
        headers = {"user-agent": cfg["user_agent"]}
        if authenticated:
            headers["hibp-api-key"] = cfg["api_key"]
        if extra_headers:
            headers.update(extra_headers)

        self.logger.debug("HIBP API request: GET %s", url)

        for attempt in range(MAX_RETRIES):
            try:
                resp = requests.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=REQUEST_TIMEOUT,
                )
            except requests.exceptions.Timeout:
                raise Exception("Connection to Have I Been Pwned timed out.")
            except requests.exceptions.ConnectionError:
                raise Exception("Unable to connect to Have I Been Pwned. Check base_url and network.")

            code = resp.status_code

            if code == 200:
                return resp
            if code == 404:
                if allow_404:
                    return resp
                raise Exception("Resource not found (HTTP 404).")
            if code == 400:
                raise Exception("Bad request (HTTP 400): the supplied value is not in an acceptable format.")
            if code == 401:
                raise Exception("Authentication failed (HTTP 401): the hibp-api-key is missing or invalid.")
            if code == 403:
                raise Exception(
                    "Forbidden (HTTP 403): a valid user-agent is required, or the account does not "
                    "have access to this resource (e.g. an unverified domain)."
                )
            if code == 429:
                retry_after = self._parse_retry_after(resp)
                if attempt < MAX_RETRIES - 1:
                    self.logger.info(
                        "Rate limited (HTTP 429). Honoring Retry-After of %s second(s).", retry_after
                    )
                    time.sleep(retry_after)
                    continue
                raise Exception(f"Rate limit exceeded (HTTP 429). Retry after {retry_after} second(s).")
            if code >= 500:
                if attempt < MAX_RETRIES - 1:
                    time.sleep(BACKOFF_FACTOR ** (attempt + 1))
                    continue
                raise Exception(f"Have I Been Pwned service unavailable (HTTP {code}).")

            raise Exception(f"Have I Been Pwned API error (HTTP {code}).")

    # -------------------------------
    # Test Connection (SOAR calls this)
    # -------------------------------
    def test_connection(self, connectionParameters: dict):
        try:
            cfg = self._get_config(connectionParameters)

            # Validate the api_key and user-agent against the authenticated subscription
            # status endpoint. A valid key returns HTTP 200; an invalid key returns HTTP 401.
            url = f"{cfg['base_url']}/subscription/status"
            self._request(url, cfg, authenticated=True, allow_404=True)

            return {"status": "success", "message": "Connected to Have I Been Pwned successfully."}
        except Exception as e:
            self.logger.error("Exception while testing Have I Been Pwned connection", exc_info=e)
            raise Exception(str(e))

    # -------------------------------
    # Authenticated actions
    # -------------------------------
    def check_breached_account(self, request: RequestBody) -> ResponseBody:
        try:
            cfg = self._get_config(request.connectionParameters)

            account = (request.parameters.get("account") or "").strip()
            if not account:
                raise Exception("account is required and cannot be empty.")

            truncate_response = self._to_bool(request.parameters.get("truncate_response"), default=True)
            include_unverified = self._to_bool(request.parameters.get("include_unverified"), default=True)
            domain = (request.parameters.get("domain") or "").strip()

            params = {
                "truncateResponse": "true" if truncate_response else "false",
                "IncludeUnverified": "true" if include_unverified else "false",
            }
            if domain:
                params["domain"] = domain

            url = f"{cfg['base_url']}/breachedaccount/{quote(account, safe='')}"
            resp = self._request(url, cfg, authenticated=True, params=params, allow_404=True)

            if resp.status_code == 404:
                return {
                    "status": "success",
                    "account": account,
                    "breached": False,
                    "truncated": truncate_response,
                    "breaches": [],
                    "total": 0,
                }

            data = resp.json() if resp.text else []
            if not isinstance(data, list):
                data = []

            return {
                "status": "success",
                "account": account,
                "breached": len(data) > 0,
                "truncated": truncate_response,
                "breaches": data,
                "total": len(data),
            }
        except Exception as e:
            self.logger.error("Error in check_breached_account", exc_info=e)
            raise Exception(str(e))

    def check_breached_domain(self, request: RequestBody) -> ResponseBody:
        try:
            cfg = self._get_config(request.connectionParameters)

            domain = (request.parameters.get("domain") or "").strip()
            if not domain:
                raise Exception("domain is required and cannot be empty.")

            url = f"{cfg['base_url']}/breacheddomain/{quote(domain, safe='')}"
            resp = self._request(url, cfg, authenticated=True, allow_404=True)

            if resp.status_code == 404:
                return {
                    "status": "success",
                    "domain": domain,
                    "breached_accounts": {},
                    "total": 0,
                }

            data = resp.json() if resp.text else {}
            if not isinstance(data, dict):
                data = {}

            return {
                "status": "success",
                "domain": domain,
                "breached_accounts": data,
                "total": len(data),
            }
        except Exception as e:
            self.logger.error("Error in check_breached_domain", exc_info=e)
            raise Exception(str(e))

    def check_paste_account(self, request: RequestBody) -> ResponseBody:
        try:
            cfg = self._get_config(request.connectionParameters)

            account = (request.parameters.get("account") or "").strip()
            if not account:
                raise Exception("account is required and cannot be empty.")

            url = f"{cfg['base_url']}/pasteaccount/{quote(account, safe='')}"
            resp = self._request(url, cfg, authenticated=True, allow_404=True)

            if resp.status_code == 404:
                return {
                    "status": "success",
                    "account": account,
                    "pastes": [],
                    "total": 0,
                }

            data = resp.json() if resp.text else []
            if not isinstance(data, list):
                data = []

            return {
                "status": "success",
                "account": account,
                "pastes": data,
                "total": len(data),
            }
        except Exception as e:
            self.logger.error("Error in check_paste_account", exc_info=e)
            raise Exception(str(e))

    def check_stealer_logs_by_email(self, request: RequestBody) -> ResponseBody:
        try:
            cfg = self._get_config(request.connectionParameters)

            email = (request.parameters.get("email") or "").strip()
            if not email:
                raise Exception("email is required and cannot be empty.")

            url = f"{cfg['base_url']}/stealerlogsbyemail/{quote(email, safe='')}"
            resp = self._request(url, cfg, authenticated=True, allow_404=True)

            if resp.status_code == 404:
                return {
                    "status": "success",
                    "email": email,
                    "website_domains": [],
                    "total": 0,
                }

            data = resp.json() if resp.text else []
            if not isinstance(data, list):
                data = []

            return {
                "status": "success",
                "email": email,
                "website_domains": data,
                "total": len(data),
            }
        except Exception as e:
            self.logger.error("Error in check_stealer_logs_by_email", exc_info=e)
            raise Exception(str(e))

    def check_breached_account_range(self, request: RequestBody) -> ResponseBody:
        try:
            cfg = self._get_config(request.connectionParameters)

            hash_prefix = (request.parameters.get("hash_prefix") or "").strip()
            if not hash_prefix:
                raise Exception("hash_prefix is required and cannot be empty.")
            if not _RE_HASH_PREFIX_6.match(hash_prefix):
                raise Exception(
                    "hash_prefix must be the first 6 hexadecimal characters of the normalized email SHA-1 hash."
                )

            url = f"{cfg['base_url']}/breachedaccount/range/{hash_prefix}"
            resp = self._request(url, cfg, authenticated=True, allow_404=True)

            # This API returns HTTP 200 for every valid prefix; 404 is not expected.
            if resp.status_code == 404:
                return {
                    "status": "success",
                    "hash_prefix": hash_prefix,
                    "results": [],
                    "total": 0,
                }

            data = resp.json() if resp.text else []
            if not isinstance(data, list):
                data = []

            return {
                "status": "success",
                "hash_prefix": hash_prefix,
                "results": data,
                "total": len(data),
            }
        except Exception as e:
            self.logger.error("Error in check_breached_account_range", exc_info=e)
            raise Exception(str(e))

    # -------------------------------
    # Unauthenticated actions (user-agent still required)
    # -------------------------------
    def check_password_range(self, request: RequestBody) -> ResponseBody:
        try:
            cfg = self._get_config(request.connectionParameters)

            hash_prefix = (request.parameters.get("hash_prefix") or "").strip()
            if not hash_prefix:
                raise Exception("hash_prefix is required and cannot be empty.")
            if not _RE_HASH_PREFIX_5.match(hash_prefix):
                raise Exception(
                    "hash_prefix must be the first 5 hexadecimal characters of a SHA-1 or NTLM password hash."
                )

            add_padding = self._to_bool(request.parameters.get("add_padding"), default=False)
            mode = (request.parameters.get("mode") or "").strip().lower()
            is_ntlm = mode == "ntlm"

            params = {}
            if is_ntlm:
                params["mode"] = "ntlm"

            extra_headers = {"Add-Padding": "true"} if add_padding else None

            # Pwned Passwords range API is unauthenticated and always returns HTTP 200.
            url = f"{cfg['passwords_base_url']}/range/{hash_prefix}"
            resp = self._request(
                url, cfg, authenticated=False, params=params, extra_headers=extra_headers, allow_404=False
            )

            results = []
            for line in (resp.text or "").splitlines():
                line = line.strip()
                if not line or ":" not in line:
                    continue
                suffix, _, count_str = line.partition(":")
                try:
                    count = int(count_str.strip())
                except (ValueError, TypeError):
                    continue
                # Padded entries always have a count of 0 and must be discarded.
                if count == 0:
                    continue
                results.append({"hashSuffix": suffix.strip(), "count": count})

            return {
                "status": "success",
                "hash_prefix": hash_prefix,
                "mode": "ntlm" if is_ntlm else "sha1",
                "results": results,
                "total": len(results),
            }
        except Exception as e:
            self.logger.error("Error in check_password_range", exc_info=e)
            raise Exception(str(e))

    def get_latest_breach(self, request: RequestBody) -> ResponseBody:
        try:
            cfg = self._get_config(request.connectionParameters)

            url = f"{cfg['base_url']}/latestbreach"
            resp = self._request(url, cfg, authenticated=False, allow_404=True)

            if resp.status_code == 404:
                return {"status": "success", "breach": {}}

            data = resp.json() if resp.text else {}
            if not isinstance(data, dict):
                data = {}

            return {"status": "success", "breach": data}
        except Exception as e:
            self.logger.error("Error in get_latest_breach", exc_info=e)
            raise Exception(str(e))

    def get_breaches(self, request: RequestBody) -> ResponseBody:
        try:
            cfg = self._get_config(request.connectionParameters)

            params = {}
            domain = (request.parameters.get("domain") or "").strip()
            if domain:
                params["Domain"] = domain
            if request.parameters.get("is_spam_list") is not None:
                params["IsSpamList"] = "true" if self._to_bool(request.parameters.get("is_spam_list")) else "false"

            url = f"{cfg['base_url']}/breaches"
            resp = self._request(url, cfg, authenticated=False, params=params, allow_404=True)

            if resp.status_code == 404:
                return {"status": "success", "breaches": [], "total": 0}

            data = resp.json() if resp.text else []
            if not isinstance(data, list):
                data = []

            return {"status": "success", "breaches": data, "total": len(data)}
        except Exception as e:
            self.logger.error("Error in get_breaches", exc_info=e)
            raise Exception(str(e))

    def get_data_classes(self, request: RequestBody) -> ResponseBody:
        try:
            cfg = self._get_config(request.connectionParameters)

            url = f"{cfg['base_url']}/dataclasses"
            resp = self._request(url, cfg, authenticated=False, allow_404=True)

            if resp.status_code == 404:
                return {"status": "success", "data_classes": [], "total": 0}

            data = resp.json() if resp.text else []
            if not isinstance(data, list):
                data = []

            return {"status": "success", "data_classes": data, "total": len(data)}
        except Exception as e:
            self.logger.error("Error in get_data_classes", exc_info=e)
            raise Exception(str(e))
