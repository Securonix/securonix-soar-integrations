from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import re
import time
import requests


_RE_IPV4 = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$")
_RE_IPV6 = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
_RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_RE_URL = re.compile(r"^https?://[^\s]{1,2040}$")
_RE_HASH = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")

VALID_RISK_LEVELS = {"none", "low", "medium", "high", "critical", "unknown"}
VALID_INDICATOR_TYPES = {"ip", "domain", "url", "hash"}

MAX_RETRIES = 3
BACKOFF_FACTOR = 2


class Pulsedive():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    def test_connection(self, connectionParameters: dict):
        try:
            api_key = connectionParameters.get("api_key", "")
            if not api_key or not str(api_key).strip():
                raise Exception("api_key is required.")
            api_key = str(api_key).strip()
            base_url = (connectionParameters.get("base_url") or "https://pulsedive.com/api").rstrip("/")
            timeout = int(connectionParameters.get("timeout") or 30)
            verify_ssl = connectionParameters.get("verify_ssl", True)
            if isinstance(verify_ssl, str):
                verify_ssl = verify_ssl.lower() in ("true", "1", "yes")
            proxy = connectionParameters.get("proxy")
            proxies = {"http": proxy, "https": proxy} if proxy else None

            resp = requests.get(
                f"{base_url}/indicator.php",
                params={"indicator": "pulsedive.com", "pretty": "1", "key": api_key},
                timeout=timeout,
                verify=verify_ssl,
                proxies=proxies,
            )
            if resp.status_code in (401, 403):
                raise Exception("Authentication failed. Verify api_key.")
            if resp.status_code >= 500:
                raise Exception(f"Pulsedive server error (HTTP {resp.status_code}).")
            return {"status": "success", "message": "Connected to Pulsedive successfully."}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Pulsedive. Check base_url and network.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Pulsedive timed out.")
        except Exception as e:
            self.logger.error("Exception while testing connection", exc_info=e)
            raise Exception(str(e))

    def get_indicator_details(self, request: RequestBody) -> ResponseBody:
        try:
            api_key = str(request.connectionParameters.get("api_key", "")).strip()
            if not api_key:
                raise Exception("api_key is required.")
            base_url = (request.connectionParameters.get("base_url") or "https://pulsedive.com/api").rstrip("/")
            timeout = int(request.connectionParameters.get("timeout") or 30)
            verify_ssl = request.connectionParameters.get("verify_ssl", True)
            if isinstance(verify_ssl, str):
                verify_ssl = verify_ssl.lower() in ("true", "1", "yes")
            proxy = request.connectionParameters.get("proxy")
            proxies = {"http": proxy, "https": proxy} if proxy else None

            indicator = (request.parameters.get("indicator") or "").strip()
            if not indicator:
                raise Exception("indicator is required and cannot be empty.")
            if len(indicator) > 2048:
                raise Exception("indicator exceeds maximum length of 2048 characters.")

            for attempt in range(MAX_RETRIES):
                resp = requests.get(
                    f"{base_url}/indicator.php",
                    params={"indicator": indicator, "pretty": "1", "key": api_key},
                    timeout=timeout,
                    verify=verify_ssl,
                    proxies=proxies,
                )
                if resp.status_code in (401, 403):
                    raise Exception("Authentication failed. Verify api_key.")
                if resp.status_code == 404:
                    return {"status": "success", "indicator": {}}
                if resp.status_code == 429 or resp.status_code >= 500:
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(BACKOFF_FACTOR ** (attempt + 1))
                        continue
                    msg = "Rate limit exceeded. Please try again later." if resp.status_code == 429 else f"Pulsedive server error (HTTP {resp.status_code})."
                    raise Exception(msg)
                if resp.status_code != 200:
                    raise Exception(f"Pulsedive API error (HTTP {resp.status_code}).")
                data = resp.json()
                if isinstance(data, dict) and data.get("error"):
                    raise Exception(f"Pulsedive API error: {data['error']}")
                return {"status": "success", "indicator": data}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Pulsedive. Check base_url and network.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Pulsedive timed out.")
        except Exception as e:
            self.logger.error("Error in get_indicator_details", exc_info=e)
            raise Exception(str(e))

    def enrich_ip(self, request: RequestBody) -> ResponseBody:
        try:
            api_key = str(request.connectionParameters.get("api_key", "")).strip()
            if not api_key:
                raise Exception("api_key is required.")
            base_url = (request.connectionParameters.get("base_url") or "https://pulsedive.com/api").rstrip("/")
            timeout = int(request.connectionParameters.get("timeout") or 30)
            verify_ssl = request.connectionParameters.get("verify_ssl", True)
            if isinstance(verify_ssl, str):
                verify_ssl = verify_ssl.lower() in ("true", "1", "yes")
            proxy = request.connectionParameters.get("proxy")
            proxies = {"http": proxy, "https": proxy} if proxy else None

            ip = (request.parameters.get("ip") or "").strip()
            if not ip:
                raise Exception("ip is required and cannot be empty.")
            if not (_RE_IPV4.match(ip) or _RE_IPV6.match(ip)):
                raise Exception(f"Invalid IP address format: {ip}")

            for attempt in range(MAX_RETRIES):
                resp = requests.get(
                    f"{base_url}/indicator.php",
                    params={"indicator": ip, "pretty": "1", "key": api_key},
                    timeout=timeout,
                    verify=verify_ssl,
                    proxies=proxies,
                )
                if resp.status_code in (401, 403):
                    raise Exception("Authentication failed. Verify api_key.")
                if resp.status_code == 404:
                    return {"status": "success", "indicator": {}}
                if resp.status_code == 429 or resp.status_code >= 500:
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(BACKOFF_FACTOR ** (attempt + 1))
                        continue
                    msg = "Rate limit exceeded. Please try again later." if resp.status_code == 429 else f"Pulsedive server error (HTTP {resp.status_code})."
                    raise Exception(msg)
                if resp.status_code != 200:
                    raise Exception(f"Pulsedive API error (HTTP {resp.status_code}).")
                data = resp.json()
                if isinstance(data, dict) and data.get("error"):
                    raise Exception(f"Pulsedive API error: {data['error']}")
                return {"status": "success", "indicator": data}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Pulsedive. Check base_url and network.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Pulsedive timed out.")
        except Exception as e:
            self.logger.error("Error in enrich_ip", exc_info=e)
            raise Exception(str(e))

    def enrich_domain(self, request: RequestBody) -> ResponseBody:
        try:
            api_key = str(request.connectionParameters.get("api_key", "")).strip()
            if not api_key:
                raise Exception("api_key is required.")
            base_url = (request.connectionParameters.get("base_url") or "https://pulsedive.com/api").rstrip("/")
            timeout = int(request.connectionParameters.get("timeout") or 30)
            verify_ssl = request.connectionParameters.get("verify_ssl", True)
            if isinstance(verify_ssl, str):
                verify_ssl = verify_ssl.lower() in ("true", "1", "yes")
            proxy = request.connectionParameters.get("proxy")
            proxies = {"http": proxy, "https": proxy} if proxy else None

            domain = (request.parameters.get("domain") or "").strip()
            if not domain:
                raise Exception("domain is required and cannot be empty.")
            if len(domain) > 253 or not _RE_DOMAIN.match(domain):
                raise Exception(f"Invalid domain format: {domain}")

            for attempt in range(MAX_RETRIES):
                resp = requests.get(
                    f"{base_url}/indicator.php",
                    params={"indicator": domain, "pretty": "1", "key": api_key},
                    timeout=timeout,
                    verify=verify_ssl,
                    proxies=proxies,
                )
                if resp.status_code in (401, 403):
                    raise Exception("Authentication failed. Verify api_key.")
                if resp.status_code == 404:
                    return {"status": "success", "indicator": {}}
                if resp.status_code == 429 or resp.status_code >= 500:
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(BACKOFF_FACTOR ** (attempt + 1))
                        continue
                    msg = "Rate limit exceeded. Please try again later." if resp.status_code == 429 else f"Pulsedive server error (HTTP {resp.status_code})."
                    raise Exception(msg)
                if resp.status_code != 200:
                    raise Exception(f"Pulsedive API error (HTTP {resp.status_code}).")
                data = resp.json()
                if isinstance(data, dict) and data.get("error"):
                    raise Exception(f"Pulsedive API error: {data['error']}")
                return {"status": "success", "indicator": data}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Pulsedive. Check base_url and network.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Pulsedive timed out.")
        except Exception as e:
            self.logger.error("Error in enrich_domain", exc_info=e)
            raise Exception(str(e))

    def enrich_url(self, request: RequestBody) -> ResponseBody:
        try:
            api_key = str(request.connectionParameters.get("api_key", "")).strip()
            if not api_key:
                raise Exception("api_key is required.")
            base_url = (request.connectionParameters.get("base_url") or "https://pulsedive.com/api").rstrip("/")
            timeout = int(request.connectionParameters.get("timeout") or 30)
            verify_ssl = request.connectionParameters.get("verify_ssl", True)
            if isinstance(verify_ssl, str):
                verify_ssl = verify_ssl.lower() in ("true", "1", "yes")
            proxy = request.connectionParameters.get("proxy")
            proxies = {"http": proxy, "https": proxy} if proxy else None

            url = (request.parameters.get("url") or "").strip()
            if not url:
                raise Exception("url is required and cannot be empty.")
            if len(url) > 2048 or not _RE_URL.match(url):
                raise Exception(f"Invalid URL format (must start with http:// or https://): {url}")

            for attempt in range(MAX_RETRIES):
                resp = requests.get(
                    f"{base_url}/indicator.php",
                    params={"indicator": url, "pretty": "1", "key": api_key},
                    timeout=timeout,
                    verify=verify_ssl,
                    proxies=proxies,
                )
                if resp.status_code in (401, 403):
                    raise Exception("Authentication failed. Verify api_key.")
                if resp.status_code == 404:
                    return {"status": "success", "indicator": {}}
                if resp.status_code == 429 or resp.status_code >= 500:
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(BACKOFF_FACTOR ** (attempt + 1))
                        continue
                    msg = "Rate limit exceeded. Please try again later." if resp.status_code == 429 else f"Pulsedive server error (HTTP {resp.status_code})."
                    raise Exception(msg)
                if resp.status_code != 200:
                    raise Exception(f"Pulsedive API error (HTTP {resp.status_code}).")
                data = resp.json()
                if isinstance(data, dict) and data.get("error"):
                    raise Exception(f"Pulsedive API error: {data['error']}")
                return {"status": "success", "indicator": data}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Pulsedive. Check base_url and network.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Pulsedive timed out.")
        except Exception as e:
            self.logger.error("Error in enrich_url", exc_info=e)
            raise Exception(str(e))

    def enrich_hash(self, request: RequestBody) -> ResponseBody:
        try:
            api_key = str(request.connectionParameters.get("api_key", "")).strip()
            if not api_key:
                raise Exception("api_key is required.")
            base_url = (request.connectionParameters.get("base_url") or "https://pulsedive.com/api").rstrip("/")
            timeout = int(request.connectionParameters.get("timeout") or 30)
            verify_ssl = request.connectionParameters.get("verify_ssl", True)
            if isinstance(verify_ssl, str):
                verify_ssl = verify_ssl.lower() in ("true", "1", "yes")
            proxy = request.connectionParameters.get("proxy")
            proxies = {"http": proxy, "https": proxy} if proxy else None

            file_hash = (request.parameters.get("hash") or "").strip()
            if not file_hash:
                raise Exception("hash is required and cannot be empty.")
            if not _RE_HASH.match(file_hash):
                raise Exception("Invalid hash format. Must be MD5 (32), SHA1 (40), or SHA256 (64) hex characters.")

            for attempt in range(MAX_RETRIES):
                resp = requests.get(
                    f"{base_url}/indicator.php",
                    params={"indicator": file_hash, "pretty": "1", "key": api_key},
                    timeout=timeout,
                    verify=verify_ssl,
                    proxies=proxies,
                )
                if resp.status_code in (401, 403):
                    raise Exception("Authentication failed. Verify api_key.")
                if resp.status_code == 404:
                    return {"status": "success", "indicator": {}}
                if resp.status_code == 429 or resp.status_code >= 500:
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(BACKOFF_FACTOR ** (attempt + 1))
                        continue
                    msg = "Rate limit exceeded. Please try again later." if resp.status_code == 429 else f"Pulsedive server error (HTTP {resp.status_code})."
                    raise Exception(msg)
                if resp.status_code != 200:
                    raise Exception(f"Pulsedive API error (HTTP {resp.status_code}).")
                data = resp.json()
                if isinstance(data, dict) and data.get("error"):
                    raise Exception(f"Pulsedive API error: {data['error']}")
                return {"status": "success", "indicator": data}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Pulsedive. Check base_url and network.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Pulsedive timed out.")
        except Exception as e:
            self.logger.error("Error in enrich_hash", exc_info=e)
            raise Exception(str(e))

    def search_indicators(self, request: RequestBody) -> ResponseBody:
        try:
            api_key = str(request.connectionParameters.get("api_key", "")).strip()
            if not api_key:
                raise Exception("api_key is required.")
            base_url = (request.connectionParameters.get("base_url") or "https://pulsedive.com/api").rstrip("/")
            timeout = int(request.connectionParameters.get("timeout") or 30)
            verify_ssl = request.connectionParameters.get("verify_ssl", True)
            if isinstance(verify_ssl, str):
                verify_ssl = verify_ssl.lower() in ("true", "1", "yes")
            proxy = request.connectionParameters.get("proxy")
            proxies = {"http": proxy, "https": proxy} if proxy else None

            query = (request.parameters.get("query") or "").strip()
            if not query:
                raise Exception("query is required and cannot be empty.")
            if len(query) > 2048:
                raise Exception("query exceeds maximum length of 2048 characters.")

            indicator_type = (request.parameters.get("indicator_type") or "").strip().lower()
            if indicator_type and indicator_type not in VALID_INDICATOR_TYPES:
                raise Exception(f"indicator_type must be one of: {', '.join(sorted(VALID_INDICATOR_TYPES))}")

            risk = (request.parameters.get("risk") or "").strip().lower()
            if risk and risk not in VALID_RISK_LEVELS:
                raise Exception(f"risk must be one of: {', '.join(sorted(VALID_RISK_LEVELS))}")

            limit = 10
            raw_limit = request.parameters.get("limit")
            if raw_limit is not None:
                try:
                    limit = int(raw_limit)
                    if limit < 1 or limit > 100:
                        raise Exception("limit must be between 1 and 100.")
                except (ValueError, TypeError):
                    pass

            params = {"q": query, "limit": limit, "key": api_key}
            if indicator_type:
                params["type"] = indicator_type
            if risk:
                params["risk"] = risk

            for attempt in range(MAX_RETRIES):
                resp = requests.get(
                    f"{base_url}/explore.php",
                    params=params,
                    timeout=timeout,
                    verify=verify_ssl,
                    proxies=proxies,
                )
                if resp.status_code in (401, 403):
                    raise Exception("Authentication failed. Verify api_key.")
                if resp.status_code == 429 or resp.status_code >= 500:
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(BACKOFF_FACTOR ** (attempt + 1))
                        continue
                    msg = "Rate limit exceeded. Please try again later." if resp.status_code == 429 else f"Pulsedive server error (HTTP {resp.status_code})."
                    raise Exception(msg)
                if resp.status_code != 200:
                    raise Exception(f"Pulsedive API error (HTTP {resp.status_code}).")
                data = resp.json()
                if isinstance(data, dict) and data.get("error"):
                    raise Exception(f"Pulsedive API error: {data['error']}")
                results = data.get("results", []) if isinstance(data, dict) else []
                return {"status": "success", "results": results, "total": len(results)}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Pulsedive. Check base_url and network.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Pulsedive timed out.")
        except Exception as e:
            self.logger.error("Error in search_indicators", exc_info=e)
            raise Exception(str(e))

    def search_threats(self, request: RequestBody) -> ResponseBody:
        try:
            api_key = str(request.connectionParameters.get("api_key", "")).strip()
            if not api_key:
                raise Exception("api_key is required.")
            base_url = (request.connectionParameters.get("base_url") or "https://pulsedive.com/api").rstrip("/")
            timeout = int(request.connectionParameters.get("timeout") or 30)
            verify_ssl = request.connectionParameters.get("verify_ssl", True)
            if isinstance(verify_ssl, str):
                verify_ssl = verify_ssl.lower() in ("true", "1", "yes")
            proxy = request.connectionParameters.get("proxy")
            proxies = {"http": proxy, "https": proxy} if proxy else None

            query = (request.parameters.get("query") or "").strip()
            if not query:
                raise Exception("query is required and cannot be empty.")
            if len(query) > 2048:
                raise Exception("query exceeds maximum length of 2048 characters.")

            for attempt in range(MAX_RETRIES):
                resp = requests.get(
                    f"{base_url}/threat.php",
                    params={"threat": query, "pretty": "1", "key": api_key},
                    timeout=timeout,
                    verify=verify_ssl,
                    proxies=proxies,
                )
                if resp.status_code in (401, 403):
                    raise Exception("Authentication failed. Verify api_key.")
                if resp.status_code == 404:
                    return {"status": "success", "results": [], "total": 0}
                if resp.status_code == 429 or resp.status_code >= 500:
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(BACKOFF_FACTOR ** (attempt + 1))
                        continue
                    msg = "Rate limit exceeded. Please try again later." if resp.status_code == 429 else f"Pulsedive server error (HTTP {resp.status_code})."
                    raise Exception(msg)
                if resp.status_code != 200:
                    raise Exception(f"Pulsedive API error (HTTP {resp.status_code}).")
                data = resp.json()
                if isinstance(data, dict) and data.get("error"):
                    raise Exception(f"Pulsedive API error: {data['error']}")
                results = [data] if isinstance(data, dict) and data else []
                return {"status": "success", "results": results, "total": len(results)}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Pulsedive. Check base_url and network.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Pulsedive timed out.")
        except Exception as e:
            self.logger.error("Error in search_threats", exc_info=e)
            raise Exception(str(e))
