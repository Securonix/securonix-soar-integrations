import logging
import re
import time
import requests
from app.model.request_body import RequestBody

IP_PATTERN = re.compile(
    r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)
DEFAULT_BASE_URL = "https://api.shodan.io"
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3
BACKOFF_FACTOR = 2


class Shodan:

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)

    def _get_connection(self, connection_params: dict):
        base_url = connection_params.get('server_url', DEFAULT_BASE_URL).rstrip('/')
        if not base_url:
            base_url = DEFAULT_BASE_URL
        api_token = connection_params.get('api_token')
        if not api_token:
            raise Exception("API Token is required.")
        timeout = DEFAULT_TIMEOUT
        try:
            t = connection_params.get('timeout')
            if t:
                timeout = max(1, int(t))
        except (ValueError, TypeError):
            pass
        return base_url, api_token, timeout

    def _make_request(self, base_url: str, endpoint: str, api_token: str, timeout: int, params: dict = None) -> dict:
        url = f"{base_url}{endpoint}"
        req_params = params.copy() if params else {}
        req_params["key"] = api_token

        last_exception = None
        for attempt in range(MAX_RETRIES):
            try:
                resp = requests.get(url, params=req_params, timeout=timeout)

                if resp.status_code == 200:
                    try:
                        return resp.json()
                    except ValueError:
                        return {"raw_text": resp.text}

                if resp.status_code in (401, 403):
                    raise Exception("Authentication failed. Please verify your API Token is correct.")

                if resp.status_code == 429:
                    if attempt < MAX_RETRIES - 1:
                        wait = BACKOFF_FACTOR ** (attempt + 1)
                        self.logger.warning("Rate limited (429). Retrying in %ds...", wait)
                        time.sleep(wait)
                        last_exception = Exception("Rate limit exceeded. Please try again later.")
                        continue
                    raise Exception("Rate limit exceeded. Please try again later.")

                if resp.status_code >= 500:
                    if attempt < MAX_RETRIES - 1:
                        wait = BACKOFF_FACTOR ** (attempt + 1)
                        self.logger.warning("Server error (%d). Retrying in %ds...", resp.status_code, wait)
                        time.sleep(wait)
                        last_exception = Exception(f"Shodan server error (HTTP {resp.status_code}).")
                        continue
                    raise Exception(f"Shodan server error (HTTP {resp.status_code}).")

                try:
                    err_body = resp.json()
                    err_msg = err_body.get("error", resp.text)
                except ValueError:
                    err_msg = resp.text
                raise Exception(f"API request failed (HTTP {resp.status_code}): {err_msg}")

            except requests.exceptions.ConnectionError:
                raise Exception("Unable to connect to Shodan. Please verify the Server URL.")
            except requests.exceptions.Timeout:
                raise Exception("Connection to Shodan timed out.")
            except Exception as e:
                if "Authentication failed" in str(e) or "Rate limit" in str(e) or "Unable to connect" in str(e) or "timed out" in str(e):
                    raise
                last_exception = e
                if attempt < MAX_RETRIES - 1:
                    continue
                raise

        if last_exception:
            raise last_exception

    def _validate_ip(self, ip: str):
        if not ip or not ip.strip():
            raise Exception("IP address is required and cannot be empty.")
        ip = ip.strip()
        if not IP_PATTERN.match(ip):
            raise Exception(f"Invalid IP address format: {ip}")
        return ip

    def _validate_required(self, value, field_name: str):
        if not value or (isinstance(value, str) and not value.strip()):
            raise Exception(f"{field_name} is required and cannot be empty.")
        return value.strip() if isinstance(value, str) else value

    def test_connection(self, connectionParameters: dict):
        try:
            base_url, api_token, timeout = self._get_connection(connectionParameters)
            self._make_request(base_url, "/api-info", api_token, timeout)
            return {"status": "success", "message": "Connected to Shodan successfully."}
        except Exception as e:
            self.logger.exception("Exception while testing connection")
            raise Exception(str(e))

    def ip_address(self, request: RequestBody) -> dict:
        try:
            base_url, api_token, timeout = self._get_connection(request.connectionParameters)
            ip = request.parameters.get('ip_addr') or request.parameters.get('ip')
            ip = self._validate_ip(ip)

            data = self._make_request(base_url, f"/shodan/host/{ip}", api_token, timeout)

            return {
                "ip": data.get("ip_str", ip),
                "organization": data.get("org"),
                "isp": data.get("isp"),
                "hostnames": data.get("hostnames", []),
                "domains": data.get("domains", []),
                "country": data.get("country_name"),
                "city": data.get("city"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "ports": data.get("ports", []),
                "os": data.get("os"),
                "vulnerabilities": data.get("vulns", []),
                "raw_response": data
            }
        except Exception as e:
            self.logger.exception("Error in ip_address action")
            raise Exception(str(e))

    def domain_lookup(self, request: RequestBody) -> dict:
        try:
            base_url, api_token, timeout = self._get_connection(request.connectionParameters)
            domain = self._validate_required(request.parameters.get('domain'), "domain")

            data = self._make_request(base_url, f"/dns/domain/{domain}", api_token, timeout)

            return {
                "domain": data.get("domain", domain),
                "subdomains": data.get("subdomains", []),
                "tags": data.get("tags", []),
                "data": data.get("data", []),
                "raw_response": data
            }
        except Exception as e:
            self.logger.exception("Error in domain_lookup action")
            raise Exception(str(e))

    def host_search(self, request: RequestBody) -> dict:
        try:
            base_url, api_token, timeout = self._get_connection(request.connectionParameters)
            query = self._validate_required(request.parameters.get('query'), "query")

            params = {"query": query}
            page = request.parameters.get('page')
            if page:
                try:
                    p = int(page)
                    if p > 0:
                        params["page"] = p
                except (ValueError, TypeError):
                    pass

            data = self._make_request(base_url, "/shodan/host/search", api_token, timeout, params)

            return {
                "total": data.get("total", 0),
                "matches": data.get("matches", []),
                "raw_response": data
            }
        except Exception as e:
            self.logger.exception("Error in host_search action")
            raise Exception(str(e))

    def host_count(self, request: RequestBody) -> dict:
        try:
            base_url, api_token, timeout = self._get_connection(request.connectionParameters)
            query = self._validate_required(request.parameters.get('query'), "query")

            params = {"query": query}
            facets = request.parameters.get('facets')
            if facets:
                params["facets"] = facets

            data = self._make_request(base_url, "/shodan/host/count", api_token, timeout, params)

            return {
                "total": data.get("total", 0),
                "facets": data.get("facets", {}),
                "raw_response": data
            }
        except Exception as e:
            self.logger.exception("Error in host_count action")
            raise Exception(str(e))

    def list_ports(self, request: RequestBody) -> dict:
        try:
            base_url, api_token, timeout = self._get_connection(request.connectionParameters)
            data = self._make_request(base_url, "/shodan/ports", api_token, timeout)

            return {
                "ports": data if isinstance(data, list) else [],
                "raw_response": data
            }
        except Exception as e:
            self.logger.exception("Error in list_ports action")
            raise Exception(str(e))

    def list_protocols(self, request: RequestBody) -> dict:
        try:
            base_url, api_token, timeout = self._get_connection(request.connectionParameters)
            data = self._make_request(base_url, "/shodan/protocols", api_token, timeout)

            return {
                "protocols": data if isinstance(data, dict) else {},
                "raw_response": data
            }
        except Exception as e:
            self.logger.exception("Error in list_protocols action")
            raise Exception(str(e))

    def list_services(self, request: RequestBody) -> dict:
        try:
            base_url, api_token, timeout = self._get_connection(request.connectionParameters)
            data = self._make_request(base_url, "/shodan/services", api_token, timeout)

            return {
                "services": data if isinstance(data, dict) else {},
                "raw_response": data
            }
        except Exception as e:
            self.logger.exception("Error in list_services action")
            raise Exception(str(e))

    def honeyscore(self, request: RequestBody) -> dict:
        try:
            base_url, api_token, timeout = self._get_connection(request.connectionParameters)
            ip = request.parameters.get('ip')
            ip = self._validate_ip(ip)

            data = self._make_request(base_url, f"/labs/honeyscore/{ip}", api_token, timeout)

            if isinstance(data, dict):
                score = data.get("honeyscore")
            else:
                try:
                    score = float(data)
                except (ValueError, TypeError):
                    score = None

            return {
                "ip": ip,
                "honeyscore": score,
                "raw_response": data
            }
        except Exception as e:
            self.logger.exception("Error in honeyscore action")
            raise Exception(str(e))

    def my_ip(self, request: RequestBody) -> dict:
        try:
            base_url, api_token, timeout = self._get_connection(request.connectionParameters)
            data = self._make_request(base_url, "/tools/myip", api_token, timeout)

            ip = data if isinstance(data, str) else data.get("ip") if isinstance(data, dict) else str(data)

            return {
                "ip": ip,
                "raw_response": data
            }
        except Exception as e:
            self.logger.exception("Error in my_ip action")
            raise Exception(str(e))

    def api_info(self, request: RequestBody) -> dict:
        try:
            base_url, api_token, timeout = self._get_connection(request.connectionParameters)
            data = self._make_request(base_url, "/api-info", api_token, timeout)

            return {
                "query_credits": data.get("query_credits"),
                "scan_credits": data.get("scan_credits"),
                "monitored_ips": data.get("monitored_ips"),
                "plan": data.get("plan"),
                "https": data.get("https"),
                "unlocked": data.get("unlocked"),
                "raw_response": data
            }
        except Exception as e:
            self.logger.exception("Error in api_info action")
            raise Exception(str(e))
