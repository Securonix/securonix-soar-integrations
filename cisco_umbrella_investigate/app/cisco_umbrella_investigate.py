from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import requests
import time
import re
import json
import urllib.parse
import ipaddress
from typing import Dict, Any, Optional, Tuple


class Cisco_Umbrella_Investigate:
    """
    Cisco Umbrella Investigate connector for Securonix SOAR.
    Uses direct Bearer token authentication (no OAuth flow).
    API Base: https://investigate.api.umbrella.com
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        self._access_token: Optional[str] = None
        self._session = requests.Session()
        self._base_url = "https://investigate.api.umbrella.com"
        self._timeout = 30
        self._verify_ssl = True

    def _get_base_url(self, connectionParameters: Dict[str, Any]) -> str:
        """Get base URL from connection parameters."""
        base_url = connectionParameters.get("base_url")
        if base_url and base_url.strip():
            return base_url.strip().rstrip("/")
        return self._base_url

    def _get_timeout(self, connectionParameters: Dict[str, Any]) -> int:
        """Get timeout from connection parameters."""
        timeout_val = connectionParameters.get("request_timeout")
        if timeout_val is not None:
            try:
                val = int(timeout_val)
                if val > 0:
                    return val
            except (ValueError, TypeError):
                pass
        return self._timeout

    def _get_verify_ssl(self, connectionParameters: Dict[str, Any]) -> bool:
        """Get verify_ssl from connection parameters."""
        verify_val = connectionParameters.get("verify_ssl")
        if verify_val is not None:
            if isinstance(verify_val, bool):
                return verify_val
            if isinstance(verify_val, str):
                return verify_val.lower() == "true"
        return self._verify_ssl

    def _validate_domain(self, domain: str) -> str:
        """Validate and normalize domain name."""
        if not domain or not isinstance(domain, str):
            raise ValueError("Domain must be a non-empty string")
        domain = domain.strip()
        # Remove URL schemes and paths
        for prefix in ["http://", "https://", "http:/", "https:/"]:
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        if "/" in domain:
            domain = domain.split("/")[0]
        domain = domain.strip().rstrip(".")
        if not domain:
            raise ValueError("Invalid domain: empty after normalization")
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$'
        if not re.match(domain_pattern, domain):
            raise ValueError(f"Invalid domain format: {domain}")
        return domain

    def _validate_ip(self, ip: str, allow_ipv6: bool = True) -> str:
        """Validate IP address."""
        if not ip or not isinstance(ip, str):
            raise ValueError("IP address must be a non-empty string")
        ip = ip.strip()
        if not allow_ipv6 and ":" in ip:
            raise ValueError("IPv6 addresses are not supported by this endpoint")
        try:
            ip_obj = ipaddress.ip_address(ip)
            return str(ip_obj)
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip}")

    def _validate_url(self, url: str) -> str:
        """Validate URL and extract hostname."""
        if not url or not isinstance(url, str):
            raise ValueError("URL must be a non-empty string")
        url = url.strip()
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme:
            raise ValueError("URL must include a scheme (http:// or https://)")
        if not parsed.netloc:
            raise ValueError("URL must include a valid hostname")
        return f"{parsed.scheme}://{parsed.netloc}"

    def _validate_email(self, email: str) -> str:
        """Validate email address."""
        if not email or not isinstance(email, str):
            raise ValueError("Email must be a non-empty string")
        email = email.strip()
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            raise ValueError(f"Invalid email format: {email}")
        return email

    def _validate_asn(self, asn: str) -> int:
        """Validate and normalize ASN."""
        if not asn or not isinstance(asn, str):
            raise ValueError("ASN must be a non-empty string")
        asn = asn.strip()
        if asn.upper().startswith("AS"):
            asn = asn[2:]
        if asn.startswith("-"):
            raise ValueError("ASN must be a positive integer")
        try:
            asn_num = int(asn)
            if asn_num <= 0:
                raise ValueError("ASN must be a positive integer")
            return asn_num
        except ValueError:
            raise ValueError(f"Invalid ASN format: {asn}")

    def _validate_search_expression(self, expression: str) -> str:
        """Validate search expression."""
        if not expression or not isinstance(expression, str):
            raise ValueError("Search expression must be a non-empty string")
        expression = expression.strip()
        if not expression:
            raise ValueError("Search expression must be non-empty")
        return expression

    def _get_access_token(self, api_key: str, api_secret: str) -> str:
        """Get Cisco Investigate API Bearer token."""
        if self._access_token:
            return self._access_token
        if not api_key:
            raise ConnectionError("API key (Bearer token) is required for Cisco Umbrella Investigate")
        self._access_token = api_key
        return self._access_token

    def _request(
        self,
        method: str,
        endpoint: str,
        connectionParameters: Dict[str, Any],
        api_key: str,
        api_secret: str,
        params: Optional[Dict[str, Any]] = None,
        retry_count: int = 0,
        max_retries: int = 3
    ) -> Tuple[int, Dict[str, Any]]:
        """Make authenticated request to Cisco Investigate API."""
        base_url = self._get_base_url(connectionParameters)
        verify_ssl = self._get_verify_ssl(connectionParameters)
        timeout = self._get_timeout(connectionParameters)
        url = f"{base_url}{endpoint}"
        access_token = self._get_access_token(api_key, api_secret)
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {access_token}"
        }
        try:
            self.logger.info(f"Making {method} request to {endpoint}")
            if method.upper() == "GET":
                response = self._session.get(url, headers=headers, params=params, timeout=timeout, verify=verify_ssl)
            elif method.upper() == "POST":
                response = self._session.post(url, headers=headers, params=params, timeout=timeout, verify=verify_ssl)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            self.logger.info(f"Received response with status code: {response.status_code}")
            if response.status_code == 204:
                return 204, {}
            try:
                json_response = response.json()
            except ValueError:
                raise ValueError("Invalid JSON response from Cisco API")
            # Handle 401 - token may be invalid, clear cache and retry
            if response.status_code == 401:
                if retry_count < 1:
                    self.logger.info("Received 401, clearing token cache and retrying")
                    self._access_token = None
                    return self._request(method, endpoint, connectionParameters, api_key, api_secret, params, retry_count + 1, max_retries)
                raise ConnectionError("Authentication failed: invalid API token")
            if response.status_code == 403:
                raise ConnectionError("Access forbidden: API token may not have Investigate permissions")
            if response.status_code == 404:
                self.logger.info(f"Not found (404) for endpoint {endpoint}")
                return 404, {}
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "1")
                try:
                    wait_time = int(retry_after)
                except ValueError:
                    wait_time = 2 ** retry_count
                if retry_count < max_retries - 1:
                    time.sleep(wait_time)
                    return self._request(method, endpoint, connectionParameters, api_key, api_secret, params, retry_count + 1, max_retries)
                raise ConnectionError(f"Rate limited after {max_retries} retries")
            if 500 <= response.status_code < 600:
                if retry_count < max_retries - 1:
                    time.sleep(2 ** retry_count)
                    return self._request(method, endpoint, connectionParameters, api_key, api_secret, params, retry_count + 1, max_retries)
                raise ConnectionError(f"Cisco API server error: {response.status_code}")
            if 200 <= response.status_code < 300:
                return response.status_code, json_response
            raise ConnectionError(f"Cisco API error: {response.status_code}")
        except requests.exceptions.Timeout:
            if retry_count < max_retries - 1:
                time.sleep(1)
                return self._request(method, endpoint, connectionParameters, api_key, api_secret, params, retry_count + 1, max_retries)
            raise ConnectionError(f"Request timed out after {max_retries} attempts")
        except requests.exceptions.SSLError:
            raise ConnectionError("TLS/SSL certificate verification failed")
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Request failed: {str(e)}")
    # ============================================================================
    # Test Connection
    # ============================================================================
    def test_connection(self, connectionParameters: Dict[str, Any]) -> ResponseBody:
        """Test Cisco Umbrella Investigate connection."""
        try:
            api_key = connectionParameters.get("api_key")
            if not api_key or not api_key.strip():
                return ResponseBody(
                    status="FAILURE", errorCode="INVALID_CREDENTIALS", httpCode=0,
                    message="API key (Bearer token) is required", response={}, input={}, output={}, incrementals=False
                )
            base_url = self._get_base_url(connectionParameters)
            if not base_url.startswith("https://"):
                return ResponseBody(
                    status="FAILURE", errorCode="INVALID_CONFIG", httpCode=0,
                    message="Base URL must use HTTPS protocol", response={}, input={}, output={}, incrementals=False
                )
            # Test Investigate endpoint with a benign domain
            try:
                status_code, raw_response = self._request(
                    "GET", "/domains/categorization/cisco.com", connectionParameters, api_key, "", {}
                )
                if status_code == 200:
                    return ResponseBody(
                        status="SUCCESS", errorCode="", httpCode=200,
                        message="Connection successful - Cisco Umbrella Investigate API is accessible",
                        response={}, input={}, output={}, incrementals=False
                    )
                elif status_code == 403:
                    return ResponseBody(
                        status="FAILURE", errorCode="INSUFFICIENT_PERMISSIONS", httpCode=0,
                        message="API token does not have Investigate permissions",
                        response={}, input={}, output={}, incrementals=False
                    )
                elif status_code == 401:
                    return ResponseBody(
                        status="FAILURE", errorCode="INVALID_CREDENTIALS", httpCode=0,
                        message="Invalid API token",
                        response={}, input={}, output={}, incrementals=False
                    )
                else:
                    return ResponseBody(
                        status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                        message=f"Cisco Investigate API test failed with status {status_code}",
                        response={}, input={}, output={}, incrementals=False
                    )
            except ConnectionError as e:
                return ResponseBody(
                    status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                    message=str(e), response={}, input={}, output={}, incrementals=False
                )
        except Exception as e:
            return ResponseBody(
                status="FAILURE", errorCode="INTERNAL_ERROR", httpCode=0,
                message=f"Unexpected error during connection test: {str(e)}",
                response={}, input={}, output={}, incrementals=False
            )
    # ============================================================================
    # Action 1: Domain Categorization
    # ============================================================================
    def umbrella_domain_categorization(self, request: RequestBody) -> ResponseBody:
        """Retrieve Cisco Umbrella security and content categories for a domain."""
        domain = request.parameters.get("domain")
        try:
            validated_domain = self._validate_domain(domain)
            status_code, raw_response = self._request(
                "GET", f"/domains/categorization/{validated_domain}",
                request.connectionParameters, request.connectionParameters.get("api_key"), "", {}
            )
            security_categories = []
            content_categories = []
            if isinstance(raw_response, dict):
                domain_result = raw_response.get(validated_domain, raw_response)
                if isinstance(domain_result, dict):
                    for cat in domain_result.get("security_categories", []):
                        security_categories.append({"name": cat, "categoryType": "security"})
                    for cat in domain_result.get("content_categories", []):
                        content_categories.append({"name": cat, "categoryType": "content"})
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Successfully retrieved categorization for {validated_domain}",
                response={}, input={"domain": domain},
                output={"domain": validated_domain, "securityCategories": security_categories, "contentCategories": content_categories},
                incrementals=False
            )
        except ValueError as e:
            return ResponseBody(status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={"domain": domain}, output={}, incrementals=False)
        except ConnectionError as e:
            return ResponseBody(status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message=str(e), response={}, input={"domain": domain}, output={}, incrementals=False)

    # ============================================================================
    # Action 2: Domain Search
    # ============================================================================
    def umbrella_domain_search(self, request: RequestBody) -> ResponseBody:
        """Search newly observed domains matching a search expression."""
        expression = request.parameters.get("expression")
        limit = request.parameters.get("limit", 100)
        try:
            validated_expression = self._validate_search_expression(expression)
            params = {}
            if limit:
                try:
                    params["limit"] = int(limit)
                except (ValueError, TypeError):
                    pass
            status_code, raw_response = self._request(
                "GET", f"/search/{urllib.parse.quote(validated_expression)}",
                request.connectionParameters, request.connectionParameters.get("api_key"), "", params
            )
            results = []
            if isinstance(raw_response, list):
                results = [r for r in raw_response if isinstance(r, str)]
            elif isinstance(raw_response, dict):
                results_list = raw_response.get("results", raw_response.get("domains", []))
                if isinstance(results_list, list):
                    results = [r for r in results_list if isinstance(r, str)]
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Found {len(results)} matching domains",
                response={}, input={"expression": expression, "limit": limit},
                output={"results": results, "count": len(results)}, incrementals=False
            )
        except ValueError as e:
            return ResponseBody(status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={"expression": expression}, output={}, incrementals=False)
        except ConnectionError as e:
            return ResponseBody(status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message=str(e), response={}, input={"expression": expression}, output={}, incrementals=False)
    # ============================================================================
    # Action 3: Domain Co-occurrences
    # ============================================================================
    def umbrella_domain_co_occurrences(self, request: RequestBody) -> ResponseBody:
        """Find domains commonly observed together with a target domain."""
        domain = request.parameters.get("domain")
        try:
            validated_domain = self._validate_domain(domain)
            status_code, raw_response = self._request(
                "GET", f"/domains/{validated_domain}/cooccurrences",
                request.connectionParameters, request.connectionParameters.get("api_key"), "", {}
            )
            co_occurrences = []
            if isinstance(raw_response, dict):
                for co_domain, count in raw_response.items():
                    if isinstance(count, (int, float)):
                        co_occurrences.append({"domain": co_domain, "count": int(count)})
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Found {len(co_occurrences)} co-occurring domains",
                response={}, input={"domain": domain},
                output={"domain": validated_domain, "coOccurrences": co_occurrences, "count": len(co_occurrences)},
                incrementals=False
            )
        except ValueError as e:
            return ResponseBody(status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={"domain": domain}, output={}, incrementals=False)
        except ConnectionError as e:
            return ResponseBody(status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message=str(e), response={}, input={"domain": domain}, output={}, incrementals=False)

    # ============================================================================
    # Action 4: Related Domains
    # ============================================================================
    def umbrella_domain_related(self, request: RequestBody) -> ResponseBody:
        """Retrieve Cisco Umbrella related-domain information for campaign expansion."""
        domain = request.parameters.get("domain")
        try:
            validated_domain = self._validate_domain(domain)
            status_code, raw_response = self._request(
                "GET", f"/links/{validated_domain}",
                request.connectionParameters, request.connectionParameters.get("api_key"), "", {}
            )
            related_domains = []
            if isinstance(raw_response, list):
                related_domains = [r for r in raw_response if isinstance(r, str)]
            elif isinstance(raw_response, dict):
                links_list = raw_response.get("links", [])
                if isinstance(links_list, list):
                    related_domains = [r for r in links_list if isinstance(r, str)]
                elif isinstance(links_list, dict):
                    related_domains = list(links_list.keys())
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Found {len(related_domains)} related domains",
                response={}, input={"domain": domain},
                output={"domain": validated_domain, "relatedDomains": related_domains, "count": len(related_domains)},
                incrementals=False
            )
        except ValueError as e:
            return ResponseBody(status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={"domain": domain}, output={}, incrementals=False)
        except ConnectionError as e:
            return ResponseBody(status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message=str(e), response={}, input={"domain": domain}, output={}, incrementals=False)
    # ============================================================================
    # Action 5: Domain Security
    # ============================================================================
    def umbrella_domain_security(self, request: RequestBody) -> ResponseBody:
        """Retrieve domain security characteristics/reputation information."""
        domain = request.parameters.get("domain")
        try:
            validated_domain = self._validate_domain(domain)
            status_code, raw_response = self._request(
                "GET", f"/security/name/{validated_domain}",
                request.connectionParameters, request.connectionParameters.get("api_key"), "", {}
            )
            security = raw_response if isinstance(raw_response, dict) else {}
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Successfully retrieved security info for {validated_domain}",
                response={}, input={"domain": domain},
                output={"domain": validated_domain, "security": security}, incrementals=False
            )
        except ValueError as e:
            return ResponseBody(status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={"domain": domain}, output={}, incrementals=False)
        except ConnectionError as e:
            return ResponseBody(status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message=str(e), response={}, input={"domain": domain}, output={}, incrementals=False)

    # ============================================================================
    # Action 6: Domain Risk Score
    # ============================================================================
    def umbrella_get_domain_risk_score(self, request: RequestBody) -> ResponseBody:
        """Retrieve domain risk score (0-100)."""
        domain = request.parameters.get("domain")
        try:
            validated_domain = self._validate_domain(domain)
            status_code, raw_response = self._request(
                "GET", f"/domains/risk-score/{validated_domain}",
                request.connectionParameters, request.connectionParameters.get("api_key"), "", {}
            )
            risk_score = 0
            if isinstance(raw_response, dict):
                risk_score = raw_response.get("risk_score", raw_response.get("score", 0))
                if isinstance(risk_score, dict):
                    risk_score = risk_score.get("value", risk_score.get("score", 0))
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Risk score for {validated_domain}: {int(risk_score)}",
                response={}, input={"domain": domain},
                output={"domain": validated_domain, "riskScore": int(risk_score) if isinstance(risk_score, (int, float)) else 0},
                incrementals=False
            )
        except ValueError as e:
            return ResponseBody(status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={"domain": domain}, output={}, incrementals=False)
        except ConnectionError as e:
            return ResponseBody(status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message=str(e), response={}, input={"domain": domain}, output={}, incrementals=False)
    # ============================================================================
    # Action 7: Passive DNS
    # ============================================================================
    def umbrella_list_resource_record(self, request: RequestBody) -> ResponseBody:
        """Retrieve passive DNS/resource-record information."""
        query = request.parameters.get("query")
        query_type = request.parameters.get("query_type", "name")
        try:
            validated_query = query.strip() if isinstance(query, str) else query
            valid_types = ["name", "domain", "ip", "raw"]
            if query_type not in valid_types:
                raise ValueError(f"Invalid query_type: {query_type}. Must be one of: {valid_types}")
            endpoint_map = {
                "name": f"/pdns/name/{urllib.parse.quote(validated_query)}",
                "domain": f"/pdns/domain/{urllib.parse.quote(validated_query)}",
                "ip": f"/pdns/ip/{validated_query}",
                "raw": f"/pdns/raw/{urllib.parse.quote(validated_query)}"
            }
            status_code, raw_response = self._request(
                "GET", endpoint_map[query_type],
                request.connectionParameters, request.connectionParameters.get("api_key"), "", {}
            )
            records = []
            if isinstance(raw_response, list):
                for record in raw_response:
                    if isinstance(record, dict):
                        records.append({
                            "recordType": record.get("type", record.get("record_type", "A")),
                            "recordName": record.get("name", record.get("rr", "")),
                            "recordData": record.get("value", record.get("rdata", "")),
                            "firstSeen": record.get("firstSeen", record.get("first_seen", 0)),
                            "lastSeen": record.get("lastSeen", record.get("last_seen", 0)),
                            "minTtl": record.get("minTtl", record.get("min_ttl", 0)),
                            "maxTtl": record.get("maxTtl", record.get("max_ttl", 0))
                        })
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Found {len(records)} passive DNS records",
                response={}, input={"query": query, "query_type": query_type},
                output={"query": query, "records": records, "count": len(records)}, incrementals=False
            )
        except ValueError as e:
            return ResponseBody(status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={"query": query}, output={}, incrementals=False)
        except ConnectionError as e:
            return ResponseBody(status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message=str(e), response={}, input={"query": query}, output={}, incrementals=False)
    # ============================================================================
    # Action 8: Subdomain Enumeration
    # ============================================================================
    def umbrella_list_domain_subdomain(self, request: RequestBody) -> ResponseBody:
        """Enumerate subdomains for a target domain."""
        domain = request.parameters.get("domain")
        limit = request.parameters.get("limit")
        try:
            validated_domain = self._validate_domain(domain)
            params = {}
            if limit:
                try:
                    params["limit"] = int(limit)
                except (ValueError, TypeError):
                    pass
            status_code, raw_response = self._request(
                "GET", f"/subdomains/{validated_domain}",
                request.connectionParameters, request.connectionParameters.get("api_key"), "", params
            )
            subdomains = []
            if isinstance(raw_response, dict):
                for sub, count in raw_response.items():
                    if isinstance(count, (int, float)):
                        subdomains.append(sub)
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Found {len(subdomains)} subdomains",
                response={}, input={"domain": domain, "limit": limit},
                output={"domain": validated_domain, "subdomains": subdomains, "count": len(subdomains)},
                incrementals=False
            )
        except ValueError as e:
            return ResponseBody(status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={"domain": domain}, output={}, incrementals=False)
        except ConnectionError as e:
            return ResponseBody(status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message=str(e), response={}, input={"domain": domain}, output={}, incrementals=False)

    # ============================================================================
    # Action 9: Domain WHOIS
    # ============================================================================
    def umbrella_get_whois_for_domain(self, request: RequestBody) -> ResponseBody:
        """Retrieve WHOIS information for a domain."""
        domain = request.parameters.get("domain")
        try:
            validated_domain = self._validate_domain(domain)
            status_code, raw_response = self._request(
                "GET", f"/whois/{validated_domain}",
                request.connectionParameters, request.connectionParameters.get("api_key"), "", {}
            )
            whois_info = raw_response if isinstance(raw_response, dict) else {}
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Successfully retrieved WHOIS for {validated_domain}",
                response={}, input={"domain": domain},
                output={"domain": validated_domain, "whois": whois_info}, incrementals=False
            )
        except ValueError as e:
            return ResponseBody(status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={"domain": domain}, output={}, incrementals=False)
        except ConnectionError as e:
            return ResponseBody(status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message=str(e), response={}, input={"domain": domain}, output={}, incrementals=False)
    # ============================================================================
    # Action 10: Domain WHOIS History
    # ============================================================================
    def umbrella_get_domain_whois_history(self, request: RequestBody) -> ResponseBody:
        """Retrieve WHOIS history for a domain."""
        domain = request.parameters.get("domain")
        try:
            validated_domain = self._validate_domain(domain)
            status_code, raw_response = self._request(
                "GET", f"/whois/{validated_domain}/history",
                request.connectionParameters, request.connectionParameters.get("api_key"), "", {}
            )
            history_records = []
            if isinstance(raw_response, list):
                for record in raw_response:
                    if isinstance(record, dict):
                        history_records.append({
                            "timestamp": record.get("timestamp", 0),
                            "whois": record.get("whois", ""),
                            "registrationDate": record.get("registrationDate", ""),
                            "expirationDate": record.get("expirationDate", "")
                        })
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Found {len(history_records)} WHOIS history records",
                response={}, input={"domain": domain},
                output={"domain": validated_domain, "history": history_records, "count": len(history_records)},
                incrementals=False
            )
        except ValueError as e:
            return ResponseBody(status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={"domain": domain}, output={}, incrementals=False)
        except ConnectionError as e:
            return ResponseBody(status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message=str(e), response={}, input={"domain": domain}, output={}, incrementals=False)

    # ============================================================================
    # Action 11: Email WHOIS
    # ============================================================================
    def umbrella_get_email_whois(self, request: RequestBody) -> ResponseBody:
        """Retrieve domains registered with an email address."""
        email = request.parameters.get("email")
        try:
            validated_email = self._validate_email(email)
            status_code, raw_response = self._request(
                "GET", f"/whois/emails/{urllib.parse.quote(validated_email)}",
                request.connectionParameters, request.connectionParameters.get("api_key"), "", {}
            )
            domains = []
            if isinstance(raw_response, list):
                domains = [d for d in raw_response if isinstance(d, str)]
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Found {len(domains)} domains registered with {validated_email}",
                response={}, input={"email": email},
                output={"email": validated_email, "domains": domains, "count": len(domains)},
                incrementals=False
            )
        except ValueError as e:
            return ResponseBody(status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={"email": email}, output={}, incrementals=False)
        except ConnectionError as e:
            return ResponseBody(status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message=str(e), response={}, input={"email": email}, output={}, incrementals=False)
    # ============================================================================
    # Action 12: Domain Timeline
    # ============================================================================
    def umbrella_get_domain_timeline(self, request: RequestBody) -> ResponseBody:
        """Retrieve timeline events for a domain."""
        domain = request.parameters.get("domain")
        try:
            validated_domain = self._validate_domain(domain)
            status_code, raw_response = self._request(
                "GET", f"/timeline/{validated_domain}",
                request.connectionParameters, request.connectionParameters.get("api_key"), "", {}
            )
            timeline = []
            if isinstance(raw_response, list):
                for event in raw_response:
                    if isinstance(event, dict):
                        timeline.append({
                            "timestamp": event.get("timestamp", 0),
                            "eventType": event.get("eventType", event.get("event_type", "")),
                            "description": event.get("description", "")
                        })
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Found {len(timeline)} timeline events for {validated_domain}",
                response={}, input={"domain": domain},
                output={"indicator": validated_domain, "indicatorType": "domain", "timeline": timeline, "count": len(timeline)},
                incrementals=False
            )
        except ValueError as e:
            return ResponseBody(status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={"domain": domain}, output={}, incrementals=False)
        except ConnectionError as e:
            return ResponseBody(status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message=str(e), response={}, input={"domain": domain}, output={}, incrementals=False)

    # ============================================================================
    # Action 13: URL Timeline
    # ============================================================================
    def umbrella_get_url_timeline(self, request: RequestBody) -> ResponseBody:
        """Retrieve timeline events for a URL."""
        url = request.parameters.get("url")
        try:
            validated_url = self._validate_url(url)
            status_code, raw_response = self._request(
                "GET", f"/timeline/{urllib.parse.quote(validated_url)}",
                request.connectionParameters, request.connectionParameters.get("api_key"), "", {}
            )
            timeline = []
            if isinstance(raw_response, list):
                for event in raw_response:
                    if isinstance(event, dict):
                        timeline.append({
                            "timestamp": event.get("timestamp", 0),
                            "eventType": event.get("eventType", event.get("event_type", "")),
                            "description": event.get("description", "")
                        })
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Found {len(timeline)} timeline events for {validated_url}",
                response={}, input={"url": url},
                output={"indicator": validated_url, "indicatorType": "url", "timeline": timeline, "count": len(timeline)},
                incrementals=False
            )
        except ValueError as e:
            return ResponseBody(status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={"url": url}, output={}, incrementals=False)
        except ConnectionError as e:
            return ResponseBody(status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message=str(e), response={}, input={"url": url}, output={}, incrementals=False)
    # ============================================================================
    # Action 14: IP Timeline
    # ============================================================================
    def umbrella_get_ip_timeline(self, request: RequestBody) -> ResponseBody:
        """Retrieve timeline events for an IP address."""
        ip = request.parameters.get("ip")
        try:
            validated_ip = self._validate_ip(ip, allow_ipv6=False)
            status_code, raw_response = self._request(
                "GET", f"/timeline/{validated_ip}",
                request.connectionParameters, request.connectionParameters.get("api_key"), "", {}
            )
            timeline = []
            if isinstance(raw_response, list):
                for event in raw_response:
                    if isinstance(event, dict):
                        timeline.append({
                            "timestamp": event.get("timestamp", 0),
                            "eventType": event.get("eventType", event.get("event_type", "")),
                            "description": event.get("description", "")
                        })
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Found {len(timeline)} timeline events for {validated_ip}",
                response={}, input={"ip": ip},
                output={"indicator": validated_ip, "indicatorType": "ip", "timeline": timeline, "count": len(timeline)},
                incrementals=False
            )
        except ValueError as e:
            return ResponseBody(status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={"ip": ip}, output={}, incrementals=False)
        except ConnectionError as e:
            return ResponseBody(status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message=str(e), response={}, input={"ip": ip}, output={}, incrementals=False)

    # ============================================================================
    # Action 15: IP BGP Lookup
    # ============================================================================
    def umbrella_get_ip_bgp(self, request: RequestBody) -> ResponseBody:
        """Retrieve BGP/ASN information for an IP address."""
        ip = request.parameters.get("ip")
        try:
            validated_ip = self._validate_ip(ip, allow_ipv6=True)
            status_code, raw_response = self._request(
                "GET", f"/bgp_routes/ip/{validated_ip}/as_for_ip.json",
                request.connectionParameters, request.connectionParameters.get("api_key"), "", {}
            )
            bgp_info = raw_response if isinstance(raw_response, dict) else {}
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Retrieved BGP info for {validated_ip}",
                response={}, input={"ip": ip},
                output={
                    "ip": validated_ip,
                    "asn": str(bgp_info.get("asn", bgp_info.get("as_number", ""))),
                    "cidr": bgp_info.get("cidr", ""),
                    "rir": bgp_info.get("rir", ""),
                    "description": bgp_info.get("description", bgp_info.get("as_description", ""))
                }, incrementals=False
            )
        except ValueError as e:
            return ResponseBody(status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={"ip": ip}, output={}, incrementals=False)
        except ConnectionError as e:
            return ResponseBody(status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message=str(e), response={}, input={"ip": ip}, output={}, incrementals=False)
    # ============================================================================
    # Action 16: ASN BGP Prefixes
    # ============================================================================
    def umbrella_get_asn_bgp(self, request: RequestBody) -> ResponseBody:
        """Retrieve network prefixes for an ASN."""
        asn = request.parameters.get("asn")
        try:
            validated_asn = self._validate_asn(asn)
            status_code, raw_response = self._request(
                "GET", f"/bgp_routes/asn/{validated_asn}/prefixes_for_asn.json",
                request.connectionParameters, request.connectionParameters.get("api_key"), "", {}
            )
            prefixes = []
            if isinstance(raw_response, dict):
                prefixes_list = raw_response.get("prefixes", [])
                if isinstance(prefixes_list, list):
                    prefixes = [p for p in prefixes_list if isinstance(p, str)]
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Found {len(prefixes)} prefixes for ASN {validated_asn}",
                response={}, input={"asn": asn},
                output={"asn": f"AS{validated_asn}", "prefixes": prefixes, "count": len(prefixes)},
                incrementals=False
            )
        except ValueError as e:
            return ResponseBody(status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={"asn": asn}, output={}, incrementals=False)
        except ConnectionError as e:
            return ResponseBody(status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message=str(e), response={}, input={"asn": asn}, output={}, incrementals=False)

    # ============================================================================
    # Action 17: ASN Info (New)
    # ============================================================================
    def umbrella_list_asn(self, request: RequestBody) -> ResponseBody:
        """List Autonomous System Number (ASN) information."""
        asn = request.parameters.get("asn")
        try:
            validated_asn = self._validate_asn(asn)
            status_code, raw_response = self._request(
                "GET", f"/bgp_routes/asn/{validated_asn}/as_for_asn.json",
                request.connectionParameters, request.connectionParameters.get("api_key"), "", {}
            )
            # Cisco returns {asn: info} format
            if isinstance(raw_response, dict):
                info = raw_response.get(str(validated_asn), raw_response)
                if isinstance(info, dict):
                    return ResponseBody(
                        status="SUCCESS", errorCode="", httpCode=status_code,
                        message=f"Retrieved ASN {validated_asn} information",
                        response={}, input={"asn": asn},
                        output={
                            "asn": f"AS{validated_asn}",
                            "asnInfo": info,
                            "description": info.get("description", ""),
                            "rir": info.get("rir", "")
                        }, incrementals=False
                    )
            return ResponseBody(
                status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message="Invalid ASN information response",
                response={}, input={"asn": asn}, output={}, incrementals=False
            )
        except ValueError as e:
            return ResponseBody(status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={"asn": asn}, output={}, incrementals=False)
        except ConnectionError as e:
            return ResponseBody(status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message=str(e), response={}, input={"asn": asn}, output={}, incrementals=False)

    # ============================================================================
    # Action 18: Find ASN for Prefix (New)
    # ============================================================================
    def umbrella_list_asn_for_prefix(self, request: RequestBody) -> ResponseBody:
        """Find the ASN associated with an IP prefix."""
        prefix = request.parameters.get("prefix")
        try:
            if not prefix or not isinstance(prefix, str):
                raise ValueError("Prefix must be a non-empty string")
            prefix = prefix.strip()
            # Validate CIDR format
            if "/" not in prefix:
                raise ValueError("Prefix must be in CIDR format (e.g., 8.8.8.0/24)")
            status_code, raw_response = self._request(
                "GET", f"/bgp_routes/prefix/{prefix}/as_for_prefix.json",
                request.connectionParameters, request.connectionParameters.get("api_key"), "", {}
            )
            # Cisco returns {prefix: info} format
            if isinstance(raw_response, dict):
                info = raw_response.get(prefix, {})
                if isinstance(info, dict):
                    return ResponseBody(
                        status="SUCCESS", errorCode="", httpCode=status_code,
                        message=f"Retrieved ASN for prefix {prefix}",
                        response={}, input={"prefix": prefix},
                        output={
                            "prefix": prefix,
                            "asn": info.get("asn", ""),
                            "asnDescription": info.get("description", ""),
                            "rir": info.get("rir", "")
                        }, incrementals=False
                    )
            return ResponseBody(
                status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message="Invalid prefix ASN response",
                response={}, input={"prefix": prefix}, output={}, incrementals=False
            )
        except ValueError as e:
            return ResponseBody(status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={"prefix": prefix}, output={}, incrementals=False)
        except ConnectionError as e:
            return ResponseBody(status="FAILURE", errorCode="CISCO_API_ERROR", httpCode=0,
                message=str(e), response={}, input={"prefix": prefix}, output={}, incrementals=False)
