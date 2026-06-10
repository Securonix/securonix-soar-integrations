from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import json
import time
import re
import requests


logger = logging.getLogger(__name__)


class Mxtoolbox():

    DEFAULT_BASE_URL = "https://mxtoolbox.com/api/v1"

    COMMON_DKIM_SELECTORS = ["google", "selector1", "s1"]

    def __init__(self) -> None:
        pass

    @staticmethod
    def _get_connection(connection_params: dict) -> tuple:
        base_url = connection_params.get('base_url', Mxtoolbox.DEFAULT_BASE_URL)
        if not base_url:
            base_url = Mxtoolbox.DEFAULT_BASE_URL
        base_url = base_url.rstrip('/')
        api_key = connection_params['api_key']
        timeout = connection_params.get('timeout', 30)
        if timeout in [None, "None", "", "null"]:
            timeout = 30
        else:
            timeout = int(timeout)
        max_retries = connection_params.get('max_retries', 3)
        if max_retries in [None, "None", "", "null"]:
            max_retries = 3
        else:
            max_retries = int(max_retries)
        return base_url, api_key, timeout, max_retries

    @staticmethod
    def _get_headers(api_key: str = '') -> dict:
        return {
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

    @staticmethod
    def _request_with_retry(url: str, headers: dict, params: dict,
                            timeout: int, max_retries: int) -> dict:
        
        last_exception = None
        for attempt in range(max_retries):
            try:
                resp = requests.get(url, headers=headers, params=params, timeout=timeout)
                if resp.status_code == 429:
                    backoff = min(2 ** attempt, 16)
                    if attempt < max_retries - 1:
                        logger.warning(
                            "Rate limited (429), retrying in %ds (attempt %d/%d)",
                            backoff, attempt + 1, max_retries
                        )
                        time.sleep(backoff)
                        continue
                    raise Exception("Rate limit exceeded after all retries")
                if resp.status_code == 401:
                    raise Exception("Authentication failed: invalid API key")
                if resp.status_code == 403:
                    raise Exception("Access denied: check API key permissions")
                if resp.status_code >= 500:
                    raise Exception(f"MXToolbox server error: {resp.status_code}")
                if resp.status_code >= 300:
                    raise Exception(f"MXToolbox API error: {resp.status_code} - {resp.text[:500]}")
                data = resp.json()
                errors = data.get("Errors", [])
                if errors:
                    error_msg = errors[0].get("message", "Unknown error") if isinstance(errors[0], dict) else str(errors[0])
                    raise Exception(f"MXToolbox API error: {error_msg}")
                return data
            except requests.exceptions.Timeout:
                last_exception = Exception("Request timed out")
                if attempt < max_retries - 1:
                    backoff = min(2 ** attempt, 16)
                    logger.warning(
                        "Timeout, retrying in %ds (attempt %d/%d)",
                        backoff, attempt + 1, max_retries
                    )
                    time.sleep(backoff)
                    continue
            except requests.exceptions.ConnectionError:
                last_exception = Exception("Failed to connect to MXToolbox")
                if attempt < max_retries - 1:
                    backoff = min(2 ** attempt, 16)
                    logger.warning(
                        "Connection error, retrying in %ds (attempt %d/%d)",
                        backoff, attempt + 1, max_retries
                    )
                    time.sleep(backoff)
                    continue
            except Exception:
                raise
        if last_exception:
            raise last_exception
        raise Exception("Request failed after all retries")

    @staticmethod
    def _validate_ip(ip_address: str) -> str:
        ip_address = ip_address.strip()
        if not ip_address:
            raise Exception("IP address is required")
        parts = ip_address.split('.')
        if len(parts) != 4:
            raise Exception(f"Invalid IP address format: {ip_address}")
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                raise Exception(f"Invalid IP address format: {ip_address}")
        return ip_address

    @staticmethod
    def _validate_domain(domain: str) -> str:
        domain = domain.strip()
        if not domain:
            raise Exception("Domain is required")
        if ' ' in domain:
            raise Exception(f"Invalid domain format: {domain}")
        if domain.startswith('.') or domain.endswith('.'):
            raise Exception(f"Invalid domain format: {domain}")
        if '..' in domain:
            raise Exception(f"Invalid domain format: {domain}")
        if '.' not in domain:
            raise Exception(f"Invalid domain format: {domain}")
        return domain

    @staticmethod
    def _lookup(base_url: str, api_key: str, timeout: int, max_retries: int,
                command: str, argument: str) -> dict:
        url = f"{base_url}/lookup/{command}/"
        headers = Mxtoolbox._get_headers(api_key)
        params = {"argument": argument}
        
        logger.debug("MXToolbox lookup: %s ?argument=%s", command, argument)
        data = Mxtoolbox._request_with_retry(url, headers, params, timeout, max_retries)
        logger.debug("MXToolbox response received for %s", command)
        return data

    @staticmethod
    def _assess_risk(listed_count: int, total_checks: int) -> str:
        if listed_count == 0:
            return "low"
        ratio = listed_count / total_checks if total_checks > 0 else 0
        if ratio >= 0.5:
            return "critical"
        if ratio >= 0.2:
            return "high"
        if ratio >= 0.05:
            return "medium"
        return "low"

    @staticmethod
    def _classify_results(results: list) -> tuple:
        listed = [r for r in results if r.get("Status") == "Failed"]
        clean = [r for r in results if r.get("Status") != "Failed"]
        return listed, clean

    # -------------------------------------------------------------------------
    # Test Connection
    # -------------------------------------------------------------------------
    def test_connection(self, connectionParameters: dict):
        try:
            base_url = connectionParameters.get('base_url', Mxtoolbox.DEFAULT_BASE_URL)
            if not base_url:
                base_url = Mxtoolbox.DEFAULT_BASE_URL
            base_url = base_url.rstrip('/')
            api_key = connectionParameters.get('api_key', '')
            timeout = connectionParameters.get('timeout', 30)
            if timeout in [None, "None", "", "null"]:
                timeout = 30
            else:
                timeout = int(timeout)

            url = f"{base_url}/lookup/dns/"
            headers = {
                "Authorization": api_key,
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            params = {"argument": "example.com"}
            resp = requests.get(url, headers=headers, params=params, timeout=timeout)
            if resp.status_code == 401:
                raise Exception("Authentication failed: invalid API key")
            if resp.status_code == 403:
                raise Exception("Access denied: check API key permissions")
            if resp.status_code >= 500:
                raise Exception(f"MXToolbox server error: {resp.status_code}")
            return {'status': 'success', 'message': 'Connected to MXToolbox successfully.'}
        except Exception as e:
            logger.error("Exception while testing MXToolbox connection", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Action 1: IP Blacklist Check
    # -------------------------------------------------------------------------
    def blacklist_ip_check(self, request: RequestBody) -> ResponseBody:
        try:
            logger.info("blacklist_ip_check called with connectionParameters keys=%s, parameters=%s",
                        list(request.connectionParameters.keys()) if request.connectionParameters else None,
                        request.parameters)
            base_url, api_key, timeout, max_retries = Mxtoolbox._get_connection(request.connectionParameters)
            ip_address = Mxtoolbox._validate_ip(request.parameters.get('ip_address', ''))
            data = Mxtoolbox._lookup(base_url, api_key, timeout, max_retries, "blacklist", ip_address)
            results = data.get("Result", [])
            listed, clean = Mxtoolbox._classify_results(results)
            verdict = "listed" if listed else "clean"
            return {
                "success": True,
                "indicator": ip_address,
                "indicator_type": "ip",
                "lookup_type": "blacklist",
                "summary": {
                    "verdict": verdict,
                    "risk_level": Mxtoolbox._assess_risk(len(listed), len(results))
                },
                "data": {
                    "listed_count": len(listed),
                    "total_checks": len(results),
                    "listed_on": listed,
                    "clean_on": clean
                },
                "raw_response": data
            }
        except Exception as e:
            logger.error("Error in blacklist_ip_check", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Action 2: Domain Blacklist Check
    # -------------------------------------------------------------------------
    def blacklist_domain_check(self, request: RequestBody) -> ResponseBody:
        try:
            logger.info("blacklist_domain_check called with connectionParameters keys=%s, parameters=%s",
                        list(request.connectionParameters.keys()) if request.connectionParameters else None,
                        request.parameters)
            base_url, api_key, timeout, max_retries = Mxtoolbox._get_connection(request.connectionParameters)
            domain = Mxtoolbox._validate_domain(request.parameters.get('domain', ''))
            data = Mxtoolbox._lookup(base_url, api_key, timeout, max_retries, "blacklist", domain)
            results = data.get("Result", [])
            listed, clean = Mxtoolbox._classify_results(results)
            verdict = "listed" if listed else "clean"
            return {
                "success": True,
                "indicator": domain,
                "indicator_type": "domain",
                "lookup_type": "blacklist",
                "summary": {
                    "verdict": verdict,
                    "risk_level": Mxtoolbox._assess_risk(len(listed), len(results))
                },
                "data": {
                    "listed_count": len(listed),
                    "total_checks": len(results),
                    "listed_on": listed,
                    "clean_on": clean
                },
                "raw_response": data
            }
        except Exception as e:
            logger.error("Error in blacklist_domain_check", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Action 3: MX Record Lookup
    # -------------------------------------------------------------------------
    def mx_lookup(self, request: RequestBody) -> ResponseBody:
        try:
            logger.info("mx_lookup called with connectionParameters keys=%s, parameters=%s",
                        list(request.connectionParameters.keys()) if request.connectionParameters else None,
                        request.parameters)
            base_url, api_key, timeout, max_retries = Mxtoolbox._get_connection(request.connectionParameters)
            domain = Mxtoolbox._validate_domain(request.parameters.get('domain', ''))
            data = Mxtoolbox._lookup(base_url, api_key, timeout, max_retries, "mx", domain)
            results = data.get("Result", [])
            return {
                "success": True,
                "indicator": domain,
                "indicator_type": "domain",
                "lookup_type": "mx",
                "summary": {
                    "verdict": "found" if results else "no_records",
                    "record_count": len(results)
                },
                "data": {
                    "records": results,
                    "record_count": len(results)
                },
                "raw_response": data
            }
        except Exception as e:
            logger.error("Error in mx_lookup", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Action 4: DNS Lookup
    # -------------------------------------------------------------------------
    def dns_lookup(self, request: RequestBody) -> ResponseBody:
        try:
            logger.info("dns_lookup called with connectionParameters keys=%s, parameters=%s",
                        list(request.connectionParameters.keys()) if request.connectionParameters else None,
                        request.parameters)
            base_url, api_key, timeout, max_retries = Mxtoolbox._get_connection(request.connectionParameters)
            domain = Mxtoolbox._validate_domain(request.parameters.get('domain', ''))
            data = Mxtoolbox._lookup(base_url, api_key, timeout, max_retries, "dns", domain)
            results = data.get("Result", [])
            return {
                "success": True,
                "indicator": domain,
                "indicator_type": "domain",
                "lookup_type": "dns",
                "summary": {
                    "verdict": "resolved" if results else "no_records",
                    "record_count": len(results)
                },
                "data": {
                    "records": results,
                    "record_count": len(results)
                },
                "raw_response": data
            }
        except Exception as e:
            logger.error("Error in dns_lookup", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Action 5: Reverse DNS (PTR) Lookup
    # -------------------------------------------------------------------------
    def reverse_dns_lookup(self, request: RequestBody) -> ResponseBody:
        try:
            logger.info("reverse_dns_lookup called with connectionParameters keys=%s, parameters=%s",
                        list(request.connectionParameters.keys()) if request.connectionParameters else None,
                        request.parameters)
            base_url, api_key, timeout, max_retries = Mxtoolbox._get_connection(request.connectionParameters)
            ip_address = Mxtoolbox._validate_ip(request.parameters.get('ip_address', ''))
            data = Mxtoolbox._lookup(base_url, api_key, timeout, max_retries, "ptr", ip_address)
            results = data.get("Result", [])
            return {
                "success": True,
                "indicator": ip_address,
                "indicator_type": "ip",
                "lookup_type": "ptr",
                "summary": {
                    "verdict": "resolved" if results else "no_records",
                    "record_count": len(results)
                },
                "data": {
                    "records": results,
                    "record_count": len(results)
                },
                "raw_response": data
            }
        except Exception as e:
            logger.error("Error in reverse_dns_lookup", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Action 6: SPF Check
    # -------------------------------------------------------------------------
    def spf_check(self, request: RequestBody) -> ResponseBody:
        try:
            logger.info("spf_check called with connectionParameters keys=%s, parameters=%s",
                        list(request.connectionParameters.keys()) if request.connectionParameters else None,
                        request.parameters)
            base_url, api_key, timeout, max_retries = Mxtoolbox._get_connection(request.connectionParameters)
            domain = Mxtoolbox._validate_domain(request.parameters.get('domain', ''))
            data = Mxtoolbox._lookup(base_url, api_key, timeout, max_retries, "spf", domain)
            results = data.get("Result", [])
            failed, passed = Mxtoolbox._classify_results(results)
            return {
                "success": True,
                "indicator": domain,
                "indicator_type": "domain",
                "lookup_type": "spf",
                "summary": {
                    "verdict": "invalid" if failed else "valid",
                    "risk_level": Mxtoolbox._assess_risk(len(failed), len(results))
                },
                "data": {
                    "spf_valid": len(failed) == 0,
                    "failures": failed,
                    "passes": passed,
                    "total_checks": len(results)
                },
                "raw_response": data
            }
        except Exception as e:
            logger.error("Error in spf_check", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Action 7: DKIM Check
    # -------------------------------------------------------------------------
    def dkim_check(self, request: RequestBody) -> ResponseBody:
        try:
            logger.info("dkim_check called with connectionParameters keys=%s, parameters=%s",
                        list(request.connectionParameters.keys()) if request.connectionParameters else None,
                        request.parameters)
            base_url, api_key, timeout, max_retries = Mxtoolbox._get_connection(request.connectionParameters)
            domain = Mxtoolbox._validate_domain(request.parameters.get('domain', ''))
            selector = request.parameters.get('selector')
            if selector:
                lookup_arg = f"{selector}._domainkey.{domain}"
                data = Mxtoolbox._lookup(base_url, api_key, timeout, max_retries, "dkim", lookup_arg)
                results = data.get("Result", [])
                failed, passed = Mxtoolbox._classify_results(results)
            else:
                failed, passed, results = [], [], []
                for sel in Mxtoolbox.COMMON_DKIM_SELECTORS:
                    lookup_arg = f"{sel}._domainkey.{domain}"
                    data = Mxtoolbox._lookup(base_url, api_key, timeout, max_retries, "dkim", lookup_arg)
                    results = data.get("Result", [])
                    failed, passed = Mxtoolbox._classify_results(results)
                    if passed:
                        selector = sel
                        break
                if not selector:
                    selector = "not_found"
            return {
                "success": True,
                "indicator": domain,
                "indicator_type": "domain",
                "lookup_type": "dkim",
                "summary": {
                    "verdict": "invalid" if failed else "valid",
                },
                "data": {
                    "dkim_valid": len(failed) == 0,
                    "selector": selector,
                    "failures": failed,
                    "passes": passed,
                    "total_checks": len(results)
                },
                "raw_response": data
            }
        except Exception as e:
            logger.error("Error in dkim_check", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Action 8: DMARC Check
    # -------------------------------------------------------------------------
    def dmarc_check(self, request: RequestBody) -> ResponseBody:
        try:
            logger.info("dmarc_check called with connectionParameters keys=%s, parameters=%s",
                        list(request.connectionParameters.keys()) if request.connectionParameters else None,
                        request.parameters)
            base_url, api_key, timeout, max_retries = Mxtoolbox._get_connection(request.connectionParameters)
            domain = Mxtoolbox._validate_domain(request.parameters.get('domain', ''))
            data = Mxtoolbox._lookup(base_url, api_key, timeout, max_retries, "dmarc", domain)
            results = data.get("Result", [])
            failed, passed = Mxtoolbox._classify_results(results)
            return {
                "success": True,
                "indicator": domain,
                "indicator_type": "domain",
                "lookup_type": "dmarc",
                "summary": {
                    "verdict": "invalid" if failed else "valid",
                    "risk_level": Mxtoolbox._assess_risk(len(failed), len(results))
                },
                "data": {
                    "dmarc_valid": len(failed) == 0,
                    "failures": failed,
                    "passes": passed,
                    "total_checks": len(results)
                },
                "raw_response": data
            }
        except Exception as e:
            logger.error("Error in dmarc_check", exc_info=e)
            raise Exception(str(e))
