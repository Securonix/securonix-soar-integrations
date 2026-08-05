from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import json
import requests


class Ipqs():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    # -------------------------------
    # Test Connection (SOAR calls this)
    # -------------------------------
    def test_connection(self, connectionParameters: dict):
        base_url = connectionParameters['base_url'].rstrip('/')
        api_key = connectionParameters['api_key']
        timeout = connectionParameters.get('timeout', 30)
        if timeout in [None, "None", "", "null"]:
            timeout = 30
        else:
            timeout = int(timeout)

        try:
            test_ip = "8.8.8.8"
            url = f"{base_url}/api/json/ip/{api_key}/{test_ip}"
            resp = requests.get(url, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("IPQS response to test_connection is %s", json.dumps(data))
            if data.get("success", False):
                return {'status': 'success', 'message': 'Connected to IPQualityScore successfully.'}
            raise Exception(f"IPQS API returned error: {data}")
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IPQS. Please verify the base_url and network connectivity.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IPQS timed out.")
        except Exception:
            self.logger.error("Exception while testing IPQS connection parameters", exc_info=True)
            raise

    # -------------------------------
    # Internal helpers
    # -------------------------------
    def _normalize_ips(self, ips):
        if isinstance(ips, str):
            return [ip.strip() for ip in ips.split(",") if ip.strip()]
        elif isinstance(ips, list):
            return [ip.strip() for ip in ips if ip.strip()]
        else:
            raise Exception("Invalid IP format")

    def _lookup_ip(self, base_url, api_key, timeout, ip):
        url = f"{base_url}/api/json/ip/{api_key}/{ip}"
        resp = requests.get(url, timeout=timeout)
        if resp.status_code in (401, 403):
            raise Exception("Authentication failed. Please verify your API key.")
        if resp.status_code >= 500:
            raise Exception(f"IPQS server error: HTTP {resp.status_code}")
        if resp.status_code >= 400:
            raise Exception(f"IPQS request failed: HTTP {resp.status_code}")
        return resp.json()

    def _get_connection(self, connectionParameters: dict):
        base_url = connectionParameters['base_url'].rstrip('/')
        api_key = connectionParameters['api_key']
        timeout = connectionParameters.get('timeout', 30)
        if timeout in [None, "None", "", "null"]:
            timeout = 30
        else:
            timeout = int(timeout)
        return base_url, api_key, timeout

    # -------------------------------
    # Actions
    # -------------------------------
    def detect_residential_proxies(self, request: RequestBody) -> ResponseBody:
        base_url, api_key, timeout = self._get_connection(request.connectionParameters)
        ips = self._normalize_ips(request.parameters["sourceaddress"])
        results = []
        try:
            for ip in ips:
                data = self._lookup_ip(base_url, api_key, timeout, ip)
                if data.get("is_residential_proxy"):
                    results.append({"ip": ip, "category": "Residential Proxy"})
            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IPQS. Please verify the base_url and network connectivity.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IPQS timed out.")
        except Exception:
            self.logger.error("error while running action 'detect_residential_proxies'", exc_info=True)
            raise

    def detect_private_vpn(self, request: RequestBody) -> ResponseBody:
        base_url, api_key, timeout = self._get_connection(request.connectionParameters)
        ips = self._normalize_ips(request.parameters["sourceaddress"])
        results = []
        try:
            for ip in ips:
                data = self._lookup_ip(base_url, api_key, timeout, ip)
                if data.get("vpn"):
                    results.append({"ip": ip, "category": "Private VPN"})
            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IPQS. Please verify the base_url and network connectivity.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IPQS timed out.")
        except Exception:
            self.logger.error("error while running action 'detect_private_vpn'", exc_info=True)
            raise

    def detect_tor_nodes(self, request: RequestBody) -> ResponseBody:
        base_url, api_key, timeout = self._get_connection(request.connectionParameters)
        ips = self._normalize_ips(request.parameters["sourceaddress"])
        results = []
        try:
            for ip in ips:
                data = self._lookup_ip(base_url, api_key, timeout, ip)
                if data.get("tor"):
                    results.append({"ip": ip, "category": "Tor Node"})
            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IPQS. Please verify the base_url and network connectivity.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IPQS timed out.")
        except Exception:
            self.logger.error("error while running action 'detect_tor_nodes'", exc_info=True)
            raise

    def detect_anonymous_proxies(self, request: RequestBody) -> ResponseBody:
        base_url, api_key, timeout = self._get_connection(request.connectionParameters)
        ips = self._normalize_ips(request.parameters["sourceaddress"])
        results = []
        try:
            for ip in ips:
                data = self._lookup_ip(base_url, api_key, timeout, ip)
                if data.get("proxy"):
                    results.append({"ip": ip, "category": "Anonymous Proxy"})
            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IPQS. Please verify the base_url and network connectivity.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IPQS timed out.")
        except Exception:
            self.logger.error("error while running action 'detect_anonymous_proxies'", exc_info=True)
            raise

    def detect_botnets(self, request: RequestBody) -> ResponseBody:
        base_url, api_key, timeout = self._get_connection(request.connectionParameters)
        ips = self._normalize_ips(request.parameters["sourceaddress"])
        results = []
        try:
            for ip in ips:
                data = self._lookup_ip(base_url, api_key, timeout, ip)
                if data.get("bot_status"):
                    results.append({"ip": ip, "category": "Botnet"})
            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IPQS. Please verify the base_url and network connectivity.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IPQS timed out.")
        except Exception:
            self.logger.error("error while running action 'detect_botnets'", exc_info=True)
            raise

    def detect_malicious_ips(self, request: RequestBody) -> ResponseBody:
        base_url, api_key, timeout = self._get_connection(request.connectionParameters)
        ips = self._normalize_ips(request.parameters["sourceaddress"])
        results = []
        try:
            for ip in ips:
                data = self._lookup_ip(base_url, api_key, timeout, ip)
                if data.get("fraud_score", 0) >= 75:
                    results.append({
                        "ip": ip,
                        "category": "Malicious IP",
                        "risk_score": data.get("fraud_score")
                    })
            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IPQS. Please verify the base_url and network connectivity.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IPQS timed out.")
        except Exception:
            self.logger.error("error while running action 'detect_malicious_ips'", exc_info=True)
            raise
