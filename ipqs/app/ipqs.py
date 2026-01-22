import logging
import json
import requests
from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody


class Ipqs:
    def __init__(self):
        self.logger = logging.getLogger()
        self.base_url = None
        self.api_key = None
        self.timeout = 30

    # This method is automatically called by SOAR (with and without params)
    def init_client(self, connectionParameters=None):
        if not connectionParameters:
            return

        self.base_url = connectionParameters["base_url"].rstrip("/")
        self.api_key = connectionParameters["api_key"]
        self.timeout = connectionParameters.get("timeout", 30)

    # Test connection to IPQS API
    def test_connection(self, connectionParameters: dict):
        self.init_client(connectionParameters)
        try:
            test_ip = "8.8.8.8"
            url = f"{self.base_url}/api/json/ip/{self.api_key}/{test_ip}"

            resp = requests.get(url, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()

            self.logger.debug("IPQS response to test_connection is %s", json.dumps(data))

            if data.get("success", False):
                return {
                    'status': 'success',
                    'message': 'Connection Successful.'
                }
            else:
                raise Exception(f"IPQS API returned error: {data}")

        except Exception as e:
            self.logger.error("Exception while testing IPQS connection parameters", exc_info=e)
            raise Exception(str(e))

    def _normalize_ips(self, ips):
        if isinstance(ips, str):
            return [ip.strip() for ip in ips.split(",")]
        elif isinstance(ips, list):
            return ips
        else:
            raise Exception("Invalid IP format")

    def _lookup_ip(self, ip: str):
        url = f"{self.base_url}/api/json/ip/{self.api_key}/{ip}"
        resp = requests.get(url, timeout=self.timeout)
        if resp.status_code != 200:
            raise Exception(f"API error: {resp.text}")
        return resp.json()

    def detect_residential_proxies(self, request: RequestBody) -> ResponseBody:
        self.init_client(request.connectionParameters)
        ips = self._normalize_ips(request.parameters["ips"])
        results = []

        for ip in ips:
            data = self._lookup_ip(ip)
            if data.get("is_residential_proxy", False):
                results.append({"ip": ip, "category": "Residential Proxy"})

        return {"status": "success", "results": results}

    def detect_private_vpn(self, request: RequestBody) -> ResponseBody:
        self.init_client(request.connectionParameters)
        ips = self._normalize_ips(request.parameters["ips"])
        results = []

        for ip in ips:
            data = self._lookup_ip(ip)
            if data.get("vpn", False):
                results.append({"ip": ip, "category": "Private VPN"})

        return {"status": "success", "results": results}

    def detect_tor_nodes(self, request: RequestBody) -> ResponseBody:
        self.init_client(request.connectionParameters)
        ips = self._normalize_ips(request.parameters["ips"])
        results = []

        for ip in ips:
            data = self._lookup_ip(ip)
            if data.get("tor", False):
                results.append({"ip": ip, "category": "Tor Node"})

        return {"status": "success", "results": results}

    def detect_anonymous_proxies(self, request: RequestBody) -> ResponseBody:
        self.init_client(request.connectionParameters)
        ips = self._normalize_ips(request.parameters["ips"])
        results = []

        for ip in ips:
            data = self._lookup_ip(ip)
            if data.get("proxy", False):
                results.append({"ip": ip, "category": "Anonymous Proxy"})

        return {"status": "success", "results": results}

    def detect_botnets(self, request: RequestBody) -> ResponseBody:
        self.init_client(request.connectionParameters)
        ips = self._normalize_ips(request.parameters["ips"])
        results = []

        for ip in ips:
            data = self._lookup_ip(ip)
            if data.get("bot_status", False):
                results.append({"ip": ip, "category": "Botnet"})

        return {"status": "success", "results": results}

    def detect_malicious_ips(self, request: RequestBody) -> ResponseBody:
        self.init_client(request.connectionParameters)
        ips = self._normalize_ips(request.parameters["ips"])
        results = []

        for ip in ips:
            data = self._lookup_ip(ip)
            if data.get("fraud_score", 0) >= 75:
                results.append({
                    "ip": ip,
                    "category": "Malicious IP",
                    "risk_score": data.get("fraud_score")
                })

        return {"status": "success", "results": results}
