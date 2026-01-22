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

    # SOAR automatically calls this with connection params
    def init_client(self, connectionParameters):
        self.base_url = connectionParameters["base_url"].rstrip("/")
        self.api_key = connectionParameters["api_key"]
        self.timeout = connectionParameters.get("timeout", 30)

    # SOAR calls this with NO arguments
    def test_connection(self):
        try:
            test_ip = "8.8.8.8"
            url = f"{self.base_url}/api/json/ip/{self.api_key}/{test_ip}"

            resp = requests.get(url, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()

            if data.get("success", False):
                return {
                    "status": "success",
                    "message": "Connection Successful."
                }
            else:
                return {
                    "status": "error",
                    "message": f"IPQS error: {data}"
                }

        except Exception as e:
            self.logger.error("IPQS connection test failed", exc_info=True)
            return {
                "status": "error",
                "message": str(e)
            }

    def _normalize_ips(self, ips):
        if isinstance(ips, str):
            return [ip.strip() for ip in ips.split(",")]
        return ips

    def _lookup_ip(self, ip):
        url = f"{self.base_url}/api/json/ip/{self.api_key}/{ip}"
        resp = requests.get(url, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def detect_residential_proxies(self, request: RequestBody) -> ResponseBody:
        ips = self._normalize_ips(request.parameters["ips"])
        results = []

        for ip in ips:
            data = self._lookup_ip(ip)
            if data.get("is_residential_proxy"):
                results.append({"ip": ip, "category": "Residential Proxy"})

        return {"status": "success", "results": results}

    def detect_private_vpn(self, request: RequestBody) -> ResponseBody:
        ips = self._normalize_ips(request.parameters["ips"])
        results = []

        for ip in ips:
            data = self._lookup_ip(ip)
            if data.get("vpn"):
                results.append({"ip": ip, "category": "Private VPN"})

        return {"status": "success", "results": results}

    def detect_tor_nodes(self, request: RequestBody) -> ResponseBody:
        ips = self._normalize_ips(request.parameters["ips"])
        results = []

        for ip in ips:
            data = self._lookup_ip(ip)
            if data.get("tor"):
                results.append({"ip": ip, "category": "Tor Node"})

        return {"status": "success", "results": results}

    def detect_anonymous_proxies(self, request: RequestBody) -> ResponseBody:
        ips = self._normalize_ips(request.parameters["ips"])
        results = []

        for ip in ips:
            data = self._lookup_ip(ip)
            if data.get("proxy"):
                results.append({"ip": ip, "category": "Anonymous Proxy"})

        return {"status": "success", "results": results}

    def detect_botnets(self, request: RequestBody) -> ResponseBody:
        ips = self._normalize_ips(request.parameters["ips"])
        results = []

        for ip in ips:
            data = self._lookup_ip(ip)
            if data.get("bot_status"):
                results.append({"ip": ip, "category": "Botnet"})

        return {"status": "success", "results": results}

    def detect_malicious_ips(self, request: RequestBody) -> ResponseBody:
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
