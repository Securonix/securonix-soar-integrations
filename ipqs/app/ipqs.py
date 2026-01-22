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

        try:
            test_ip = "8.8.8.8"
            url = f"{base_url}/api/json/ip/{api_key}/{test_ip}"

            resp = requests.get(url, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()

            self.logger.debug("IPQS response to test_connection is %s", json.dumps(data))

            if data.get("success", False):
                return {'status': 'success', 'message': 'Connected to IPQualityScore successfully.'}
            else:
                raise Exception(f"IPQS API returned error: {data}")

        except Exception as e:
            self.logger.error("Exception while testing IPQS connection parameters", exc_info=e)
            raise Exception(str(e))

    # -------------------------------
    # Internal helpers
    # -------------------------------
    def _normalize_ips(self, ips):
        if isinstance(ips, str):
            return [ip.strip() for ip in ips.split(",")]
        elif isinstance(ips, list):
            return ips
        else:
            raise Exception("Invalid IP format")

    def _lookup_ip(self, base_url, api_key, timeout, ip):
        url = f"{base_url}/api/json/ip/{api_key}/{ip}"
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.json()

    # -------------------------------
    # Actions
    # -------------------------------
    def detect_residential_proxies(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        api_key = request.connectionParameters['api_key']
        timeout = request.connectionParameters.get('timeout', 30)

        ips = self._normalize_ips(request.parameters["ips"])
        results = []

        for ip in ips:
            data = self._lookup_ip(base_url, api_key, timeout, ip)
            if data.get("is_residential_proxy"):
                results.append({"ip": ip, "category": "Residential Proxy"})

        return {"status": "success", "results": results}

    def detect_private_vpn(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        api_key = request.connectionParameters['api_key']
        timeout = request.connectionParameters.get('timeout', 30)

        ips = self._normalize_ips(request.parameters["ips"])
        results = []

        for ip in ips:
            data = self._lookup_ip(base_url, api_key, timeout, ip)
            if data.get("vpn"):
                results.append({"ip": ip, "category": "Private VPN"})

        return {"status": "success", "results": results}

    def detect_tor_nodes(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        api_key = request.connectionParameters['api_key']
        timeout = request.connectionParameters.get('timeout', 30)

        ips = self._normalize_ips(request.parameters["ips"])
        results = []

        for ip in ips:
            data = self._lookup_ip(base_url, api_key, timeout, ip)
            if data.get("tor"):
                results.append({"ip": ip, "category": "Tor Node"})

        return {"status": "success", "results": results}

    def detect_anonymous_proxies(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        api_key = request.connectionParameters['api_key']
        timeout = request.connectionParameters.get('timeout', 30)

        ips = self._normalize_ips(request.parameters["ips"])
        results = []

        for ip in ips:
            data = self._lookup_ip(base_url, api_key, timeout, ip)
            if data.get("proxy"):
                results.append({"ip": ip, "category": "Anonymous Proxy"})

        return {"status": "success", "results": results}

    def detect_botnets(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        api_key = request.connectionParameters['api_key']
        timeout = request.connectionParameters.get('timeout', 30)

        ips = self._normalize_ips(request.parameters["ips"])
        results = []

        for ip in ips:
            data = self._lookup_ip(base_url, api_key, timeout, ip)
            if data.get("bot_status"):
                results.append({"ip": ip, "category": "Botnet"})

        return {"status": "success", "results": results}

    def detect_malicious_ips(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        api_key = request.connectionParameters['api_key']
        timeout = request.connectionParameters.get('timeout', 30)

        ips = self._normalize_ips(request.parameters["ips"])
        results = []

        for ip in ips:
            data = self._lookup_ip(base_url, api_key, timeout, ip)
            if data.get("fraud_score", 0) >= 75:
                results.append({
                    "ip": ip,
                    "category": "Malicious IP",
                    "risk_score": data.get("fraud_score")
                })

        return {"status": "success", "results": results}
