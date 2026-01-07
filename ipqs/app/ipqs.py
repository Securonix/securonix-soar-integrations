from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import json
import requests
import hmac
import hashlib
import base64
import time
import uuid


class Ipqs():

    def __init__(self):
        self.logger = logging.getLogger()

    def _init_client(self, connectionParameters):
        self.base_url = connectionParameters["base_url"]
        self.api_key = connectionParameters["api_key"]
        self.timeout = connectionParameters.get("timeout", 30)

    def _normalize_ips(self, ips):
        if isinstance(ips, str):
            return [ip.strip() for ip in ips.split(",")]
        elif isinstance(ips, list):
            return ips
        else:
            raise Exception("Invalid IP format")

    def _lookup_ip(self, ip):
        url = f"{self.base_url}/ip/{ip}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json"
        }
        resp = requests.get(url, headers=headers, timeout=self.timeout)
        if resp.status_code != 200:
            raise Exception(f"API error: {resp.text}")
        return resp.json()

    def detect_residential_proxies(self, request: RequestBody) -> ResponseBody:
        self._init_client(request.connectionParameters)
        ips = self._normalize_ips(request.parameters["ips"])
        results = []
        for ip in ips:
            data = self._lookup_ip(ip)
            if data.get("is_residential_proxy", False):
                results.append({"ip": ip, "category": "Residential Proxy"})
        return {"status": "success", "results": results}

    def detect_private_vpn(self, request: RequestBody) -> ResponseBody:
        self._init_client(request.connectionParameters)
        ips = self._normalize_ips(request.parameters["ips"])
        results = []
        for ip in ips:
            data = self._lookup_ip(ip)
            if data.get("is_vpn", False):
                results.append({"ip": ip, "category": "Private VPN"})
        return {"status": "success", "results": results}

    def detect_tor_nodes(self, request: RequestBody) -> ResponseBody:
        self._init_client(request.connectionParameters)
        ips = self._normalize_ips(request.parameters["ips"])
        results = []
        for ip in ips:
            data = self._lookup_ip(ip)
            if data.get("is_tor", False):
                results.append({"ip": ip, "category": "Tor Node"})
        return {"status": "success", "results": results}

    def detect_anonymous_proxies(self, request: RequestBody) -> ResponseBody:
        self._init_client(request.connectionParameters)
        ips = self._normalize_ips(request.parameters["ips"])
        results = []
        for ip in ips:
            data = self._lookup_ip(ip)
            if data.get("is_proxy", False):
                results.append({"ip": ip, "category": "Anonymous Proxy"})
        return {"status": "success", "results": results}

    def detect_botnets(self, request: RequestBody) -> ResponseBody:
        self._init_client(request.connectionParameters)
        ips = self._normalize_ips(request.parameters["ips"])
        results = []
        for ip in ips:
            data = self._lookup_ip(ip)
            if data.get("is_bot", False):
                results.append({"ip": ip, "category": "Botnet"})
        return {"status": "success", "results": results}

    def detect_malicious_ips(self, request: RequestBody) -> ResponseBody:
        self._init_client(request.connectionParameters)
        ips = self._normalize_ips(request.parameters["ips"])
        results = []
        for ip in ips:
            data = self._lookup_ip(ip)
            if data.get("risk_score", 0) >= 75:
                results.append({"ip": ip, "category": "Malicious IP", "risk_score": data.get("risk_score")})
        return {"status": "success", "results": results}