from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import requests


DEFAULT_TIMEOUT = 30


def _get_timeout(connectionParameters: dict) -> int:
    timeout = connectionParameters.get('timeout', '')
    if not timeout or timeout in [None, 'None', 'null']:
        return DEFAULT_TIMEOUT
    return int(timeout)


def _normalize_ips(ips):
    if isinstance(ips, str):
        return [ip.strip() for ip in ips.split(",") if ip.strip()]
    elif isinstance(ips, list):
        return [ip.strip() for ip in ips if ip.strip()]
    else:
        raise Exception("Invalid IP format")


def _lookup_ip(base_url, api_key, timeout, ip):
    url = f"{base_url}/api/json/ip/{api_key}/{ip}"
    resp = requests.get(url, timeout=timeout)
    if resp.status_code in (401, 403):
        raise Exception("Authentication failed. Please verify your API key.")
    if resp.status_code >= 500:
        raise Exception(f"IPQS server error: HTTP {resp.status_code}")
    if resp.status_code >= 400:
        raise Exception(f"IPQS request failed: HTTP {resp.status_code}")
    return resp.json()


class Ipqs():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    # -------------------------------
    # Test Connection
    # -------------------------------
    def test_connection(self, connectionParameters: dict):
        base_url = connectionParameters['base_url'].rstrip('/')
        api_key = connectionParameters['api_key']
        timeout = _get_timeout(connectionParameters)

        try:
            url = f"{base_url}/api/json/ip/{api_key}/8.8.8.8"
            resp = requests.get(url, timeout=timeout)
            if resp.status_code in (401, 403):
                raise Exception("Authentication failed. Please verify your API key.")
            if resp.status_code >= 500:
                raise Exception(f"IPQS server error: HTTP {resp.status_code}")
            if resp.status_code >= 400:
                raise Exception(f"IPQS request failed: HTTP {resp.status_code}")
            data = resp.json()
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
    # Actions
    # -------------------------------
    def detect_residential_proxies(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        api_key = request.connectionParameters['api_key']
        timeout = _get_timeout(request.connectionParameters)
        ips = _normalize_ips(request.parameters["ips"])
        results = []
        try:
            for ip in ips:
                data = _lookup_ip(base_url, api_key, timeout, ip)
                is_residential = data.get("is_residential_proxy", False)
                results.append({
                    "ip": ip,
                    "category": "Residential Proxy" if is_residential else "Not a Residential Proxy",
                    "proxy": data.get("proxy", False),
                    "vpn": data.get("vpn", False),
                    "fraud_score": data.get("fraud_score", 0),
                })
            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IPQS. Please verify the base_url and network connectivity.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IPQS timed out.")
        except Exception:
            self.logger.error("error while running action 'detect_residential_proxies'", exc_info=True)
            raise

    def detect_private_vpn(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        api_key = request.connectionParameters['api_key']
        timeout = _get_timeout(request.connectionParameters)
        ips = _normalize_ips(request.parameters["ips"])
        results = []
        try:
            for ip in ips:
                data = _lookup_ip(base_url, api_key, timeout, ip)
                is_vpn = data.get("vpn", False)
                results.append({
                    "ip": ip,
                    "category": "Private VPN" if is_vpn else "Not a VPN",
                    "vpn": is_vpn,
                    "proxy": data.get("proxy", False),
                    "fraud_score": data.get("fraud_score", 0),
                })
            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IPQS. Please verify the base_url and network connectivity.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IPQS timed out.")
        except Exception:
            self.logger.error("error while running action 'detect_private_vpn'", exc_info=True)
            raise

    def detect_tor_nodes(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        api_key = request.connectionParameters['api_key']
        timeout = _get_timeout(request.connectionParameters)
        ips = _normalize_ips(request.parameters["ips"])
        results = []
        try:
            for ip in ips:
                data = _lookup_ip(base_url, api_key, timeout, ip)
                is_tor = data.get("tor", False)
                results.append({
                    "ip": ip,
                    "category": "Tor Node" if is_tor else "Not a Tor Node",
                    "tor": is_tor,
                    "proxy": data.get("proxy", False),
                    "fraud_score": data.get("fraud_score", 0),
                })
            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IPQS. Please verify the base_url and network connectivity.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IPQS timed out.")
        except Exception:
            self.logger.error("error while running action 'detect_tor_nodes'", exc_info=True)
            raise

    def detect_anonymous_proxies(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        api_key = request.connectionParameters['api_key']
        timeout = _get_timeout(request.connectionParameters)
        ips = _normalize_ips(request.parameters["ips"])
        results = []
        try:
            for ip in ips:
                data = _lookup_ip(base_url, api_key, timeout, ip)
                is_proxy = data.get("proxy", False)
                results.append({
                    "ip": ip,
                    "category": "Anonymous Proxy" if is_proxy else "Not a Proxy",
                    "proxy": is_proxy,
                    "vpn": data.get("vpn", False),
                    "fraud_score": data.get("fraud_score", 0),
                })
            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IPQS. Please verify the base_url and network connectivity.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IPQS timed out.")
        except Exception:
            self.logger.error("error while running action 'detect_anonymous_proxies'", exc_info=True)
            raise

    def detect_botnets(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        api_key = request.connectionParameters['api_key']
        timeout = _get_timeout(request.connectionParameters)
        ips = _normalize_ips(request.parameters["ips"])
        results = []
        try:
            for ip in ips:
                data = _lookup_ip(base_url, api_key, timeout, ip)
                is_bot = data.get("bot_status", False)
                results.append({
                    "ip": ip,
                    "category": "Botnet" if is_bot else "Not a Botnet",
                    "bot_status": is_bot,
                    "proxy": data.get("proxy", False),
                    "fraud_score": data.get("fraud_score", 0),
                })
            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IPQS. Please verify the base_url and network connectivity.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IPQS timed out.")
        except Exception:
            self.logger.error("error while running action 'detect_botnets'", exc_info=True)
            raise

    def detect_malicious_ips(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        api_key = request.connectionParameters['api_key']
        timeout = _get_timeout(request.connectionParameters)
        ips = _normalize_ips(request.parameters["ips"])
        results = []
        try:
            for ip in ips:
                data = _lookup_ip(base_url, api_key, timeout, ip)
                fraud_score = data.get("fraud_score", 0)
                results.append({
                    "ip": ip,
                    "category": "Malicious IP" if fraud_score >= 75 else "Not Malicious",
                    "risk_score": fraud_score,
                    "proxy": data.get("proxy", False),
                    "vpn": data.get("vpn", False),
                    "tor": data.get("tor", False),
                    "recent_abuse": data.get("recent_abuse", False),
                    "bot_status": data.get("bot_status", False),
                    "country_code": data.get("country_code", ""),
                    "isp": data.get("ISP", ""),
                })
            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IPQS. Please verify the base_url and network connectivity.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IPQS timed out.")
        except Exception:
            self.logger.error("error while running action 'detect_malicious_ips'", exc_info=True)
            raise
