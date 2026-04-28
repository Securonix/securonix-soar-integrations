from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import json
import requests
import base64


class IbmXforce():

    TIMEOUT = 30

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    def _get_connection(self, connection_params):
        base_url = connection_params['base_url'].rstrip('/')
        api_key = connection_params['api_key']
        api_password = connection_params['api_password']
        return base_url, api_key, api_password

    def _get_headers(self, api_key, api_password):
        credentials = base64.b64encode(f"{api_key}:{api_password}".encode()).decode()
        return {"Authorization": f"Basic {credentials}", "Accept": "application/json"}

    def _normalize_indicators(self, indicators):
        if isinstance(indicators, str):
            return [i.strip() for i in indicators.split(",") if i.strip()]
        elif isinstance(indicators, list):
            return indicators
        else:
            raise Exception("Invalid indicator format")

    def test_connection(self, connectionParameters: dict):
        try:
            base_url = connectionParameters['base_url'].rstrip('/')
            api_key = connectionParameters['api_key']
            api_password = connectionParameters['api_password']
            credentials = base64.b64encode(f"{api_key}:{api_password}".encode()).decode()
            headers = {"Authorization": f"Basic {credentials}", "Accept": "application/json"}

            resp = requests.get(f"{base_url}/ipr/8.8.8.8", headers=headers, timeout=self.TIMEOUT)
            if resp.status_code in (401, 403):
                raise Exception(f"Authentication failed: {resp.status_code} {resp.text}")
            if resp.status_code >= 500:
                raise Exception(f"Server error: {resp.status_code} {resp.text}")
            return {'status': 'success', 'message': 'Connected to IBM X-Force Exchange successfully.'}
        except requests.exceptions.ConnectionError:
            raise Exception('Unable to connect to IBM X-Force Exchange. Please verify the Base URL.')
        except requests.exceptions.Timeout:
            raise Exception('Connection to IBM X-Force Exchange timed out.')
        except Exception as e:
            self.logger.error("Exception while testing connection", exc_info=e)
            raise Exception(str(e))

    def lookup_ip(self, request: RequestBody) -> ResponseBody:
        base_url, api_key, api_password = self._get_connection(request.connectionParameters)
        credentials = base64.b64encode(f"{api_key}:{api_password}".encode()).decode()
        headers = {"Authorization": f"Basic {credentials}", "Accept": "application/json"}
        ips = self._normalize_indicators(request.parameters["ips"])
        results = []

        for ip in ips:
            try:
                url = f"{base_url}/ipr/{ip}"
                resp = requests.get(url, headers=headers, timeout=self.TIMEOUT)
                resp.raise_for_status()
                data = resp.json()
                results.append({"ip": ip, "reputation": data})
            except Exception as e:
                self.logger.error("Error looking up IP %s", ip, exc_info=e)
                results.append({"ip": ip, "error": str(e)})

        return {"status": "success", "results": results}

    def lookup_domain(self, request: RequestBody) -> ResponseBody:
        base_url, api_key, api_password = self._get_connection(request.connectionParameters)
        credentials = base64.b64encode(f"{api_key}:{api_password}".encode()).decode()
        headers = {"Authorization": f"Basic {credentials}", "Accept": "application/json"}
        domains = self._normalize_indicators(request.parameters["domains"])
        results = []

        for domain in domains:
            try:
                url = f"{base_url}/url/{domain}"
                resp = requests.get(url, headers=headers, timeout=self.TIMEOUT)
                resp.raise_for_status()
                data = resp.json()
                results.append({"domain": domain, "reputation": data})
            except Exception as e:
                self.logger.error("Error looking up domain %s", domain, exc_info=e)
                results.append({"domain": domain, "error": str(e)})

        return {"status": "success", "results": results}

    def lookup_url(self, request: RequestBody) -> ResponseBody:
        base_url, api_key, api_password = self._get_connection(request.connectionParameters)
        credentials = base64.b64encode(f"{api_key}:{api_password}".encode()).decode()
        headers = {"Authorization": f"Basic {credentials}", "Accept": "application/json"}
        urls = self._normalize_indicators(request.parameters["urls"])
        results = []

        for target_url in urls:
            try:
                url = f"{base_url}/url/{target_url}"
                resp = requests.get(url, headers=headers, timeout=self.TIMEOUT)
                resp.raise_for_status()
                data = resp.json()
                results.append({"url": target_url, "reputation": data})
            except Exception as e:
                self.logger.error("Error looking up URL %s", target_url, exc_info=e)
                results.append({"url": target_url, "error": str(e)})

        return {"status": "success", "results": results}
