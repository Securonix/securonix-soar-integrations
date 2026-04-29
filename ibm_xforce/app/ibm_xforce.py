from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import requests
import base64


class IbmXforce():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    def test_connection(self, connectionParameters: dict):
        try:
            base_url = connectionParameters['base_url'].rstrip('/')
            api_key = connectionParameters['api_key']
            api_password = connectionParameters['api_password']
            credentials = base64.b64encode(f"{api_key}:{api_password}".encode()).decode()
            headers = {"Authorization": f"Basic {credentials}", "Accept": "application/json"}

            resp = requests.get(f"{base_url}/ipr/8.8.8.8", headers=headers, timeout=30)
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
        try:
            base_url = request.connectionParameters['base_url'].rstrip('/')
            api_key = request.connectionParameters['api_key']
            api_password = request.connectionParameters['api_password']
            credentials = base64.b64encode(f"{api_key}:{api_password}".encode()).decode()
            headers = {"Authorization": f"Basic {credentials}", "Accept": "application/json"}

            ips = request.parameters["ips"]
            if isinstance(ips, str):
                ips = [i.strip() for i in ips.split(",") if i.strip()]

            results = []
            for ip in ips:
                resp = requests.get(f"{base_url}/ipr/{ip}", headers=headers, timeout=30)
                if resp.status_code >= 300:
                    raise Exception(resp.text)
                results.append({"ip": ip, "reputation": resp.json()})

            return {"status": "success", "results": results}
        except Exception as e:
            self.logger.error("error while running action 'lookup_ip'", exc_info=e)
            raise Exception(str(e))

    def lookup_domain(self, request: RequestBody) -> ResponseBody:
        try:
            base_url = request.connectionParameters['base_url'].rstrip('/')
            api_key = request.connectionParameters['api_key']
            api_password = request.connectionParameters['api_password']
            credentials = base64.b64encode(f"{api_key}:{api_password}".encode()).decode()
            headers = {"Authorization": f"Basic {credentials}", "Accept": "application/json"}

            domains = request.parameters["domains"]
            if isinstance(domains, str):
                domains = [d.strip() for d in domains.split(",") if d.strip()]

            results = []
            for domain in domains:
                resp = requests.get(f"{base_url}/url/{domain}", headers=headers, timeout=30)
                if resp.status_code >= 300:
                    raise Exception(resp.text)
                results.append({"domain": domain, "reputation": resp.json()})

            return {"status": "success", "results": results}
        except Exception as e:
            self.logger.error("error while running action 'lookup_domain'", exc_info=e)
            raise Exception(str(e))

    def lookup_url(self, request: RequestBody) -> ResponseBody:
        try:
            base_url = request.connectionParameters['base_url'].rstrip('/')
            api_key = request.connectionParameters['api_key']
            api_password = request.connectionParameters['api_password']
            credentials = base64.b64encode(f"{api_key}:{api_password}".encode()).decode()
            headers = {"Authorization": f"Basic {credentials}", "Accept": "application/json"}

            urls = request.parameters["urls"]
            if isinstance(urls, str):
                urls = [u.strip() for u in urls.split(",") if u.strip()]

            results = []
            for target_url in urls:
                resp = requests.get(f"{base_url}/url/{target_url}", headers=headers, timeout=30)
                if resp.status_code >= 300:
                    raise Exception(resp.text)
                results.append({"url": target_url, "reputation": resp.json()})

            return {"status": "success", "results": results}
        except Exception as e:
            self.logger.error("error while running action 'lookup_url'", exc_info=e)
            raise Exception(str(e))
