from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import requests
import base64
import ipaddress
from urllib.parse import quote


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

            invalid_ips = []
            for ip in ips:
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    invalid_ips.append(ip)
            if invalid_ips:
                raise Exception(f"Invalid IP address format: {', '.join(invalid_ips)}. Expected format: x.x.x.x (e.g., 1.1.1.1)")

            results = []
            for ip in ips:
                resp = requests.get(f"{base_url}/ipr/{ip}", headers=headers, timeout=30)
                if resp.status_code in (401, 403):
                    raise Exception("Authentication failed. Please verify your API Key and API Password are correct.")
                if resp.status_code == 404:
                    raise Exception(f"No threat data found for IP: {ip}")
                if resp.status_code >= 300:
                    raise Exception(f"API request failed with status {resp.status_code}. Please check your configuration.")
                try:
                    results.append({"ip": ip, "reputation": resp.json()})
                except ValueError:
                    raise Exception("Invalid response from API. Please verify your API Key and API Password are correct.")

            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IBM X-Force Exchange. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IBM X-Force Exchange timed out.")
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
                encoded_domain = quote(domain, safe='')
                resp = requests.get(f"{base_url}/url/{encoded_domain}", headers=headers, timeout=30)
                if resp.status_code in (401, 403):
                    raise Exception("Authentication failed. Please verify your API Key and API Password are correct.")
                if resp.status_code == 404:
                    raise Exception(f"No threat data found for domain: {domain}")
                if resp.status_code >= 300:
                    raise Exception(f"API request failed with status {resp.status_code}. Please check your configuration.")
                try:
                    results.append({"domain": domain, "reputation": resp.json()})
                except ValueError:
                    raise Exception("Invalid response from API. Please verify your API Key and API Password are correct.")

            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IBM X-Force Exchange. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IBM X-Force Exchange timed out.")
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
                encoded_url = quote(target_url, safe='')
                resp = requests.get(f"{base_url}/url/{encoded_url}", headers=headers, timeout=30)
                if resp.status_code in (401, 403):
                    raise Exception("Authentication failed. Please verify your API Key and API Password are correct.")
                if resp.status_code == 404:
                    raise Exception(f"No threat data found for URL: {target_url}")
                if resp.status_code >= 300:
                    raise Exception(f"API request failed with status {resp.status_code}. Please check your configuration.")
                try:
                    results.append({"url": target_url, "reputation": resp.json()})
                except ValueError:
                    raise Exception("Invalid response from API. Please verify your API Key and API Password are correct.")

            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IBM X-Force Exchange. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IBM X-Force Exchange timed out.")
        except Exception as e:
            self.logger.error("error while running action 'lookup_url'", exc_info=e)
            raise Exception(str(e))

    def lookup_file_hash(self, request: RequestBody) -> ResponseBody:
        try:
            base_url = request.connectionParameters['base_url'].rstrip('/')
            api_key = request.connectionParameters['api_key']
            api_password = request.connectionParameters['api_password']
            credentials = base64.b64encode(f"{api_key}:{api_password}".encode()).decode()
            headers = {"Authorization": f"Basic {credentials}", "Accept": "application/json"}

            hashes = request.parameters["hashes"]
            if isinstance(hashes, str):
                hashes = [h.strip() for h in hashes.split(",") if h.strip()]

            import re
            invalid_hashes = [h for h in hashes if not re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', h)]
            if invalid_hashes:
                raise Exception(f"Invalid file hash format: {', '.join(invalid_hashes)}. Expected MD5 (32 chars), SHA1 (40 chars), or SHA256 (64 chars).")

            results = []
            for file_hash in hashes:
                encoded_hash = quote(file_hash, safe='')
                resp = requests.get(f"{base_url}/malware/{encoded_hash}", headers=headers, timeout=30)
                if resp.status_code in (401, 403):
                    raise Exception("Authentication failed. Please verify your API Key and API Password are correct.")
                if resp.status_code == 404:
                    raise Exception(f"No malware data found for hash: {file_hash}")
                if resp.status_code >= 300:
                    raise Exception(f"API request failed with status {resp.status_code}. Please check your configuration.")
                try:
                    results.append({"hash": file_hash, "malware": resp.json()})
                except ValueError:
                    raise Exception("Invalid response from API. Please verify your API Key and API Password are correct.")

            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IBM X-Force Exchange. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IBM X-Force Exchange timed out.")
        except Exception as e:
            self.logger.error("error while running action 'lookup_file_hash'", exc_info=e)
            raise Exception(str(e))

    def lookup_cve(self, request: RequestBody) -> ResponseBody:
        try:
            base_url = request.connectionParameters['base_url'].rstrip('/')
            api_key = request.connectionParameters['api_key']
            api_password = request.connectionParameters['api_password']
            credentials = base64.b64encode(f"{api_key}:{api_password}".encode()).decode()
            headers = {"Authorization": f"Basic {credentials}", "Accept": "application/json"}

            cve_ids = request.parameters["cve_ids"]
            if isinstance(cve_ids, str):
                cve_ids = [c.strip() for c in cve_ids.split(",") if c.strip()]

            import re
            invalid_cves = [c for c in cve_ids if not re.match(r'^CVE-\d{4}-\d{4,}$', c, re.IGNORECASE)]
            if invalid_cves:
                raise Exception(f"Invalid CVE ID format: {', '.join(invalid_cves)}. Expected format: CVE-YYYY-NNNNN (e.g., CVE-2023-12345)")

            results = []
            for cve_id in cve_ids:
                encoded_cve = quote(cve_id, safe='')
                resp = requests.get(f"{base_url}/vulnerabilities/{encoded_cve}", headers=headers, timeout=30)
                if resp.status_code in (401, 403):
                    raise Exception("Authentication failed. Please verify your API Key and API Password are correct.")
                if resp.status_code == 404:
                    raise Exception(f"No vulnerability data found for: {cve_id}")
                if resp.status_code >= 300:
                    raise Exception(f"API request failed with status {resp.status_code}. Please check your configuration.")
                try:
                    results.append({"cve_id": cve_id, "vulnerability": resp.json()})
                except ValueError:
                    raise Exception("Invalid response from API. Please verify your API Key and API Password are correct.")

            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IBM X-Force Exchange. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IBM X-Force Exchange timed out.")
        except Exception as e:
            self.logger.error("error while running action 'lookup_cve'", exc_info=e)
            raise Exception(str(e))

    def get_latest_cves(self, request: RequestBody) -> ResponseBody:
        try:
            base_url = request.connectionParameters['base_url'].rstrip('/')
            api_key = request.connectionParameters['api_key']
            api_password = request.connectionParameters['api_password']
            credentials = base64.b64encode(f"{api_key}:{api_password}".encode()).decode()
            headers = {"Authorization": f"Basic {credentials}", "Accept": "application/json"}

            params = {}
            if request.parameters.get("limit"):
                params["limit"] = request.parameters["limit"]

            resp = requests.get(f"{base_url}/vulnerabilities", headers=headers, params=params, timeout=30)
            if resp.status_code in (401, 403):
                raise Exception("Authentication failed. Please verify your API Key and API Password are correct.")
            if resp.status_code >= 300:
                raise Exception(f"API request failed with status {resp.status_code}. Please check your configuration.")
            try:
                data = resp.json()
            except ValueError:
                raise Exception("Invalid response from API. Please verify your API Key and API Password are correct.")

            return {"status": "success", "vulnerabilities": data}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IBM X-Force Exchange. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IBM X-Force Exchange timed out.")
        except Exception as e:
            self.logger.error("error while running action 'get_latest_cves'", exc_info=e)
            raise Exception(str(e))

    def whois_lookup(self, request: RequestBody) -> ResponseBody:
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
                encoded_domain = quote(domain, safe='')
                resp = requests.get(f"{base_url}/whois/{encoded_domain}", headers=headers, timeout=30)
                if resp.status_code in (401, 403):
                    raise Exception("Authentication failed. Please verify your API Key and API Password are correct.")
                if resp.status_code == 404:
                    raise Exception(f"No WHOIS data found for domain: {domain}")
                if resp.status_code >= 300:
                    raise Exception(f"API request failed with status {resp.status_code}. Please check your configuration.")
                try:
                    results.append({"domain": domain, "whois": resp.json()})
                except ValueError:
                    raise Exception("Invalid response from API. Please verify your API Key and API Password are correct.")

            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IBM X-Force Exchange. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IBM X-Force Exchange timed out.")
        except Exception as e:
            self.logger.error("error while running action 'whois_lookup'", exc_info=e)
            raise Exception(str(e))

    def search_cves(self, request: RequestBody) -> ResponseBody:
        try:
            base_url = request.connectionParameters['base_url'].rstrip('/')
            api_key = request.connectionParameters['api_key']
            api_password = request.connectionParameters['api_password']
            credentials = base64.b64encode(f"{api_key}:{api_password}".encode()).decode()
            headers = {"Authorization": f"Basic {credentials}", "Accept": "application/json"}

            query = request.parameters.get("query", "").strip()
            if not query:
                raise Exception("Search query is required. Please provide a keyword or phrase to search CVEs.")

            params = {"q": query}
            if request.parameters.get("bookmark"):
                params["bookmark"] = request.parameters["bookmark"]

            resp = requests.get(f"{base_url}/cves/fulltext", headers=headers, params=params, timeout=30)
            if resp.status_code in (401, 403):
                raise Exception("Authentication failed. Please verify your API Key and API Password are correct.")
            if resp.status_code >= 300:
                raise Exception(f"API request failed with status {resp.status_code}. Please check your configuration.")
            try:
                data = resp.json()
            except ValueError:
                raise Exception("Invalid response from API. Please verify your API Key and API Password are correct.")

            return {"status": "success", "results": data}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to IBM X-Force Exchange. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to IBM X-Force Exchange timed out.")
        except Exception as e:
            self.logger.error("error while running action 'search_cves'", exc_info=e)
            raise Exception(str(e))
