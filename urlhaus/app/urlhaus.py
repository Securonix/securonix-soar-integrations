from app.model.request_body import RequestBody
import logging
import json
import requests


class Urlhaus():

    def __init__(self) -> None:
        self.logger = logging.getLogger()
        self.timeout = 30

    # -------------------------------
    # Test Connection
    # -------------------------------
    def test_connection(self, connectionParameters: dict):
        base_url = connectionParameters['base_url'].rstrip('/')
        api_key = connectionParameters.get('api_key', '')
        headers = self._build_headers(api_key)

        try:
            resp = requests.post(
                f"{base_url}/url/",
                headers=headers,
                data={"url": "https://example.com"},
                timeout=self.timeout
            )
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("URLhaus test_connection response: %s", json.dumps(data))

            if "query_status" in data:
                return {"status": "success", "message": "Connected to URLhaus successfully."}

            raise Exception(f"Unexpected response from URLhaus: {data}")
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to URLhaus. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to URLhaus timed out.")
        except Exception as e:
            self.logger.error("Exception while testing URLhaus connection", exc_info=e)
            raise Exception(str(e))

    # -------------------------------
    # Helpers
    # -------------------------------
    def _build_headers(self, api_key):
        headers = {}
        if api_key:
            headers["Auth-Key"] = api_key
        return headers

    def _normalize_values(self, value):
        if isinstance(value, str):
            return [v.strip() for v in value.split(",") if v.strip()]
        elif isinstance(value, list):
            return value
        else:
            raise Exception("Invalid input format")

    def _lookup(self, base_url, endpoint, payload, headers):
        resp = requests.post(f"{base_url}/{endpoint}", headers=headers, data=payload, timeout=self.timeout)
        if resp.status_code >= 400:
            raise Exception(f"URLhaus API returned HTTP {resp.status_code}: {resp.text}")
        data = resp.json()
        self.logger.debug("URLhaus response from %s: %s", endpoint, json.dumps(data))
        return data

    def _determine_reputation(self, data, entity_type="url"):
        status = data.get("query_status")
        if status == "no_results":
            return "unknown"
        if status != "ok":
            return "error"
        if entity_type == "url":
            threat = data.get("threat")
            url_status = data.get("url_status")
            if threat and threat != "none":
                return "malicious"
            if url_status == "online":
                return "malicious"
            if url_status == "offline":
                return "suspicious"
            return "suspicious"
        if entity_type == "host":
            return "malicious" if data.get("url_count", 0) > 0 else "unknown"
        if entity_type == "payload":
            return "malicious"
        return "unknown"

    # -------------------------------
    # Actions (Reputation Style)
    # -------------------------------

    def url_reputation(self, request: RequestBody) -> dict:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        api_key = request.connectionParameters.get('api_key', '')
        headers = self._build_headers(api_key)

        try:
            urls = self._normalize_values(request.parameters["urls"])
            results = []

            for url in urls:
                data = self._lookup(base_url, "url/", {"url": url}, headers)
                results.append({"url": url, "reputation": self._determine_reputation(data)})

            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to URLhaus. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to URLhaus timed out.")
        except Exception as e:
            self.logger.error("error while running action 'url_reputation'", exc_info=e)
            raise Exception(str(e))

    def host_reputation(self, request: RequestBody) -> dict:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        api_key = request.connectionParameters.get('api_key', '')
        headers = self._build_headers(api_key)

        try:
            hosts = self._normalize_values(request.parameters["hosts"])
            results = []

            for host in hosts:
                data = self._lookup(base_url, "host/", {"host": host}, headers)
                results.append({"host": host, "reputation": self._determine_reputation(data, "host")})

            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to URLhaus. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to URLhaus timed out.")
        except Exception as e:
            self.logger.error("error while running action 'host_reputation'", exc_info=e)
            raise Exception(str(e))

    def domain_reputation(self, request: RequestBody) -> dict:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        api_key = request.connectionParameters.get('api_key', '')
        headers = self._build_headers(api_key)

        try:
            domains = self._normalize_values(request.parameters["domains"])
            results = []

            for domain in domains:
                data = self._lookup(base_url, "host/", {"host": domain}, headers)
                results.append({"domain": domain, "reputation": self._determine_reputation(data, "host")})

            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to URLhaus. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to URLhaus timed out.")
        except Exception as e:
            self.logger.error("error while running action 'domain_reputation'", exc_info=e)
            raise Exception(str(e))

    def file_reputation(self, request: RequestBody) -> dict:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        api_key = request.connectionParameters.get('api_key', '')
        headers = self._build_headers(api_key)

        try:
            hashes = self._normalize_values(request.parameters["sha256_hashes"])
            results = []

            for file_hash in hashes:
                data = self._lookup(base_url, "payload/", {"sha256_hash": file_hash}, headers)
                results.append({"sha256_hash": file_hash, "reputation": self._determine_reputation(data, "payload")})

            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to URLhaus. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to URLhaus timed out.")
        except Exception as e:
            self.logger.error("error while running action 'file_reputation'", exc_info=e)
            raise Exception(str(e))