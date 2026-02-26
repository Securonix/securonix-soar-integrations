from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import json
import requests


class Urlhaus():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

   # -------------------------------
    # Test Connection
    # -------------------------------
    def test_connection(self, connectionParameters: dict):
        base_url = connectionParameters['base_url'].rstrip('/')
        auth_key = connectionParameters['auth_key']

        try:
            test_url = "https://example.com"

            resp = requests.post(
                f"{base_url}/url/",
                data={"url": test_url, "auth_key": auth_key}
            )
            resp.raise_for_status()

            data = resp.json()
            self.logger.debug("URLhaus test_connection response: %s", json.dumps(data))

            if "query_status" in data:
                return {
                    "status": "success",
                    "message": "Connected to URLhaus successfully."
                }

            raise Exception(f"Unexpected response from URLhaus: {data}")

        except Exception as e:
            self.logger.error("Exception while testing URLhaus connection", exc_info=e)
            raise Exception(str(e))

    # -------------------------------
    # Helpers
    # -------------------------------
    def _normalize_values(self, value):
        if isinstance(value, str):
            return [v.strip() for v in value.split(",")]
        elif isinstance(value, list):
            return value
        else:
            raise Exception("Invalid input format")

    def _lookup(self, base_url, endpoint, payload):
        resp = requests.post(f"{base_url}/{endpoint}", data=payload)
        resp.raise_for_status()
        data = resp.json()

        self.logger.debug("URLhaus response from %s: %s", endpoint, json.dumps(data))
        return data

    # -------------------------------
    # Actions (Reputation Style)
    # -------------------------------

    def url_reputation(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        auth_key = request.connectionParameters['auth_key']

        urls = self._normalize_values(request.parameters["urls"])
        results = []

        for url in urls:
            data = self._lookup(base_url, "url/", {"url": url, "auth_key": auth_key})

            if data.get("query_status") == "ok":
                results.append({
                    "url": url,
                    "reputation": "malicious"
                })
            else:
                results.append({
                    "url": url,
                    "reputation": "unknown"
                })

        return {"status": "success", "results": results}

    def host_reputation(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        auth_key = request.connectionParameters['auth_key']

        hosts = self._normalize_values(request.parameters["hosts"])
        results = []

        for host in hosts:
            data = self._lookup(base_url, "host/", {"host": host, "auth_key": auth_key})

            if data.get("query_status") == "ok":
                results.append({
                    "host": host,
                    "reputation": "malicious"
                })
            else:
                results.append({
                    "host": host,
                    "reputation": "unknown"
                })

        return {"status": "success", "results": results}

    def domain_reputation(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        auth_key = request.connectionParameters['auth_key']

        domains = self._normalize_values(request.parameters["domains"])
        results = []

        for domain in domains:
            data = self._lookup(base_url, "domain/", {"domain": domain, "auth_key": auth_key})

            if data.get("query_status") == "ok":
                results.append({
                    "domain": domain,
                    "reputation": "malicious"
                })
            else:
                results.append({
                    "domain": domain,
                    "reputation": "unknown"
                })

        return {"status": "success", "results": results}

    def file_reputation(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        auth_key = request.connectionParameters['auth_key']

        hashes = self._normalize_values(request.parameters["sha256_hashes"])
        results = []

        for file_hash in hashes:
            data = self._lookup(
                base_url,
                "payload/",
                {"sha256_hash": file_hash, "auth_key": auth_key}
            )

            if data.get("query_status") == "ok":
                results.append({
                    "sha256_hash": file_hash,
                    "reputation": "malicious"
                })
            else:
                results.append({
                    "sha256_hash": file_hash,
                    "reputation": "unknown"
                })

        return {"status": "success", "results": results}