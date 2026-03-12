from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import json
import requests


class Skyboxsecurity():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    # -------------------------------
    # Internal helpers
    # -------------------------------
    def _get_headers(self, token):
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    def _get_session(self, base_url, username, password):
        url = f"{base_url}/skybox/webservice/jaxrs/login"
        payload = {"username": username, "password": password}
        resp = requests.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        token = data.get("token") or data.get("authToken") or data.get("access_token")
        if not token:
            raise Exception("Failed to retrieve auth token from Skybox login response")
        return token

    # -------------------------------
    # Test Connection (SOAR calls this)
    # -------------------------------
    def test_connection(self, connectionParameters: dict):
        base_url = connectionParameters['base_url'].rstrip('/')
        username = connectionParameters['username']
        password = connectionParameters['password']

        try:
            token = self._get_session(base_url, username, password)
            if token:
                return {'status': 'success', 'message': 'Connected to Skybox Security successfully.'}
            else:
                raise Exception("Authentication failed: No token returned.")

        except Exception as e:
            self.logger.error("Exception while testing Skybox Security connection", exc_info=e)
            raise Exception(str(e))

    # -------------------------------
    # Actions
    # -------------------------------

    def get_threat_alerts(self, request: RequestBody) -> ResponseBody:
        """
        Retrieve threat alerts from Skybox Security.
        Parameters: severity (optional), limit (optional)
        """
        base_url = request.connectionParameters['base_url'].rstrip('/')
        username = request.connectionParameters['username']
        password = request.connectionParameters['password']

        severity = request.parameters.get('severity', None)
        limit = request.parameters.get('limit', 100)

        try:
            token = self._get_session(base_url, username, password)
            url = f"{base_url}/skybox/webservice/jaxrs/threats/alerts"
            params = {"limit": limit}
            if severity:
                params["severity"] = severity

            resp = requests.get(url, headers=self._get_headers(token), params=params)
            resp.raise_for_status()
            data = resp.json()

            self.logger.debug("Skybox get_threat_alerts response: %s", json.dumps(data))
            return {"status": "success", "results": data}

        except Exception as e:
            self.logger.error("Exception in get_threat_alerts", exc_info=e)
            raise Exception(str(e))

    def get_vulnerabilities(self, request: RequestBody) -> ResponseBody:
        """
        Retrieve vulnerability details from Skybox Security.
        Parameters: asset_ip (optional), severity (optional), limit (optional)
        """
        base_url = request.connectionParameters['base_url'].rstrip('/')
        username = request.connectionParameters['username']
        password = request.connectionParameters['password']

        asset_ip = request.parameters.get('asset_ip', None)
        severity = request.parameters.get('severity', None)
        limit = request.parameters.get('limit', 100)

        try:
            token = self._get_session(base_url, username, password)
            url = f"{base_url}/skybox/webservice/jaxrs/vulnerabilities"
            params = {"limit": limit}
            if asset_ip:
                params["assetIp"] = asset_ip
            if severity:
                params["severity"] = severity

            resp = requests.get(url, headers=self._get_headers(token), params=params)
            resp.raise_for_status()
            data = resp.json()

            self.logger.debug("Skybox get_vulnerabilities response: %s", json.dumps(data))
            return {"status": "success", "results": data}

        except Exception as e:
            self.logger.error("Exception in get_vulnerabilities", exc_info=e)
            raise Exception(str(e))

    def get_exposed_vulnerabilities(self, request: RequestBody) -> ResponseBody:
        """
        Retrieve vulnerabilities that are exposed/exploitable based on network access.
        Parameters: asset_ip (required), limit (optional)
        """
        base_url = request.connectionParameters['base_url'].rstrip('/')
        username = request.connectionParameters['username']
        password = request.connectionParameters['password']

        asset_ip = request.parameters['asset_ip']
        limit = request.parameters.get('limit', 100)

        try:
            token = self._get_session(base_url, username, password)
            url = f"{base_url}/skybox/webservice/jaxrs/vulnerabilities/exposed"
            params = {"assetIp": asset_ip, "limit": limit}

            resp = requests.get(url, headers=self._get_headers(token), params=params)
            resp.raise_for_status()
            data = resp.json()

            self.logger.debug("Skybox get_exposed_vulnerabilities response: %s", json.dumps(data))
            return {"status": "success", "results": data}

        except Exception as e:
            self.logger.error("Exception in get_exposed_vulnerabilities", exc_info=e)
            raise Exception(str(e))

    def get_network_access_rules(self, request: RequestBody) -> ResponseBody:
        """
        Retrieve firewall/network access rules from Skybox.
        Parameters: firewall_name (optional), source_ip (optional), destination_ip (optional)
        """
        base_url = request.connectionParameters['base_url'].rstrip('/')
        username = request.connectionParameters['username']
        password = request.connectionParameters['password']

        firewall_name = request.parameters.get('firewall_name', None)
        source_ip = request.parameters.get('source_ip', None)
        destination_ip = request.parameters.get('destination_ip', None)

        try:
            token = self._get_session(base_url, username, password)
            url = f"{base_url}/skybox/webservice/jaxrs/firewall/rules"
            params = {}
            if firewall_name:
                params["firewallName"] = firewall_name
            if source_ip:
                params["sourceIp"] = source_ip
            if destination_ip:
                params["destinationIp"] = destination_ip

            resp = requests.get(url, headers=self._get_headers(token), params=params)
            resp.raise_for_status()
            data = resp.json()

            self.logger.debug("Skybox get_network_access_rules response: %s", json.dumps(data))
            return {"status": "success", "results": data}

        except Exception as e:
            self.logger.error("Exception in get_network_access_rules", exc_info=e)
            raise Exception(str(e))

    def run_attack_simulation(self, request: RequestBody) -> ResponseBody:
        """
        Run an attack simulation to check if a source can reach a destination.
        Parameters: source_ip (required), destination_ip (required), port (optional), protocol (optional)
        """
        base_url = request.connectionParameters['base_url'].rstrip('/')
        username = request.connectionParameters['username']
        password = request.connectionParameters['password']

        source_ip = request.parameters['source_ip']
        destination_ip = request.parameters['destination_ip']
        port = request.parameters.get('port', None)
        protocol = request.parameters.get('protocol', 'TCP')

        try:
            token = self._get_session(base_url, username, password)
            url = f"{base_url}/skybox/webservice/jaxrs/simulation/attack"
            payload = {
                "sourceIp": source_ip,
                "destinationIp": destination_ip,
                "protocol": protocol
            }
            if port:
                payload["port"] = port

            resp = requests.post(url, headers=self._get_headers(token), json=payload)
            resp.raise_for_status()
            data = resp.json()

            self.logger.debug("Skybox run_attack_simulation response: %s", json.dumps(data))
            return {"status": "success", "results": data}

        except Exception as e:
            self.logger.error("Exception in run_attack_simulation", exc_info=e)
            raise Exception(str(e))

    def get_security_policy_violations(self, request: RequestBody) -> ResponseBody:
        """
        Retrieve security policy violations from Skybox.
        Parameters: policy_name (optional), severity (optional), limit (optional)
        """
        base_url = request.connectionParameters['base_url'].rstrip('/')
        username = request.connectionParameters['username']
        password = request.connectionParameters['password']

        policy_name = request.parameters.get('policy_name', None)
        severity = request.parameters.get('severity', None)
        limit = request.parameters.get('limit', 100)

        try:
            token = self._get_session(base_url, username, password)
            url = f"{base_url}/skybox/webservice/jaxrs/policy/violations"
            params = {"limit": limit}
            if policy_name:
                params["policyName"] = policy_name
            if severity:
                params["severity"] = severity

            resp = requests.get(url, headers=self._get_headers(token), params=params)
            resp.raise_for_status()
            data = resp.json()

            self.logger.debug("Skybox get_security_policy_violations response: %s", json.dumps(data))
            return {"status": "success", "results": data}

        except Exception as e:
            self.logger.error("Exception in get_security_policy_violations", exc_info=e)
            raise Exception(str(e))

    def get_asset_risk_score(self, request: RequestBody) -> ResponseBody:
        """
        Get the risk score for a specific asset.
        Parameters: asset_ip (required)
        """
        base_url = request.connectionParameters['base_url'].rstrip('/')
        username = request.connectionParameters['username']
        password = request.connectionParameters['password']

        asset_ip = request.parameters['asset_ip']

        try:
            token = self._get_session(base_url, username, password)
            url = f"{base_url}/skybox/webservice/jaxrs/assets/riskscore"
            params = {"assetIp": asset_ip}

            resp = requests.get(url, headers=self._get_headers(token), params=params)
            resp.raise_for_status()
            data = resp.json()

            self.logger.debug("Skybox get_asset_risk_score response: %s", json.dumps(data))
            return {"status": "success", "results": data}

        except Exception as e:
            self.logger.error("Exception in get_asset_risk_score", exc_info=e)
            raise Exception(str(e))

    def get_threat_intelligence(self, request: RequestBody) -> ResponseBody:
        """
        Retrieve threat intelligence data for an IP or CVE.
        Parameters: indicator (required), indicator_type (required: ip/cve/hostname)
        """
        base_url = request.connectionParameters['base_url'].rstrip('/')
        username = request.connectionParameters['username']
        password = request.connectionParameters['password']

        indicator = request.parameters['indicator']
        indicator_type = request.parameters['indicator_type']

        try:
            token = self._get_session(base_url, username, password)
            url = f"{base_url}/skybox/webservice/jaxrs/threatintelligence"
            params = {
                "indicator": indicator,
                "indicatorType": indicator_type
            }

            resp = requests.get(url, headers=self._get_headers(token), params=params)
            resp.raise_for_status()
            data = resp.json()

            self.logger.debug("Skybox get_threat_intelligence response: %s", json.dumps(data))
            return {"status": "success", "results": data}

        except Exception as e:
            self.logger.error("Exception in get_threat_intelligence", exc_info=e)
            raise Exception(str(e))

    def block_ip_on_firewall(self, request: RequestBody) -> ResponseBody:
        """
        Block a specific IP on a target firewall via Skybox change management.
        Parameters: firewall_name (required), ip_to_block (required), reason (optional)
        """
        base_url = request.connectionParameters['base_url'].rstrip('/')
        username = request.connectionParameters['username']
        password = request.connectionParameters['password']

        firewall_name = request.parameters['firewall_name']
        ip_to_block = request.parameters['ip_to_block']
        reason = request.parameters.get('reason', 'Blocked via Securonix SOAR')

        try:
            token = self._get_session(base_url, username, password)
            url = f"{base_url}/skybox/webservice/jaxrs/firewall/blockip"
            payload = {
                "firewallName": firewall_name,
                "ipAddress": ip_to_block,
                "reason": reason
            }

            resp = requests.post(url, headers=self._get_headers(token), json=payload)
            resp.raise_for_status()
            data = resp.json()

            self.logger.debug("Skybox block_ip_on_firewall response: %s", json.dumps(data))
            return {"status": "success", "results": data}

        except Exception as e:
            self.logger.error("Exception in block_ip_on_firewall", exc_info=e)
            raise Exception(str(e))

    def get_change_requests(self, request: RequestBody) -> ResponseBody:
        """
        Retrieve firewall change requests from Skybox.
        Parameters: status (optional: open/closed/pending), limit (optional)
        """
        base_url = request.connectionParameters['base_url'].rstrip('/')
        username = request.connectionParameters['username']
        password = request.connectionParameters['password']

        status = request.parameters.get('status', None)
        limit = request.parameters.get('limit', 100)

        try:
            token = self._get_session(base_url, username, password)
            url = f"{base_url}/skybox/webservice/jaxrs/changerequests"
            params = {"limit": limit}
            if status:
                params["status"] = status

            resp = requests.get(url, headers=self._get_headers(token), params=params)
            resp.raise_for_status()
            data = resp.json()

            self.logger.debug("Skybox get_change_requests response: %s", json.dumps(data))
            return {"status": "success", "results": data}

        except Exception as e:
            self.logger.error("Exception in get_change_requests", exc_info=e)
            raise Exception(str(e))