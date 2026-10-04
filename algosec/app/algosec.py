from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import json
import requests


class Algosec():
    """
    AlgoSec (ASMS) SOAR connector.

    Covers three AlgoSec products via their REST APIs:
      - AFA (Firewall Analyzer): device inventory, rules, objects, risk,
        reports, traffic simulation.
      - FireFlow: firewall change-request tickets (traffic / object) and status.
      - AppViz (BusinessFlow): business applications.

    Authentication is cookie/session based and differs per product:
      - AFA      : login returns a sessionId, sent as cookie PHPSESSID.
      - FireFlow : POST /FireFlow/api/authentication/authenticate returns
                   data.sessionId, sent as cookie FireFlow_Session.
      - AppViz   : POST /BusinessFlow/rest/v1/login (HTTP Basic) returns a
                   jsessionid, sent as cookie JSESSIONID.

    The SSL certificate on AlgoSec appliances is frequently self-signed, so the
    connection's "verify_ssl" parameter controls certificate verification.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    # -------------------------------
    # Connection helpers
    # -------------------------------
    def _conn(self, connectionParameters: dict):
        """Extract common connection fields."""
        base_url = connectionParameters['base_url'].rstrip('/')
        username = connectionParameters['username']
        password = connectionParameters['password']
        verify = connectionParameters.get('verify_ssl', False)
        if isinstance(verify, str):
            verify = verify.strip().lower() in ("true", "1", "yes")
        return base_url, username, password, verify

    # ---- AFA session (cookie PHPSESSID) ----
    def _afa_session(self, base_url, username, password, verify):
        # AFA login: POST /fa/server/connection/login returns SessionID,
        # which is used as the PHPSESSID cookie for /afa/api/v1 endpoints.
        url = f"{base_url}/fa/server/connection/login"
        payload = {"username": username, "password": password}
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        resp = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify)
        resp.raise_for_status()
        data = resp.json()
        session_id = self._extract_session_id(data)
        if not session_id:
            raise Exception("Failed to retrieve AFA SessionID from login response")
        return {"PHPSESSID": session_id}

    # ---- FireFlow session (cookie FireFlow_Session) ----
    def _fireflow_session(self, base_url, username, password, verify):
        url = f"{base_url}/FireFlow/api/authentication/authenticate"
        payload = {"username": username, "password": password}
        headers = {"Content-Type": "application/json"}
        resp = requests.post(url, data=json.dumps(payload), headers=headers, verify=verify)
        resp.raise_for_status()
        data = resp.json()
        session_id = None
        if isinstance(data.get("data"), dict):
            session_id = data["data"].get("sessionId")
        if not session_id:
            raise Exception("Failed to retrieve FireFlow sessionId from login response")
        return {"FireFlow_Session": session_id}

    # ---- AppViz session (cookie JSESSIONID) ----
    def _appviz_session(self, base_url, username, password, verify):
        url = f"{base_url}/BusinessFlow/rest/v1/login"
        resp = requests.post(url, auth=(username, password), verify=verify)
        resp.raise_for_status()
        data = resp.json()
        jsessionid = data.get("jsessionid") or data.get("JSESSIONID")
        if not jsessionid:
            raise Exception("Failed to retrieve AppViz jsessionid from login response")
        return {"JSESSIONID": jsessionid}

    def _extract_session_id(self, data):
        """AFA login returns SessionID; accept common key variants."""
        if not isinstance(data, dict):
            return None
        session_id = data.get("SessionID") or data.get("sessionId")
        if session_id:
            return session_id
        if isinstance(data.get("data"), dict):
            return data["data"].get("SessionID") or data["data"].get("sessionId")
        return None

    def _headers(self):
        return {"Content-Type": "application/json", "Accept": "application/json"}

    # -------------------------------
    # Test Connection (SOAR calls this)
    # -------------------------------
    def test_connection(self, connectionParameters: dict):
        base_url, username, password, verify = self._conn(connectionParameters)
        try:
            # FireFlow login is the most consistently documented REST auth path.
            cookies = self._fireflow_session(base_url, username, password, verify)
            if cookies.get("FireFlow_Session"):
                return {"status": "success", "message": "Connected to AlgoSec successfully."}
            raise Exception("Authentication failed: no session returned.")
        except Exception as e:
            self.logger.error("Exception while testing AlgoSec connection", exc_info=e)
            raise Exception(str(e))

    # =========================================================
    # AFA — Investigate / read
    # =========================================================

    def get_devices(self, request: RequestBody) -> ResponseBody:
        """List managed devices. Parameters: none."""
        base_url, username, password, verify = self._conn(request.connectionParameters)
        try:
            cookies = self._afa_session(base_url, username, password, verify)
            url = f"{base_url}/afa/api/v1/devices"
            resp = requests.get(url, headers=self._headers(), cookies=cookies, verify=verify)
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("AlgoSec get_devices response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_devices", exc_info=e)
            raise Exception(str(e))

    def get_devices_with_policy(self, request: RequestBody) -> ResponseBody:
        """List devices with policy details. Parameters: none."""
        base_url, username, password, verify = self._conn(request.connectionParameters)
        try:
            cookies = self._afa_session(base_url, username, password, verify)
            url = f"{base_url}/afa/api/v1/allowedDevices"
            resp = requests.get(url, headers=self._headers(), cookies=cookies, verify=verify)
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("AlgoSec get_devices_with_policy response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_devices_with_policy", exc_info=e)
            raise Exception(str(e))

    def get_device_rules(self, request: RequestBody) -> ResponseBody:
        """
        Get all rules in a device's/group's policy.
        Parameters: device_name (required), entity_type (optional: FIREWALL/group/matrix).
        """
        base_url, username, password, verify = self._conn(request.connectionParameters)
        device_name = request.parameters['device_name']
        entity_type = request.parameters.get('entity_type', 'FIREWALL')
        try:
            cookies = self._afa_session(base_url, username, password, verify)
            url = f"{base_url}/afa/api/v1/rules"
            params = {"entity": device_name, "entityType": entity_type}
            resp = requests.get(url, headers=self._headers(), cookies=cookies, params=params, verify=verify)
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("AlgoSec get_device_rules response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_device_rules", exc_info=e)
            raise Exception(str(e))

    def get_risky_rules(self, request: RequestBody) -> ResponseBody:
        """
        Get risky rules for a device.
        Parameters: device_name (required), entity_type (optional: FIREWALL/GROUP).
        """
        base_url, username, password, verify = self._conn(request.connectionParameters)
        device_name = request.parameters['device_name']
        entity_type = request.parameters.get('entity_type', 'FIREWALL')
        try:
            cookies = self._afa_session(base_url, username, password, verify)
            url = f"{base_url}/afa/api/v1/risks/riskyRules"
            params = {"entity": device_name, "entityType": entity_type}
            resp = requests.get(url, headers=self._headers(), cookies=cookies, params=params, verify=verify)
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("AlgoSec get_risky_rules response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_risky_rules", exc_info=e)
            raise Exception(str(e))

    def get_nat_rules(self, request: RequestBody) -> ResponseBody:
        """Get NAT rules information for a device. Parameters: device_name (required)."""
        base_url, username, password, verify = self._conn(request.connectionParameters)
        device_name = request.parameters['device_name']
        try:
            cookies = self._afa_session(base_url, username, password, verify)
            url = f"{base_url}/afa/api/v1/rule/natRulesInfo"
            params = {"entityTreeName": device_name}
            resp = requests.get(url, headers=self._headers(), cookies=cookies, params=params, verify=verify)
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("AlgoSec get_nat_rules response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_nat_rules", exc_info=e)
            raise Exception(str(e))

    def get_network_objects(self, request: RequestBody) -> ResponseBody:
        """
        Get a list of matching network objects (search by original name).
        Parameters: device_name (optional), query (optional - name substring to match).
        """
        base_url, username, password, verify = self._conn(request.connectionParameters)
        device_name = request.parameters.get('device_name', None)
        query = request.parameters.get('query', None)
        try:
            cookies = self._afa_session(base_url, username, password, verify)
            url = f"{base_url}/afa/api/v1/networkObject/search/findByOriginalNameContaining"
            params = {}
            if device_name:
                params["deviceName"] = device_name
            if query:
                params["query"] = query
            resp = requests.get(url, headers=self._headers(), cookies=cookies, params=params, verify=verify)
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("AlgoSec get_network_objects response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_network_objects", exc_info=e)
            raise Exception(str(e))

    def get_service_objects(self, request: RequestBody) -> ResponseBody:
        """
        Retrieve service objects of a device or group.
        Parameters: device_name (required), entity_type (optional: FIREWALL/GROUP).
        """
        base_url, username, password, verify = self._conn(request.connectionParameters)
        device_name = request.parameters['device_name']
        entity_type = request.parameters.get('entity_type', 'FIREWALL')
        try:
            cookies = self._afa_session(base_url, username, password, verify)
            url = f"{base_url}/afa/api/v1/network_services"
            params = {"entity": device_name, "entityType": entity_type}
            resp = requests.get(url, headers=self._headers(), cookies=cookies, params=params, verify=verify)
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("AlgoSec get_service_objects response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_service_objects", exc_info=e)
            raise Exception(str(e))

    def get_reports(self, request: RequestBody) -> ResponseBody:
        """
        Get all reports for a device.
        Parameters: device_name (required), from_date (optional, format yyyy-mm-dd).
        """
        base_url, username, password, verify = self._conn(request.connectionParameters)
        device_name = request.parameters['device_name']
        from_date = request.parameters.get('from_date', None)
        try:
            cookies = self._afa_session(base_url, username, password, verify)
            url = f"{base_url}/afa/api/v1/report/findAllReports"
            params = {"deviceName": device_name}
            if from_date:
                params["fromDate"] = from_date
            resp = requests.get(url, headers=self._headers(), cookies=cookies, params=params, verify=verify)
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("AlgoSec get_reports response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_reports", exc_info=e)
            raise Exception(str(e))

    # =========================================================
    # AppViz — Investigate / read
    # =========================================================

    def get_applications(self, request: RequestBody) -> ResponseBody:
        """Get business applications from AppViz. Parameters: page_number (optional)."""
        base_url, username, password, verify = self._conn(request.connectionParameters)
        page_number = request.parameters.get('page_number', None)
        try:
            cookies = self._appviz_session(base_url, username, password, verify)
            url = f"{base_url}/BusinessFlow/rest/v1/applications/"
            params = {}
            if page_number:
                params["page_number"] = page_number
            resp = requests.get(url, headers=self._headers(), cookies=cookies, params=params, verify=verify)
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("AlgoSec get_applications response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_applications", exc_info=e)
            raise Exception(str(e))

    # =========================================================
    # AFA — Analyze
    # =========================================================

    def run_traffic_simulation(self, request: RequestBody) -> ResponseBody:
        """
        Perform a Traffic Simulation Query.
        Parameters: source (required), destination (required), service (optional),
                    device_name (optional).
        """
        base_url, username, password, verify = self._conn(request.connectionParameters)
        source = request.parameters['source']
        destination = request.parameters['destination']
        service = request.parameters.get('service', None)
        device_name = request.parameters.get('device_name', None)
        try:
            cookies = self._afa_session(base_url, username, password, verify)
            url = f"{base_url}/afa/api/v1/query/"
            query_item = {"source": source, "destination": destination}
            if service:
                query_item["service"] = service
            payload = {"QueryInput": [query_item]}
            if device_name:
                payload["QueryTarget"] = device_name
            resp = requests.post(url, headers=self._headers(), cookies=cookies, json=payload, verify=verify)
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("AlgoSec run_traffic_simulation response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in run_traffic_simulation", exc_info=e)
            raise Exception(str(e))

    def find_route(self, request: RequestBody) -> ResponseBody:
        """
        Find the route (Firewalls in Path) between a source and destination.
        Parameters: source (required), destination (required).
        Source/destination may be comma-separated lists of IPs or ranges.
        """
        base_url, username, password, verify = self._conn(request.connectionParameters)
        source = request.parameters['source']
        destination = request.parameters['destination']
        try:
            cookies = self._afa_session(base_url, username, password, verify)
            url = f"{base_url}/afa/api/v1/query/routing"
            payload = {"source": source, "destination": destination}
            resp = requests.post(url, headers=self._headers(), cookies=cookies, json=payload, verify=verify)
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("AlgoSec find_route response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in find_route", exc_info=e)
            raise Exception(str(e))

    def get_risk_profiles(self, request: RequestBody) -> ResponseBody:
        """Retrieve the list of risk profiles. Parameters: none."""
        base_url, username, password, verify = self._conn(request.connectionParameters)
        try:
            cookies = self._afa_session(base_url, username, password, verify)
            url = f"{base_url}/afa/api/v1/risks/profiles"
            resp = requests.get(url, headers=self._headers(), cookies=cookies, verify=verify)
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("AlgoSec get_risk_profiles response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_risk_profiles", exc_info=e)
            raise Exception(str(e))

    def run_risk_check(self, request: RequestBody) -> ResponseBody:
        """
        Run a Risk Check for requested traffic.
        Parameters: source (required), destination (required), service (optional),
                    risk_profile (optional).

        Note: endpoint path is confirmed from the AlgoSec Risks REST group
        (/afa/api/v1/risks/calculate). The exact request-body field names should
        be confirmed against a live instance's Swagger before production use.
        """
        base_url, username, password, verify = self._conn(request.connectionParameters)
        source = request.parameters['source']
        destination = request.parameters['destination']
        service = request.parameters.get('service', None)
        risk_profile = request.parameters.get('risk_profile', None)
        try:
            cookies = self._afa_session(base_url, username, password, verify)
            url = f"{base_url}/afa/api/v1/risks/calculate"
            traffic = {"source": source, "destination": destination}
            if service:
                traffic["service"] = service
            payload = {"traffic": [traffic]}
            if risk_profile:
                payload["riskProfile"] = risk_profile
            resp = requests.post(url, headers=self._headers(), cookies=cookies, json=payload, verify=verify)
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("AlgoSec run_risk_check response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in run_risk_check", exc_info=e)
            raise Exception(str(e))

    # =========================================================
    # FireFlow — Remediate / act
    # =========================================================

    def create_traffic_change_request(self, request: RequestBody) -> ResponseBody:
        """
        Create a FireFlow traffic change request (allow/block traffic).
        Parameters:
            template (required)     - FireFlow ticket template name.
            source (required)       - source IP/subnet.
            destination (required)  - destination IP/subnet.
            service (required)      - e.g. "tcp/443".
            action (optional)       - "Allow" (default) or "Drop".
            application (optional)  - application name (default "any").
            user (optional)         - user name (default "any").
        """
        base_url, username, password, verify = self._conn(request.connectionParameters)
        template = request.parameters['template']
        source = request.parameters['source']
        destination = request.parameters['destination']
        service = request.parameters['service']
        action = request.parameters.get('action', 'Allow')
        application = request.parameters.get('application', 'any')
        user = request.parameters.get('user', 'any')
        try:
            cookies = self._fireflow_session(base_url, username, password, verify)
            url = f"{base_url}/FireFlow/api/change-requests/traffic"
            ticket = {
                "template": template,
                "traffic": [
                    {
                        "source": {"items": [{"address": source}]},
                        "destination": {"items": [{"address": destination}]},
                        "service": {"items": [{"service": service}]},
                        "application": {"items": [{"name": application}]},
                        "user": {"items": [{"name": user}]},
                        "action": action
                    }
                ]
            }
            resp = requests.post(url, headers=self._headers(), cookies=cookies,
                                 data=json.dumps(ticket), verify=verify)
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("AlgoSec create_traffic_change_request response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in create_traffic_change_request", exc_info=e)
            raise Exception(str(e))

    def create_object_change_request(self, request: RequestBody) -> ResponseBody:
        """
        Create a FireFlow object change request.
        Parameters:
            template (required)    - FireFlow ticket template name.
            object_name (required) - name of the network object.
            object_type (optional) - e.g. "Host" (default), "Network", "Range".
            content (required)     - the object content (IP/subnet/range).
            devices (optional)     - comma-separated device database names.
        """
        base_url, username, password, verify = self._conn(request.connectionParameters)
        template = request.parameters['template']
        object_name = request.parameters['object_name']
        content = request.parameters['content']
        object_type = request.parameters.get('object_type', 'Host')
        devices = request.parameters.get('devices', None)
        try:
            cookies = self._fireflow_session(base_url, username, password, verify)
            url = f"{base_url}/FireFlow/api/change-requests/object"
            change = {
                "template": template,
                "objects": [
                    {
                        "name": object_name,
                        "type": object_type,
                        "content": content
                    }
                ]
            }
            if devices:
                change["devices"] = [d.strip() for d in devices.split(",") if d.strip()]
            resp = requests.post(url, headers=self._headers(), cookies=cookies,
                                 data=json.dumps(change), verify=verify)
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("AlgoSec create_object_change_request response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in create_object_change_request", exc_info=e)
            raise Exception(str(e))

    def get_change_request_status(self, request: RequestBody) -> ResponseBody:
        """
        Get the details/status of a FireFlow change request by ID.
        Parameters: change_request_id (required).
        """
        base_url, username, password, verify = self._conn(request.connectionParameters)
        change_request_id = request.parameters['change_request_id']
        try:
            cookies = self._fireflow_session(base_url, username, password, verify)
            url = f"{base_url}/FireFlow/api/change-requests/traffic/{change_request_id}"
            resp = requests.get(url, headers=self._headers(), cookies=cookies, verify=verify)
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("AlgoSec get_change_request_status response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_change_request_status", exc_info=e)
            raise Exception(str(e))
