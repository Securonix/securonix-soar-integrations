from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import json
import requests


class StellarCyber():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    # -------------------------------
    # Internal helpers
    # -------------------------------
    def _get_access_token(self, base_url, api_token, email=None):
        url = f"{base_url}/connect/api/v1/access_token"
        if email:
            resp = requests.post(url, auth=(email, api_token), timeout=30)
        else:
            headers = {"Authorization": f"Bearer {api_token}"}
            resp = requests.post(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        token = data.get("access_token")
        if not token:
            raise Exception("Failed to retrieve access token from Stellar Cyber")
        return token

    def _get_headers(self, jwt_token):
        return {
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    def _request(self, conn, method, endpoint, params=None, json_data=None):
        base_url, api_token, jwt_token, email = conn
        url = f"{base_url}/connect/api/v1{endpoint}"
        self.logger.debug("Stellar Cyber API request: %s %s", method, url)

        try:
            resp = requests.request(
                method, url,
                headers=self._get_headers(jwt_token),
                params=params,
                json=json_data,
                timeout=30
            )

            if resp.status_code == 401:
                self.logger.info("JWT expired, refreshing token and retrying")
                jwt_token = self._get_access_token(base_url, api_token, email)
                resp = requests.request(
                    method, url,
                    headers=self._get_headers(jwt_token),
                    params=params,
                    json=json_data,
                    timeout=30
                )
                if resp.status_code == 401:
                    raise Exception("Authentication failed")

            if resp.status_code == 400:
                raise Exception(f"Invalid request: {resp.text[:500]}")
            elif resp.status_code == 403:
                raise Exception("Permission denied")
            elif resp.status_code == 404:
                raise Exception("Case not found")
            elif resp.status_code >= 500:
                raise Exception(f"Stellar Cyber server error: {resp.status_code}")
            elif resp.status_code >= 300:
                raise Exception(f"Unexpected error: {resp.status_code} - {resp.text[:500]}")

            data = resp.json() if resp.text else {}
            self.logger.debug("Stellar Cyber API response: %s", str(data)[:1000])
            return data

        except requests.exceptions.Timeout:
            raise Exception("Connection timed out")
        except requests.exceptions.ConnectionError:
            raise Exception("Failed to connect to Stellar Cyber")

    def _connect(self, connectionParameters):
        base_url = connectionParameters['base_url'].rstrip('/')
        api_token = connectionParameters['api_token']
        email = connectionParameters.get('email')
        jwt_token = self._get_access_token(base_url, api_token, email)
        return base_url, api_token, jwt_token, email

    # -------------------------------
    # Test Connection
    # -------------------------------
    def test_connection(self, connectionParameters: dict):
        try:
            base_url = connectionParameters['base_url'].rstrip('/')
            api_token = connectionParameters['api_token']
            email = connectionParameters.get('email')
            self._get_access_token(base_url, api_token, email)
            return {'status': 'success', 'message': 'Connected to Stellar Cyber successfully.'}
        except Exception as e:
            self.logger.error("Exception while testing Stellar Cyber connection", exc_info=e)
            raise Exception(str(e))

    # -------------------------------
    # Write Actions
    # -------------------------------
    def create_case(self, request: RequestBody) -> ResponseBody:
        try:
            conn = self._connect(request.connectionParameters)
            name = request.parameters['name']

            payload = {"name": name}
            for field in ['description', 'severity', 'status', 'assignee']:
                value = request.parameters.get(field)
                if value is not None:
                    payload[field] = value

            tags = request.parameters.get('tags')
            if tags is not None:
                if isinstance(tags, str):
                    tags = [t.strip() for t in tags.split(',')]
                payload['tags'] = tags

            data = self._request(conn, "POST", "/cases", json_data=payload)

            return {
                "status": "success",
                "case_id": data.get("_id") or data.get("data", {}).get("_id"),
                "severity": data.get("severity", ""),
                "raw_response": data
            }
        except Exception as e:
            self.logger.error("Exception in create_case", exc_info=e)
            raise Exception(str(e))

    def update_case(self, request: RequestBody) -> ResponseBody:
        try:
            conn = self._connect(request.connectionParameters)
            case_id = request.parameters['case_id']

            payload = {}
            updated_fields = []
            for field in ['status', 'severity', 'assignee', 'description']:
                if request.parameters.get(field) is not None:
                    payload[field] = request.parameters[field]
                    updated_fields.append(field)

            tags_add = request.parameters.get('tags_to_add')
            tags_remove = request.parameters.get('tags_to_remove')
            if tags_add or tags_remove:
                payload['tags'] = {}
                if tags_add:
                    payload['tags']['add'] = tags_add
                if tags_remove:
                    payload['tags']['delete'] = tags_remove
                updated_fields.append('tags')

            data = self._request(conn, "PUT", f"/cases/{case_id}", json_data=payload)

            return {
                "status": "success",
                "case_id": case_id,
                "updated_fields": updated_fields,
                "raw_response": data
            }
        except Exception as e:
            self.logger.error("Exception in update_case", exc_info=e)
            raise Exception(str(e))

    def add_case_comment(self, request: RequestBody) -> ResponseBody:
        try:
            conn = self._connect(request.connectionParameters)
            case_id = request.parameters['case_id']
            comment_text = request.parameters['comment']

            data = self._request(conn, "POST", f"/cases/{case_id}/comments", json_data={"comment": comment_text})

            return {
                "status": "success",
                "case_id": case_id,
                "comment_id": data.get("_id") or data.get("id"),
                "raw_response": data
            }
        except Exception as e:
            self.logger.error("Exception in add_case_comment", exc_info=e)
            raise Exception(str(e))

    # -------------------------------
    # Read Actions
    # -------------------------------
    def get_case_summary(self, request: RequestBody) -> ResponseBody:
        try:
            conn = self._connect(request.connectionParameters)
            case_id = request.parameters['case_id']
            data = self._request(conn, "GET", f"/cases/{case_id}/summary")
            return {
                "status": "success",
                "case_id": case_id,
                "summary": data if isinstance(data, dict) else {},
                "raw_response": data
            }
        except Exception as e:
            self.logger.error("Exception in get_case_summary", exc_info=e)
            raise Exception(str(e))

    def get_case_scores(self, request: RequestBody) -> ResponseBody:
        try:
            conn = self._connect(request.connectionParameters)
            case_id = request.parameters['case_id']
            data = self._request(conn, "GET", f"/cases/{case_id}/scores")
            return {
                "status": "success",
                "case_id": case_id,
                "score_details": data if isinstance(data, dict) else {},
                "raw_response": data
            }
        except Exception as e:
            self.logger.error("Exception in get_case_scores", exc_info=e)
            raise Exception(str(e))

    def get_case_alerts(self, request: RequestBody) -> ResponseBody:
        try:
            conn = self._connect(request.connectionParameters)
            case_id = request.parameters['case_id']
            data = self._request(conn, "GET", f"/cases/{case_id}/alerts")

            if isinstance(data, list):
                alerts_list = data
            elif isinstance(data, dict):
                alerts_list = data.get("data", [])
            else:
                alerts_list = []

            return {
                "status": "success",
                "case_id": case_id,
                "alerts": alerts_list,
                "total_count": len(alerts_list),
                "raw_response": data
            }
        except Exception as e:
            self.logger.error("Exception in get_case_alerts", exc_info=e)
            raise Exception(str(e))

    def get_case_observables(self, request: RequestBody) -> ResponseBody:
        try:
            conn = self._connect(request.connectionParameters)
            case_id = request.parameters['case_id']
            data = self._request(conn, "GET", f"/cases/{case_id}/observables")

            if isinstance(data, list):
                observables_list = data
            elif isinstance(data, dict):
                observables_list = data.get("data", [])
            else:
                observables_list = []

            return {
                "status": "success",
                "case_id": case_id,
                "observables": observables_list,
                "total_count": len(observables_list),
                "raw_response": data
            }
        except Exception as e:
            self.logger.error("Exception in get_case_observables", exc_info=e)
            raise Exception(str(e))

    def list_cases(self, request: RequestBody) -> ResponseBody:
        try:
            conn = self._connect(request.connectionParameters)

            params = {}
            for field in ['status', 'severity', 'assignee', 'page', 'size']:
                value = request.parameters.get(field)
                if value is not None:
                    params[field] = value

            tags = request.parameters.get('tags')
            if tags is not None:
                if isinstance(tags, str):
                    tags = [t.strip() for t in tags.split(',')]
                params['tags'] = tags

            data = self._request(conn, "GET", "/cases", params=params)

            if isinstance(data, list):
                cases = data
            elif isinstance(data, dict):
                cases = data.get("data", [])
            else:
                cases = []

            return {
                "status": "success",
                "cases": cases,
                "total_count": len(cases),
                "raw_response": data
            }
        except Exception as e:
            self.logger.error("Exception in list_cases", exc_info=e)
            raise Exception(str(e))

    def get_case_details(self, request: RequestBody) -> ResponseBody:
        try:
            conn = self._connect(request.connectionParameters)
            case_id = request.parameters['case_id']
            data = self._request(conn, "GET", f"/cases/{case_id}")
            return {
                "status": "success",
                "case_id": case_id,
                "case_details": data if isinstance(data, dict) else {},
                "raw_response": data
            }
        except Exception as e:
            self.logger.error("Exception in get_case_details", exc_info=e)
            raise Exception(str(e))
