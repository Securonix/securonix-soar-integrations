from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import json
import requests


class Workday():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    # -------------------------------
    # OAuth Token Generation
    # -------------------------------
    def get_access_token(self, connectionParameters):
        token_url = connectionParameters["token_url"]

        payload = {
            "grant_type": "refresh_token",
            "refresh_token": connectionParameters["refresh_token"],
            "client_id": connectionParameters["client_id"],
            "client_secret": connectionParameters["client_secret"]
        }

        response = requests.post(token_url, data=payload)
        response.raise_for_status()

        return response.json().get("access_token")

    # -------------------------------
    # Test Connection
    # -------------------------------
    def test_connection(self, connectionParameters: dict):
        base_url = connectionParameters['base_url'].rstrip('/')
        tenant = connectionParameters['tenant']
        timeout = int(connectionParameters.get('timeout', 30))

        try:
            token = self.get_access_token(connectionParameters)

            url = f"{base_url}/ccx/api/v1/{tenant}/workers?limit=1"
            headers = {
                "Authorization": f"Bearer {token}"
            }

            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()

            return {'status': 'success', 'message': 'Connected to Workday successfully.'}

        except Exception as e:
            self.logger.error("Workday test connection failed", exc_info=e)
            raise Exception(str(e))

    # -------------------------------
    # Internal Helpers
    # -------------------------------
    def _get_headers(self, token):
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

    def _get(self, url, headers, timeout):
        resp = requests.get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()
        return resp.json()

    def _post(self, url, headers, payload, timeout):
        resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
        resp.raise_for_status()
        return resp.json()

    # -------------------------------
    # Actions
    # -------------------------------

    #  1. Get Employee Details
    def get_employee_details(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        tenant = request.connectionParameters['tenant']
        timeout = int(request.connectionParameters.get('timeout', 30))

        employee_id = request.parameters["employee_id"]

        try:
            token = self.get_access_token(request.connectionParameters)

            url = f"{base_url}/ccx/api/v1/{tenant}/workers/{employee_id}"
            data = self._get(url, self._get_headers(token), timeout)

            return {
                "status": "success",
                "employee": data
            }

        except Exception as e:
            self.logger.error("Error fetching employee details", exc_info=e)
            return {"status": "error", "message": str(e)}

    #  2. Fetch User Risk Profile (Custom / Middleware)
    def get_user_risk_profile(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        tenant = request.connectionParameters['tenant']
        timeout = int(request.connectionParameters.get('timeout', 30))

        employee_id = request.parameters["employee_id"]

        try:
            token = self.get_access_token(request.connectionParameters)

            # Usually a custom endpoint or report
            url = f"{base_url}/ccx/api/v1/{tenant}/risk-profile/{employee_id}"
            data = self._get(url, self._get_headers(token), timeout)

            return {
                "status": "success",
                "risk_profile": data
            }

        except Exception as e:
            self.logger.error("Error fetching risk profile", exc_info=e)
            return {"status": "error", "message": str(e)}

    #  3. Trigger Onboarding (Custom API)
    def trigger_onboarding(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        tenant = request.connectionParameters['tenant']
        timeout = int(request.connectionParameters.get('timeout', 30))

        try:
            token = self.get_access_token(request.connectionParameters)

            payload = {
                "employeeId": request.parameters["employee_id"],
                "name": request.parameters["name"],
                "department": request.parameters["department"],
                "startDate": request.parameters["start_date"]
            }

            url = f"{base_url}/ccx/api/v1/{tenant}/onboarding"
            data = self._post(url, self._get_headers(token), payload, timeout)

            return {
                "status": "success",
                "message": "Onboarding triggered",
                "response": data
            }

        except Exception as e:
            self.logger.error("Error triggering onboarding", exc_info=e)
            return {"status": "error", "message": str(e)}

    # 4. Sync Employee Data
    def sync_employee_data(self, request: RequestBody) -> ResponseBody:
        base_url = request.connectionParameters['base_url'].rstrip('/')
        tenant = request.connectionParameters['tenant']
        timeout = int(request.connectionParameters.get('timeout', 30))

        try:
            token = self.get_access_token(request.connectionParameters)

            url = f"{base_url}/ccx/api/v1/{tenant}/workers"
            data = self._get(url, self._get_headers(token), timeout)

            employees = data.get("workers", data)

            return {
                "status": "success",
                "count": len(employees),
                "employees": employees
            }

        except Exception as e:
            self.logger.error("Error syncing employees", exc_info=e)
            return {"status": "error", "message": str(e)}