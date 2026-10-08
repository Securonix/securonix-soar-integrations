from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import base64
import logging
import json
import requests


class Zoom():
    """
    Zoom SOAR connector.

    Covers the SOAR-relevant subset of the Zoom REST API (base URL
    https://api.zoom.us/v2): user identity/visibility, meeting visibility,
    security/audit reports, and light remediation.

    Authentication is Server-to-Server (S2S) OAuth, a two-legged flow that needs
    no user interaction:
      POST https://zoom.us/oauth/token
        Header: Authorization: Basic base64(client_id:client_secret)
        Body:   grant_type=account_credentials&account_id=<account_id>
      -> returns a Bearer access_token (valid 1 hour, no refresh token).
    The token is sent as "Authorization: Bearer <token>" on every API call.
    """

    API_BASE = "https://api.zoom.us/v2"
    TOKEN_URL = "https://zoom.us/oauth/token"

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    # -------------------------------
    # Connection / auth helpers
    # -------------------------------
    def _conn(self, connectionParameters: dict):
        account_id = connectionParameters['account_id']
        client_id = connectionParameters['client_id']
        client_secret = connectionParameters['client_secret']
        verify = connectionParameters.get('verify_ssl', True)
        if isinstance(verify, str):
            verify = verify.strip().lower() in ("true", "1", "yes")
        return account_id, client_id, client_secret, verify

    def _get_token(self, account_id, client_id, client_secret, verify):
        creds = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        headers = {
            "Authorization": f"Basic {creds}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {"grant_type": "account_credentials", "account_id": account_id}
        resp = requests.post(self.TOKEN_URL, headers=headers, data=data, verify=verify)
        resp.raise_for_status()
        body = resp.json()
        token = body.get("access_token")
        if not token:
            raise Exception("Failed to retrieve access token from Zoom OAuth response")
        return token

    def _auth_headers(self, token):
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _request(self, method, path, connectionParameters, params=None, body=None):
        """Authenticate, then issue a single API request and return parsed JSON."""
        account_id, client_id, client_secret, verify = self._conn(connectionParameters)
        token = self._get_token(account_id, client_id, client_secret, verify)
        url = f"{self.API_BASE}{path}"
        resp = requests.request(
            method, url, headers=self._auth_headers(token),
            params=params, json=body, verify=verify
        )
        resp.raise_for_status()
        # Some endpoints (DELETE/PUT) return 204 with no body.
        if resp.status_code == 204 or not resp.content:
            return {}
        return resp.json()

    # -------------------------------
    # Test Connection (SOAR calls this)
    # -------------------------------
    def test_connection(self, connectionParameters: dict):
        account_id, client_id, client_secret, verify = self._conn(connectionParameters)
        try:
            token = self._get_token(account_id, client_id, client_secret, verify)
            if token:
                return {"status": "success", "message": "Connected to Zoom successfully."}
            raise Exception("Authentication failed: no access token returned.")
        except Exception as e:
            self.logger.error("Exception while testing Zoom connection", exc_info=e)
            raise Exception(str(e))

    # =========================================================
    # Users — Investigate / read
    # =========================================================

    def list_users(self, request: RequestBody) -> ResponseBody:
        """
        List users on the account.
        Parameters: status (optional: active/inactive/pending), page_size (optional),
                    next_page_token (optional).
        """
        status = request.parameters.get('status', None)
        page_size = request.parameters.get('page_size', 30)
        next_page_token = request.parameters.get('next_page_token', None)
        try:
            params = {"page_size": page_size}
            if status:
                params["status"] = status
            if next_page_token:
                params["next_page_token"] = next_page_token
            data = self._request("GET", "/users", request.connectionParameters, params=params)
            self.logger.debug("Zoom list_users response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in list_users", exc_info=e)
            raise Exception(str(e))

    def get_user(self, request: RequestBody) -> ResponseBody:
        """Get a user. Parameters: user_id (required)."""
        user_id = request.parameters['user_id']
        try:
            data = self._request("GET", f"/users/{user_id}", request.connectionParameters)
            self.logger.debug("Zoom get_user response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_user", exc_info=e)
            raise Exception(str(e))

    def get_user_settings(self, request: RequestBody) -> ResponseBody:
        """Get a user's settings. Parameters: user_id (required)."""
        user_id = request.parameters['user_id']
        try:
            data = self._request("GET", f"/users/{user_id}/settings", request.connectionParameters)
            self.logger.debug("Zoom get_user_settings response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_user_settings", exc_info=e)
            raise Exception(str(e))

    def get_user_permissions(self, request: RequestBody) -> ResponseBody:
        """Get a user's permissions. Parameters: user_id (required)."""
        user_id = request.parameters['user_id']
        try:
            data = self._request("GET", f"/users/{user_id}/permissions", request.connectionParameters)
            self.logger.debug("Zoom get_user_permissions response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_user_permissions", exc_info=e)
            raise Exception(str(e))

    def get_user_presence_status(self, request: RequestBody) -> ResponseBody:
        """Get a user's presence status. Parameters: user_id (required)."""
        user_id = request.parameters['user_id']
        try:
            data = self._request("GET", f"/users/{user_id}/presence_status", request.connectionParameters)
            self.logger.debug("Zoom get_user_presence_status response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_user_presence_status", exc_info=e)
            raise Exception(str(e))

    # =========================================================
    # Meetings — Investigate / read
    # =========================================================

    def list_meetings(self, request: RequestBody) -> ResponseBody:
        """
        List a user's meetings.
        Parameters: user_id (required), type (optional: scheduled/live/upcoming),
                    page_size (optional), next_page_token (optional).
        """
        user_id = request.parameters['user_id']
        meeting_type = request.parameters.get('type', None)
        page_size = request.parameters.get('page_size', 30)
        next_page_token = request.parameters.get('next_page_token', None)
        try:
            params = {"page_size": page_size}
            if meeting_type:
                params["type"] = meeting_type
            if next_page_token:
                params["next_page_token"] = next_page_token
            data = self._request("GET", f"/users/{user_id}/meetings", request.connectionParameters, params=params)
            self.logger.debug("Zoom list_meetings response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in list_meetings", exc_info=e)
            raise Exception(str(e))

    def get_meeting(self, request: RequestBody) -> ResponseBody:
        """Get a meeting. Parameters: meeting_id (required)."""
        meeting_id = request.parameters['meeting_id']
        try:
            data = self._request("GET", f"/meetings/{meeting_id}", request.connectionParameters)
            self.logger.debug("Zoom get_meeting response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_meeting", exc_info=e)
            raise Exception(str(e))

    def get_past_meeting_details(self, request: RequestBody) -> ResponseBody:
        """Get past meeting details. Parameters: meeting_id (required)."""
        meeting_id = request.parameters['meeting_id']
        try:
            data = self._request("GET", f"/past_meetings/{meeting_id}", request.connectionParameters)
            self.logger.debug("Zoom get_past_meeting_details response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_past_meeting_details", exc_info=e)
            raise Exception(str(e))

    def get_past_meeting_participants(self, request: RequestBody) -> ResponseBody:
        """
        Get past meeting participants.
        Parameters: meeting_id (required), page_size (optional), next_page_token (optional).
        """
        meeting_id = request.parameters['meeting_id']
        page_size = request.parameters.get('page_size', 30)
        next_page_token = request.parameters.get('next_page_token', None)
        try:
            params = {"page_size": page_size}
            if next_page_token:
                params["next_page_token"] = next_page_token
            data = self._request("GET", f"/past_meetings/{meeting_id}/participants",
                                 request.connectionParameters, params=params)
            self.logger.debug("Zoom get_past_meeting_participants response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_past_meeting_participants", exc_info=e)
            raise Exception(str(e))

    # =========================================================
    # Reports — Audit
    # =========================================================

    def get_signin_signout_activity(self, request: RequestBody) -> ResponseBody:
        """
        Get sign in / sign out activity report.
        Parameters: from (optional, yyyy-mm-dd), to (optional, yyyy-mm-dd),
                    page_size (optional), next_page_token (optional).

        Note: per the Zoom API spec, from/to are optional for this report.
        Requires a Zoom Business/Enterprise (or higher) plan.
        """
        from_date = request.parameters.get('from', None)
        to_date = request.parameters.get('to', None)
        page_size = request.parameters.get('page_size', 30)
        next_page_token = request.parameters.get('next_page_token', None)
        try:
            params = {"page_size": page_size}
            if from_date:
                params["from"] = from_date
            if to_date:
                params["to"] = to_date
            if next_page_token:
                params["next_page_token"] = next_page_token
            data = self._request("GET", "/report/activities", request.connectionParameters, params=params)
            self.logger.debug("Zoom get_signin_signout_activity response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_signin_signout_activity", exc_info=e)
            raise Exception(str(e))

    def get_operation_logs(self, request: RequestBody) -> ResponseBody:
        """
        Get operation logs report.
        Parameters: from (required, yyyy-mm-dd), to (required, yyyy-mm-dd),
                    category_type (optional), page_size (optional), next_page_token (optional).
        """
        from_date = request.parameters['from']
        to_date = request.parameters['to']
        category_type = request.parameters.get('category_type', None)
        page_size = request.parameters.get('page_size', 30)
        next_page_token = request.parameters.get('next_page_token', None)
        try:
            params = {"from": from_date, "to": to_date, "page_size": page_size}
            if category_type:
                params["category_type"] = category_type
            if next_page_token:
                params["next_page_token"] = next_page_token
            data = self._request("GET", "/report/operationlogs", request.connectionParameters, params=params)
            self.logger.debug("Zoom get_operation_logs response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_operation_logs", exc_info=e)
            raise Exception(str(e))

    def get_active_inactive_hosts(self, request: RequestBody) -> ResponseBody:
        """
        Get active or inactive host report.
        Parameters: from (required, yyyy-mm-dd), to (required, yyyy-mm-dd),
                    type (optional: active/inactive), page_size (optional),
                    next_page_token (optional).
        """
        from_date = request.parameters['from']
        to_date = request.parameters['to']
        report_type = request.parameters.get('type', None)
        page_size = request.parameters.get('page_size', 30)
        next_page_token = request.parameters.get('next_page_token', None)
        try:
            params = {"from": from_date, "to": to_date, "page_size": page_size}
            if report_type:
                params["type"] = report_type
            if next_page_token:
                params["next_page_token"] = next_page_token
            data = self._request("GET", "/report/users", request.connectionParameters, params=params)
            self.logger.debug("Zoom get_active_inactive_hosts response: %s", json.dumps(data))
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in get_active_inactive_hosts", exc_info=e)
            raise Exception(str(e))

    # =========================================================
    # Remediate / act
    # =========================================================

    def update_user_status(self, request: RequestBody) -> ResponseBody:
        """
        Activate or deactivate a user.
        Parameters: user_id (required), action (required: activate/deactivate).
        """
        user_id = request.parameters['user_id']
        action = request.parameters['action']
        try:
            body = {"action": action}
            self._request("PUT", f"/users/{user_id}/status", request.connectionParameters, body=body)
            return {"status": "success", "results": {"user_id": user_id, "action": action}}
        except Exception as e:
            self.logger.error("Exception in update_user_status", exc_info=e)
            raise Exception(str(e))

    def revoke_user_sso_token(self, request: RequestBody) -> ResponseBody:
        """
        Revoke a user's SSO token (forces the user to sign out).
        Parameters: user_id (required).
        """
        user_id = request.parameters['user_id']
        try:
            self._request("DELETE", f"/users/{user_id}/token", request.connectionParameters)
            return {"status": "success", "results": {"user_id": user_id, "message": "SSO token revoked"}}
        except Exception as e:
            self.logger.error("Exception in revoke_user_sso_token", exc_info=e)
            raise Exception(str(e))

    def delete_meeting(self, request: RequestBody) -> ResponseBody:
        """
        Delete a meeting.
        Parameters:
            meeting_id (required)
            occurrence_id (optional) - the occurrence ID of a recurring meeting.
            notify_hosts (optional: true/false) - notify host and alternative
                hosts that the meeting was cancelled (maps to the Zoom
                `cancel_meeting_reminder` query parameter).
        """
        meeting_id = request.parameters['meeting_id']
        occurrence_id = request.parameters.get('occurrence_id', None)
        notify_hosts = request.parameters.get('notify_hosts', None)
        try:
            params = {}
            if occurrence_id:
                params["occurrence_id"] = occurrence_id
            if notify_hosts is not None:
                params["cancel_meeting_reminder"] = notify_hosts
            self._request("DELETE", f"/meetings/{meeting_id}", request.connectionParameters, params=params)
            return {"status": "success", "results": {"meeting_id": meeting_id, "message": "Meeting deleted"}}
        except Exception as e:
            self.logger.error("Exception in delete_meeting", exc_info=e)
            raise Exception(str(e))
