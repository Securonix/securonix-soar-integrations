"""
Cisco Duo SOAR Integration.

Main integration class implementing all Duo Admin API actions with
HMAC-SHA512 authentication, rate-limit retry logic, and credential protection.
"""

import logging
import re
import time

import requests

from app.duo_auth import get_auth_headers
from app.model.request_body import RequestBody


class CiscoDuo:

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    # ---------------------------------------------------------------------
    # Test Connection
    # ---------------------------------------------------------------------

    def test_connection(self, connectionParameters: dict):
        """
        Verify Duo API credentials by making an authenticated request to /admin/v1/info/summary.
        """
        host = connectionParameters.get('api_hostname', '').strip()
        ikey = connectionParameters.get('integration_key', '').strip()
        skey = connectionParameters.get('secret_key', '').strip()

        # Validate connection parameters
        if not host:
            raise Exception("Missing required connection parameter: api_hostname")
        if not ikey:
            raise Exception("Missing required connection parameter: integration_key")
        if not skey:
            raise Exception("Missing required connection parameter: secret_key")

        try:
            resp = self._get_with_retry(host, "/admin/v1/info/summary", {}, ikey, skey)
            body = resp.json()
            if body.get("stat") == "OK":
                return {"status": "success", "message": "Connected to Cisco Duo successfully."}
            else:
                raise Exception(f"Duo API returned error: {body.get('message', 'Unknown error')}")
        except Exception as e:
            self.logger.error("Exception while testing connection", exc_info=e)
            raise Exception(str(e))

    # ---------------------------------------------------------------------
    # Get User
    # ---------------------------------------------------------------------

    def duo_get_user(self, request: RequestBody) -> dict:
        """
        Retrieve a Duo user by user_id or username.

        Prioritizes user_id over username when both are provided.
        Returns a failed status dict when the user is not found.
        """
        try:
            host = request.connectionParameters['api_hostname']
            ikey = request.connectionParameters['integration_key']
            skey = request.connectionParameters['secret_key']

            user_id = request.parameters.get('user_id')
            username = request.parameters.get('username')

            # Validate at least one identifier
            if not user_id and not username:
                raise Exception("Either user_id or username must be provided")

            # Prioritize user_id over username
            if user_id:
                try:
                    resp = self._get_with_retry(host, f"/admin/v1/users/{user_id}", {}, ikey, skey)
                    body = resp.json()
                    if body.get("stat") != "OK":
                        return {"status": "failed", "message": f"User not found: {user_id}"}
                    user = body.get("response")
                except Exception as e:
                    error_msg = str(e)
                    if "404" in error_msg or "Not Found" in error_msg:
                        return {"status": "failed", "message": f"User not found: {user_id}"}
                    raise
            else:
                params = {"username": username}
                resp = self._get_with_retry(host, "/admin/v1/users", params, ikey, skey)
                body = resp.json()
                users = body.get("response", [])
                if not users:
                    return {"status": "failed", "message": f"User not found: {username}"}
                user = users[0]

            return {
                "status": "success",
                "message": "User retrieved successfully.",
                "user": user,
                "user_id": user.get("user_id")
            }
        except Exception as e:
            self.logger.error("error while running action 'duo_get_user'", exc_info=e)
            raise Exception(str(e))

    # ---------------------------------------------------------------------
    # Get User Devices
    # ---------------------------------------------------------------------

    def duo_get_user_devices(self, request: RequestBody) -> dict:
        """
        Retrieve phones/devices registered to a Duo user.

        Prioritizes user_id over username when both are provided.
        Returns a failed status dict when the user is not found or neither param provided.
        """
        try:
            host = request.connectionParameters['api_hostname']
            ikey = request.connectionParameters['integration_key']
            skey = request.connectionParameters['secret_key']

            user_id = request.parameters.get('user_id')
            username = request.parameters.get('username')

            if not user_id and not username:
                return {"status": "failed", "message": "Either user_id or username must be provided"}

            # Prioritize user_id over username
            if not user_id:
                try:
                    user_id = self._resolve_username(username, host, ikey, skey)
                except Exception:
                    return {"status": "failed", "message": f"User not found: {username}"}

            resp = self._get_with_retry(host, f"/admin/v1/users/{user_id}/phones", {}, ikey, skey)
            body = resp.json()

            if body.get("stat") != "OK":
                return {"status": "failed", "message": body.get("message", "Failed to retrieve devices")}

            phones = body.get("response", [])

            return {
                "status": "success",
                "message": "User devices retrieved successfully.",
                "phones": phones,
                "count": len(phones)
            }

        except Exception as e:
            self.logger.error("error while running action 'duo_get_user_devices'", exc_info=e)
            raise Exception(str(e))

    # ---------------------------------------------------------------------
    # Get Authentication Logs
    # ---------------------------------------------------------------------

    def duo_get_auth_logs(self, request: RequestBody) -> dict:
        """
        Retrieve Duo authentication logs with filtering and cursor-based pagination.

        Uses the v2 auth logs endpoint which returns:
        {"stat": "OK", "response": {"authlogs": [...], "metadata": {...}}}

        Validates mintime (13-digit ms timestamp within 180 days), caps limit at 1000.
        """
        try:
            host = request.connectionParameters['api_hostname']
            ikey = request.connectionParameters['integration_key']
            skey = request.connectionParameters['secret_key']

            # Get limit with default and cap
            limit = request.parameters.get('limit', 100)
            limit = min(int(limit), 1000)

            # Validate mintime if provided
            mintime = request.parameters.get('mintime')
            if mintime:
                mintime_str = str(mintime)
                if len(mintime_str) != 13 or not mintime_str.isdigit():
                    raise Exception("Invalid mintime: must be a 13-digit Unix timestamp in milliseconds")
                # Check if within last 180 days
                import time as time_module
                current_ms = int(time_module.time() * 1000)
                max_lookback_ms = 180 * 24 * 60 * 60 * 1000  # 180 days in ms
                if current_ms - int(mintime_str) > max_lookback_ms:
                    raise Exception("Invalid mintime: must be within the last 180 days")

            # Build params
            params = {"limit": str(limit)}

            if mintime:
                params['mintime'] = str(mintime)
            if request.parameters.get('maxtime'):
                params['maxtime'] = str(request.parameters['maxtime'])
            if request.parameters.get('users'):
                params['users'] = request.parameters['users']
            if request.parameters.get('results'):
                params['results'] = request.parameters['results']
            if request.parameters.get('factors'):
                params['factors'] = request.parameters['factors']
            if request.parameters.get('applications'):
                params['applications'] = request.parameters['applications']
            if request.parameters.get('reasons'):
                params['reasons'] = request.parameters['reasons']
            if request.parameters.get('event_types'):
                params['event_types'] = request.parameters['event_types']
            if request.parameters.get('next_offset'):
                params['next_offset'] = request.parameters['next_offset']

            resp = self._get_with_retry(host, "/admin/v2/logs/authentication", params, ikey, skey)
            body = resp.json()

            if body.get("stat") != "OK":
                return {"status": "failed", "message": body.get("message", "Failed to retrieve auth logs")}

            response_data = body.get("response", {})
            authlogs = response_data.get("authlogs", [])
            metadata = response_data.get("metadata", {})

            result = {
                "status": "success",
                "message": "Authentication logs retrieved successfully.",
                "authlogs": authlogs,
                "count": len(authlogs),
                "total_objects": metadata.get("total_objects", len(authlogs))
            }

            # Include pagination metadata if next_offset is available
            next_offset = metadata.get("next_offset")
            if next_offset:
                result["pagination"] = {
                    "next_offset": next_offset,
                    "total_objects": metadata.get("total_objects")
                }
                result["next_offset"] = next_offset

            return result

        except Exception as e:
            self.logger.error("error while running action 'duo_get_auth_logs'", exc_info=e)
            raise Exception(str(e))

    # ---------------------------------------------------------------------
    # Get User Groups
    # ---------------------------------------------------------------------

    def duo_get_user_groups(self, request: RequestBody) -> dict:
        """
        Retrieve groups for a Duo user by user_id or username.

        Resolves username to user_id if only username is provided.
        Returns a failed status dict when the user is not found or neither param provided.
        """
        try:
            host = request.connectionParameters['api_hostname']
            ikey = request.connectionParameters['integration_key']
            skey = request.connectionParameters['secret_key']

            user_id = request.parameters.get('user_id')
            username = request.parameters.get('username')

            if not user_id and not username:
                return {"status": "failed", "message": "Either user_id or username must be provided"}

            # Resolve username to user_id if needed
            if not user_id:
                try:
                    user_id = self._resolve_username(username, host, ikey, skey)
                except Exception:
                    return {"status": "failed", "message": f"User not found: {username}"}

            resp = self._get_with_retry(host, f"/admin/v1/users/{user_id}/groups", {}, ikey, skey)
            body = resp.json()

            if body.get("stat") != "OK":
                return {"status": "failed", "message": body.get("message", "Failed to retrieve groups")}

            groups = body.get("response", [])

            return {
                "status": "success",
                "message": "User groups retrieved successfully.",
                "groups": groups,
                "count": len(groups)
            }

        except Exception as e:
            self.logger.error("error while running action 'duo_get_user_groups'", exc_info=e)
            raise Exception(str(e))

    # ---------------------------------------------------------------------
    # Add User to Group
    # ---------------------------------------------------------------------

    def duo_add_user_to_group(self, request: RequestBody) -> dict:
        """
        Add a Duo user to a group.

        Requires both user_id and group_id parameters.
        Uses POST /admin/v1/users/{user_id}/groups with group_id as form-encoded body.

        Args:
            request: RequestBody containing parameters (user_id, group_id)
                     and connectionParameters.

        Returns:
            Dict with status, message, user_id, and group_id on success.

        Raises:
            Exception: On missing parameters or API errors.
        """
        try:
            host = request.connectionParameters['api_hostname']
            ikey = request.connectionParameters['integration_key']
            skey = request.connectionParameters['secret_key']

            user_id = request.parameters.get('user_id')
            group_id = request.parameters.get('group_id')

            if not user_id:
                raise Exception("Missing required parameter: user_id")
            if not group_id:
                raise Exception("Missing required parameter: group_id")

            # POST with group_id as form-encoded body
            data = {"group_id": group_id}
            resp = self._post_with_retry(host, f"/admin/v1/users/{user_id}/groups", {}, data, ikey, skey)
            body = resp.json()

            if body.get("stat") != "OK":
                raise Exception(body.get("message", "Failed to add user to group"))

            return {
                "status": "success",
                "message": "User added to group successfully.",
                "user_id": user_id,
                "group_id": group_id
            }

        except Exception as e:
            self.logger.error("error while running action 'duo_add_user_to_group'", exc_info=e)
            raise Exception(str(e))

    # ---------------------------------------------------------------------
    # Update User Status
    # ---------------------------------------------------------------------

    def duo_update_user_status(self, request: RequestBody) -> dict:
        """
        Update a Duo user's status (active, bypass, or disabled).

        Validates the status value before making the API call. Resolves
        username to user_id if only username is provided. Returns the
        updated user object on success.

        Args:
            request: RequestBody with parameters: user_id (optional),
                     username (optional), status (required).

        Returns:
            Dict with status "success", message, user object, and user_id.

        Raises:
            Exception: If neither user_id nor username provided, status missing/invalid,
                       user not found, or API error.
        """
        try:
            host = request.connectionParameters['api_hostname']
            ikey = request.connectionParameters['integration_key']
            skey = request.connectionParameters['secret_key']

            user_id = request.parameters.get('user_id')
            username = request.parameters.get('username')
            status = request.parameters.get('status')

            # Validate required params
            if not user_id and not username:
                raise Exception("Either user_id or username must be provided")
            if not status:
                raise Exception("status parameter is required")

            # Validate status value
            valid_statuses = ['active', 'bypass', 'disabled']
            if status not in valid_statuses:
                raise Exception(f"Invalid status: '{status}'. Allowed values: {', '.join(valid_statuses)}")

            # Resolve username to user_id if needed
            if not user_id:
                user_id = self._resolve_username(username, host, ikey, skey)

            # POST to update user status (form-encoded)
            data = {"status": status}
            resp = self._post_with_retry(host, f"/admin/v1/users/{user_id}", {}, data, ikey, skey)
            body = resp.json()

            if body.get("stat") != "OK":
                raise Exception(body.get("message", "Failed to update user status"))

            user = body.get("response")

            return {
                "status": "success",
                "message": f"User status updated to '{status}' successfully.",
                "user": user,
                "user_id": user.get("user_id")
            }

        except Exception as e:
            self.logger.error("error while running action 'duo_update_user_status'", exc_info=e)
            raise Exception(str(e))

    # ---------------------------------------------------------------------
    # Remove User from Group
    # ---------------------------------------------------------------------

    def duo_remove_user_from_group(self, request: RequestBody) -> dict:
        """
        Remove a Duo user from a group.

        Requires both user_id and group_id parameters.
        Returns a failed status dict if the user is not a member of the group (404).
        """
        try:
            host = request.connectionParameters['api_hostname']
            ikey = request.connectionParameters['integration_key']
            skey = request.connectionParameters['secret_key']

            user_id = request.parameters.get('user_id')
            group_id = request.parameters.get('group_id')

            if not user_id:
                raise Exception("Missing required parameter: user_id")
            if not group_id:
                raise Exception("Missing required parameter: group_id")

            # DELETE request
            try:
                resp = self._delete_with_retry(host, f"/admin/v1/users/{user_id}/groups/{group_id}", {}, ikey, skey)
                body = resp.json()

                if body.get("stat") != "OK":
                    return {"status": "failed", "message": body.get("message", "Failed to remove user from group")}

                return {
                    "status": "success",
                    "message": "User removed from group successfully.",
                    "user_id": user_id,
                    "group_id": group_id
                }
            except Exception as e:
                error_msg = str(e)
                if "404" in error_msg or "Not Found" in error_msg:
                    return {"status": "failed", "message": "User is not a member of the specified group"}
                raise

        except Exception as e:
            self.logger.error("error while running action 'duo_remove_user_from_group'", exc_info=e)
            raise Exception(str(e))

    # =========================================================================
    # Internal helpers
    # =========================================================================

    def _build_headers(self, method: str, host: str, path: str, params: dict, ikey: str, skey: str) -> dict:
        """
        Build signed headers for a Duo API request.

        Calls duo_auth.get_auth_headers and adds Content-Type for POST requests.

        Args:
            method: HTTP method (GET, POST, DELETE).
            host: Duo API hostname.
            path: Request path.
            params: Parameters to sign (query params for GET/DELETE, body params for POST).
            ikey: Integration key.
            skey: Secret key.

        Returns:
            Headers dict with Authorization, Date, and optionally Content-Type.
        """
        headers = get_auth_headers(method, host, path, params, ikey, skey)
        if method.upper() == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        return headers

    def _strip_credentials(self, message: str, ikey: str = None, skey: str = None) -> str:
        """
        Strip credential material from an error message before re-raising.

        Removes: secret_key, integration_key, Authorization header values, HMAC signatures.
        """
        if not message:
            return message

        sanitized = message

        # Strip secret_key
        if skey and skey in sanitized:
            sanitized = sanitized.replace(skey, "***")

        # Strip integration_key
        if ikey and ikey in sanitized:
            sanitized = sanitized.replace(ikey, "***")

        # Strip Authorization header values (Basic base64...)
        sanitized = re.sub(r'Basic [A-Za-z0-9+/=]+', 'Basic ***', sanitized)

        # Strip hex-encoded HMAC signatures (128-char hex strings typical of SHA-512)
        sanitized = re.sub(r'[a-f0-9]{128}', '***', sanitized)

        return sanitized

    def _handle_error_response(self, resp, ikey: str = None, skey: str = None):
        """
        Handle non-success HTTP responses from Duo API.

        Args:
            resp: The requests.Response object.
            ikey: Integration key for credential stripping.
            skey: Secret key for credential stripping.

        Raises:
            Exception: With appropriate error message based on status code.
        """
        status = resp.status_code

        if status == 401:
            raise Exception("Authentication failed: invalid credentials or clock skew")

        if status == 400:
            try:
                body = resp.json()
                error_msg = body.get("message", resp.text)
            except Exception:
                error_msg = resp.text
            raise Exception(self._strip_credentials(error_msg, ikey, skey))

        if 500 <= status < 600:
            raise Exception("Duo service error")

        # Generic error for other non-success codes
        raise Exception(self._strip_credentials(
            f"Duo API error (HTTP {status}): {resp.text}", ikey, skey
        ))

    def _get_with_retry(self, host: str, path: str, params: dict, ikey: str, skey: str, max_retries: int = 3):
        """
        Make a signed GET request to the Duo API with retry logic.

        Handles:
        - 429: Retry with Retry-After header (default 1s, max 60s), up to max_retries
        - 401: Raise auth error
        - 400: Raise with Duo error message
        - 5xx: Raise service error
        - Returns response on success (status < 300)

        Args:
            host: Duo API hostname.
            path: Request path.
            params: Query parameters (also used for signing).
            ikey: Integration key.
            skey: Secret key.
            max_retries: Maximum retry attempts for 429 responses.

        Returns:
            requests.Response on success.

        Raises:
            Exception: On non-retryable errors or after retries exhausted.
        """
        url = f"https://{host}{path}"

        try:
            for attempt in range(max_retries):
                headers = self._build_headers("GET", host, path, params, ikey, skey)
                resp = requests.get(url, headers=headers, params=params, timeout=30)

                if resp.status_code == 429:
                    retry_after = min(int(resp.headers.get("Retry-After", 1)), 60)
                    if attempt < max_retries - 1:
                        time.sleep(retry_after)
                        continue
                    else:
                        raise Exception(f"Rate limited after {max_retries} retries")

                if resp.status_code >= 300:
                    self._handle_error_response(resp, ikey, skey)

                return resp

            # Should not reach here, but safety net
            raise Exception(f"Rate limited after {max_retries} retries")

        except requests.exceptions.Timeout as e:
            self.logger.error("Request timed out", exc_info=e)
            raise Exception("Request timed out after 30 seconds")
        except requests.exceptions.ConnectionError as e:
            self.logger.error("Connection error", exc_info=e)
            raise Exception("Unable to connect to Duo API. Please check network connectivity and hostname.")
        except Exception as e:
            # Re-raise if already handled (our own exceptions)
            if "Rate limited" in str(e) or "timed out" in str(e) or "Unable to connect" in str(e):
                raise
            if "Authentication failed" in str(e) or "Duo service error" in str(e):
                raise
            self.logger.error("Error during GET request", exc_info=e)
            raise Exception(self._strip_credentials(str(e), ikey, skey))

    def _post_with_retry(self, host: str, path: str, params: dict, data: dict, ikey: str, skey: str, max_retries: int = 3):
        """
        Make a signed POST request to the Duo API with retry logic.

        For POST requests, the params to sign are the form body params (data).
        The request sends form-encoded body via data= parameter.

        Args:
            host: Duo API hostname.
            path: Request path.
            params: Query parameters (not used for signing in POST).
            data: Form body parameters (used for signing and sent as body).
            ikey: Integration key.
            skey: Secret key.
            max_retries: Maximum retry attempts for 429 responses.

        Returns:
            requests.Response on success.

        Raises:
            Exception: On non-retryable errors or after retries exhausted.
        """
        url = f"https://{host}{path}"

        try:
            for attempt in range(max_retries):
                # For POST, sign with body params
                headers = self._build_headers("POST", host, path, data, ikey, skey)
                resp = requests.post(url, headers=headers, data=data, timeout=30)

                if resp.status_code == 429:
                    retry_after = min(int(resp.headers.get("Retry-After", 1)), 60)
                    if attempt < max_retries - 1:
                        time.sleep(retry_after)
                        continue
                    else:
                        raise Exception(f"Rate limited after {max_retries} retries")

                if resp.status_code >= 300:
                    self._handle_error_response(resp, ikey, skey)

                return resp

            # Should not reach here, but safety net
            raise Exception(f"Rate limited after {max_retries} retries")

        except requests.exceptions.Timeout as e:
            self.logger.error("Request timed out", exc_info=e)
            raise Exception("Request timed out after 30 seconds")
        except requests.exceptions.ConnectionError as e:
            self.logger.error("Connection error", exc_info=e)
            raise Exception("Unable to connect to Duo API. Please check network connectivity and hostname.")
        except Exception as e:
            if "Rate limited" in str(e) or "timed out" in str(e) or "Unable to connect" in str(e):
                raise
            if "Authentication failed" in str(e) or "Duo service error" in str(e):
                raise
            self.logger.error("Error during POST request", exc_info=e)
            raise Exception(self._strip_credentials(str(e), ikey, skey))

    def _delete_with_retry(self, host: str, path: str, params: dict, ikey: str, skey: str, max_retries: int = 3):
        """
        Make a signed DELETE request to the Duo API with retry logic.

        Args:
            host: Duo API hostname.
            path: Request path.
            params: Query parameters (used for signing).
            ikey: Integration key.
            skey: Secret key.
            max_retries: Maximum retry attempts for 429 responses.

        Returns:
            requests.Response on success.

        Raises:
            Exception: On non-retryable errors or after retries exhausted.
        """
        url = f"https://{host}{path}"

        try:
            for attempt in range(max_retries):
                headers = self._build_headers("DELETE", host, path, params, ikey, skey)
                resp = requests.delete(url, headers=headers, params=params, timeout=30)

                if resp.status_code == 429:
                    retry_after = min(int(resp.headers.get("Retry-After", 1)), 60)
                    if attempt < max_retries - 1:
                        time.sleep(retry_after)
                        continue
                    else:
                        raise Exception(f"Rate limited after {max_retries} retries")

                if resp.status_code >= 300:
                    self._handle_error_response(resp, ikey, skey)

                return resp

            # Should not reach here, but safety net
            raise Exception(f"Rate limited after {max_retries} retries")

        except requests.exceptions.Timeout as e:
            self.logger.error("Request timed out", exc_info=e)
            raise Exception("Request timed out after 30 seconds")
        except requests.exceptions.ConnectionError as e:
            self.logger.error("Connection error", exc_info=e)
            raise Exception("Unable to connect to Duo API. Please check network connectivity and hostname.")
        except Exception as e:
            if "Rate limited" in str(e) or "timed out" in str(e) or "Unable to connect" in str(e):
                raise
            if "Authentication failed" in str(e) or "Duo service error" in str(e):
                raise
            self.logger.error("Error during DELETE request", exc_info=e)
            raise Exception(self._strip_credentials(str(e), ikey, skey))

    def _resolve_username(self, username: str, host: str, ikey: str, skey: str) -> str:
        """
        Resolve a username to a user_id via GET /admin/v1/users?username=X.

        Args:
            username: The Duo username to look up.
            host: Duo API hostname.
            ikey: Integration key.
            skey: Secret key.

        Returns:
            The user_id string from the first matching user.

        Raises:
            Exception: If no user is found for the given username.
        """
        params = {"username": username}
        resp = self._get_with_retry(host, "/admin/v1/users", params, ikey, skey)

        body = resp.json()
        users = body.get("response", [])

        if not users:
            raise Exception(f"User not found: {username}")

        return users[0].get("user_id")

    # ---------------------------------------------------------------------
    # Search Users
    # ---------------------------------------------------------------------
    def duo_search_users(self, request: RequestBody) -> dict:
        """
        Search for Duo users with optional filtering and pagination.

        Supports filtering by username, email, and status. Results are paginated
        with configurable limit (max 300) and offset (max 10000).

        Args:
            request: RequestBody containing parameters (username, email, status,
                     limit, offset) and connectionParameters.

        Returns:
            Dict with status, message, users list, total_objects, count,
            and optional pagination metadata.

        Raises:
            Exception: On invalid status filter, offset exceeding 10000, or API errors.
        """
        try:
            host = request.connectionParameters['api_hostname']
            ikey = request.connectionParameters['integration_key']
            skey = request.connectionParameters['secret_key']

            # Get params with defaults
            limit = request.parameters.get('limit', 100)
            offset = request.parameters.get('offset', 0)

            # Validate status filter
            status_filter = request.parameters.get('status')
            valid_statuses = ['active', 'bypass', 'disabled', 'locked_out', 'pending_deletion']
            if status_filter and status_filter not in valid_statuses:
                raise Exception(f"Invalid status filter: '{status_filter}'. Allowed values: {', '.join(valid_statuses)}")

            # Validate offset limit
            if offset > 10000:
                raise Exception("Offset exceeds maximum retrievable records limit of 10000")

            # Cap limit at 300 (Duo API max for users endpoint)
            limit = min(int(limit), 300)

            # Build query params
            params = {"limit": str(limit), "offset": str(offset)}

            if request.parameters.get('username'):
                params['username'] = request.parameters['username']
            if request.parameters.get('email'):
                params['email'] = request.parameters['email']
            if status_filter:
                params['status'] = status_filter

            resp = self._get_with_retry(host, "/admin/v1/users", params, ikey, skey)
            body = resp.json()

            users = body.get("response", [])
            metadata = body.get("metadata", {})
            total_objects = metadata.get("total_objects", len(users))

            result = {
                "status": "success",
                "message": "Users retrieved successfully.",
                "users": users,
                "total_objects": total_objects,
                "count": len(users)
            }

            # Add pagination metadata if more pages available
            if total_objects > offset + limit:
                result["pagination"] = {
                    "offset": offset,
                    "limit": limit,
                    "total_objects": total_objects,
                    "next_offset": offset + limit
                }

            return result

        except Exception as e:
            self.logger.error("error while running action 'duo_search_users'", exc_info=e)
            raise Exception(str(e))
