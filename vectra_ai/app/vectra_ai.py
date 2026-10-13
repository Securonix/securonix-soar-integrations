from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import requests
import json
import base64
from datetime import datetime, timedelta

class VectraAi:
    """
    Vectra AI SOAR connector.

    Provides integration with Vectra AI breach detection platform through REST API v3.4/v3.5.
    Supports investigation of detections, accounts, hosts, and entities,
    plus remediation actions for marking detections as fixed, closing accounts,
    and setting key assets.

    Authentication: OAuth2 Client Credentials Grant
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger()
        self._token = None
        self._token_expiry = None

    def _get_auth_headers(self, client_id: str, client_secret: str) -> dict:
        """Generate Basic Auth headers for OAuth2 token request."""
        credentials = f"{client_id}:{client_secret}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return {"Authorization": f"Basic {encoded}", "Content-Type": "application/x-www-form-urlencoded"}

    def _get_oauth2_token(self, api_host: str, client_id: str, client_secret: str) -> dict:
        """
        Retrieve OAuth2 access token using client credentials.

        Returns:
            dict: Token response with access_token, expires_in, refresh_token
        """
        url = f"{api_host.rstrip('/')}/oauth2/token"
        headers = self._get_auth_headers(client_id, client_secret)
        data = {"grant_type": "client_credentials"}

        try:
            response = requests.post(url, headers=headers, data=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 401:
                raise Exception("Authentication failed: Invalid client credentials")
            elif response.status_code == 429:
                raise Exception("Rate limit exceeded: Too many requests")
            elif response.status_code == 503:
                raise Exception("Service unavailable: Vectra API temporarily unavailable")
            elif response.status_code == 504:
                raise Exception("Gateway timeout: Vectra API response timeout")
            else:
                raise Exception(f"Authentication failed: HTTP {response.status_code}")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Connection error: {str(e)}")

    def _ensure_token_valid(self, api_host: str, client_id: str, client_secret: str) -> str:
        """
        Ensure we have a valid access token, refreshing if necessary.

        Returns:
            str: Access token
        """
        if self._token is None or self._token_expiry is None or datetime.now() >= self._token_expiry:
            token_data = self._get_oauth2_token(api_host, client_id, client_secret)
            self._token = token_data.get("access_token")
            expires_in = token_data.get("expires_in", 3600)
            self._token_expiry = datetime.now() + timedelta(seconds=expires_in - 60)  # Refresh 60s early

        return self._token

    def _get_headers(self, api_host: str, client_id: str, client_secret: str) -> dict:
        """Get authorization headers with fresh token."""
        token = self._ensure_token_valid(api_host, client_id, client_secret)
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    def _build_url(self, api_host: str, path: str) -> str:
        """Build full API URL from path."""
        base = api_host.rstrip('/')
        if not path.startswith('/'):
            path = '/' + path
        return f"{base}{path}"

    def _handle_error(self, response: requests.Response) -> dict:
        """Handle API errors and return structured error response."""
        error_details = response.text

        try:
            json_error = response.json()
            if isinstance(json_error, dict):
                error_details = json_error.get("detail", json_error.get("message", str(json_error)))
        except (json.JSONDecodeError, AttributeError):
            pass

        status_code = response.status_code

        if status_code == 401:
            return {
                "status": "error",
                "message": "Authentication error: Invalid or expired token",
                "status_code": status_code
            }
        elif status_code == 403:
            return {
                "status": "error",
                "message": "Authorization error: Insufficient permissions",
                "status_code": status_code
            }
        elif status_code == 404:
            return {
                "status": "error",
                "message": f"Not found: {error_details}",
                "status_code": status_code
            }
        elif status_code == 413:
            return {
                "status": "error",
                "message": "Request too large: Response exceeds size limit",
                "status_code": status_code
            }
        elif status_code == 429:
            return {
                "status": "error",
                "message": "Rate limit exceeded: Too many requests",
                "status_code": status_code
            }
        elif status_code == 500:
            return {
                "status": "error",
                "message": "Internal server error: Vectra API encountered an error",
                "status_code": status_code
            }
        elif status_code == 503:
            return {
                "status": "error",
                "message": "Service unavailable: Vectra API temporarily unavailable",
                "status_code": status_code
            }
        elif status_code == 504:
            return {
                "status": "error",
                "message": "Gateway timeout: Vectra API response timeout",
                "status_code": status_code
            }
        else:
            return {
                "status": "error",
                "message": f"API request failed with status {status_code}: {error_details}",
                "status_code": status_code
            }

    def _make_request(self, method: str, api_host: str, client_id: str, client_secret: str,
                      path: str, params: dict = None, data: dict = None,
                      verify_ssl: bool = True) -> dict:
        """
        Make authenticated request to Vectra API.

        Args:
            method: HTTP method (GET, POST, PATCH)
            api_host: Vectra API base URL
            client_id: OAuth2 client ID
            client_secret: OAuth2 client secret
            path: API endpoint path
            params: Query parameters
            data: Request body for POST/PATCH
            verify_ssl: Verify SSL certificate

        Returns:
            dict: Parsed JSON response or error dict
        """
        url = self._build_url(api_host, path)
        headers = self._get_headers(api_host, client_id, client_secret)

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=data,
                verify=verify_ssl
            )
            response.raise_for_status()
            return {"status": "success", "results": response.json()}
        except requests.exceptions.HTTPError:
            return self._handle_error(response)
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "message": f"Request failed: {str(e)}",
                "status_code": getattr(e.response, 'status_code', None) if e.response else None
            }

    # =========================================================
    # Test Connection
    # =========================================================

    def test_connection(self, connectionParameters: dict) -> dict:
        """
        Test connection to Vectra API.

        Verifies authentication credentials and API connectivity.

        Args:
            connectionParameters: Connection params with api_host, client_id, client_secret, verify_ssl

        Returns:
            dict: Success/error response
        """
        api_host = connectionParameters.get('api_host')
        client_id = connectionParameters.get('client_id')
        client_secret = connectionParameters.get('client_secret')
        verify_ssl = connectionParameters.get('verify_ssl', True)

        if not all([api_host, client_id, client_secret]):
            return {
                "status": "error",
                "message": "Missing required connection parameters: api_host, client_id, client_secret"
            }

        try:
            token = self._get_oauth2_token(api_host, client_id, client_secret)
            if token.get("access_token"):
                return {
                    "status": "success",
                    "message": "Connected to Vectra AI successfully"
                }
            else:
                return {
                    "status": "error",
                    "message": "Authentication failed: No access token returned"
                }
        except Exception as e:
            self.logger.error("Exception while testing Vectra AI connection", exc_info=True)
            return {
                "status": "error",
                "message": str(e)
            }

    # =========================================================
    # Investigate Functions
    # =========================================================

    def get_detections(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of detections with optional filtering.

        Parameters:
            ordering (str): Field to order by (e.g., last_timestamp, -threat)
            page (int): Page number
            page_size (int): Results per page
            detection_category (str): Filter by category
            state (str): Filter by state (active, closed)
            threat (int): Minimum threat score
            certainty (int): Minimum certainty score
            is_targeting_key_asset (bool): Filter for key asset targets
            is_triaged (bool): Filter for triaged detections
            created_timestamp_gte (str): ISO8601 start date
            created_timestamp_lte (str): ISO8601 end date
            fields (str): Fields to include
            exclude_fields (str): Fields to exclude
            size (str): Response tier (small, regular, detailed)
        """
        params = self._build_query_params(request.parameters, [
            'ordering', 'page', 'page_size', 'detection_category', 'state',
            'threat', 'certainty', 'is_targeting_key_asset', 'is_triaged',
            'created_timestamp_gte', 'created_timestamp_lte', 'fields',
            'exclude_fields', 'size'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            '/api/v3.5/detections/',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_detection_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single detection by ID.

        Parameters:
            detection_id (int): Detection ID
            fields (str): Fields to include
            exclude_fields (str): Fields to exclude
        """
        detection_id = request.parameters['detection_id']
        params = self._build_query_params(request.parameters, ['fields', 'exclude_fields'])

        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.5/detections/{detection_id}/',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_accounts(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of accounts.

        Parameters:
            ordering (str): Field to order by
            page (int): Page number
            page_size (int): Results per page
            state (str): Filter by state
            threat (int): Minimum threat score
            fields (str): Fields to include
            exclude_fields (str): Fields to exclude
            size (str): Response tier
        """
        params = self._build_query_params(request.parameters, [
            'ordering', 'page', 'page_size', 'state', 'threat',
            'fields', 'exclude_fields', 'size'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            '/api/v3.5/accounts/',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_account_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single account by ID.

        Parameters:
            account_id (int): Account ID
            fields (str): Fields to include
            exclude_fields (str): Fields to exclude
        """
        account_id = request.parameters['account_id']
        params = self._build_query_params(request.parameters, ['fields', 'exclude_fields'])

        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.5/accounts/{account_id}/',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_hosts(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of hosts.

        Parameters:
            ordering (str): Field to order by
            page (int): Page number
            page_size (int): Results per page
            state (str): Filter by state
            threat (int): Minimum threat score
            fields (str): Fields to include
            exclude_fields (str): Fields to exclude
            size (str): Response tier
        """
        params = self._build_query_params(request.parameters, [
            'ordering', 'page', 'page_size', 'state', 'threat',
            'fields', 'exclude_fields', 'size'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            '/api/v3.5/hosts/',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_host_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single host by ID.

        Parameters:
            host_id (int): Host ID
            fields (str): Fields to include
            exclude_fields (str): Fields to exclude
            size (str): Response tier
        """
        host_id = request.parameters['host_id']
        params = self._build_query_params(request.parameters, ['fields', 'exclude_fields', 'size'])

        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.5/hosts/{host_id}/',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_entities(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of entities (hosts and accounts).

        Parameters:
            ordering (str): Field to order by
            page (int): Page number
            page_size (int): Results per page
            type (str): Filter by type (host, account)
            fields (str): Fields to include
            exclude_fields (str): Fields to exclude
        """
        params = self._build_query_params(request.parameters, [
            'ordering', 'page', 'page_size', 'type', 'fields', 'exclude_fields'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            '/api/v3.5/entities/',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_entity_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single entity by ID.

        Parameters:
            entity_id (int): Entity ID
            type (str): Entity type (host or account)
            fields (str): Fields to include
            exclude_fields (str): Fields to exclude
        """
        entity_id = request.parameters['entity_id']
        entity_type = request.parameters['type']
        params = self._build_query_params(request.parameters, ['fields', 'exclude_fields'])

        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.5/entities/{entity_id}/',
            params={**params, 'type': entity_type},
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def search_detections_by_criteria(self, request: RequestBody) -> ResponseBody:
        """
        Search detections with multiple filter criteria.

        Parameters:
            src_ip (str): Source IP address
            src_account (str): Source account name
            detection_category (str): Detection category
            threat_gte (int): Minimum threat score
            created_timestamp_gte (str): Start date
            is_targeting_key_asset (bool): Key asset filter
            tags (str): Comma-separated tags
            external_reference_id (str): External ticket ID
            fields (str): Fields to include
            exclude_fields (str): Fields to exclude
        """
        params = self._build_query_params(request.parameters, [
            'src_ip', 'src_account', 'detection_category', 'threat_gte',
            'created_timestamp_gte', 'is_targeting_key_asset', 'tags',
            'external_reference_id', 'fields', 'exclude_fields'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            '/api/v3.5/detections/',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def _build_query_params(self, parameters: dict, allowed_keys: list) -> dict:
        """Build query params dict from parameters, filtering to allowed keys."""
        return {k: v for k, v in parameters.items() if k in allowed_keys and v is not None}

    # =========================================================
    # Remediate Functions
    # =========================================================

    def mark_detection_fixed(self, request: RequestBody) -> ResponseBody:
        """
        Mark one or more detections as fixed.

        Parameters:
            detection_id_list (list): List of detection IDs
            external_reference_id (str): External ticket reference
            investigation_status (str): Status for workflow
        """
        detection_ids = request.parameters.get('detection_id_list', [])
        if isinstance(detection_ids, str):
            detection_ids = [int(x.strip()) for x in detection_ids.split(',') if x.strip()]

        payload = {
            "detectionIdList": detection_ids,
            "mark_as_fixed": True
        }

        if 'external_reference_id' in request.parameters:
            payload["external_reference_id"] = request.parameters['external_reference_id']

        if 'investigation_status' in request.parameters:
            payload["investigation_status"] = request.parameters['investigation_status']

        return self._make_request(
            'PATCH',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            '/api/v3.5/detections/',
            data=payload,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def close_account(self, request: RequestBody) -> ResponseBody:
        """
        Close an account and its associated detections.

        Parameters:
            account_id (int): Account ID
            reason (str): Close reason (remediated, benign)
        """
        account_id = request.parameters['account_id']
        reason = request.parameters['reason']

        payload = {"reason": reason}

        return self._make_request(
            'PATCH',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.4/accounts/{account_id}/close',
            data=payload,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def set_host_as_key_asset(self, request: RequestBody) -> ResponseBody:
        """
        Mark a host as a key asset or remove the flag.

        Parameters:
            host_id (int): Host ID
            key_asset (bool): Set to true to mark as key asset
        """
        host_id = request.parameters['host_id']
        key_asset = request.parameters['key_asset']

        payload = {"key_asset": str(key_asset).lower()}

        return self._make_request(
            'PATCH',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.5/hosts/{host_id}/',
            data=payload,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Additional SOAR Functions (API v3.4/v3.5)
    # =========================================================

    def get_findings(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of posture findings.

        Parameters:
            page (int): Page number
            page_size (int): Results per page (max 5000)
            ordering (str): Order by severity (-severity for descending)
            finding_type_uid (str): Filter by finding type
            first_seen_gte (str): Start date (ISO8601)
            first_seen_lte (str): End date (ISO8601)
            last_seen_gte (str): Last seen start date
            last_seen_lte (str): Last seen end date
            status (str): Filter by status (all, active, inactive)
            category (str): Filter by category
            severity (str): Filter by severity (low, medium, high, critical)
            size (str): Response tier (small, regular, detailed)
            resolution (str): Filter by resolution (open, in_progress, remediated, risk_accepted)

        Returns:
            dict: Paginated findings list
        """
        params = self._build_query_params(request.parameters, [
            'page', 'page_size', 'ordering', 'finding_type_uid',
            'first_seen_gte', 'first_seen_lte', 'last_seen_gte', 'last_seen_lte',
            'status', 'category', 'severity', 'size', 'resolution'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            '/api/v3.5/findings/',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_finding_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single finding by ID.

        Parameters:
            finding_id (str): Finding ID
            fields (str): Fields to include
            exclude_fields (str): Fields to exclude

        Returns:
            dict: Detailed finding object
        """
        finding_id = request.parameters['finding_id']
        params = self._build_query_params(request.parameters, ['fields', 'exclude_fields'])

        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.5/findings/{finding_id}/',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_host_findings(self, request: RequestBody) -> ResponseBody:
        """
        Get entity findings associated with a finding.

        Parameters:
            finding_id (str): Finding ID
            page (int): Page number
            page_size (int): Results per page
            ordering (str): Order by field (e.g., -updated_at)
            first_seen_gte (str): Start date (ISO8601)
            first_seen_lte (str): End date (ISO8601)
            last_seen_gte (str): Last seen start date
            last_seen_lte (str): Last seen end date

        Returns:
            dict: Paginated list of entity findings
        """
        finding_id = request.parameters['finding_id']
        params = self._build_query_params(request.parameters, [
            'page', 'page_size', 'ordering',
            'first_seen_gte', 'first_seen_lte', 'last_seen_gte', 'last_seen_lte'
        ])

        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.5/findings/{finding_id}/entities/',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_assignment_outcomes(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of assignment outcomes.

        Parameters:
            page (int): Page number
            page_size (int): Results per page

        Returns:
            dict: Paginated list of assignment outcomes
        """
        params = self._build_query_params(request.parameters, ['page', 'page_size'])

        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            '/api/v3.4/assignment_outcomes/',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_assignment_outcome(self, request: RequestBody) -> ResponseBody:
        """
        Create a new assignment outcome.

        Parameters:
            title (str): Title of the outcome
            category (str): Category of the outcome
            description (str): Description of the outcome

        Returns:
            dict: Created assignment outcome
        """
        payload = {}
        if 'title' in request.parameters:
            payload['title'] = request.parameters['title']
        if 'category' in request.parameters:
            payload['category'] = request.parameters['category']
        if 'description' in request.parameters:
            payload['description'] = request.parameters['description']

        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            '/api/v3.4/assignment_outcomes/',
            data=payload,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_assignments(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of assignments.

        Parameters:
            page (int): Page number
            page_size (int): Results per page
            accounts (str): Filter by account IDs (comma-separated)
            assignees (str): Filter by assignee usernames
            created_after (str): Filter by creation date (ISO8601)
            hosts (str): Filter by host IDs (comma-separated)
            resolution (str): Filter by resolution
            resolved (str): Filter by resolved status (true/false)

        Returns:
            dict: Paginated list of assignments
        """
        params = self._build_query_params(request.parameters, [
            'page', 'page_size', 'accounts', 'assignees',
            'created_after', 'hosts', 'resolution', 'resolved'
        ])

        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            '/api/v3.4/assignments/',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_assignment_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single assignment by ID.

        Parameters:
            assignment_id (int): Assignment ID

        Returns:
            dict: Detailed assignment object
        """
        assignment_id = request.parameters['assignment_id']

        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.4/assignments/{assignment_id}/',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_detection_events(self, request: RequestBody) -> ResponseBody:
        """
        Get detection events from a checkpoint.

        Parameters:
            from (int): Checkpoint ID to start from
            account_uid (str): Filter by account UID
            event_timestamp_gte (str): Start date (ISO8601)
            event_timestamp_lte (str): End date (ISO8601)
            detection_id (int): Filter by detection ID
            id (int): Filter by event ID
            include_info_category (bool): Include INFO detections
            include_triaged (bool): Include triaged detections
            limit (int): Max results per page
            ordering (str): Order by field
            type (str): Event type
            include_all_process_context (bool): Include process context
            change_type (str): Change type filter
            entity_id (int): Filter by entity ID
            entity_uid (str): Filter by entity UID
            external_reference_id (str): Filter by external reference
            investigation_status (str): Filter by investigation status
            size (str): Response tier
            unresolved_priority (bool): Filter by unresolved priority

        Returns:
            dict: Detection events list
        """
        params = self._build_query_params(request.parameters, [
            'from', 'account_uid', 'event_timestamp_gte', 'event_timestamp_lte',
            'detection_id', 'id', 'include_info_category', 'include_triaged',
            'limit', 'ordering', 'type', 'include_all_process_context',
            'change_type', 'entity_id', 'entity_uid', 'external_reference_id',
            'investigation_status', 'size', 'unresolved_priority'
        ])

        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            '/api/v3.5/events/detections/',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_detection_by_id_patch(self, request: RequestBody) -> ResponseBody:
        """
        Update a single detection with note, triageAs, investigation_status, or external_reference_id.

        Parameters:
            detection_id (int): Detection ID
            note (str): Note to attach to the detection
            triageAs (str): Triage status (benign, unknown, unknown_positive)
            investigation_status (str): Investigation status
            external_reference_id (str): External ticket reference ID

        Returns:
            dict: Updated detection object
        """
        detection_id = request.parameters['detection_id']
        payload = {}

        if 'note' in request.parameters:
            payload['note'] = request.parameters['note']
        if 'triageAs' in request.parameters:
            payload['triageAs'] = request.parameters['triageAs']
        if 'investigation_status' in request.parameters:
            payload['investigation_status'] = request.parameters['investigation_status']
        if 'external_reference_id' in request.parameters:
            payload['external_reference_id'] = request.parameters['external_reference_id']

        return self._make_request(
            'PATCH',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.5/detections/{detection_id}/',
            data=payload,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def patch_single_entity(self, request: RequestBody) -> ResponseBody:
        """
        Update a single entity with unresolved_priority or external_reference_id.

        Parameters:
            entity_id (int): Entity ID
            unresolved_priority (str): Priority level (low, medium, high, critical)
            external_reference_id (str): External ticket reference ID

        Returns:
            dict: Updated entity object
        """
        entity_id = request.parameters['entity_id']
        payload = {}

        if 'unresolved_priority' in request.parameters:
            payload['unresolved_priority'] = request.parameters['unresolved_priority']
        if 'external_reference_id' in request.parameters:
            payload['external_reference_id'] = request.parameters['external_reference_id']

        return self._make_request(
            'PATCH',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.5/entities/{entity_id}/',
            data=payload,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_assignment_outcome(self, request: RequestBody) -> ResponseBody:
        """
        Delete an assignment outcome.

        Parameters:
            assignment_outcome_id (int): Assignment outcome ID

        Returns:
            dict: Delete response (empty on success)
        """
        assignment_outcome_id = request.parameters['assignment_outcome_id']

        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.4/assignment_outcomes/{assignment_outcome_id}/',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_assignment_outcome(self, request: RequestBody) -> ResponseBody:
        """
        Update an assignment outcome.

        Parameters:
            assignment_outcome_id (int): Assignment outcome ID
            title (str): Title of the outcome
            category (str): Category of the outcome
            description (str): Description of the outcome

        Returns:
            dict: Updated assignment outcome
        """
        assignment_outcome_id = request.parameters['assignment_outcome_id']
        payload = {}

        if 'title' in request.parameters:
            payload['title'] = request.parameters['title']
        if 'category' in request.parameters:
            payload['category'] = request.parameters['category']
        if 'description' in request.parameters:
            payload['description'] = request.parameters['description']

        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.4/assignment_outcomes/{assignment_outcome_id}/',
            data=payload,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_assignment_outcome_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single assignment outcome by ID.

        Parameters:
            assignment_outcome_id (int): Assignment outcome ID

        Returns:
            dict: Assignment outcome object
        """
        assignment_outcome_id = request.parameters['assignment_outcome_id']

        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.4/assignment_outcomes/{assignment_outcome_id}/',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_rules(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of triage rules.

        Parameters:
            page (int): Page number
            page_size (int): Results per page
            is_active (bool): Filter by active status

        Returns:
            dict: Paginated list of triage rules
        """
        params = self._build_query_params(request.parameters, ['page', 'page_size', 'is_active'])

        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            '/api/v3.4/rules/',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_rules(self, request: RequestBody) -> ResponseBody:
        """
        Create a new triage rule.

        Parameters:
            name (str): Rule name
            source_conditions (list): List of source condition dictionaries
            additional_conditions (list): List of additional condition dictionaries

        Returns:
            dict: Created triage rule
        """
        payload = {}

        if 'name' in request.parameters:
            payload['name'] = request.parameters['name']
        if 'source_conditions' in request.parameters:
            payload['source_conditions'] = request.parameters['source_conditions']
        if 'additional_conditions' in request.parameters:
            payload['additional_conditions'] = request.parameters['additional_conditions']

        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            '/api/v3.4/rules/',
            data=payload,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_rules(self, request: RequestBody) -> ResponseBody:
        """
        Update a triage rule by ID.

        Parameters:
            rule_id (int): Rule ID
            name (str): Rule name
            source_conditions (list): List of source condition dictionaries
            additional_conditions (list): List of additional condition dictionaries

        Returns:
            dict: Updated triage rule
        """
        rule_id = request.parameters['rule_id']
        payload = {}

        if 'name' in request.parameters:
            payload['name'] = request.parameters['name']
        if 'source_conditions' in request.parameters:
            payload['source_conditions'] = request.parameters['source_conditions']
        if 'additional_conditions' in request.parameters:
            payload['additional_conditions'] = request.parameters['additional_conditions']

        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.4/rules/{rule_id}/',
            data=payload,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_rules(self, request: RequestBody) -> ResponseBody:
        """
        Delete a triage rule by ID.

        Parameters:
            rule_id (int): Rule ID

        Returns:
            dict: Delete response (empty on success)
        """
        rule_id = request.parameters['rule_id']

        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.4/rules/{rule_id}/',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_rules_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single triage rule by ID.

        Parameters:
            rule_id (int): Rule ID

        Returns:
            dict: Triage rule object
        """
        rule_id = request.parameters['rule_id']

        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.4/rules/{rule_id}/',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_assignment(self, request: RequestBody) -> ResponseBody:
        """
        Create a new assignment.

        Parameters:
            account_id (int): Account ID to assign
            host_id (int): Host ID to assign
            assignee (str): Username of the assignee
            assignment_outcome_id (int): Assignment outcome ID

        Returns:
            dict: Created assignment
        """
        payload = {}

        if 'account_id' in request.parameters:
            payload['account_id'] = request.parameters['account_id']
        if 'host_id' in request.parameters:
            payload['host_id'] = request.parameters['host_id']
        if 'assignee' in request.parameters:
            payload['assignee'] = request.parameters['assignee']
        if 'assignment_outcome_id' in request.parameters:
            payload['assignment_outcome_id'] = request.parameters['assignment_outcome_id']

        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            '/api/v3.4/assignments/',
            data=payload,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_assignment(self, request: RequestBody) -> ResponseBody:
        """
        Update an assignment by ID.

        Parameters:
            assignment_id (int): Assignment ID
            account_id (int): Account ID to assign
            host_id (int): Host ID to assign
            assignee (str): Username of the assignee
            assignment_outcome_id (int): Assignment outcome ID

        Returns:
            dict: Updated assignment
        """
        assignment_id = request.parameters['assignment_id']
        payload = {}

        if 'account_id' in request.parameters:
            payload['account_id'] = request.parameters['account_id']
        if 'host_id' in request.parameters:
            payload['host_id'] = request.parameters['host_id']
        if 'assignee' in request.parameters:
            payload['assignee'] = request.parameters['assignee']
        if 'assignment_outcome_id' in request.parameters:
            payload['assignment_outcome_id'] = request.parameters['assignment_outcome_id']

        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.4/assignments/{assignment_id}/',
            data=payload,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_assignment(self, request: RequestBody) -> ResponseBody:
        """
        Delete an assignment by ID.

        Parameters:
            assignment_id (int): Assignment ID

        Returns:
            dict: Delete response (empty on success)
        """
        assignment_id = request.parameters['assignment_id']

        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.4/assignments/{assignment_id}/',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_single_detection_events(self, request: RequestBody) -> ResponseBody:
        """
        Get detection events for a specific detection ID.

        Parameters:
            detection_id (int): Detection ID
            from (int): Checkpoint ID to start from
            event_timestamp_gte (str): Start date (ISO8601)
            event_timestamp_lte (str): End date (ISO8601)
            id (int): Filter by event ID
            include_info_category (bool): Include INFO detections
            include_triaged (bool): Include triaged detections
            limit (int): Max results per page
            ordering (str): Order by field
            type (str): Event type
            include_all_process_context (bool): Include process context
            change_type (str): Change type filter
            entity_id (int): Filter by entity ID
            entity_uid (str): Filter by entity UID
            external_reference_id (str): Filter by external reference
            investigation_status (str): Filter by investigation status
            size (str): Response tier
            unresolved_priority (bool): Filter by unresolved priority

        Returns:
            dict: Detection events list
        """
        detection_id = request.parameters['detection_id']
        params = self._build_query_params(request.parameters, [
            'from', 'event_timestamp_gte', 'event_timestamp_lte',
            'id', 'include_info_category', 'include_triaged',
            'limit', 'ordering', 'type', 'include_all_process_context',
            'change_type', 'entity_id', 'entity_uid', 'external_reference_id',
            'investigation_status', 'size', 'unresolved_priority'
        ])

        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['client_id'],
            request.connectionParameters['client_secret'],
            f'/api/v3.5/events/detections/{detection_id}/',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )
