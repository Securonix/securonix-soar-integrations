from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import requests
import json
import base64
from datetime import datetime, timedelta


class FreshserviceItsm:
    """
    Freshservice ITSM SOAR connector.

    Provides integration with Freshservice ITSM platform through REST API v2.
    Supports ticket management, agent and requester management, asset management,
    and location management operations.

    Authentication: HTTP Basic Auth with API Key
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger()
        self._token = None
        self._token_expiry = None

    def _get_auth_headers(self, api_key: str) -> dict:
        """Generate Basic Auth headers using API key."""
        credentials = f"{api_key}:X"
        encoded = base64.b64encode(credentials.encode()).decode()
        return {"Authorization": f"Basic {encoded}", "Content-Type": "application/json"}

    def _build_url(self, api_host: str, path: str) -> str:
        """Build full API URL from path."""
        base = api_host.rstrip('/')
        if path.startswith('/'):
            path = path[1:]
        return f"{base}/api/v2/{path}"

    def _handle_error(self, response: requests.Response) -> dict:
        """Handle API errors and return structured error response."""
        error_details = response.text

        try:
            json_error = response.json()
            if isinstance(json_error, dict):
                error_details = json_error.get("description", json_error.get("error", str(json_error)))
        except (json.JSONDecodeError, AttributeError):
            pass

        status_code = response.status_code

        if status_code == 401:
            return {
                "status": "error",
                "message": "Authentication error: Invalid API key",
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
        elif status_code == 409:
            return {
                "status": "error",
                "message": f"Conflict: {error_details}",
                "status_code": status_code
            }
        elif status_code == 422:
            return {
                "status": "error",
                "message": f"Validation error: {error_details}",
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
                "message": "Internal server error: Freshservice API encountered an error",
                "status_code": status_code
            }
        elif status_code == 503:
            return {
                "status": "error",
                "message": "Service unavailable: Freshservice API temporarily unavailable",
                "status_code": status_code
            }
        elif status_code == 504:
            return {
                "status": "error",
                "message": "Gateway timeout: Freshservice API response timeout",
                "status_code": status_code
            }
        else:
            return {
                "status": "error",
                "message": f"API request failed with status {status_code}: {error_details}",
                "status_code": status_code
            }

    def _make_request(self, method: str, api_host: str, api_key: str,
                      path: str, params: dict = None, data: dict = None,
                      verify_ssl: bool = True) -> dict:
        """
        Make authenticated request to Freshservice API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            api_host: Freshservice base URL
            api_key: API key for authentication
            path: API endpoint path
            params: Query parameters
            data: Request body for POST/PUT
            verify_ssl: Verify SSL certificate

        Returns:
            dict: Parsed JSON response or error dict
        """
        url = self._build_url(api_host, path)
        headers = self._get_auth_headers(api_key)

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

    def _build_query_params(self, parameters: dict, allowed_keys: list) -> dict:
        """Build query parameters from request parameters."""
        params = {}
        for key in allowed_keys:
            if key in parameters and parameters[key] is not None:
                params[key] = parameters[key]
        return params

    # =========================================================
    # Test Connection
    # =========================================================

    def test_connection(self, connectionParameters: dict) -> dict:
        """
        Test connection to Freshservice API.

        Verifies API key and API connectivity.

        Args:
            connectionParameters: Connection params with api_host, api_key, verify_ssl

        Returns:
            dict: Success/error response
        """
        api_host = connectionParameters.get('api_host')
        api_key = connectionParameters.get('api_key')

        if not all([api_host, api_key]):
            return {
                "status": "error",
                "message": "Missing required connection parameters: api_host, api_key"
            }

        # Test by listing tickets (lightweight endpoint)
        result = self._make_request(
            'GET',
            api_host,
            api_key,
            'tickets',
            params={'page': 1, 'per_page': 1},
            verify_ssl=connectionParameters.get('verify_ssl', True)
        )

        return result

    # =========================================================
    # Ticket Operations
    # =========================================================

    def get_tickets(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of tickets with optional filtering.

        Parameters:
            page (int): Page number
            per_page (int): Results per page (max 100)
            filter (str): Filter name (new_and_my_open, watching, spam, deleted)
            query (str): Advanced query for filtering
            requester_id (int): Filter by requester ID
            email (str): Filter by requester email
            updated_since (str): Filter by last updated timestamp
            type (str): Filter by ticket type (Incident, Service Request)
            workspace_id (int): Filter by workspace ID
            include (str): Comma-separated list of includes (requester, stats, tags, etc.)
            order_type (str): Sort order (asc/desc)
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'filter', 'query', 'requester_id', 'email',
            'updated_since', 'type', 'workspace_id', 'include', 'order_type'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'tickets',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_ticket_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single ticket by ID with optional embedded resources.

        Parameters:
            ticket_id (int): Ticket ID
            include (str): Comma-separated list of includes (requester, stats, tags, conversations, assets, etc.)
        """
        ticket_id = request.parameters['ticket_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'tickets/{ticket_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def search_tickets_by_criteria(self, request: RequestBody) -> ResponseBody:
        """
        Search tickets using Freshservice's advanced query syntax.

        Parameters:
            query (str): Query string using Freshservice field names
            page (int): Page number
            per_page (int): Results per page

        Example query: "priority: 1 AND status: 2 OR urgency: 3"
        """
        params = self._build_query_params(request.parameters, ['query', 'page', 'per_page'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'tickets/filter',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_ticket(self, request: RequestBody) -> ResponseBody:
        """
        Create a new ticket.

        Parameters:
            subject (str): Ticket subject
            description (str): Ticket description
            requester_id (int): Requester ID
            requester (str): Requester email (creates new requester if not exists)
            email (str): Requester email
            type (str): Ticket type (Incident, Service Request, Problem, Change)
            priority (int): Priority (1=Low, 2=Medium, 3=High, 4=Urgent)
            status (int): Status (1=Open, 2=Pending, 3=Resolved, 4=Closed)
            service_id (int): Service ID
            category (str): Category
            sub_category (str): Sub category
            item_category (str): Item category
            group_id (int): Group ID
            agent_id (int): Assigned agent ID
            due_by (str): Due date (ISO8601)
            fr_due_by (str): First response due date (ISO8601)
            tags (str): Comma-separated tags
            custom_fields (dict): Custom field values
            workspace_id (int): Workspace ID
            attachments (list): File paths for attachments
        """
        params = self._build_query_params(request.parameters, [
            'subject', 'description', 'requester_id', 'requester', 'email',
            'type', 'priority', 'status', 'service_id', 'category',
            'sub_category', 'item_category', 'group_id', 'agent_id',
            'due_by', 'fr_due_by', 'tags', 'custom_fields', 'workspace_id',
            'attachments'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'tickets',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_ticket(self, request: RequestBody) -> ResponseBody:
        """
        Update an existing ticket.

        Parameters:
            ticket_id (int): Ticket ID
            subject (str): Ticket subject
            description (str): Ticket description
            requester_id (int): Requester ID
            type (str): Ticket type
            priority (int): Priority
            status (int): Status
            group_id (int): Group ID
            agent_id (int): Assigned agent ID
            due_by (str): Due date (ISO8601)
            fr_due_by (str): First response due date (ISO8601)
            tags (str): Comma-separated tags
            custom_fields (dict): Custom field values
            attachments (list): File paths for attachments
        """
        ticket_id = request.parameters['ticket_id']
        params = self._build_query_params(request.parameters, [
            'subject', 'description', 'requester_id', 'type', 'priority',
            'status', 'group_id', 'agent_id', 'due_by', 'fr_due_by',
            'tags', 'custom_fields', 'attachments'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'tickets/{ticket_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def close_ticket(self, request: RequestBody) -> ResponseBody:
        """
        Close a ticket.

        Parameters:
            ticket_id (int): Ticket ID
            status (int): Status (4=Closed)
            resolution (str): Resolution description
        """
        ticket_id = request.parameters['ticket_id']
        params = {
            'status': 4,
            'resolution': request.parameters.get('resolution', 'Ticket closed via SOAR')
        }
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'tickets/{ticket_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def resolve_ticket(self, request: RequestBody) -> ResponseBody:
        """
        Resolve a ticket.

        Parameters:
            ticket_id (int): Ticket ID
            status (int): Status (3=Resolved)
            resolution (str): Resolution description
        """
        ticket_id = request.parameters['ticket_id']
        params = {
            'status': 3,
            'resolution': request.parameters.get('resolution', 'Ticket resolved via SOAR')
        }
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'tickets/{ticket_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_ticket(self, request: RequestBody) -> ResponseBody:
        """
        Soft delete a ticket.

        Parameters:
            ticket_id (int): Ticket ID
        """
        ticket_id = request.parameters['ticket_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'tickets/{ticket_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Agent Operations
    # =========================================================

    def get_agents(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of agents.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            filter (str): Filter by email, mobile_phone_number, work_phone_number, or active status
            state (str): Filter by state (fulltime, occasional)
            query (str): Advanced query for filtering
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'filter', 'state', 'query', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'agents',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_agent_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single agent by ID.

        Parameters:
            agent_id (int): Agent ID
        """
        agent_id = request.parameters['agent_id']
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'agents/{agent_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Requester/Contact Operations
    # =========================================================

    def get_requesters(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of requesters (contacts).

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            email (str): Filter by email
            mobile_phone_number (str): Filter by mobile phone
            work_phone_number (str): Filter by work phone
            query (str): Advanced query for filtering
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'email', 'mobile_phone_number', 'work_phone_number',
            'query', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'requesters',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_requester_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single requester by ID.

        Parameters:
            requester_id (int): Requester ID
        """
        requester_id = request.parameters['requester_id']
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'requesters/{requester_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Asset Operations
    # =========================================================

    def get_assets(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of assets.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            order_by (str): Order by field (created_at, updated_at, etc.)
            order_type (str): Order type (asc/desc)
            include (str): Comma-separated list of includes (type_fields)
            trashed (bool): Include trashed assets
            workspace_id (int): Filter by workspace ID
            query (str): Advanced query for filtering
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'order_by', 'order_type', 'include',
            'trashed', 'workspace_id', 'query'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'assets',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_asset_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single asset by display ID.

        Parameters:
            display_id (str): Asset display ID
            include (str): Comma-separated list of includes (type_fields)
        """
        display_id = request.parameters['display_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'assets/{display_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Location Operations
    # =========================================================

    def get_locations(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of locations.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            query (str): Advanced query for filtering
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'query', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'locations',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_location_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single location by ID.

        Parameters:
            location_id (int): Location ID
        """
        location_id = request.parameters['location_id']
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'locations/{location_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )
