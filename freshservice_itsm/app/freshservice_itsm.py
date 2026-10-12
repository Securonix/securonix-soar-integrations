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
    # =========================================================
    # Service Catalog Operations
    # =========================================================

    def get_service_catalog_items(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of service catalog items.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            category_id (int): Filter by category ID
            workspace_id (int): Filter by workspace ID
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'category_id', 'workspace_id', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'service_catalog/items',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_service_catalog_item_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single service catalog item by ID.

        Parameters:
            item_id (int): Item ID
            include (str): Comma-separated list of includes
        """
        item_id = request.parameters['item_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'service_catalog/items/{item_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_service_catalog_categories(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of service catalog categories.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            workspace_id (int): Filter by workspace ID
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'workspace_id', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'service_catalog/categories',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_service_catalog_category_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single service catalog category by ID.

        Parameters:
            category_id (int): Category ID
            include (str): Comma-separated list of includes
        """
        category_id = request.parameters['category_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'service_catalog/categories/{category_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Solution Management Operations
    # =========================================================

    def get_solution_articles(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of solution articles.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            folder_id (int): Filter by folder ID (required)
            category_id (int): Filter by category ID
            workspace_id (int): Filter by workspace ID
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'folder_id', 'category_id', 'workspace_id', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'solutions/articles',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_solution_article_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single solution article by ID.

        Parameters:
            article_id (int): Article ID
            folder_id (int): Folder ID (required)
            include (str): Comma-separated list of includes
        """
        article_id = request.parameters['article_id']
        folder_id = request.parameters.get('folder_id')
        if not folder_id:
            return {
                "status": "error",
                "message": "folder_id is required parameter"
            }
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/articles/{article_id}?folder_id={folder_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_solution_categories(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of solution categories.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            workspace_id (int): Filter by workspace ID
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'workspace_id', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'solutions/categories',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_solution_category_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single solution category by ID.

        Parameters:
            category_id (int): Category ID
            include (str): Comma-separated list of includes
        """
        category_id = request.parameters['category_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/categories/{category_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_solution_folders(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of solution folders.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            category_id (int): Filter by category ID
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'category_id', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'solutions/folders',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_solution_folder_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single solution folder by ID.

        Parameters:
            folder_id (int): Folder ID
            include (str): Comma-separated list of includes
        """
        folder_id = request.parameters['folder_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/folders/{folder_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_solution_folder(self, request: RequestBody) -> ResponseBody:
        """
        Create a new solution folder.

        Parameters:
            category_id (int): Category ID
            name (str): Folder name
            description (str): Folder description
            visibility (str): Visibility (all, logged_in_users, agents)
            workspace_id (int): Workspace ID
        """
        params = self._build_query_params(request.parameters, [
            'category_id', 'name', 'description', 'visibility', 'workspace_id'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'solutions/folders',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_solution_folder(self, request: RequestBody) -> ResponseBody:
        """
        Update an existing solution folder.

        Parameters:
            folder_id (int): Folder ID
            name (str): Folder name
            description (str): Folder description
            visibility (str): Visibility (all, logged_in_users, agents)
            workspace_id (int): Workspace ID
        """
        folder_id = request.parameters['folder_id']
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'visibility', 'workspace_id'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/folders/{folder_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_solution_folder(self, request: RequestBody) -> ResponseBody:
        """
        Delete a solution folder.

        Parameters:
            folder_id (int): Folder ID
        """
        folder_id = request.parameters['folder_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/folders/{folder_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def restore_solution_folder(self, request: RequestBody) -> ResponseBody:
        """
        Restore a deleted solution folder.

        Parameters:
            folder_id (int): Folder ID
        """
        folder_id = request.parameters['folder_id']
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/folders/{folder_id}/restore',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_solution_category(self, request: RequestBody) -> ResponseBody:
        """
        Create a new solution category.

        Parameters:
            name (str): Category name
            description (str): Category description
            visibility (str): Visibility (all, logged_in_users, agents)
            workspace_id (int): Workspace ID
        """
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'visibility', 'workspace_id'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'solutions/categories',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_solution_category(self, request: RequestBody) -> ResponseBody:
        """
        Update an existing solution category.

        Parameters:
            category_id (int): Category ID
            name (str): Category name
            description (str): Category description
            visibility (str): Visibility
            workspace_id (int): Workspace ID
        """
        category_id = request.parameters['category_id']
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'visibility', 'workspace_id'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/categories/{category_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_solution_category(self, request: RequestBody) -> ResponseBody:
        """
        Delete a solution category.

        Parameters:
            category_id (int): Category ID
        """
        category_id = request.parameters['category_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/categories/{category_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def restore_solution_category(self, request: RequestBody) -> ResponseBody:
        """
        Restore a deleted solution category.

        Parameters:
            category_id (int): Category ID
        """
        category_id = request.parameters['category_id']
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/categories/{category_id}/restore',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_solution_article(self, request: RequestBody) -> ResponseBody:
        """
        Create a new solution article.

        Parameters:
            folder_id (int): Folder ID
            title (str): Article title
            body (str): Article body
            status (int): Status (1=Draft, 2=Published)
            is_enabled_for_self_service (bool): Enable for self service
            category_id (int): Category ID
            workspace_id (int): Workspace ID
        """
        params = self._build_query_params(request.parameters, [
            'folder_id', 'title', 'body', 'status', 'is_enabled_for_self_service',
            'category_id', 'workspace_id'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'solutions/articles',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_solution_article(self, request: RequestBody) -> ResponseBody:
        """
        Update an existing solution article.

        Parameters:
            article_id (int): Article ID
            folder_id (int): Folder ID
            title (str): Article title
            body (str): Article body
            status (int): Status
            is_enabled_for_self_service (bool): Enable for self service
            category_id (int): Category ID
            workspace_id (int): Workspace ID
        """
        article_id = request.parameters['article_id']
        params = self._build_query_params(request.parameters, [
            'folder_id', 'title', 'body', 'status', 'is_enabled_for_self_service',
            'category_id', 'workspace_id'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/articles/{article_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_solution_article(self, request: RequestBody) -> ResponseBody:
        """
        Delete a solution article.

        Parameters:
            article_id (int): Article ID
        """
        article_id = request.parameters['article_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/articles/{article_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def restore_solution_article(self, request: RequestBody) -> ResponseBody:
        """
        Restore a deleted solution article.

        Parameters:
            article_id (int): Article ID
        """
        article_id = request.parameters['article_id']
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/articles/{article_id}/restore',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def bulk_restore_solution_articles(self, request: RequestBody) -> ResponseBody:
        """
        Restore multiple solution articles from trash.

        Parameters:
            ids (str): Comma-separated list of article IDs
        """
        article_ids = request.parameters.get('ids')
        if not article_ids:
            return {
                "status": "error",
                "message": "ids parameter is required"
            }
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/articles/bulk_restore?ids={article_ids}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # CAB (Change Advisory Board) Operations
    # =========================================================

    def get_cabs(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of CABs (Change Advisory Boards).

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            include (str): Comma-separated list of includes (member_details)
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'cabs',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_cab_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single CAB by ID.

        Parameters:
            cab_id (int): CAB ID
            include (str): Comma-separated list of includes (member_details)
        """
        cab_id = request.parameters['cab_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'cabs/{cab_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_cab(self, request: RequestBody) -> ResponseBody:
        """
        Create a new CAB.

        Parameters:
            name (str): CAB name
            description (str): CAB description
            members (list): Array of member IDs
        """
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'members'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'cabs',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_cab(self, request: RequestBody) -> ResponseBody:
        """
        Update an existing CAB.

        Parameters:
            cab_id (int): CAB ID
            name (str): CAB name
            description (str): CAB description
            members (list): Array of member IDs
        """
        cab_id = request.parameters['cab_id']
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'members'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'cabs/{cab_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_cab(self, request: RequestBody) -> ResponseBody:
        """
        Delete a CAB.

        Parameters:
            cab_id (int): CAB ID
        """
        cab_id = request.parameters['cab_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'cabs/{cab_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Change Operations
    # =========================================================

    def get_changes(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of changes.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            order_by (str): Order by field (priority, created_at, etc.)
            order_type (str): Order type (asc/desc)
            view (str): View name (my_open, all, completed, etc.)
            updated_since (str): Filter by updated timestamp
            workspace_id (int): Filter by workspace ID
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'order_by', 'order_type', 'view',
            'updated_since', 'workspace_id', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'changes',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_change_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single change by ID.

        Parameters:
            change_id (int): Change ID
            include (str): Comma-separated list of includes (stats)
        """
        change_id = request.parameters['change_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'changes/{change_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_change(self, request: RequestBody) -> ResponseBody:
        """
        Create a new change.

        Parameters:
            subject (str): Change subject
            description (str): Change description
            priority (int): Priority (1=Low, 2=Medium, 3=High, 4=Urgent)
            status (int): Status (1=Approved, 2=Cancelled, 3=Implemented, 4=Reviewing, 5=Testing, 6=Scheduled, 7=Approved, 8=Rejected)
            cab_id (int): CAB ID
            start_time (str): Start time (ISO8601)
            end_time (str): End time (ISO8601)
           实施者_id (int): Implementer ID
            reviewer_id (int): Reviewer ID
            approval_status (int): Approval status
            workspace_id (int): Workspace ID
        """
        params = self._build_query_params(request.parameters, [
            'subject', 'description', 'priority', 'status', 'cab_id',
            'start_time', 'end_time', 'implementer_id', 'reviewer_id',
            'approval_status', 'workspace_id'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'changes',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_change(self, request: RequestBody) -> ResponseBody:
        """
        Update an existing change.

        Parameters:
            change_id (int): Change ID
            subject (str): Change subject
            description (str): Change description
            priority (int): Priority
            status (int): Status
            cab_id (int): CAB ID
            start_time (str): Start time
            end_time (str): End time
           实施者_id (int): Implementer ID
            reviewer_id (int): Reviewer ID
            approval_status (int): Approval status
        """
        change_id = request.parameters['change_id']
        params = self._build_query_params(request.parameters, [
            'subject', 'description', 'priority', 'status', 'cab_id',
            'start_time', 'end_time', 'implementer_id', 'reviewer_id',
            'approval_status'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'changes/{change_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_change(self, request: RequestBody) -> ResponseBody:
        """
        Delete a change.

        Parameters:
            change_id (int): Change ID
        """
        change_id = request.parameters['change_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'changes/{change_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Release Operations
    # =========================================================

    def get_releases(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of releases.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            filter_name (str): Filter name (all, my_open, unassigned, completed, etc.)
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'filter_name', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'releases',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_release_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single release by ID.

        Parameters:
            release_id (int): Release ID
            include (str): Comma-separated list of includes
        """
        release_id = request.parameters['release_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'releases/{release_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_release(self, request: RequestBody) -> ResponseBody:
        """
        Create a new release.

        Parameters:
            name (str): Release name
            description (str): Release description
            start_date (str): Start date (ISO8601)
            end_date (str): End date (ISO8601)
            status (str): Status (planned, in_progress, completed, cancelled)
            workspace_id (int): Workspace ID
        """
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'start_date', 'end_date', 'status', 'workspace_id'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'releases',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_release(self, request: RequestBody) -> ResponseBody:
        """
        Update an existing release.

        Parameters:
            release_id (int): Release ID
            name (str): Release name
            description (str): Release description
            start_date (str): Start date
            end_date (str): End date
            status (str): Status
            workspace_id (int): Workspace ID
        """
        release_id = request.parameters['release_id']
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'start_date', 'end_date', 'status', 'workspace_id'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'releases/{release_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_release(self, request: RequestBody) -> ResponseBody:
        """
        Delete a release.

        Parameters:
            release_id (int): Release ID
        """
        release_id = request.parameters['release_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'releases/{release_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Announcement Operations
    # =========================================================

    def get_announcements(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of announcements.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            state (str): Filter by state (archived, active, scheduled, unread)
            workspace_id (int): Filter by workspace ID
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'state', 'workspace_id', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'announcements',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_announcement_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single announcement by ID.

        Parameters:
            announcement_id (int): Announcement ID
            include (str): Comma-separated list of includes
        """
        announcement_id = request.parameters['announcement_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'announcements/{announcement_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_announcement(self, request: RequestBody) -> ResponseBody:
        """
        Create a new announcement.

        Parameters:
            subject (str): Announcement subject
            description (str): Announcement description
            state (str): State (active, scheduled, archived)
            start_time (str): Start time (ISO8601)
            end_time (str): End time (ISO8601)
            visibility (str): Visibility (all, logged_in_users, agents)
            workspace_id (int): Workspace ID
        """
        params = self._build_query_params(request.parameters, [
            'subject', 'description', 'state', 'start_time', 'end_time',
            'visibility', 'workspace_id'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'announcements',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_announcement(self, request: RequestBody) -> ResponseBody:
        """
        Update an existing announcement.

        Parameters:
            announcement_id (int): Announcement ID
            subject (str): Announcement subject
            description (str): Announcement description
            state (str): State
            start_time (str): Start time
            end_time (str): End time
            visibility (str): Visibility
            workspace_id (int): Workspace ID
        """
        announcement_id = request.parameters['announcement_id']
        params = self._build_query_params(request.parameters, [
            'subject', 'description', 'state', 'start_time', 'end_time',
            'visibility', 'workspace_id'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'announcements/{announcement_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_announcement(self, request: RequestBody) -> ResponseBody:
        """
        Delete an announcement.

        Parameters:
            announcement_id (int): Announcement ID
        """
        announcement_id = request.parameters['announcement_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'announcements/{announcement_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Application Management Operations
    # =========================================================

    def get_applications(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of applications (software).

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            workspace_id (int): Filter by workspace ID
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'workspace_id', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'applications',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_application_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single application by ID.

        Parameters:
            application_id (int): Application ID
            include (str): Comma-separated list of includes
        """
        application_id = request.parameters['application_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'applications/{application_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # SLA Policy Operations
    # =========================================================

    def get_sla_policies(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of SLA policies.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            workspace_id (int): Filter by workspace ID
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'workspace_id', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'sla_policies',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_sla_policy_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single SLA policy by ID.

        Parameters:
            sla_policy_id (int): SLA policy ID
            include (str): Comma-separated list of includes
        """
        sla_policy_id = request.parameters['sla_policy_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'sla_policies/{sla_policy_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Contract Operations
    # =========================================================

    def get_contracts(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of contracts.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            workspace_id (int): Filter by workspace ID
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'workspace_id', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'contracts',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_contract_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single contract by ID.

        Parameters:
            contract_id (int): Contract ID
            include (str): Comma-separated list of includes
        """
        contract_id = request.parameters['contract_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'contracts/{contract_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Canned Response Operations
    # =========================================================

    def get_canned_responses(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of canned responses.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            workspace_id (int): Filter by workspace ID
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'workspace_id', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'canned_responses',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_canned_response_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single canned response by ID.

        Parameters:
            canned_response_id (int): Canned response ID
            include (str): Comma-separated list of includes
        """
        canned_response_id = request.parameters['canned_response_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'canned_responses/{canned_response_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_canned_response_folders(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of canned response folders.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            workspace_id (int): Filter by workspace ID
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'workspace_id', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'canned_response_folders',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_canned_response_folder_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single canned response folder by ID.

        Parameters:
            folder_id (int): Folder ID
            include (str): Comma-separated list of includes
        """
        folder_id = request.parameters['folder_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'canned_response_folders/{folder_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # User Field Operations
    # =========================================================

    def get_agent_fields(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of agent fields.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            include (str): Comma-separated list of includes (user_field_groups)
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'agent_fields',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_agent_field_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single agent field by ID.

        Parameters:
            field_id (int): Field ID
            include (str): Comma-separated list of includes
        """
        field_id = request.parameters['field_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'agent_fields/{field_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_requester_fields(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of requester fields.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            include (str): Comma-separated list of includes (user_field_groups)
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'requester_fields',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_requester_field_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single requester field by ID.

        Parameters:
            field_id (int): Field ID
            include (str): Comma-separated list of includes
        """
        field_id = request.parameters['field_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'requester_fields/{field_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Service Item Operations
    # =========================================================

    def get_service_items(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of service items.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            category_id (int): Filter by category ID
            workspace_id (int): Filter by workspace ID
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'category_id', 'workspace_id', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'service_catalog/items',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_service_item_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single service item by ID.

        Parameters:
            item_id (int): Item ID
            include (str): Comma-separated list of includes
        """
        item_id = request.parameters['item_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'service_catalog/items/{item_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Service Request Operations
    # =========================================================

    def get_service_requests(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of service requests.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            service_item_id (int): Filter by service item ID
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'service_item_id', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'service_requests',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_service_request_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single service request by ID.

        Parameters:
            service_request_id (int): Service request ID
            include (str): Comma-separated list of includes
        """
        service_request_id = request.parameters['service_request_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'service_requests/{service_request_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def add_service_request_item(self, request: RequestBody) -> ResponseBody:
        """
        Add a catalog item to an existing service request.

        Parameters:
            service_request_id (int): Service request ID
            service_item_id (int): Service item ID
            quantity (int): Quantity
        """
        service_request_id = request.parameters['service_request_id']
        params = self._build_query_params(request.parameters, [
            'service_item_id', 'quantity'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'service_requests/{service_request_id}/items',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def cancel_service_request(self, request: RequestBody) -> ResponseBody:
        """
        Cancel a service request.

        Parameters:
            service_request_id (int): Service request ID
        """
        service_request_id = request.parameters['service_request_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'service_requests/{service_request_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Approval Operations
    # =========================================================

    def get_approvals(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of approvals.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            status (str): Filter by status (pending, approved, rejected)
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'status', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'approvals',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_approval_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single approval by ID.

        Parameters:
            approval_id (int): Approval ID
            include (str): Comma-separated list of includes
        """
        approval_id = request.parameters['approval_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'approvals/{approval_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def approve_request(self, request: RequestBody) -> ResponseBody:
        """
        Approve a request.

        Parameters:
            approval_id (int): Approval ID
            comments (str): Approval comments
        """
        approval_id = request.parameters['approval_id']
        params = self._build_query_params(request.parameters, ['comments'])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'approvals/{approval_id}/approve',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def reject_request(self, request: RequestBody) -> ResponseBody:
        """
        Reject a request.

        Parameters:
            approval_id (int): Approval ID
            comments (str): Rejection comments
        """
        approval_id = request.parameters['approval_id']
        params = self._build_query_params(request.parameters, ['comments'])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'approvals/{approval_id}/reject',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Delegation Operations
    # =========================================================

    def get_delegations(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of delegations.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'delegations',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_delegation_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single delegation by ID.

        Parameters:
            delegation_id (int): Delegation ID
            include (str): Comma-separated list of includes
        """
        delegation_id = request.parameters['delegation_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'delegations/{delegation_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_delegation(self, request: RequestBody) -> ResponseBody:
        """
        Create a new delegation.

        Parameters:
            delegatee_id (int): Delegatee ID
            start_date (str): Start date (ISO8601)
            end_date (str): End date (ISO8601)
            permissions (list): Permissions to delegate
        """
        params = self._build_query_params(request.parameters, [
            'delegatee_id', 'start_date', 'end_date', 'permissions'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'delegations',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_delegation(self, request: RequestBody) -> ResponseBody:
        """
        Update an existing delegation.

        Parameters:
            delegation_id (int): Delegation ID
            delegatee_id (int): Delegatee ID
            start_date (str): Start date
            end_date (str): End date
            permissions (list): Permissions
        """
        delegation_id = request.parameters['delegation_id']
        params = self._build_query_params(request.parameters, [
            'delegatee_id', 'start_date', 'end_date', 'permissions'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'delegations/{delegation_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_delegation(self, request: RequestBody) -> ResponseBody:
        """
        Delete a delegation.

        Parameters:
            delegation_id (int): Delegation ID
        """
        delegation_id = request.parameters['delegation_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'delegations/{delegation_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Journeys Operations
    # =========================================================

    def get_journey_requests(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of journey requests.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            filter_name (str): Filter name (all, in_progress, completed, etc.)
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'filter_name', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'journeys/requests',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_journey_request_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single journey request by ID.

        Parameters:
            journey_request_id (int): Journey request ID
            include (str): Comma-separated list of includes
        """
        journey_request_id = request.parameters['journey_request_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'journeys/requests/{journey_request_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_journey_request(self, request: RequestBody) -> ResponseBody:
        """
        Create a new journey request.

        Parameters:
            journey_id (int): Journey ID
            requester_id (int): Requester ID
            journey_data (dict): Journey data fields
        """
        params = self._build_query_params(request.parameters, [
            'journey_id', 'requester_id', 'journey_data'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'journeys/requests',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def cancel_journey_request(self, request: RequestBody) -> ResponseBody:
        """
        Cancel a journey request.

        Parameters:
            journey_request_id (int): Journey request ID
        """
        journey_request_id = request.parameters['journey_request_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'journeys/requests/{journey_request_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Project Management Operations
    # =========================================================

    def get_pm_projects(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of project management projects.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            workspace_id (int): Filter by workspace ID
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'workspace_id', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'pm/projects',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_pm_project_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single project management project by ID.

        Parameters:
            project_id (int): Project ID
            include (str): Comma-separated list of includes
        """
        project_id = request.parameters['project_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'pm/projects/{project_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_pm_project(self, request: RequestBody) -> ResponseBody:
        """
        Create a new project management project.

        Parameters:
            name (str): Project name
            description (str): Project description
            start_date (str): Start date (ISO8601)
            end_date (str): End date (ISO8601)
            workspace_id (int): Workspace ID
        """
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'start_date', 'end_date', 'workspace_id'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'pm/projects',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_pm_project(self, request: RequestBody) -> ResponseBody:
        """
        Update an existing project management project.

        Parameters:
            project_id (int): Project ID
            name (str): Project name
            description (str): Project description
            start_date (str): Start date
            end_date (str): End date
            workspace_id (int): Workspace ID
        """
        project_id = request.parameters['project_id']
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'start_date', 'end_date', 'workspace_id'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'pm/projects/{project_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_pm_project(self, request: RequestBody) -> ResponseBody:
        """
        Delete a project management project.

        Parameters:
            project_id (int): Project ID
        """
        project_id = request.parameters['project_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'pm/projects/{project_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_pm_tasks(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of project management tasks.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            project_id (int): Filter by project ID
            parent_id (int): Filter by parent task ID
            include (str): Comma-separated list of includes
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'project_id', 'parent_id', 'include'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'pm/tasks',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_pm_task_by_id(self, request: RequestBody) -> ResponseBody:
        """
        Get a single project management task by ID.

        Parameters:
            task_id (int): Task ID
            include (str): Comma-separated list of includes
        """
        task_id = request.parameters['task_id']
        params = self._build_query_params(request.parameters, ['include'])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'pm/tasks/{task_id}',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_pm_task(self, request: RequestBody) -> ResponseBody:
        """
        Create a new project management task.

        Parameters:
            project_id (int): Project ID
            parent_id (int): Parent task ID
            name (str): Task name
            description (str): Task description
            start_date (str): Start date (ISO8601)
            end_date (str): End date (ISO8601)
            status (int): Status
        """
        params = self._build_query_params(request.parameters, [
            'project_id', 'parent_id', 'name', 'description', 'start_date',
            'end_date', 'status'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'pm/tasks',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_pm_task(self, request: RequestBody) -> ResponseBody:
        """
        Update an existing project management task.

        Parameters:
            task_id (int): Task ID
            name (str): Task name
            description (str): Task description
            start_date (str): Start date
            end_date (str): End date
            status (int): Status
        """
        task_id = request.parameters['task_id']
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'start_date', 'end_date', 'status'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'pm/tasks/{task_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_pm_task(self, request: RequestBody) -> ResponseBody:
        """
        Delete a project management task.

        Parameters:
            task_id (int): Task ID
        """
        task_id = request.parameters['task_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'pm/tasks/{task_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Audit Log Operations
    # =========================================================

    def get_audit_logs(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of audit logs.

        Parameters:
            cursor (str): Cursor for pagination
            per_page (int): Results per page
            start_time (str): Start time (ISO8601)
            end_time (str): End time (ISO8601)
            type (str): Filter by type
            user_id (int): Filter by user ID
        """
        params = self._build_query_params(request.parameters, [
            'cursor', 'per_page', 'start_time', 'end_time', 'type', 'user_id'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'audits',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Service Catalog Management (Additional) - 12 endpoints
    # =========================================================

    def create_service_catalog_item(self, request: RequestBody) -> ResponseBody:
        """
        Create a new service catalog item.

        Parameters:
            display_id (str): Display ID
            name (str): Item name (required)
            description (str): Item description
            category_id (int): Category ID
            visibility (str): Visibility (all, logged_in_users, agents)
            workspace_id (int): Workspace ID
        """
        params = self._build_query_params(request.parameters, [
            'display_id', 'name', 'description', 'category_id', 'visibility', 'workspace_id'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'service_catalog/items',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_service_catalog_item(self, request: RequestBody) -> ResponseBody:
        """
        Update an existing service catalog item.

        Parameters:
            display_id (str): Display ID
            name (str): Item name
            description (str): Item description
            category_id (int): Category ID
            visibility (str): Visibility
        """
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'category_id', 'visibility'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'service_catalog/items/{request.parameters.get("display_id")}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_service_catalog_item(self, request: RequestBody) -> ResponseBody:
        """
        Delete a service catalog item.

        Parameters:
            display_id (str): Display ID
        """
        display_id = request.parameters['display_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'service_catalog/items/{display_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def place_service_catalog_request(self, request: RequestBody) -> ResponseBody:
        """
        Place a service catalog request.

        Parameters:
            display_id (str): Display ID (required)
            requester_id (int): Requester ID
            requested_for (str): Requested for (email or ID)
            variables (dict): Variable values
        """
        display_id = request.parameters['display_id']
        params = self._build_query_params(request.parameters, [
            'requester_id', 'requested_for', 'variables'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'service_catalog/items/{display_id}/place_request',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def archive_service_catalog_shared_field(self, request: RequestBody) -> ResponseBody:
        """
        Archive a service catalog shared field.

        Parameters:
            id (int): Shared field ID (required)
        """
        field_id = request.parameters['id']
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'service-catalog/shared-fields/{field_id}/archive',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def unarchive_service_catalog_shared_field(self, request: RequestBody) -> ResponseBody:
        """
        Unarchive a service catalog shared field.

        Parameters:
            id (int): Shared field ID (required)
        """
        field_id = request.parameters['id']
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'service-catalog/shared-fields/{field_id}/unarchive',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_service_catalog_shared_field(self, request: RequestBody) -> ResponseBody:
        """
        Create a new service catalog shared field.

        Parameters:
            name (str): Field name (required)
            type (str): Field type
            description (str): Field description
            required (bool): Is required
            visible (bool): Is visible
            enabled (bool): Is enabled
        """
        params = self._build_query_params(request.parameters, [
            'name', 'type', 'description', 'required', 'visible', 'enabled'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'service-catalog/shared-fields',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_service_catalog_shared_field(self, request: RequestBody) -> ResponseBody:
        """
        Update an existing service catalog shared field.

        Parameters:
            id (int): Shared field ID (required)
            name (str): Field name
            type (str): Field type
            description (str): Field description
            required (bool): Is required
            visible (bool): Is visible
            enabled (bool): Is enabled
        """
        field_id = request.parameters['id']
        params = self._build_query_params(request.parameters, [
            'name', 'type', 'description', 'required', 'visible', 'enabled'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'service-catalog/shared-fields/{field_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_service_catalog_shared_field(self, request: RequestBody) -> ResponseBody:
        """
        Delete a service catalog shared field.

        Parameters:
            id (int): Shared field ID (required)
        """
        field_id = request.parameters['id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'service-catalog/shared-fields/{field_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_service_catalog_shared_fields(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of service catalog shared fields.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'service-catalog/shared-fields',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_service_item(self, request: RequestBody) -> ResponseBody:
        """
        Delete a service item.

        Parameters:
            service_item_id (int): Service item ID (required)
        """
        service_item_id = request.parameters['service_item_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'service-catalog/items/{service_item_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_service_item(self, request: RequestBody) -> ResponseBody:
        """
        Update an existing service item.

        Parameters:
            service_item_id (int): Service item ID (required)
            display_id (str): Display ID
            name (str): Service item name
            description (str): Service item description
            category_id (int): Category ID
        """
        service_item_id = request.parameters['service_item_id']
        params = self._build_query_params(request.parameters, [
            'display_id', 'name', 'description', 'category_id'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'service-catalog/items/{service_item_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Solution Management Enhancements - 8 endpoints
    # =========================================================

    def get_solution_folder_subfolders(self, request: RequestBody) -> ResponseBody:
        """
        Get subfolders of a solution folder.

        Parameters:
            folder_id (int): Folder ID (required)
            page (int): Page number
            per_page (int): Results per page
        """
        folder_id = request.parameters['folder_id']
        params = self._build_query_params(request.parameters, [
            'page', 'per_page'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/folders/{folder_id}/sub-folders',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_solution_subfolder(self, request: RequestBody) -> ResponseBody:
        """
        Create a new subfolder under a solution folder.

        Parameters:
            folder_id (int): Parent folder ID (required)
            name (str): Subfolder name (required)
            description (str): Subfolder description
            visibility (str): Visibility (all, logged_in_users, agents)
            category_id (int): Category ID
        """
        folder_id = request.parameters['folder_id']
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'visibility', 'category_id'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/folders/{folder_id}/sub-folders',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_solution_subfolder(self, request: RequestBody) -> ResponseBody:
        """
        Delete a solution subfolder.

        Parameters:
            folder_id (int): Parent folder ID (required)
            subfolder_id (int): Subfolder ID (required)
        """
        folder_id = request.parameters['folder_id']
        subfolder_id = request.parameters['subfolder_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/folders/{folder_id}/sub-folders/{subfolder_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def restore_solution_subfolder(self, request: RequestBody) -> ResponseBody:
        """
        Restore a deleted solution subfolder.

        Parameters:
            folder_id (int): Parent folder ID (required)
            subfolder_id (int): Subfolder ID (required)
        """
        folder_id = request.parameters['folder_id']
        subfolder_id = request.parameters['subfolder_id']
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/folders/{folder_id}/restore',
            data={'subfolder_id': subfolder_id},
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def send_solution_article_for_approval(self, request: RequestBody) -> ResponseBody:
        """
        Send a solution article for approval.

        Parameters:
            article_id (int): Article ID (required)
            folder_id (int): Folder ID (required)
            approver_ids (list): Array of approver IDs
            message (str): Approval message
        """
        article_id = request.parameters['article_id']
        folder_id = request.parameters['folder_id']
        params = self._build_query_params(request.parameters, [
            'folder_id', 'approver_ids', 'message'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/articles/{article_id}/send_for_approval',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_solution_article_forever(self, request: RequestBody) -> ResponseBody:
        """
        Delete a solution article forever (permanently).

        Parameters:
            article_id (int): Article ID (required)
        """
        article_id = request.parameters['article_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/articles/{article_id}/delete_forever',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_solution_category_forever(self, request: RequestBody) -> ResponseBody:
        """
        Delete a solution category forever (permanently).

        Parameters:
            category_id (int): Category ID (required)
        """
        category_id = request.parameters['category_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/categories/{category_id}/delete_forever',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def bulk_restore_solution_articles_alternate(self, request: RequestBody) -> ResponseBody:
        """
        Bulk restore solution articles from trash.

        Parameters:
            ids (str): Comma-separated list of article IDs (required)
        """
        article_ids = request.parameters.get('ids')
        if not article_ids:
            return {
                "status": "error",
                "message": "ids parameter is required"
            }
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'solutions/articles/bulk_restore?ids={article_ids}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # CAB Management - 10 endpoints
    # =========================================================

    def create_cab_approval(self, request: RequestBody) -> ResponseBody:
        """
        Create a CAB approval.

        Parameters:
            cab_id (int): CAB ID (required)
            change_id (int): Change ID (required)
            member_ids (list): Array of member IDs
            due_by (str): Due date (ISO8601)
        """
        cab_id = request.parameters['cab_id']
        params = self._build_query_params(request.parameters, [
            'change_id', 'member_ids', 'due_by'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'cabs/{cab_id}/approvals',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_cab_approval(self, request: RequestBody) -> ResponseBody:
        """
        Update a CAB approval.

        Parameters:
            cab_id (int): CAB ID (required)
            approval_id (int): Approval ID (required)
            due_by (str): Due date (ISO8601)
        """
        cab_id = request.parameters['cab_id']
        approval_id = request.parameters['approval_id']
        params = self._build_query_params(request.parameters, ['due_by'])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'cabs/{cab_id}/approvals/{approval_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_cab_approval(self, request: RequestBody) -> ResponseBody:
        """
        Delete a CAB approval.

        Parameters:
            cab_id (int): CAB ID (required)
            approval_id (int): Approval ID (required)
        """
        cab_id = request.parameters['cab_id']
        approval_id = request.parameters['approval_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'cabs/{cab_id}/approvals/{approval_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def add_cab_member(self, request: RequestBody) -> ResponseBody:
        """
        Add a member to a CAB.

        Parameters:
            cab_id (int): CAB ID (required)
            member_id (int): Member ID (required)
        """
        cab_id = request.parameters['cab_id']
        member_id = request.parameters['member_id']
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'cabs/{cab_id}/members',
            data={'member_id': member_id},
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def remove_cab_member(self, request: RequestBody) -> ResponseBody:
        """
        Remove a member from a CAB.

        Parameters:
            cab_id (int): CAB ID (required)
            member_id (int): Member ID (required)
        """
        cab_id = request.parameters['cab_id']
        member_id = request.parameters['member_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'cabs/{cab_id}/members/{member_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_cab_templates(self, request: RequestBody) -> ResponseBody:
        """
        Get CAB templates.

        Parameters:
            cab_id (int): CAB ID (required)
        """
        cab_id = request.parameters['cab_id']
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'cabs/{cab_id}/templates',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_cab_template(self, request: RequestBody) -> ResponseBody:
        """
        Create a CAB template.

        Parameters:
            cab_id (int): CAB ID (required)
            name (str): Template name (required)
            description (str): Template description
            member_ids (list): Array of member IDs
        """
        cab_id = request.parameters['cab_id']
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'member_ids'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'cabs/{cab_id}/templates',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_cab_template(self, request: RequestBody) -> ResponseBody:
        """
        Update a CAB template.

        Parameters:
            cab_id (int): CAB ID (required)
            template_id (int): Template ID (required)
            name (str): Template name
            description (str): Template description
            member_ids (list): Array of member IDs
        """
        cab_id = request.parameters['cab_id']
        template_id = request.parameters['template_id']
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'member_ids'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'cabs/{cab_id}/templates/{template_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_cab_template(self, request: RequestBody) -> ResponseBody:
        """
        Delete a CAB template.

        Parameters:
            cab_id (int): CAB ID (required)
            template_id (int): Template ID (required)
        """
        cab_id = request.parameters['cab_id']
        template_id = request.parameters['template_id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'cabs/{cab_id}/templates/{template_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def cast_cab_vote(self, request: RequestBody) -> ResponseBody:
        """
        Cast a vote in a CAB approval.

        Parameters:
            cab_id (int): CAB ID (required)
            approval_id (int): Approval ID (required)
            vote (str): Vote (approve/reject) (required)
            comments (str): Vote comments
        """
        cab_id = request.parameters['cab_id']
        approval_id = request.parameters['approval_id']
        params = self._build_query_params(request.parameters, [
            'vote', 'comments'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'cabs/{cab_id}/votes',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Change Management Enhancements - 9 endpoints
    # =========================================================

    def get_change_approvals(self, request: RequestBody) -> ResponseBody:
        """
        Get change approvals.

        Parameters:
            change_id (int): Change ID (required)
        """
        change_id = request.parameters['change_id']
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'changes/{change_id}/approvals',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_change_approval(self, request: RequestBody) -> ResponseBody:
        """
        Create a change approval.

        Parameters:
            change_id (int): Change ID (required)
            member_ids (list): Array of member IDs
            due_by (str): Due date (ISO8601)
        """
        change_id = request.parameters['change_id']
        params = self._build_query_params(request.parameters, [
            'member_ids', 'due_by'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'changes/{change_id}/approvals',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_change_approval_groups(self, request: RequestBody) -> ResponseBody:
        """
        Get change approval groups.

        Parameters:
            change_id (int): Change ID (required)
        """
        change_id = request.parameters['change_id']
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'changes/{change_id}/approval-groups',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_change_approval_group(self, request: RequestBody) -> ResponseBody:
        """
        Create a change approval group.

        Parameters:
            change_id (int): Change ID (required)
            group_id (int): Group ID (required)
        """
        change_id = request.parameters['change_id']
        group_id = request.parameters['group_id']
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'changes/{change_id}/approval-groups',
            data={'group_id': group_id},
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_change_approval_chain(self, request: RequestBody) -> ResponseBody:
        """
        Get change approval chain.

        Parameters:
            change_id (int): Change ID (required)
        """
        change_id = request.parameters['change_id']
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'changes/{change_id}/approval-chain-rule',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_change_approval_chain(self, request: RequestBody) -> ResponseBody:
        """
        Create a change approval chain.

        Parameters:
            change_id (int): Change ID (required)
            approval_sequence (dict): Approval sequence configuration
        """
        change_id = request.parameters['change_id']
        params = self._build_query_params(request.parameters, ['approval_sequence'])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'changes/{change_id}/approval-chain-rule',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_problem_form_fields(self, request: RequestBody) -> ResponseBody:
        """
        Get problem form fields.

        Parameters:
            None
        """
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'problem_form_fields',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_problem_tasks(self, request: RequestBody) -> ResponseBody:
        """
        Get problem tasks.

        Parameters:
            problem_id (int): Problem ID (required)
            page (int): Page number
            per_page (int): Results per page
        """
        problem_id = request.parameters['problem_id']
        params = self._build_query_params(request.parameters, [
            'page', 'per_page'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'problems/{problem_id}/tasks',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_problem_task(self, request: RequestBody) -> ResponseBody:
        """
        Create a problem task.

        Parameters:
            problem_id (int): Problem ID (required)
            title (str): Task title (required)
            description (str): Task description
            status (int): Task status
            due_by (str): Due date (ISO8601)
        """
        problem_id = request.parameters['problem_id']
        params = self._build_query_params(request.parameters, [
            'title', 'description', 'status', 'due_by'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'problems/{problem_id}/tasks',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Release Management - 10 endpoints
    # =========================================================

    def get_release_tasks(self, request: RequestBody) -> ResponseBody:
        """
        Get release tasks.

        Parameters:
            release_id (int): Release ID (required)
            page (int): Page number
            per_page (int): Results per page
        """
        release_id = request.parameters['release_id']
        params = self._build_query_params(request.parameters, [
            'page', 'per_page'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'releases/{release_id}/tasks',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_release_task(self, request: RequestBody) -> ResponseBody:
        """
        Create a release task.

        Parameters:
            release_id (int): Release ID (required)
            title (str): Task title (required)
            description (str): Task description
            status (int): Task status
            due_by (str): Due date (ISO8601)
        """
        release_id = request.parameters['release_id']
        params = self._build_query_params(request.parameters, [
            'title', 'description', 'status', 'due_by'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'releases/{release_id}/tasks',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_release_notes(self, request: RequestBody) -> ResponseBody:
        """
        Get release notes.

        Parameters:
            release_id (int): Release ID (required)
            page (int): Page number
            per_page (int): Results per page
        """
        release_id = request.parameters['release_id']
        params = self._build_query_params(request.parameters, [
            'page', 'per_page'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'releases/{release_id}/notes',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def add_release_note(self, request: RequestBody) -> ResponseBody:
        """
        Add a release note.

        Parameters:
            release_id (int): Release ID (required)
            body (str): Note body (required)
            private (bool): Is private note
        """
        release_id = request.parameters['release_id']
        params = self._build_query_params(request.parameters, [
            'body', 'private'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'releases/{release_id}/notes',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_release_time_entries(self, request: RequestBody) -> ResponseBody:
        """
        Get release time entries.

        Parameters:
            release_id (int): Release ID (required)
            page (int): Page number
            per_page (int): Results per page
        """
        release_id = request.parameters['release_id']
        params = self._build_query_params(request.parameters, [
            'page', 'per_page'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'releases/{release_id}/time_entries',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def add_release_time_entry(self, request: RequestBody) -> ResponseBody:
        """
        Add a release time entry.

        Parameters:
            release_id (int): Release ID (required)
            hours (float): Hours spent (required)
            notes (str): Time entry notes
            spent_date (str): Spent date (ISO8601)
        """
        release_id = request.parameters['release_id']
        params = self._build_query_params(request.parameters, [
            'hours', 'notes', 'spent_date'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'releases/{release_id}/time_entries',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def move_release_workspace(self, request: RequestBody) -> ResponseBody:
        """
        Move a release to a different workspace.

        Parameters:
            release_id (int): Release ID (required)
            workspace_id (int): Workspace ID (required)
        """
        release_id = request.parameters['release_id']
        workspace_id = request.parameters['workspace_id']
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'releases/{release_id}/move_workspace',
            data={'workspace_id': workspace_id},
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def restore_release(self, request: RequestBody) -> ResponseBody:
        """
        Restore a deleted release.

        Parameters:
            release_id (int): Release ID (required)
        """
        release_id = request.parameters['release_id']
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'releases/{release_id}/restore',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_release_form_fields(self, request: RequestBody) -> ResponseBody:
        """
        Get release form fields.

        Parameters:
            None
        """
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'release_form_fields',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_sla_breach(self, request: RequestBody) -> ResponseBody:
        """
        Update an SLA breach.

        Parameters:
            id (int): SLA breach ID (required)
            resolution_notes (str): Resolution notes
            resolved_at (str): Resolved timestamp (ISO8601)
        """
        breach_id = request.parameters['id']
        params = self._build_query_params(request.parameters, [
            'resolution_notes', 'resolved_at'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'sla_breaches/{breach_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Group & Department Management - 12 endpoints
    # =========================================================

    def get_groups(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of groups.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'groups',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_group(self, request: RequestBody) -> ResponseBody:
        """
        Create a new group.

        Parameters:
            name (str): Group name (required)
            description (str): Group description
            member_ids (list): Array of member IDs
            email (str): Group email
        """
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'member_ids', 'email'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'groups',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_group(self, request: RequestBody) -> ResponseBody:
        """
        Update an existing group.

        Parameters:
            id (int): Group ID (required)
            name (str): Group name
            description (str): Group description
            member_ids (list): Array of member IDs
            email (str): Group email
        """
        group_id = request.parameters['id']
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'member_ids', 'email'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'groups/{group_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_group(self, request: RequestBody) -> ResponseBody:
        """
        Delete a group.

        Parameters:
            id (int): Group ID (required)
        """
        group_id = request.parameters['id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'groups/{group_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_requester_groups(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of requester groups.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'requester_groups',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_requester_group(self, request: RequestBody) -> ResponseBody:
        """
        Create a new requester group.

        Parameters:
            name (str): Group name (required)
            description (str): Group description
            requester_ids (list): Array of requester IDs
        """
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'requester_ids'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'requester_groups',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_requester_group(self, request: RequestBody) -> ResponseBody:
        """
        Update an existing requester group.

        Parameters:
            id (int): Group ID (required)
            name (str): Group name
            description (str): Group description
            requester_ids (list): Array of requester IDs
        """
        group_id = request.parameters['id']
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'requester_ids'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'requester_groups/{group_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_requester_group(self, request: RequestBody) -> ResponseBody:
        """
        Delete a requester group.

        Parameters:
            id (int): Group ID (required)
        """
        group_id = request.parameters['id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'requester_groups/{group_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_departments(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of departments.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
            query (str): Query for filtering
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page', 'query'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'departments',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_department(self, request: RequestBody) -> ResponseBody:
        """
        Create a new department.

        Parameters:
            name (str): Department name (required)
            description (str): Department description
            email (str): Department email
            parent_id (int): Parent department ID
        """
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'email', 'parent_id'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'departments',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_department(self, request: RequestBody) -> ResponseBody:
        """
        Update an existing department.

        Parameters:
            id (int): Department ID (required)
            name (str): Department name
            description (str): Department description
            email (str): Department email
            parent_id (int): Parent department ID
        """
        department_id = request.parameters['id']
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'email', 'parent_id'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'departments/{department_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_department(self, request: RequestBody) -> ResponseBody:
        """
        Delete a department.

        Parameters:
            id (int): Department ID (required)
        """
        department_id = request.parameters['id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'departments/{department_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Product/Vendor Operations - 6 endpoints
    # =========================================================

    def get_products(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of products.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'products',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_product(self, request: RequestBody) -> ResponseBody:
        """
        Create a new product.

        Parameters:
            name (str): Product name (required)
            description (str): Product description
            vendor_id (int): Vendor ID
            category (str): Product category
        """
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'vendor_id', 'category'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'products',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def update_product(self, request: RequestBody) -> ResponseBody:
        """
        Update an existing product.

        Parameters:
            id (int): Product ID (required)
            name (str): Product name
            description (str): Product description
            vendor_id (int): Vendor ID
            category (str): Product category
        """
        product_id = request.parameters['id']
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'vendor_id', 'category'
        ])
        return self._make_request(
            'PUT',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'products/{product_id}',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def delete_product(self, request: RequestBody) -> ResponseBody:
        """
        Delete a product.

        Parameters:
            id (int): Product ID (required)
        """
        product_id = request.parameters['id']
        return self._make_request(
            'DELETE',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            f'products/{product_id}',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_vendors(self, request: RequestBody) -> ResponseBody:
        """
        Get a paginated list of vendors.

        Parameters:
            page (int): Page number
            per_page (int): Results per page
        """
        params = self._build_query_params(request.parameters, [
            'page', 'per_page'
        ])
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'vendors',
            params=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def create_vendor(self, request: RequestBody) -> ResponseBody:
        """
        Create a new vendor.

        Parameters:
            name (str): Vendor name (required)
            description (str): Vendor description
            website (str): Vendor website
            email (str): Vendor email
        """
        params = self._build_query_params(request.parameters, [
            'name', 'description', 'website', 'email'
        ])
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'vendors',
            data=params,
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Relationship Operations - 1 endpoint
    # =========================================================

    def bulk_create_relationships(self, request: RequestBody) -> ResponseBody:
        """
        Bulk create relationships.

        Parameters:
            relationships (list): Array of relationship objects with from_id, to_id, relationship_type_id
        """
        relationships = request.parameters.get('relationships')
        if not relationships:
            return {
                "status": "error",
                "message": "relationships parameter is required"
            }
        return self._make_request(
            'POST',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'relationships/bulk-create',
            data={'relationships': relationships},
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    # =========================================================
    # Additional Endpoints - 5 endpoints
    # =========================================================

    def get_all_tickets(self, request: RequestBody) -> ResponseBody:
        """
        Get all tickets with optional filtering.

        Parameters:
            Same as get_tickets
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

    def get_ticket_form_fields(self, request: RequestBody) -> ResponseBody:
        """
        Get ticket form fields.

        Parameters:
            None
        """
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'ticket_form_fields',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )

    def get_roles(self, request: RequestBody) -> ResponseBody:
        """
        Get a list of roles.

        Parameters:
            None
        """
        return self._make_request(
            'GET',
            request.connectionParameters['api_host'],
            request.connectionParameters['api_key'],
            'roles',
            verify_ssl=request.connectionParameters.get('verify_ssl', True)
        )
