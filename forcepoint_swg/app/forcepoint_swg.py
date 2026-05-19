from app.model.request_body import RequestBody
import logging
import requests


class ForcepointSwg():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    def _get_headers(self, api_key):
        return {
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

    def _get_connection(self, connection_params):
        base_url = connection_params['server_url'].rstrip('/')
        token_url = connection_params['token_url'].rstrip('/')
        api_key = connection_params['api_key']
        return base_url, token_url, api_key

    def _get_bearer_token(self, token_url, api_key):
        resp = requests.post(token_url, headers={"X-API-KEY": api_key}, timeout=30)
        if resp.status_code >= 300:
            raise Exception(f"Token generation failed: {resp.status_code} {resp.text}")
        return resp.json().get('token')

    # -------------------------------------------------------------------------
    # Test Connection
    # -------------------------------------------------------------------------
    def test_connection(self, connectionParameters: dict):
        try:
            base_url = connectionParameters['server_url'].rstrip('/')
            token_url = connectionParameters['token_url'].rstrip('/')
            api_key = connectionParameters['api_key']

            token = self._get_bearer_token(token_url, api_key)
            headers = self._get_headers(token)

            resp = requests.get(base_url, headers=headers, timeout=30)
            if resp.status_code in (401, 403):
                raise Exception(f"Authentication failed: {resp.status_code} {resp.text}")
            if resp.status_code >= 500:
                raise Exception(f"Server error: {resp.status_code} {resp.text}")
            return {'status': 'success', 'message': 'Connected to Forcepoint SWG successfully.'}
        except requests.exceptions.ConnectionError:
            raise Exception('Unable to connect to Forcepoint SWG. Please verify the Server URL.')
        except requests.exceptions.Timeout:
            raise Exception('Connection to Forcepoint SWG timed out.')
        except Exception as e:
            self.logger.error("Exception while testing connection", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Get All Custom Categories
    # -------------------------------------------------------------------------
    def get_all_custom_categories(self, request: RequestBody) -> dict:
        try:
            base_url, token_url, api_key = self._get_connection(request.connectionParameters)
            token = self._get_bearer_token(token_url, api_key)
            headers = self._get_headers(token)

            all_categories = []
            cursor = request.parameters.get('cursor', '')

            while True:
                params = {}
                if cursor:
                    params['cursor'] = cursor

                resp = requests.get(base_url, headers=headers, params=params, timeout=30)
                if resp.status_code >= 300:
                    raise Exception(resp.text)

                data = resp.json()
                categories = data.get('categories', [])
                all_categories.extend(categories)

                cursor = data.get('nextPageCursor')
                if not cursor:
                    break

            return {
                "status": "success",
                "message": "Categories retrieved successfully.",
                "totalResults": len(all_categories),
                "categories": all_categories
            }

        except Exception as e:
            self.logger.error("error while running action 'get_all_custom_categories'", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Create Category
    # -------------------------------------------------------------------------
    def create_category(self, request: RequestBody) -> dict:
        try:
            base_url, token_url, api_key = self._get_connection(request.connectionParameters)
            token = self._get_bearer_token(token_url, api_key)
            headers = self._get_headers(token)

            payload = {"name": request.parameters['name']}
            if request.parameters.get('description'):
                payload['description'] = request.parameters['description']
            if request.parameters.get('sites'):
                payload['sites'] = request.parameters['sites']
            if request.parameters.get('policyName'):
                payload['policyName'] = request.parameters['policyName']
            if request.parameters.get('comment'):
                payload['comment'] = request.parameters['comment']

            resp = requests.post(base_url, headers=headers, json=payload, timeout=30)
            if resp.status_code >= 300:
                raise Exception(resp.text)

            transaction_data = resp.json()
            return {
                "status": "success",
                "message": "Category creation request accepted.",
                "transactionId": transaction_data.get("transactionId"),
                "transactionStatus": transaction_data.get("status"),
                "data": transaction_data.get("data"),
                "comment": transaction_data.get("comment")
            }

        except Exception as e:
            self.logger.error("error while running action 'create_category'", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Get Category by ID
    # -------------------------------------------------------------------------
    def get_category_by_id(self, request: RequestBody) -> dict:
        try:
            base_url, token_url, api_key = self._get_connection(request.connectionParameters)
            token = self._get_bearer_token(token_url, api_key)
            headers = self._get_headers(token)

            category_id = request.parameters['categoryId']
            all_sites = []
            cursor = request.parameters.get('cursor', '')

            category_info = {}
            while True:
                params = {}
                if cursor:
                    params['cursor'] = cursor

                resp = requests.get(f"{base_url}/{category_id}", headers=headers, params=params, timeout=30)
                if resp.status_code >= 300:
                    raise Exception(resp.text)

                data = resp.json()
                if not category_info:
                    category_info = {
                        "id": data.get("id"),
                        "name": data.get("name"),
                        "description": data.get("description"),
                        "policyName": data.get("policyName")
                    }

                sites = data.get('sites', [])
                all_sites.extend(sites)

                cursor = data.get('nextPageCursor')
                if not cursor:
                    break

            category_info['sites'] = all_sites

            return {
                "status": "success",
                "message": "Category retrieved successfully.",
                "category": category_info
            }

        except Exception as e:
            self.logger.error("error while running action 'get_category_by_id'", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Add or Remove Category Sites
    # -------------------------------------------------------------------------
    def add_or_remove_category_sites(self, request: RequestBody) -> dict:
        try:
            base_url, token_url, api_key = self._get_connection(request.connectionParameters)
            token = self._get_bearer_token(token_url, api_key)
            headers = self._get_headers(token)

            category_id = request.parameters['categoryId']
            action = request.parameters['action']

            payload = {"sites": request.parameters['sites']}
            if request.parameters.get('comment'):
                payload['comment'] = request.parameters['comment']

            resp = requests.patch(
                f"{base_url}/{category_id}",
                headers=headers,
                json=payload,
                params={"action": action},
                timeout=30
            )
            if resp.status_code >= 300:
                raise Exception(resp.text)

            transaction_data = resp.json()
            return {
                "status": "success",
                "message": f"Sites {action} operation accepted.",
                "transactionId": transaction_data.get("transactionId"),
                "transactionStatus": transaction_data.get("status"),
                "data": transaction_data.get("data"),
                "comment": transaction_data.get("comment")
            }

        except Exception as e:
            self.logger.error("error while running action 'add_or_remove_category_sites'", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Delete Category
    # -------------------------------------------------------------------------
    def delete_category(self, request: RequestBody) -> dict:
        try:
            base_url, token_url, api_key = self._get_connection(request.connectionParameters)
            token = self._get_bearer_token(token_url, api_key)
            headers = self._get_headers(token)

            category_id = request.parameters['categoryId']

            resp = requests.delete(f"{base_url}/{category_id}", headers=headers, timeout=30)
            if resp.status_code >= 300:
                raise Exception(resp.text)

            transaction_data = resp.json()
            return {
                "status": "success",
                "message": "Category deletion request accepted.",
                "transactionId": transaction_data.get("transactionId"),
                "transactionStatus": transaction_data.get("status"),
                "data": transaction_data.get("data"),
                "comment": transaction_data.get("comment")
            }

        except Exception as e:
            self.logger.error("error while running action 'delete_category'", exc_info=e)
            raise Exception(str(e))
