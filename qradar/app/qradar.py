from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import time
import requests


class Qradar():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    def _get_connection(self, connection_params: dict) -> tuple:
        base_url = connection_params.get('base_url', '')
        if not base_url:
            raise Exception("base_url is required for QRadar connection")
        base_url = base_url.rstrip('/')
        api_token = connection_params.get('api_token', '')
        if not api_token:
            raise Exception("api_token is required for QRadar connection")
        timeout = connection_params.get('timeout', 30)
        if timeout in [None, "None", "", "null"]:
            timeout = 30
        else:
            timeout = int(timeout)
        max_retries = connection_params.get('max_retries', 3)
        if max_retries in [None, "None", "", "null"]:
            max_retries = 3
        else:
            max_retries = int(max_retries)
        api_version = connection_params.get('api_version', '14.0')
        if api_version in [None, "None", "", "null"]:
            api_version = '14.0'
        return base_url, api_token, timeout, max_retries, api_version

    def _get_headers(self, api_token: str = '', api_version: str = '14.0', range_header: str = None) -> dict:
        headers = {
            "SEC": api_token,
            "Version": api_version,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        if range_header:
            headers["Range"] = range_header
        return headers

    def _request_with_retry(self, method: str, url: str, headers: dict,
                            timeout: int, max_retries: int,
                            params: dict = None, json_body: dict = None) -> dict:
        last_exception = None
        for attempt in range(max_retries):
            try:
                if method == "GET":
                    resp = requests.get(url, headers=headers, params=params, timeout=timeout)
                else:
                    resp = requests.post(url, headers=headers, params=params, json=json_body, timeout=timeout)

                if resp.status_code == 429:
                    if attempt < max_retries - 1:
                        backoff = 2 ** attempt
                        self.logger.warning("Rate limited (429), retrying in %ds (attempt %d/%d)",
                                            backoff, attempt + 1, max_retries)
                        time.sleep(backoff)
                        continue
                    raise Exception("Rate limit exceeded after all retries")
                if resp.status_code == 401:
                    raise Exception("Authentication failed: invalid SEC token")
                if resp.status_code == 403:
                    raise Exception("Access denied: check API token permissions")
                if resp.status_code == 404:
                    raise Exception(f"Resource not found: {url}")
                if resp.status_code == 409:
                    raise Exception(f"Conflict: {resp.text[:500]}")
                if resp.status_code == 422:
                    raise Exception(f"Validation error: {resp.text[:500]}")
                if resp.status_code >= 500:
                    raise Exception(f"QRadar server error: {resp.status_code}")
                if resp.status_code >= 300:
                    raise Exception(f"QRadar API error: {resp.status_code} - {resp.text[:500]}")

                if resp.status_code == 204:
                    return {}
                return resp.json()
            except requests.exceptions.Timeout:
                last_exception = Exception("Request timed out")
                if attempt < max_retries - 1:
                    backoff = 2 ** attempt
                    self.logger.warning("Timeout, retrying in %ds (attempt %d/%d)",
                                        backoff, attempt + 1, max_retries)
                    time.sleep(backoff)
                    continue
            except requests.exceptions.ConnectionError:
                last_exception = Exception("Failed to connect to QRadar")
                if attempt < max_retries - 1:
                    backoff = 2 ** attempt
                    self.logger.warning("Connection error, retrying in %ds (attempt %d/%d)",
                                        backoff, attempt + 1, max_retries)
                    time.sleep(backoff)
                    continue
            except Exception:
                raise
        if last_exception:
            raise last_exception
        raise Exception("Request failed after all retries")

    @staticmethod
    def _validate_offense_id(offense_id) -> int:
        if offense_id is None or str(offense_id).strip() == '':
            raise Exception("offense_id is required")
        try:
            oid = int(offense_id)
        except (ValueError, TypeError):
            raise Exception(f"offense_id must be a valid integer, got: {offense_id}")
        if oid <= 0:
            raise Exception(f"offense_id must be a positive integer, got: {oid}")
        return oid

    @staticmethod
    def _assess_risk(magnitude) -> str:
        if magnitude is None:
            return "low"
        try:
            mag = int(magnitude)
        except (ValueError, TypeError):
            return "low"
        if mag >= 9:
            return "critical"
        if mag >= 7:
            return "high"
        if mag >= 4:
            return "medium"
        return "low"

    # -------------------------------------------------------------------------
    # Test Connection
    # -------------------------------------------------------------------------
    def test_connection(self, connectionParameters: dict):
        try:
            base_url = connectionParameters.get('base_url', '')
            if not base_url:
                raise Exception("base_url is required for QRadar connection")
            base_url = base_url.rstrip('/')
            api_token = connectionParameters.get('api_token', '')
            if not api_token:
                raise Exception("api_token is required for QRadar connection")
            timeout = connectionParameters.get('timeout', 30)
            if timeout in [None, "None", "", "null"]:
                timeout = 30
            else:
                timeout = int(timeout)
            api_version = connectionParameters.get('api_version', '14.0')
            if api_version in [None, "None", "", "null"]:
                api_version = '14.0'

            url = f"{base_url}/siem/offenses"
            headers = self._get_headers(api_token, api_version, range_header="items=0-0")
            resp = requests.get(url, headers=headers, timeout=timeout, verify=False)
            if resp.status_code == 401:
                raise Exception("Authentication failed: invalid API token")
            if resp.status_code == 403:
                raise Exception("Access denied: check API token permissions")
            if resp.status_code >= 500:
                raise Exception(f"QRadar server error: {resp.status_code}")
            return {'status': 'success', 'message': 'Connected to QRadar successfully.'}
        except Exception as e:
            self.logger.error("Exception while testing QRadar connection", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Action 1: Fetch Offenses
    # -------------------------------------------------------------------------
    def fetch_offenses(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, api_token, timeout, max_retries, api_version = self._get_connection(request.connectionParameters)
            filter_expr = request.parameters.get('filter', '')
            range_start = int(request.parameters.get('range_start', 0))
            range_end = int(request.parameters.get('range_end', 49))
            if range_start > range_end:
                raise Exception("range_start must be <= range_end")
            range_header = f"items={range_start}-{range_end}"
            url = f"{base_url}/siem/offenses"
            headers = self._get_headers(api_token, api_version, range_header=range_header)
            params = {}
            if filter_expr:
                params['filter'] = filter_expr
            data = self._request_with_retry("GET", url, headers, timeout, max_retries, params=params)
            offenses = data if isinstance(data, list) else []
            max_magnitude = max((o.get('magnitude', 0) for o in offenses), default=0)
            return {
                "success": True,
                "indicator": None,
                "indicator_type": "offense",
                "lookup_type": "fetch_offenses",
                "summary": {
                    "verdict": f"{len(offenses)} offenses retrieved",
                    "risk_level": self._assess_risk(max_magnitude)
                },
                "data": {"offenses": offenses, "count": len(offenses)},
                "raw_response": data
            }
        except Exception as e:
            self.logger.error("Error in fetch_offenses", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Action 2: Get Offense Details
    # -------------------------------------------------------------------------
    def get_offense_details(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, api_token, timeout, max_retries, api_version = self._get_connection(request.connectionParameters)
            offense_id = self._validate_offense_id(request.parameters.get('offense_id'))
            url = f"{base_url}/siem/offenses/{offense_id}"
            headers = self._get_headers(api_token, api_version)
            data = self._request_with_retry("GET", url, headers, timeout, max_retries)
            return {
                "success": True,
                "indicator": offense_id,
                "indicator_type": "offense",
                "lookup_type": "get_offense_details",
                "summary": {
                    "verdict": data.get('description', 'Offense retrieved'),
                    "risk_level": self._assess_risk(data.get('magnitude'))
                },
                "data": data,
                "raw_response": data
            }
        except Exception as e:
            self.logger.error("Error in get_offense_details", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Action 3: Update Offense (query params, NOT JSON body)
    # -------------------------------------------------------------------------
    def update_offense(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, api_token, timeout, max_retries, api_version = self._get_connection(request.connectionParameters)
            offense_id = self._validate_offense_id(request.parameters.get('offense_id'))
            url = f"{base_url}/siem/offenses/{offense_id}"
            headers = self._get_headers(api_token, api_version)
            params = {}
            status = request.parameters.get('status')
            if status:
                params['status'] = status
            closing_reason_id = request.parameters.get('closing_reason_id')
            if closing_reason_id:
                params['closing_reason_id'] = closing_reason_id
            assigned_to = request.parameters.get('assigned_to')
            if assigned_to:
                params['assigned_to'] = assigned_to
            if not params:
                raise Exception("At least one update parameter required (status, closing_reason_id, or assigned_to)")
            data = self._request_with_retry("POST", url, headers, timeout, max_retries, params=params)
            return {
                "success": True,
                "indicator": offense_id,
                "indicator_type": "offense",
                "lookup_type": "update_offense",
                "summary": {
                    "verdict": f"Offense {offense_id} updated",
                    "risk_level": self._assess_risk(data.get('magnitude'))
                },
                "data": data,
                "raw_response": data
            }
        except Exception as e:
            self.logger.error("Error in update_offense for offense_id=%s", request.parameters.get('offense_id'), exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Action 4: Get Offense Notes
    # -------------------------------------------------------------------------
    def get_offense_notes(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, api_token, timeout, max_retries, api_version = self._get_connection(request.connectionParameters)
            offense_id = self._validate_offense_id(request.parameters.get('offense_id'))
            url = f"{base_url}/siem/offenses/{offense_id}/notes"
            headers = self._get_headers(api_token, api_version)
            data = self._request_with_retry("GET", url, headers, timeout, max_retries)
            notes = data if isinstance(data, list) else []
            return {
                "success": True,
                "indicator": offense_id,
                "indicator_type": "offense",
                "lookup_type": "get_offense_notes",
                "summary": {
                    "verdict": f"{len(notes)} notes retrieved",
                    "risk_level": "low"
                },
                "data": {"notes": notes, "count": len(notes)},
                "raw_response": data
            }
        except Exception as e:
            self.logger.error("Error in get_offense_notes", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Action 5: Add Offense Note
    # -------------------------------------------------------------------------
    def add_offense_note(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, api_token, timeout, max_retries, api_version = self._get_connection(request.connectionParameters)
            offense_id = self._validate_offense_id(request.parameters.get('offense_id'))
            note_text = request.parameters.get('note_text', '').strip()
            if not note_text:
                raise Exception("note_text is required and cannot be empty")
            url = f"{base_url}/siem/offenses/{offense_id}/notes"
            headers = self._get_headers(api_token, api_version)
            json_body = {"note_text": note_text}
            data = self._request_with_retry("POST", url, headers, timeout, max_retries, json_body=json_body)
            return {
                "success": True,
                "indicator": offense_id,
                "indicator_type": "offense",
                "lookup_type": "add_offense_note",
                "summary": {
                    "verdict": "Note added successfully",
                    "risk_level": "low"
                },
                "data": data,
                "raw_response": data
            }
        except Exception as e:
            self.logger.error("Error in add_offense_note", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Action 6: Get Closing Reasons
    # -------------------------------------------------------------------------
    def get_closing_reasons(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, api_token, timeout, max_retries, api_version = self._get_connection(request.connectionParameters)
            url = f"{base_url}/siem/offense_closing_reasons"
            headers = self._get_headers(api_token, api_version)
            data = self._request_with_retry("GET", url, headers, timeout, max_retries)
            reasons = data if isinstance(data, list) else []
            return {
                "success": True,
                "indicator": None,
                "indicator_type": "offense",
                "lookup_type": "get_closing_reasons",
                "summary": {
                    "verdict": f"{len(reasons)} closing reasons available",
                    "risk_level": "low"
                },
                "data": {"closing_reasons": reasons, "count": len(reasons)},
                "raw_response": data
            }
        except Exception as e:
            self.logger.error("Error in get_closing_reasons", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Ariel Polling Helper
    # -------------------------------------------------------------------------
    def _poll_search_until_complete(self, base_url: str, api_token: str, api_version: str,
                                    timeout: int, max_retries: int, search_id: str,
                                    poll_interval: int = 2, poll_timeout: int = 60) -> dict:
        elapsed = 0
        while elapsed < poll_timeout:
            url = f"{base_url}/ariel/searches/{search_id}"
            headers = self._get_headers(api_token, api_version)
            data = self._request_with_retry("GET", url, headers, timeout, max_retries)
            status = data.get('status', 'UNKNOWN')
            if status == 'COMPLETED':
                return data
            if status in ('ERROR', 'CANCELED'):
                raise Exception(f"Search {search_id} failed with status: {status}")
            time.sleep(poll_interval)
            elapsed += poll_interval
        raise Exception(f"Search {search_id} timed out after {poll_timeout}s (last status: {status})")

    # -------------------------------------------------------------------------
    # Action 7: Create Search (Ariel) — creates and polls until complete
    # -------------------------------------------------------------------------
    def create_search(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, api_token, timeout, max_retries, api_version = self._get_connection(request.connectionParameters)
            query_expression = request.parameters.get('query_expression', '').strip()
            if not query_expression:
                raise Exception("query_expression is required and cannot be empty")
            wait_for_completion = request.parameters.get('wait_for_completion', True)
            poll_interval = max(1, int(request.parameters.get('poll_interval', 2)))
            poll_timeout = max(1, int(request.parameters.get('poll_timeout', 60)))
            url = f"{base_url}/ariel/searches"
            headers = self._get_headers(api_token, api_version)
            json_body = {"query_expression": query_expression}
            data = self._request_with_retry("POST", url, headers, timeout, max_retries, json_body=json_body)
            search_id = data.get('search_id')
            if not search_id:
                raise Exception("Failed to create search: no search_id returned")
            if wait_for_completion:
                data = self._poll_search_until_complete(
                    base_url, api_token, api_version, timeout, max_retries,
                    search_id, poll_interval, poll_timeout
                )
                # Sync mode: also fetch results
                results_url = f"{base_url}/ariel/searches/{search_id}/results"
                results_headers = self._get_headers(api_token, api_version, range_header="items=0-49")
                results_data = self._request_with_retry("GET", results_url, results_headers, timeout, max_retries)
                return {
                    "success": True,
                    "indicator": search_id,
                    "indicator_type": "search",
                    "lookup_type": "create_search",
                    "summary": {
                        "verdict": f"Search {search_id} completed",
                        "risk_level": "low"
                    },
                    "data": {"search": data, "results": results_data},
                    "raw_response": results_data
                }
            # Async mode: return search_id immediately
            return {
                "success": True,
                "indicator": search_id,
                "indicator_type": "search",
                "lookup_type": "create_search",
                "summary": {
                    "verdict": f"Search {search_id} created (async)",
                    "risk_level": "low"
                },
                "data": data,
                "raw_response": data
            }
        except Exception as e:
            self.logger.error("Error in create_search query=%s", query_expression, exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Action 8: Get Search Status (Ariel)
    # -------------------------------------------------------------------------
    def get_search_status(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, api_token, timeout, max_retries, api_version = self._get_connection(request.connectionParameters)
            search_id = request.parameters.get('search_id', '').strip()
            if not search_id:
                raise Exception("search_id is required")
            url = f"{base_url}/ariel/searches/{search_id}"
            headers = self._get_headers(api_token, api_version)
            data = self._request_with_retry("GET", url, headers, timeout, max_retries)
            status = data.get('status', 'UNKNOWN')
            return {
                "success": True,
                "indicator": search_id,
                "indicator_type": "search",
                "lookup_type": "get_search_status",
                "summary": {
                    "verdict": f"Search status: {status}",
                    "risk_level": "low"
                },
                "data": data,
                "raw_response": data
            }
        except Exception as e:
            self.logger.error("Error in get_search_status", exc_info=e)
            raise Exception(str(e))

    # -------------------------------------------------------------------------
    # Action 9: Get Search Results (Ariel)
    # -------------------------------------------------------------------------
    def get_search_results(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, api_token, timeout, max_retries, api_version = self._get_connection(request.connectionParameters)
            search_id = request.parameters.get('search_id', '').strip()
            if not search_id:
                raise Exception("search_id is required")
            range_start = int(request.parameters.get('range_start', 0))
            range_end = int(request.parameters.get('range_end', 49))
            if range_start > range_end:
                raise Exception("range_start must be <= range_end")
            range_header = f"items={range_start}-{range_end}"
            url = f"{base_url}/ariel/searches/{search_id}/results"
            headers = self._get_headers(api_token, api_version, range_header=range_header)
            data = self._request_with_retry("GET", url, headers, timeout, max_retries)
            if 'events' in data:
                results = data['events']
            elif 'flows' in data:
                results = data['flows']
            else:
                results = []
            return {
                "success": True,
                "indicator": search_id,
                "indicator_type": "search",
                "lookup_type": "get_search_results",
                "summary": {
                    "verdict": f"{len(results)} results retrieved",
                    "risk_level": "low"
                },
                "data": data,
                "raw_response": data
            }
        except Exception as e:
            self.logger.error("Error in get_search_results", exc_info=e)
            raise Exception(str(e))
