from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import requests


ALLOWED_OBSERVABLE_TYPES = {"IPv4-Addr", "Domain-Name", "Url", "StixFile"}

OBSERVABLE_QUERY = """
query StixCyberObservables($filters: FilterGroup) {
  stixCyberObservables(filters: $filters) {
    edges {
      node {
        id
        entity_type
        observable_value
        created_at
        updated_at
        objectLabel { value }
        objectMarking { definition }
        indicators { edges { node { id name pattern } } }
      }
    }
  }
}
"""

INDICATOR_QUERY = """
query Indicator($id: String!) {
  indicator(id: $id) {
    id
    name
    pattern
    pattern_type
    valid_from
    valid_until
    confidence
    created
    modified
    objectLabel { value }
    objectMarking { definition }
    createdBy { name }
    killChainPhases { kill_chain_name phase_name }
  }
}
"""

SEARCH_ENTITIES_QUERY = """
query StixDomainObjects($search: String, $types: [String], $first: Int) {
  stixDomainObjects(search: $search, types: $types, first: $first) {
    edges {
      node {
        id
        entity_type
        ... on BasicObject { id }
        ... on StixObject { created_at updated_at }
        ... on StixDomainObject { name description created modified }
        objectLabel { value }
      }
    }
  }
}
"""


class Opencti():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    def _graphql_request(self, base_url: str, headers: dict, query: str, variables: dict) -> dict:
        resp = requests.post(
            f"{base_url}/graphql",
            json={"query": query, "variables": variables},
            headers=headers,
            timeout=30
        )
        if resp.status_code in (401, 403):
            raise Exception("Authentication failed. Please verify your API Token is correct.")
        if resp.status_code >= 300:
            raise Exception(f"API request failed with status {resp.status_code}. Please check your configuration.")
        try:
            data = resp.json()
        except ValueError:
            raise Exception("Invalid response from API. Please verify your API Token and Base URL are correct.")
        if "errors" in data and data["errors"]:
            raise Exception(f"GraphQL error: {data['errors'][0].get('message', 'Unknown error')}")
        return data.get("data", {})

    def test_connection(self, connectionParameters: dict):
        try:
            base_url = connectionParameters['base_url'].rstrip('/')
            api_token = connectionParameters['api_token']
            headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}

            self._graphql_request(base_url, headers, "{ about { version } }", {})
            return {'status': 'success', 'message': 'Connected to OpenCTI successfully.'}
        except requests.exceptions.ConnectionError:
            raise Exception('Unable to connect to OpenCTI. Please verify the Base URL.')
        except requests.exceptions.Timeout:
            raise Exception('Connection to OpenCTI timed out.')
        except Exception as e:
            self.logger.error("Exception while testing connection", exc_info=e)
            raise Exception(str(e))

    def lookup_observable(self, request: RequestBody) -> ResponseBody:
        try:
            base_url = request.connectionParameters['base_url'].rstrip('/')
            api_token = request.connectionParameters['api_token']
            headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}

            observables = request.parameters["observables"]
            if isinstance(observables, str):
                observables = [o.strip() for o in observables.split(",") if o.strip()]
            elif not isinstance(observables, list):
                raise Exception("observables must be a string or list.")

            if not observables:
                raise Exception("observables is required and cannot be empty.")

            observable_type = request.parameters["observable_type"]
            if observable_type not in ALLOWED_OBSERVABLE_TYPES:
                raise Exception(
                    f"Invalid observable_type: {observable_type}. "
                    f"Allowed: {', '.join(sorted(ALLOWED_OBSERVABLE_TYPES))}"
                )

            results = []
            for obs in observables:
                filters = {
                    "mode": "and",
                    "filters": [
                        {
                            "key": ["entity_type"],
                            "values": [observable_type],
                            "operator": "eq",
                            "mode": "or"
                        },
                        {
                            "key": ["observable_value"],
                            "values": [obs],
                            "operator": "eq",
                            "mode": "or"
                        }
                    ],
                    "filterGroups": []
                }
                data = self._graphql_request(base_url, headers, OBSERVABLE_QUERY, {"filters": filters})
                edges = data.get("stixCyberObservables", {}).get("edges", [])
                results.append({
                    "observable": obs,
                    "type": observable_type,
                    "matches": [e["node"] for e in edges]
                })

            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to OpenCTI. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to OpenCTI timed out.")
        except Exception as e:
            self.logger.error("error while running action 'lookup_observable'", exc_info=e)
            raise Exception(str(e))

    def get_indicator_details(self, request: RequestBody) -> ResponseBody:
        try:
            base_url = request.connectionParameters['base_url'].rstrip('/')
            api_token = request.connectionParameters['api_token']
            headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}

            indicator_ids = request.parameters["indicator_ids"]
            if isinstance(indicator_ids, str):
                indicator_ids = [i.strip() for i in indicator_ids.split(",") if i.strip()]
            elif not isinstance(indicator_ids, list):
                raise Exception("indicator_ids must be a string or list.")
            if not indicator_ids:
                raise Exception("indicator_ids is required and cannot be empty.")

            results = []
            for ind_id in indicator_ids:
                if not ind_id:
                    raise Exception("Indicator ID cannot be empty.")
                data = self._graphql_request(base_url, headers, INDICATOR_QUERY, {"id": ind_id})
                indicator = data.get("indicator")
                if not indicator:
                    raise Exception(f"No indicator found for ID: {ind_id}")
                results.append(indicator)

            return {"status": "success", "results": results}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to OpenCTI. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to OpenCTI timed out.")
        except Exception as e:
            self.logger.error("error while running action 'get_indicator_details'", exc_info=e)
            raise Exception(str(e))

    def search_entities(self, request: RequestBody) -> ResponseBody:
        try:
            base_url = request.connectionParameters['base_url'].rstrip('/')
            api_token = request.connectionParameters['api_token']
            headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}

            search_term = request.parameters["search_term"]
            if not search_term or not search_term.strip():
                raise Exception("search_term is required and cannot be empty.")

            entity_type = request.parameters.get("entity_type")
            limit = request.parameters.get("limit", "25")
            try:
                limit = max(1, min(int(limit), 100))
            except (ValueError, TypeError):
                limit = 25

            variables = {"search": search_term.strip(), "first": limit}
            if entity_type and entity_type.strip():
                variables["types"] = [entity_type.strip()]

            data = self._graphql_request(base_url, headers, SEARCH_ENTITIES_QUERY, variables)
            edges = data.get("stixDomainObjects", {}).get("edges", [])

            return {"status": "success", "results": [e["node"] for e in edges]}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to OpenCTI. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to OpenCTI timed out.")
        except Exception as e:
            self.logger.error("error while running action 'search_entities'", exc_info=e)
            raise Exception(str(e))
