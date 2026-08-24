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

INDICATORS_QUERY = """
query Indicators($search: String, $filters: FilterGroup, $first: Int) {
  indicators(search: $search, filters: $filters, first: $first) {
    edges {
      node {
        id
        name
        pattern
        pattern_type
        confidence
        valid_from
        valid_until
        objectLabel { value }
        objectMarking { definition }
        createdBy { name }
      }
    }
  }
}
"""

RELATIONSHIPS_QUERY = """
query StixCoreRelationships($filters: FilterGroup, $first: Int) {
  stixCoreRelationships(filters: $filters, first: $first) {
    edges {
      node {
        id
        relationship_type
        start_time
        stop_time
        confidence
        from { ... on BasicObject { id entity_type } ... on StixDomainObject { name } ... on StixCyberObservable { observable_value } }
        to { ... on BasicObject { id entity_type } ... on StixDomainObject { name } ... on StixCyberObservable { observable_value } }
      }
    }
  }
}
"""

LABELS_QUERY = """
query Labels {
  labels { edges { node { id value color } } }
}
"""

MARKING_DEFINITIONS_QUERY = """
query MarkingDefinitions {
  markingDefinitions { edges { node { id definition definition_type } } }
}
"""

ORGANIZATIONS_QUERY = """
query Organizations($first: Int) {
  organizations(first: $first) {
    edges {
      node {
        id
        name
        description
      }
    }
  }
}
"""


def _graphql_request(base_url: str, headers: dict, query: str, variables: dict) -> dict:
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


def _get_connection(connection_params: dict):
    base_url = connection_params['base_url'].rstrip('/')
    api_token = connection_params['api_token']
    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
    return base_url, headers


def _parse_limit(raw_limit, default=25):
    try:
        return max(1, min(int(raw_limit), 100))
    except (ValueError, TypeError):
        return default


class Opencti():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    def test_connection(self, connectionParameters: dict):
        try:
            base_url, headers = _get_connection(connectionParameters)
            _graphql_request(base_url, headers, "{ about { version } }", {})
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
            base_url, headers = _get_connection(request.connectionParameters)

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
                        {"key": ["entity_type"], "values": [observable_type], "operator": "eq", "mode": "or"},
                        {"key": ["observable_value"], "values": [obs], "operator": "eq", "mode": "or"}
                    ],
                    "filterGroups": []
                }
                data = _graphql_request(base_url, headers, OBSERVABLE_QUERY, {"filters": filters})
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
            base_url, headers = _get_connection(request.connectionParameters)

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
                data = _graphql_request(base_url, headers, INDICATOR_QUERY, {"id": ind_id})
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
            base_url, headers = _get_connection(request.connectionParameters)

            search_term = request.parameters["search_term"]
            if not search_term or not search_term.strip():
                raise Exception("search_term is required and cannot be empty.")

            entity_type = request.parameters.get("entity_type")
            limit = _parse_limit(request.parameters.get("limit", "25"))

            variables = {"search": search_term.strip(), "first": limit}
            if entity_type and entity_type.strip():
                variables["types"] = [entity_type.strip()]

            data = _graphql_request(base_url, headers, SEARCH_ENTITIES_QUERY, variables)
            edges = data.get("stixDomainObjects", {}).get("edges", [])

            return {"status": "success", "results": [e["node"] for e in edges]}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to OpenCTI. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to OpenCTI timed out.")
        except Exception as e:
            self.logger.error("error while running action 'search_entities'", exc_info=e)
            raise Exception(str(e))

    def get_indicators(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, headers = _get_connection(request.connectionParameters)

            search = request.parameters.get("search")
            labels = request.parameters.get("labels")
            confidence = request.parameters.get("confidence")
            indicator_type = request.parameters.get("indicator_type")
            limit = _parse_limit(request.parameters.get("limit", "25"))

            filters_list = []
            if labels:
                label_values = [l.strip() for l in labels.split(",")] if isinstance(labels, str) else labels
                filters_list.append({"key": ["objectLabel"], "values": label_values, "operator": "eq", "mode": "or"})
            if confidence:
                filters_list.append({"key": ["confidence"], "values": [str(confidence)], "operator": "gte", "mode": "or"})
            if indicator_type:
                filters_list.append({"key": ["pattern_type"], "values": [indicator_type.strip()], "operator": "eq", "mode": "or"})

            variables = {"first": limit}
            if search and search.strip():
                variables["search"] = search.strip()
            if filters_list:
                variables["filters"] = {"mode": "and", "filters": filters_list, "filterGroups": []}

            data = _graphql_request(base_url, headers, INDICATORS_QUERY, variables)
            edges = data.get("indicators", {}).get("edges", [])

            return {"status": "success", "results": [e["node"] for e in edges]}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to OpenCTI. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to OpenCTI timed out.")
        except Exception as e:
            self.logger.error("error while running action 'get_indicators'", exc_info=e)
            raise Exception(str(e))

    def get_relationships(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, headers = _get_connection(request.connectionParameters)

            entity_id = request.parameters.get("entity_id")
            if not entity_id or not entity_id.strip():
                raise Exception("entity_id is required and cannot be empty.")

            relationship_type = request.parameters.get("relationship_type")
            limit = _parse_limit(request.parameters.get("limit", "25"))

            filters_list = [
                {"key": ["fromId", "toId"], "values": [entity_id.strip()], "operator": "eq", "mode": "or"}
            ]
            if relationship_type and relationship_type.strip():
                filters_list.append({"key": ["relationship_type"], "values": [relationship_type.strip()], "operator": "eq", "mode": "or"})

            variables = {
                "first": limit,
                "filters": {"mode": "and", "filters": filters_list, "filterGroups": []}
            }

            data = _graphql_request(base_url, headers, RELATIONSHIPS_QUERY, variables)
            edges = data.get("stixCoreRelationships", {}).get("edges", [])

            return {"status": "success", "results": [e["node"] for e in edges]}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to OpenCTI. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to OpenCTI timed out.")
        except Exception as e:
            self.logger.error("error while running action 'get_relationships'", exc_info=e)
            raise Exception(str(e))

    def list_labels(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, headers = _get_connection(request.connectionParameters)
            data = _graphql_request(base_url, headers, LABELS_QUERY, {})
            edges = data.get("labels", {}).get("edges", [])
            return {"status": "success", "results": [e["node"] for e in edges]}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to OpenCTI. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to OpenCTI timed out.")
        except Exception as e:
            self.logger.error("error while running action 'list_labels'", exc_info=e)
            raise Exception(str(e))

    def list_marking_definitions(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, headers = _get_connection(request.connectionParameters)
            data = _graphql_request(base_url, headers, MARKING_DEFINITIONS_QUERY, {})
            edges = data.get("markingDefinitions", {}).get("edges", [])
            return {"status": "success", "results": [e["node"] for e in edges]}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to OpenCTI. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to OpenCTI timed out.")
        except Exception as e:
            self.logger.error("error while running action 'list_marking_definitions'", exc_info=e)
            raise Exception(str(e))

    def list_organizations(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, headers = _get_connection(request.connectionParameters)
            limit = _parse_limit(request.parameters.get("limit", "100"))
            data = _graphql_request(base_url, headers, ORGANIZATIONS_QUERY, {"first": limit})
            edges = data.get("organizations", {}).get("edges", [])
            return {"status": "success", "results": [e["node"] for e in edges]}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to OpenCTI. Please verify the Base URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to OpenCTI timed out.")
        except Exception as e:
            self.logger.error("error while running action 'list_organizations'", exc_info=e)
            raise Exception(str(e))
