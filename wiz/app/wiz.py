from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import time
import requests


AUTH_URL = "https://auth.app.wiz.io/oauth/token"
DEFAULT_REGION = "us1"
DEFAULT_TIMEOUT = 60
DEFAULT_PAGE_SIZE = 100
MAX_RETRIES = 3
BACKOFF_FACTOR = 2

TEST_CONNECTIVITY_QUERY = """
query TestConnectivity {
    userInfo { id email }
}
"""

GET_ISSUES_QUERY = """
query GetIssues($first: Int, $after: String, $filterBy: IssueFilters) {
    issues(first: $first, after: $after, filterBy: $filterBy) {
        nodes {
            id title severity status type createdAt updatedAt
            entitySnapshot { id name type }
            resource { id name type }
        }
        pageInfo { hasNextPage endCursor }
        totalCount
    }
}
"""

GET_ISSUE_BY_ID_QUERY = """
query GetIssueById($id: ID!) {
    issue(id: $id) {
        id title severity status type createdAt updatedAt description remediation
        entitySnapshot { id name type }
        resource { id name type region cloudPlatform }
        project { id name }
    }
}
"""

GET_ISSUE_EVIDENCE_QUERY = """
query GetIssueEvidence($id: ID!) {
    issue(id: $id) {
        id title
        evidence { currentValue expectedValue cloudConfigurationLink activityLog }
        notes { text createdAt updatedBy { email } }
    }
}
"""

GET_RESOURCES_QUERY = """
query GetResources($first: Int, $after: String, $filterBy: ResourceFilters) {
    resources(first: $first, after: $after, filterBy: $filterBy) {
        nodes {
            id name type region cloudPlatform subscriptionId subscriptionExternalId
            cloudAccount { id name }
            project { id name }
            status
        }
        pageInfo { hasNextPage endCursor }
        totalCount
    }
}
"""

GET_RESOURCE_QUERY = """
query GetResource($id: ID!) {
    resource(id: $id) {
        id name type region cloudPlatform subscriptionId subscriptionExternalId
        cloudAccount { id name }
        project { id name }
        status properties tags
    }
}
"""

GET_RESOURCE_BY_NAME_QUERY = """
query GetResourceByName($first: Int, $filterBy: ResourceFilters) {
    resources(first: $first, filterBy: $filterBy) {
        nodes {
            id name type region cloudPlatform subscriptionId subscriptionExternalId
            cloudAccount { id name }
            project { id name }
            status properties tags
        }
        totalCount
    }
}
"""

GET_PROJECT_TEAM_QUERY = """
query GetProjectTeam($filterBy: ProjectFilters) {
    projects(first: 1, filterBy: $filterBy) {
        nodes {
            id name
            owners { id email name }
            securityChampions { id email name }
            projectMembers { id email name }
        }
    }
}
"""


class Wiz:

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)

    def _get_connection(self, connection_params: dict):
        client_id = connection_params.get("client_id")
        client_secret = connection_params.get("client_secret")
        if not client_id:
            raise Exception("client_id is required.")
        if not client_secret:
            raise Exception("client_secret is required.")

        region = connection_params.get("region", DEFAULT_REGION) or DEFAULT_REGION
        graphql_url = f"https://api.{region}.app.wiz.io/graphql"

        timeout = DEFAULT_TIMEOUT
        try:
            t = connection_params.get("timeout")
            if t:
                timeout = max(1, int(t))
        except (ValueError, TypeError):
            pass

        verify_ssl = connection_params.get("verify_ssl", True)
        if isinstance(verify_ssl, str):
            verify_ssl = verify_ssl.lower() in ("true", "1", "yes")

        page_size = DEFAULT_PAGE_SIZE
        try:
            ps = connection_params.get("page_size")
            if ps:
                page_size = max(1, min(int(ps), 500))
        except (ValueError, TypeError):
            pass

        proxy = connection_params.get("proxy")
        proxies = {"https": proxy, "http": proxy} if proxy else None

        return client_id, client_secret, graphql_url, timeout, verify_ssl, page_size, proxies

    def _authenticate(self, client_id: str, client_secret: str, timeout: int,
                      verify_ssl: bool, proxies: dict) -> str:
        try:
            resp = requests.post(
                AUTH_URL,
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "audience": "wiz-api",
                },
                timeout=timeout,
                verify=verify_ssl,
                proxies=proxies,
            )
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Wiz auth endpoint.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Wiz auth endpoint timed out.")

        if resp.status_code in (401, 403):
            raise Exception("Authentication failed. Verify client_id and client_secret.")
        if resp.status_code != 200:
            raise Exception(f"Authentication failed (HTTP {resp.status_code}).")

        token = resp.json().get("access_token")
        if not token:
            raise Exception("Authentication response missing access_token.")
        return token

    def _graphql_request(self, graphql_url: str, token: str, query: str,
                         variables: dict, timeout: int, verify_ssl: bool,
                         proxies: dict) -> dict:
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        payload = {"query": query, "variables": variables}

        last_exception = None
        for attempt in range(MAX_RETRIES):
            try:
                resp = requests.post(
                    graphql_url,
                    json=payload,
                    headers=headers,
                    timeout=timeout,
                    verify=verify_ssl,
                    proxies=proxies,
                )
            except requests.exceptions.ConnectionError:
                raise Exception("Unable to connect to Wiz GraphQL endpoint.")
            except requests.exceptions.Timeout:
                raise Exception("Connection to Wiz GraphQL endpoint timed out.")

            if resp.status_code == 200:
                data = resp.json()
                if "errors" in data and data["errors"]:
                    error_msg = data["errors"][0].get("message", "Unknown GraphQL error")
                    raise Exception(f"GraphQL error: {error_msg}")
                return data.get("data", {})

            if resp.status_code in (401, 403):
                raise Exception("Authentication failed. Verify credentials.")

            if resp.status_code == 429:
                if attempt < MAX_RETRIES - 1:
                    wait = BACKOFF_FACTOR ** (attempt + 1)
                    self.logger.warning("Rate limited (429). Retrying in %ds...", wait)
                    time.sleep(wait)
                    last_exception = Exception("Rate limit exceeded. Please try again later.")
                    continue
                raise Exception("Rate limit exceeded. Please try again later.")

            if resp.status_code >= 500:
                if attempt < MAX_RETRIES - 1:
                    wait = BACKOFF_FACTOR ** (attempt + 1)
                    self.logger.warning("Server error (%d). Retrying in %ds...", resp.status_code, wait)
                    time.sleep(wait)
                    last_exception = Exception(f"Wiz server error (HTTP {resp.status_code}).")
                    continue
                raise Exception(f"Wiz server error (HTTP {resp.status_code}).")

            raise Exception(f"Wiz API error (HTTP {resp.status_code}).")

        if last_exception:
            raise last_exception

    def _validate_required(self, value, field_name: str) -> str:
        if not value or (isinstance(value, str) and not value.strip()):
            raise Exception(f"{field_name} is required and cannot be empty.")
        return value.strip() if isinstance(value, str) else value

    def test_connection(self, connectionParameters: dict):
        try:
            client_id, client_secret, graphql_url, timeout, verify_ssl, _, proxies = \
                self._get_connection(connectionParameters)
            token = self._authenticate(client_id, client_secret, timeout, verify_ssl, proxies)
            self._graphql_request(graphql_url, token, TEST_CONNECTIVITY_QUERY, {}, timeout, verify_ssl, proxies)
            return {"status": "success", "message": "Connected to Wiz successfully."}
        except Exception as e:
            self.logger.error("Exception while testing connection", exc_info=e)
            raise Exception(str(e))

    def get_issues(self, request: RequestBody) -> dict:
        try:
            client_id, client_secret, graphql_url, timeout, verify_ssl, page_size, proxies = \
                self._get_connection(request.connectionParameters)
            token = self._authenticate(client_id, client_secret, timeout, verify_ssl, proxies)

            params = request.parameters or {}
            filter_by = {}
            if params.get("issue_type"):
                filter_by["type"] = [params["issue_type"].strip()]
            if params.get("entity_type"):
                filter_by["entityType"] = [params["entity_type"].strip()]
            if params.get("resource_id"):
                filter_by["relatedEntity"] = {"id": params["resource_id"].strip()}
            if params.get("severity"):
                filter_by["severity"] = [params["severity"].strip().upper()]

            variables = {"first": self._parse_page_size(params.get("page_size"), page_size)}
            if params.get("page_token"):
                variables["after"] = params["page_token"]
            if filter_by:
                variables["filterBy"] = filter_by

            data = self._graphql_request(graphql_url, token, GET_ISSUES_QUERY, variables, timeout, verify_ssl, proxies)
            issues_data = data.get("issues", {})
            return {
                "status": "success",
                "issues": issues_data.get("nodes", []),
                "total_count": issues_data.get("totalCount", 0),
                "page_info": issues_data.get("pageInfo", {}),
            }
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Wiz. Please verify the region.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Wiz timed out.")
        except Exception as e:
            self.logger.error("Error in get_issues action", exc_info=e)
            raise Exception(str(e))

    def get_issue_by_id(self, request: RequestBody) -> dict:
        try:
            client_id, client_secret, graphql_url, timeout, verify_ssl, _, proxies = \
                self._get_connection(request.connectionParameters)
            token = self._authenticate(client_id, client_secret, timeout, verify_ssl, proxies)

            params = request.parameters or {}
            issue_id = self._validate_required(params.get("issue_id"), "issue_id")

            data = self._graphql_request(graphql_url, token, GET_ISSUE_BY_ID_QUERY, {"id": issue_id}, timeout, verify_ssl, proxies)
            return {"status": "success", "issue": data.get("issue", {})}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Wiz. Please verify the region.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Wiz timed out.")
        except Exception as e:
            self.logger.error("Error in get_issue_by_id action", exc_info=e)
            raise Exception(str(e))

    def get_issue_evidence(self, request: RequestBody) -> dict:
        try:
            client_id, client_secret, graphql_url, timeout, verify_ssl, _, proxies = \
                self._get_connection(request.connectionParameters)
            token = self._authenticate(client_id, client_secret, timeout, verify_ssl, proxies)

            params = request.parameters or {}
            issue_id = self._validate_required(params.get("issue_id"), "issue_id")

            data = self._graphql_request(graphql_url, token, GET_ISSUE_EVIDENCE_QUERY, {"id": issue_id}, timeout, verify_ssl, proxies)
            issue = data.get("issue", {})
            return {
                "status": "success",
                "issue_id": issue.get("id"),
                "title": issue.get("title"),
                "evidence": issue.get("evidence", {}),
                "notes": issue.get("notes", []),
            }
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Wiz. Please verify the region.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Wiz timed out.")
        except Exception as e:
            self.logger.error("Error in get_issue_evidence action", exc_info=e)
            raise Exception(str(e))

    def get_resources(self, request: RequestBody) -> dict:
        try:
            client_id, client_secret, graphql_url, timeout, verify_ssl, page_size, proxies = \
                self._get_connection(request.connectionParameters)
            token = self._authenticate(client_id, client_secret, timeout, verify_ssl, proxies)

            params = request.parameters or {}
            filter_by = {}
            if params.get("resource_name"):
                filter_by["search"] = params["resource_name"].strip()
            if params.get("resource_type"):
                filter_by["type"] = [params["resource_type"].strip()]
            if params.get("cloud_account"):
                filter_by["cloudAccount"] = {"id": params["cloud_account"].strip()}
            if params.get("subscription_id"):
                filter_by["subscriptionExternalId"] = params["subscription_id"].strip()
            if params.get("project_name"):
                filter_by["project"] = {"name": params["project_name"].strip()}

            variables = {"first": self._parse_page_size(params.get("page_size"), page_size)}
            if params.get("page_token"):
                variables["after"] = params["page_token"]
            if filter_by:
                variables["filterBy"] = filter_by

            data = self._graphql_request(graphql_url, token, GET_RESOURCES_QUERY, variables, timeout, verify_ssl, proxies)
            resources_data = data.get("resources", {})
            return {
                "status": "success",
                "resources": resources_data.get("nodes", []),
                "total_count": resources_data.get("totalCount", 0),
                "page_info": resources_data.get("pageInfo", {}),
            }
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Wiz. Please verify the region.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Wiz timed out.")
        except Exception as e:
            self.logger.error("Error in get_resources action", exc_info=e)
            raise Exception(str(e))

    def get_resource(self, request: RequestBody) -> dict:
        try:
            client_id, client_secret, graphql_url, timeout, verify_ssl, _, proxies = \
                self._get_connection(request.connectionParameters)
            token = self._authenticate(client_id, client_secret, timeout, verify_ssl, proxies)

            params = request.parameters or {}
            resource_id = params.get("resource_id")
            resource_name = params.get("resource_name")

            if not resource_id and not resource_name:
                raise Exception("At least one of ['resource_id', 'resource_name'] must be provided.")

            if resource_id:
                data = self._graphql_request(graphql_url, token, GET_RESOURCE_QUERY, {"id": resource_id.strip()}, timeout, verify_ssl, proxies)
                return {"status": "success", "resource": data.get("resource", {})}
            else:
                variables = {"first": 1, "filterBy": {"search": resource_name.strip()}}
                data = self._graphql_request(graphql_url, token, GET_RESOURCE_BY_NAME_QUERY, variables, timeout, verify_ssl, proxies)
                nodes = data.get("resources", {}).get("nodes", [])
                return {"status": "success", "resource": nodes[0] if nodes else {}}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Wiz. Please verify the region.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Wiz timed out.")
        except Exception as e:
            self.logger.error("Error in get_resource action", exc_info=e)
            raise Exception(str(e))

    def get_project_team(self, request: RequestBody) -> dict:
        try:
            client_id, client_secret, graphql_url, timeout, verify_ssl, _, proxies = \
                self._get_connection(request.connectionParameters)
            token = self._authenticate(client_id, client_secret, timeout, verify_ssl, proxies)

            params = request.parameters or {}
            project_name = self._validate_required(params.get("project_name"), "project_name")

            variables = {"filterBy": {"name": project_name}}
            data = self._graphql_request(graphql_url, token, GET_PROJECT_TEAM_QUERY, variables, timeout, verify_ssl, proxies)
            nodes = data.get("projects", {}).get("nodes", [])

            if not nodes:
                return {
                    "status": "success",
                    "project_name": project_name,
                    "owners": [],
                    "security_champions": [],
                    "members": [],
                }

            project = nodes[0]
            return {
                "status": "success",
                "project_name": project.get("name", project_name),
                "owners": project.get("owners", []),
                "security_champions": project.get("securityChampions", []),
                "members": project.get("projectMembers", []),
            }
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Wiz. Please verify the region.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Wiz timed out.")
        except Exception as e:
            self.logger.error("Error in get_project_team action", exc_info=e)
            raise Exception(str(e))

    def _parse_page_size(self, raw_page_size, default):
        try:
            if raw_page_size:
                return max(1, min(int(raw_page_size), 500))
        except (ValueError, TypeError):
            pass
        return default
