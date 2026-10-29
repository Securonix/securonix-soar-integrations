from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import requests
import time
import re
import urllib.parse
from typing import Dict, Any, Optional, Tuple


class ForcepointSmc:
    """
    Forcepoint Security Management Center (SMC) connector for Securonix SOAR.
    Uses API key authentication.
    API Base: /api
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        self._session = requests.Session()
        self._default_port = 8082
        self._timeout = 30
        self._verify_ssl = True

    def _get_api_host(self, connectionParameters: Dict[str, Any]) -> str:
        """Get API host from connection parameters."""
        host = connectionParameters.get("api_host")
        if host and host.strip():
            return host.strip()
        raise ValueError("API host is required")

    def _get_api_port(self, connectionParameters: Dict[str, Any]) -> int:
        """Get API port from connection parameters."""
        port_val = connectionParameters.get("api_port")
        if port_val is not None:
            try:
                val = int(port_val)
                if val > 0 and val <= 65535:
                    return val
            except (ValueError, TypeError):
                pass
        return self._default_port

    def _get_verify_ssl(self, connectionParameters: Dict[str, Any]) -> bool:
        """Get verify_ssl from connection parameters."""
        verify_val = connectionParameters.get("verify_ssl")
        if verify_val is not None:
            if isinstance(verify_val, bool):
                return verify_val
            if isinstance(verify_val, str):
                return verify_val.lower() == "true"
        return self._verify_ssl

    def _get_api_key(self, connectionParameters: Dict[str, Any]) -> str:
        """Get API key from connection parameters."""
        api_key = connectionParameters.get("api_key")
        if api_key and api_key.strip():
            return api_key.strip()
        raise ValueError("API key is required for Forcepoint SMC")

    def _get_timeout(self, connectionParameters: Dict[str, Any]) -> int:
        """Get timeout from connection parameters."""
        timeout_val = connectionParameters.get("request_timeout")
        if timeout_val is not None:
            try:
                val = int(timeout_val)
                if val > 0:
                    return val
            except (ValueError, TypeError):
                pass
        return self._timeout

    def _validate_hostname(self, hostname: str) -> str:
        """Validate hostname."""
        if not hostname or not isinstance(hostname, str):
            raise ValueError("Hostname must be a non-empty string")
        hostname = hostname.strip()
        if not hostname:
            raise ValueError("Hostname must be non-empty")
        # Allow FQDN or IP
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$|^\d{1,3}(\.\d{1,3}){3}$'
        if not re.match(hostname_pattern, hostname):
            raise ValueError(f"Invalid hostname format: {hostname}")
        return hostname

    def _validate_ip(self, ip: str) -> str:
        """Validate IP address."""
        if not ip or not isinstance(ip, str):
            raise ValueError("IP address must be a non-empty string")
        ip = ip.strip()
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return str(ip_obj)
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip}")

    def _validate_name(self, name: str, field_name: str = "name") -> str:
        """Validate name field."""
        if not name or not isinstance(name, str):
            raise ValueError(f"{field_name} must be a non-empty string")
        name = name.strip()
        if not name:
            raise ValueError(f"{field_name} must be non-empty")
        # Allow alphanumeric, hyphens, underscores, spaces
        name_pattern = r'^[a-zA-Z0-9\-_\s]+$'
        if not re.match(name_pattern, name):
            raise ValueError(f"Invalid {field_name} format: only alphanumeric, hyphens, underscores, and spaces allowed")
        return name

    def _request(
        self,
        method: str,
        endpoint: str,
        connectionParameters: Dict[str, Any],
        api_key: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        retry_count: int = 0,
        max_retries: int = 3
    ) -> Tuple[int, Dict[str, Any]]:
        """Make authenticated request to Forcepoint SMC API."""
        api_host = self._get_api_host(connectionParameters)
        api_port = self._get_api_port(connectionParameters)
        verify_ssl = self._get_verify_ssl(connectionParameters)
        timeout = self._get_timeout(connectionParameters)
        
        base_url = f"{api_host}:{api_port}"
        url = f"{base_url}{endpoint}"
        
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-API-KEY": api_key
        }
        
        try:
            self.logger.info(f"Making {method} request to {endpoint}")
            if method.upper() == "GET":
                response = self._session.get(url, headers=headers, params=params, timeout=timeout, verify=verify_ssl)
            elif method.upper() == "POST":
                response = self._session.post(url, headers=headers, params=params, json=data, timeout=timeout, verify=verify_ssl)
            elif method.upper() == "PUT":
                response = self._session.put(url, headers=headers, params=params, json=data, timeout=timeout, verify=verify_ssl)
            elif method.upper() == "DELETE":
                response = self._session.delete(url, headers=headers, params=params, timeout=timeout, verify=verify_ssl)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            self.logger.info(f"Received response with status code: {response.status_code}")
            
            if response.status_code == 204:
                return 204, {}
            
            try:
                json_response = response.json()
            except ValueError:
                raise ValueError("Invalid JSON response from Forcepoint SMC API")
            
            # Handle 401 - API key may be invalid
            if response.status_code == 401:
                raise ConnectionError("Authentication failed: invalid API key")
            
            if response.status_code == 403:
                raise ConnectionError("Access forbidden: API key may not have required permissions")
            
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "1")
                try:
                    wait_time = int(retry_after)
                except ValueError:
                    wait_time = 2 ** retry_count
                if retry_count < max_retries - 1:
                    time.sleep(wait_time)
                    return self._request(method, endpoint, connectionParameters, api_key, params, data, retry_count + 1, max_retries)
                raise ConnectionError(f"Rate limited after {max_retries} retries")
            
            if 500 <= response.status_code < 600:
                if retry_count < max_retries - 1:
                    time.sleep(2 ** retry_count)
                    return self._request(method, endpoint, connectionParameters, api_key, params, data, retry_count + 1, max_retries)
                raise ConnectionError(f"Forcepoint SMC server error: {response.status_code}")
            
            if 200 <= response.status_code < 300:
                return response.status_code, json_response
            
            raise ConnectionError(f"Forcepoint SMC API error: {response.status_code}")
            
        except requests.exceptions.Timeout:
            if retry_count < max_retries - 1:
                time.sleep(1)
                return self._request(method, endpoint, connectionParameters, api_key, params, data, retry_count + 1, max_retries)
            raise ConnectionError(f"Request timed out after {max_retries} attempts")
        
        except requests.exceptions.SSLError:
            raise ConnectionError("TLS/SSL certificate verification failed")
        
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Request failed: {str(e)}")

    # ============================================================================
    # Test Connection
    # ============================================================================
    def test_connection(self, connectionParameters: Dict[str, Any]) -> ResponseBody:
        """Test Forcepoint SMC connection."""
        try:
            api_key = connectionParameters.get("api_key")
            if not api_key or not api_key.strip():
                return ResponseBody(
                    status="FAILURE", errorCode="INVALID_CREDENTIALS", httpCode=0,
                    message="API key is required", response={}, input={}, output={}, incrementals=False
                )
            
            api_host = self._get_api_host(connectionParameters)
            api_port = self._get_api_port(connectionParameters)
            
            # Test basic connectivity to the SMC server
            status_code, raw_response = self._request(
                "GET", "/api/hosts", connectionParameters, api_key, {}
            )
            
            if status_code == 200:
                return ResponseBody(
                    status="SUCCESS", errorCode="", httpCode=200,
                    message=f"Connection successful - Forcepoint SMC API is accessible at {api_host}:{api_port}",
                    response={}, input={}, output={}, incrementals=False
                )
            else:
                return ResponseBody(
                    status="FAILURE", errorCode="FORCEPOINT_API_ERROR", httpCode=0,
                    message=f"Forcepoint SMC API test failed with status {status_code}",
                    response={}, input={}, output={}, incrementals=False
                )
                
        except ValueError as e:
            return ResponseBody(
                status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )
        except ConnectionError as e:
            return ResponseBody(
                status="FAILURE", errorCode="CONNECTION_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )
        except Exception as e:
            return ResponseBody(
                status="FAILURE", errorCode="INTERNAL_ERROR", httpCode=0,
                message=f"Unexpected error during connection test: {str(e)}",
                response={}, input={}, output={}, incrementals=False
            )

    # ============================================================================
    # Action 1: Get Hosts
    # ============================================================================
    def get_hosts(self, request: RequestBody) -> ResponseBody:
        """Retrieve a list of all hosts from SMC."""
        api_key = request.connectionParameters.get("api_key")
        try:
            status_code, raw_response = self._request(
                "GET", "/api/hosts", request.connectionParameters, api_key, {}
            )
            
            hosts = []
            if isinstance(raw_response, list):
                for host in raw_response:
                    if isinstance(host, dict):
                        hosts.append({
                            "name": host.get("name", ""),
                            "uid": host.get("uid", ""),
                            "ipaddr": host.get("ipaddr", ""),
                            "type": host.get("type", "")
                        })
            
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Retrieved {len(hosts)} hosts",
                response={}, input={}, output={"hosts": hosts, "count": len(hosts)},
                incrementals=False
            )
        except ConnectionError as e:
            return ResponseBody(
                status="FAILURE", errorCode="FORCEPOINT_API_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )

    # ============================================================================
    # Action 2: Create Host
    # ============================================================================
    def create_host(self, request: RequestBody) -> ResponseBody:
        """Create a new host in SMC."""
        api_key = request.connectionParameters.get("api_key")
        name = request.parameters.get("name")
        ipaddr = request.parameters.get("ipaddr")
        host_type = request.parameters.get("type", "host")
        
        try:
            validated_name = self._validate_name(name, "name")
            
            if not ipaddr:
                raise ValueError("IP address (ipaddr) is required for host creation")
            
            # Validate IP address
            self._validate_ip(ipaddr)
            
            data = {
                "name": validated_name,
                "ipaddr": ipaddr,
                "type": host_type
            }
            
            status_code, raw_response = self._request(
                "POST", "/api/hosts", request.connectionParameters, api_key, {}, data
            )
            
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Host '{validated_name}' created successfully",
                response={}, input={"name": name, "ipaddr": ipaddr, "type": host_type},
                output={"uid": raw_response.get("uid", ""), "name": validated_name},
                incrementals=False
            )
        except ValueError as e:
            return ResponseBody(
                status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )
        except ConnectionError as e:
            return ResponseBody(
                status="FAILURE", errorCode="FORCEPOINT_API_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )

    # ============================================================================
    # Action 3: Update Host
    # ============================================================================
    def update_host(self, request: RequestBody) -> ResponseBody:
        """Update an existing host in SMC."""
        api_key = request.connectionParameters.get("api_key")
        uid = request.parameters.get("uid")
        name = request.parameters.get("name")
        ipaddr = request.parameters.get("ipaddr")
        
        try:
            if not uid:
                raise ValueError("Host UID is required for update")
            
            data = {}
            if name:
                data["name"] = self._validate_name(name, "name")
            if ipaddr:
                data["ipaddr"] = self._validate_ip(ipaddr)
            
            if not data:
                raise ValueError("At least one field (name or ipaddr) must be provided for update")
            
            status_code, raw_response = self._request(
                "PUT", f"/api/hosts/{uid}", request.connectionParameters, api_key, {}, data
            )
            
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Host '{uid}' updated successfully",
                response={}, input={"uid": uid, "name": name, "ipaddr": ipaddr},
                output={"uid": uid},
                incrementals=False
            )
        except ValueError as e:
            return ResponseBody(
                status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )
        except ConnectionError as e:
            return ResponseBody(
                status="FAILURE", errorCode="FORCEPOINT_API_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )

    # ============================================================================
    # Action 4: Delete Host
    # ============================================================================
    def delete_host(self, request: RequestBody) -> ResponseBody:
        """Delete a host from SMC."""
        api_key = request.connectionParameters.get("api_key")
        uid = request.parameters.get("uid")
        
        try:
            if not uid:
                raise ValueError("Host UID is required for deletion")
            
            status_code, raw_response = self._request(
                "DELETE", f"/api/hosts/{uid}", request.connectionParameters, api_key, {}
            )
            
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Host '{uid}' deleted successfully",
                response={}, input={"uid": uid},
                output={"uid": uid},
                incrementals=False
            )
        except ValueError as e:
            return ResponseBody(
                status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )
        except ConnectionError as e:
            return ResponseBody(
                status="FAILURE", errorCode="FORCEPOINT_API_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )

    # ============================================================================
    # Action 5: Get Networks
    # ============================================================================
    def get_networks(self, request: RequestBody) -> ResponseBody:
        """Retrieve a list of all networks from SMC."""
        api_key = request.connectionParameters.get("api_key")
        
        try:
            status_code, raw_response = self._request(
                "GET", "/api/networks", request.connectionParameters, api_key, {}
            )
            
            networks = []
            if isinstance(raw_response, list):
                for network in raw_response:
                    if isinstance(network, dict):
                        networks.append({
                            "name": network.get("name", ""),
                            "uid": network.get("uid", ""),
                            "subnet": network.get("subnet", ""),
                            "cidr": network.get("cidr", ""),
                            "type": network.get("type", "")
                        })
            
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Retrieved {len(networks)} networks",
                response={}, input={}, output={"networks": networks, "count": len(networks)},
                incrementals=False
            )
        except ConnectionError as e:
            return ResponseBody(
                status="FAILURE", errorCode="FORCEPOINT_API_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )

    # ============================================================================
    # Action 6: Create Network
    # ============================================================================
    def create_network(self, request: RequestBody) -> ResponseBody:
        """Create a new network in SMC."""
        api_key = request.connectionParameters.get("api_key")
        name = request.parameters.get("name")
        subnet = request.parameters.get("subnet")
        cidr = request.parameters.get("cidr")
        
        try:
            validated_name = self._validate_name(name, "name")
            
            if not subnet:
                raise ValueError("Subnet is required for network creation")
            
            # Validate CIDR if provided
            if cidr:
                try:
                    import ipaddress
                    network = ipaddress.ip_network(f"{subnet}/{cidr}", strict=False)
                except ValueError:
                    raise ValueError(f"Invalid CIDR: {cidr}")
            
            data = {
                "name": validated_name,
                "subnet": subnet,
                "type": "network"
            }
            
            if cidr:
                data["cidr"] = int(cidr)
            
            status_code, raw_response = self._request(
                "POST", "/api/networks", request.connectionParameters, api_key, {}, data
            )
            
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Network '{validated_name}' created successfully",
                response={}, input={"name": name, "subnet": subnet, "cidr": cidr},
                output={"uid": raw_response.get("uid", ""), "name": validated_name},
                incrementals=False
            )
        except ValueError as e:
            return ResponseBody(
                status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )
        except ConnectionError as e:
            return ResponseBody(
                status="FAILURE", errorCode="FORCEPOINT_API_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )

    # ============================================================================
    # Action 7: Get Services
    # ============================================================================
    def get_services(self, request: RequestBody) -> ResponseBody:
        """Retrieve a list of all services from SMC."""
        api_key = request.connectionParameters.get("api_key")
        
        try:
            status_code, raw_response = self._request(
                "GET", "/api/services", request.connectionParameters, api_key, {}
            )
            
            services = []
            if isinstance(raw_response, list):
                for service in raw_response:
                    if isinstance(service, dict):
                        services.append({
                            "name": service.get("name", ""),
                            "uid": service.get("uid", ""),
                            "protocol": service.get("protocol", ""),
                            "port": service.get("port", ""),
                            "type": service.get("type", "")
                        })
            
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Retrieved {len(services)} services",
                response={}, input={}, output={"services": services, "count": len(services)},
                incrementals=False
            )
        except ConnectionError as e:
            return ResponseBody(
                status="FAILURE", errorCode="FORCEPOINT_API_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )

    # ============================================================================
    # Action 8: Create Service
    # ============================================================================
    def create_service(self, request: RequestBody) -> ResponseBody:
        """Create a new service in SMC."""
        api_key = request.connectionParameters.get("api_key")
        name = request.parameters.get("name")
        protocol = request.parameters.get("protocol", "tcp")
        port = request.parameters.get("port")
        
        try:
            validated_name = self._validate_name(name, "name")
            
            if not port:
                raise ValueError("Port is required for service creation")
            
            # Validate port
            try:
                port_int = int(port)
                if port_int < 1 or port_int > 65535:
                    raise ValueError("Port must be between 1 and 65535")
            except ValueError:
                raise ValueError("Port must be a valid number between 1 and 65535")
            
            data = {
                "name": validated_name,
                "protocol": protocol.lower(),
                "port": str(port_int),
                "type": "service"
            }
            
            status_code, raw_response = self._request(
                "POST", "/api/services", request.connectionParameters, api_key, {}, data
            )
            
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Service '{validated_name}' created successfully",
                response={}, input={"name": name, "protocol": protocol, "port": port},
                output={"uid": raw_response.get("uid", ""), "name": validated_name},
                incrementals=False
            )
        except ValueError as e:
            return ResponseBody(
                status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )
        except ConnectionError as e:
            return ResponseBody(
                status="FAILURE", errorCode="FORCEPOINT_API_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )

    # ============================================================================
    # Action 9: Get Policies
    # ============================================================================
    def get_policies(self, request: RequestBody) -> ResponseBody:
        """Retrieve a list of all policies from SMC."""
        api_key = request.connectionParameters.get("api_key")
        
        try:
            status_code, raw_response = self._request(
                "GET", "/api/policies", request.connectionParameters, api_key, {}
            )
            
            policies = []
            if isinstance(raw_response, list):
                for policy in raw_response:
                    if isinstance(policy, dict):
                        policies.append({
                            "name": policy.get("name", ""),
                            "uid": policy.get("uid", ""),
                            "type": policy.get("type", ""),
                            "engine_count": policy.get("engine_count", 0)
                        })
            
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Retrieved {len(policies)} policies",
                response={}, input={}, output={"policies": policies, "count": len(policies)},
                incrementals=False
            )
        except ConnectionError as e:
            return ResponseBody(
                status="FAILURE", errorCode="FORCEPOINT_API_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )

    # ============================================================================
    # Action 10: Get Policy Rules
    # ============================================================================
    def get_policy_rules(self, request: RequestBody) -> ResponseBody:
        """Retrieve rules for a specific policy."""
        api_key = request.connectionParameters.get("api_key")
        uid = request.parameters.get("uid")
        
        try:
            if not uid:
                raise ValueError("Policy UID is required")
            
            status_code, raw_response = self._request(
                "GET", f"/api/policies/{uid}/rules", request.connectionParameters, api_key, {}
            )
            
            rules = []
            if isinstance(raw_response, list):
                for rule in raw_response:
                    if isinstance(rule, dict):
                        rules.append({
                            "name": rule.get("name", ""),
                            "uid": rule.get("uid", ""),
                            "source": rule.get("source", ""),
                            "destination": rule.get("destination", ""),
                            "service": rule.get("service", ""),
                            "action": rule.get("action", ""),
                            "enabled": rule.get("enabled", True)
                        })
            
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Retrieved {len(rules)} rules for policy '{uid}'",
                response={}, input={"uid": uid},
                output={"rules": rules, "count": len(rules)},
                incrementals=False
            )
        except ValueError as e:
            return ResponseBody(
                status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )
        except ConnectionError as e:
            return ResponseBody(
                status="FAILURE", errorCode="FORCEPOINT_API_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )

    # ============================================================================
    # Action 11: Search Unused Elements
    # ============================================================================
    def search_unused_elements(self, request: RequestBody) -> ResponseBody:
        """Search for unused elements in SMC."""
        api_key = request.connectionParameters.get("api_key")
        element_type = request.parameters.get("type", "all")
        
        try:
            # Validate element type
            valid_types = ["all", "host", "network", "service", "user", "tag"]
            if element_type.lower() not in valid_types:
                raise ValueError(f"Invalid element type: {element_type}. Must be one of: {valid_types}")
            
            params = {"type": element_type.lower()}
            
            status_code, raw_response = self._request(
                "GET", "/api/unused_elements", request.connectionParameters, api_key, params
            )
            
            unused = []
            if isinstance(raw_response, list):
                for item in raw_response:
                    if isinstance(item, dict):
                        unused.append({
                            "name": item.get("name", ""),
                            "uid": item.get("uid", ""),
                            "type": item.get("type", "")
                        })
            
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Found {len(unused)} unused elements",
                response={}, input={"type": element_type},
                output={"unused_elements": unused, "count": len(unused)},
                incrementals=False
            )
        except ValueError as e:
            return ResponseBody(
                status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )
        except ConnectionError as e:
            return ResponseBody(
                status="FAILURE", errorCode="FORCEPOINT_API_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )

    # ============================================================================
    # Action 12: Search Duplicate IPs
    # ============================================================================
    def search_duplicate_ips(self, request: RequestBody) -> ResponseBody:
        """Search for duplicate IP addresses in SMC."""
        api_key = request.connectionParameters.get("api_key")
        
        try:
            status_code, raw_response = self._request(
                "GET", "/api/duplicates/ip", request.connectionParameters, api_key, {}
            )
            
            duplicates = []
            if isinstance(raw_response, list):
                for dup in raw_response:
                    if isinstance(dup, dict):
                        duplicates.append({
                            "ip": dup.get("ip", ""),
                            "count": dup.get("count", 0),
                            "elements": dup.get("elements", [])
                        })
            
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Found {len(duplicates)} IP addresses with duplicates",
                response={}, input={},
                output={"duplicates": duplicates, "count": len(duplicates)},
                incrementals=False
            )
        except ConnectionError as e:
            return ResponseBody(
                status="FAILURE", errorCode="FORCEPOINT_API_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )

    # ============================================================================
    # Action 13: Get System Status
    # ============================================================================
    def get_system_status(self, request: RequestBody) -> ResponseBody:
        """Retrieve system status from SMC."""
        api_key = request.connectionParameters.get("api_key")
        
        try:
            status_code, raw_response = self._request(
                "GET", "/api/status", request.connectionParameters, api_key, {}
            )
            
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message="System status retrieved successfully",
                response={}, input={},
                output={"status": raw_response},
                incrementals=False
            )
        except ConnectionError as e:
            return ResponseBody(
                status="FAILURE", errorCode="FORCEPOINT_API_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )

    # ============================================================================
    # Action 14: Deploy Policy
    # ============================================================================
    def deploy_policy(self, request: RequestBody) -> ResponseBody:
        """Deploy a policy to engines."""
        api_key = request.connectionParameters.get("api_key")
        uid = request.parameters.get("uid")
        engine_uids = request.parameters.get("engine_uids", [])
        
        try:
            if not uid:
                raise ValueError("Policy UID is required for deployment")
            
            data = {
                "policies": [uid],
                "engines": engine_uids if isinstance(engine_uids, list) else [engine_uids]
            }
            
            status_code, raw_response = self._request(
                "POST", "/api/deploy", request.connectionParameters, api_key, {}, data
            )
            
            return ResponseBody(
                status="SUCCESS", errorCode="", httpCode=status_code,
                message=f"Policy '{uid}' deployment initiated successfully",
                response={}, input={"uid": uid, "engine_uids": engine_uids},
                output={"deployment_id": raw_response.get("deployment_id", ""), "status": "in_progress"},
                incrementals=False
            )
        except ValueError as e:
            return ResponseBody(
                status="FAILURE", errorCode="VALIDATION_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )
        except ConnectionError as e:
            return ResponseBody(
                status="FAILURE", errorCode="FORCEPOINT_API_ERROR", httpCode=0,
                message=str(e), response={}, input={}, output={}, incrementals=False
            )
