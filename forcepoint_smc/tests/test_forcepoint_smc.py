import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from app.forcepoint_smc import ForcepointSmc
from app.model.request_body import RequestBody
from pykson import Pykson
import pytest
from unittest.mock import Mock, patch, MagicMock
import json


# ============================================================================
# Test Fixtures
# ============================================================================
@pytest.fixture
def integration():
    """Create a fresh integration instance for each test."""
    return ForcepointSmc()


@pytest.fixture
def connection_params():
    """Standard connection parameters for testing."""
    return {
        "api_host": "smc.example.com",
        "api_port": "8082",
        "api_key": "test_api_key",
        "verify_ssl": "true"
    }


# ============================================================================
# Test Input Validation
# ============================================================================
class TestInputValidation:
    """Test input validation methods."""
    
    def test_validate_hostname_success(self, integration):
        """Test valid hostname validation."""
        result = integration._validate_hostname("smc.example.com")
        assert result == "smc.example.com"
    
    def test_validate_hostname_with_ip(self, integration):
        """Test IP address validation."""
        result = integration._validate_hostname("192.168.1.100")
        assert result == "192.168.1.100"
    
    def test_validate_hostname_empty(self, integration):
        """Test empty hostname raises error."""
        with pytest.raises(ValueError, match="Hostname must be a non-empty string"):
            integration._validate_hostname("")
    
    def test_validate_hostname_whitespace_only(self, integration):
        """Test whitespace hostname raises error."""
        with pytest.raises(ValueError, match="Hostname must be non-empty"):
            integration._validate_hostname("   ")
    
    def test_validate_ip_success(self, integration):
        """Test valid IP validation."""
        result = integration._validate_ip("192.168.1.100")
        assert result == "192.168.1.100"
    
    def test_validate_ip_invalid(self, integration):
        """Test invalid IP raises error."""
        with pytest.raises(ValueError, match="Invalid IP address"):
            integration._validate_ip("999.999.999.999")
    
    def test_validate_name_success(self, integration):
        """Test valid name validation."""
        result = integration._validate_name("test-host")
        assert result == "test-host"
    
    def test_validate_name_with_spaces(self, integration):
        """Test name with spaces."""
        result = integration._validate_name("test host")
        assert result == "test host"
    
    def test_validate_name_empty(self, integration):
        """Test empty name raises error."""
        with pytest.raises(ValueError, match="name must be a non-empty string"):
            integration._validate_name("", "name")
    
    def test_validate_name_invalid_characters(self, integration):
        """Test name with invalid characters raises error."""
        with pytest.raises(ValueError, match="Invalid name format"):
            integration._validate_name("test@host!", "name")


# ============================================================================
# Test Connection Parameters
# ============================================================================
class TestConnectionParameters:
    """Test connection parameter validation."""
    
    def test_get_api_host_success(self, integration, connection_params):
        """Test successful API host retrieval."""
        host = integration._get_api_host(connection_params)
        assert host == "smc.example.com"
    
    def test_get_api_port_default(self, integration):
        """Test default port when not specified."""
        params = {"api_host": "smc.example.com"}
        port = integration._get_api_port(params)
        assert port == 8082
    
    def test_get_api_port_custom(self, integration, connection_params):
        """Test custom port."""
        port = integration._get_api_port(connection_params)
        assert port == 8082
    
    def test_get_verify_ssl_true(self, integration, connection_params):
        """Test SSL verification enabled."""
        verify = integration._get_verify_ssl(connection_params)
        assert verify is True
    
    def test_get_verify_ssl_false(self, integration):
        """Test SSL verification disabled."""
        params = {
            "api_host": "smc.example.com",
            "api_key": "test_key",
            "verify_ssl": "false"
        }
        verify = integration._get_verify_ssl(params)
        assert verify is False
    
    def test_get_api_key_success(self, integration, connection_params):
        """Test successful API key retrieval."""
        key = integration._get_api_key(connection_params)
        assert key == "test_api_key"
    
    def test_get_api_key_empty(self, integration):
        """Test empty API key raises error."""
        params = {"api_host": "smc.example.com"}
        with pytest.raises(ValueError, match="API key is required"):
            integration._get_api_key(params)


# ============================================================================
# Test HTTP Layer
# ============================================================================
class TestHTTPRequests:
    """Test HTTP request handling."""
    
    @patch('requests.Session.get')
    def test_request_success(self, mock_get, integration, connection_params):
        """Test successful GET request."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"name": "test-host", "uid": "12345"}]
        mock_get.return_value = mock_response
        
        status, response = integration._request(
            "GET",
            "/api/hosts",
            connection_params,
            "test_key"
        )
        
        assert status == 200
        assert len(response) == 1
    
    @patch('requests.Session.get')
    def test_request_401(self, mock_get, integration, connection_params):
        """Test 401 unauthorized response."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_get.return_value = mock_response
        
        with pytest.raises(ConnectionError, match="Authentication failed"):
            integration._request("GET", "/api/hosts", connection_params, "invalid_key")
    
    @patch('requests.Session.get')
    def test_request_403(self, mock_get, integration, connection_params):
        """Test 403 forbidden response."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = "Forbidden"
        mock_get.return_value = mock_response
        
        with pytest.raises(ConnectionError, match="Access forbidden"):
            integration._request("GET", "/api/hosts", connection_params, "test_key")
    
    @patch('requests.Session.get')
    def test_request_204_no_content(self, mock_get, integration, connection_params):
        """Test 204 No Content response."""
        mock_response = Mock()
        mock_response.status_code = 204
        mock_response.text = ""
        mock_get.return_value = mock_response
        
        status, response = integration._request(
            "GET",
            "/api/test",
            connection_params,
            "test_key"
        )
        
        assert status == 204
        assert response == {}


# ============================================================================
# Test Test Connection
# ============================================================================
class TestTestConnection:
    """Test test_connection action."""
    
    @patch.object(ForcepointSmc, '_request')
    def test_success(self, mock_request, integration):
        """Test successful connection."""
        mock_request.return_value = (200, [{"name": "host1", "uid": "123"}])
        
        params = {
            "api_host": "smc.example.com",
            "api_port": 8082,
            "api_key": "test_key"
        }
        
        response = integration.test_connection(params)
        
        assert response.status == "SUCCESS"
        assert "Connection successful" in response.message
    
    def test_connection_missing_api_key(self, integration):
        """Test connection without API key."""
        params = {
            "api_host": "smc.example.com",
            "api_port": 8082
        }
        
        response = integration.test_connection(params)
        
        assert response.status == "FAILURE"
        assert response.errorCode == "INVALID_CREDENTIALS"
    
    @patch.object(ForcepointSmc, '_request')
    def test_connection_failure(self, mock_request, integration):
        """Test connection failure."""
        mock_request.side_effect = ConnectionError("Connection refused")
        
        params = {
            "api_host": "smc.example.com",
            "api_port": 8082,
            "api_key": "test_key"
        }
        
        response = integration.test_connection(params)
        
        assert response.status == "FAILURE"
        assert response.errorCode == "CONNECTION_ERROR"


# ============================================================================
# Test Get Hosts
# ============================================================================
class TestGetHosts:
    """Test get_hosts action."""
    
    @patch.object(ForcepointSmc, '_request')
    def test_success(self, mock_request, integration):
        """Test successful host retrieval."""
        mock_request.return_value = (200, [
            {"name": "web-server", "uid": "12345", "ipaddr": "192.168.1.10", "type": "host"},
            {"name": "db-server", "uid": "12346", "ipaddr": "192.168.1.20", "type": "host"}
        ])
        
        request = RequestBody()
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.get_hosts(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 2
    
    @patch.object(ForcepointSmc, '_request')
    def test_empty_hosts(self, mock_request, integration):
        """Test host retrieval with no hosts."""
        mock_request.return_value = (200, [])
        
        request = RequestBody()
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.get_hosts(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 0


# ============================================================================
# Test Create Host
# ============================================================================
class TestCreateHost:
    """Test create_host action."""
    
    @patch.object(ForcepointSmc, '_request')
    def test_success(self, mock_request, integration):
        """Test successful host creation."""
        mock_request.return_value = (201, {"uid": "12345", "name": "test-host", "ipaddr": "192.168.1.10"})
        
        request = RequestBody()
        request.parameters = {"name": "test-host", "ipaddr": "192.168.1.10", "type": "host"}
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.create_host(request)
        
        assert response.status == "SUCCESS"
        assert response.output["uid"] == "12345"
    
    def test_create_host_missing_ip(self, integration):
        """Test host creation without IP address."""
        request = RequestBody()
        request.parameters = {"name": "test-host"}
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.create_host(request)
        
        assert response.status == "FAILURE"
        assert response.errorCode == "VALIDATION_ERROR"


# ============================================================================
# Test Update Host
# ============================================================================
class TestUpdateHost:
    """Test update_host action."""
    
    @patch.object(ForcepointSmc, '_request')
    def test_success(self, mock_request, integration):
        """Test successful host update."""
        mock_request.return_value = (200, {"uid": "12345"})
        
        request = RequestBody()
        request.parameters = {"uid": "12345", "name": "updated-host", "ipaddr": "192.168.1.100"}
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.update_host(request)
        
        assert response.status == "SUCCESS"
        assert response.output["uid"] == "12345"
    
    def test_update_host_missing_uid(self, integration):
        """Test host update without UID."""
        request = RequestBody()
        request.parameters = {"name": "updated-host"}
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.update_host(request)
        
        assert response.status == "FAILURE"
        assert response.errorCode == "VALIDATION_ERROR"


# ============================================================================
# Test Delete Host
# ============================================================================
class TestDeleteHost:
    """Test delete_host action."""
    
    @patch.object(ForcepointSmc, '_request')
    def test_success(self, mock_request, integration):
        """Test successful host deletion."""
        mock_request.return_value = (204, {})
        
        request = RequestBody()
        request.parameters = {"uid": "12345"}
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.delete_host(request)
        
        assert response.status == "SUCCESS"
        assert response.output["uid"] == "12345"
    
    def test_delete_host_missing_uid(self, integration):
        """Test host deletion without UID."""
        request = RequestBody()
        request.parameters = {}
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.delete_host(request)
        
        assert response.status == "FAILURE"
        assert response.errorCode == "VALIDATION_ERROR"


# ============================================================================
# Test Get Networks
# ============================================================================
class TestGetNetworks:
    """Test get_networks action."""
    
    @patch.object(ForcepointSmc, '_request')
    def test_success(self, mock_request, integration):
        """Test successful network retrieval."""
        mock_request.return_value = (200, [
            {"name": "internal", "uid": "12345", "subnet": "192.168.0.0", "cidr": "16", "type": "network"}
        ])
        
        request = RequestBody()
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.get_networks(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 1


# ============================================================================
# Test Create Network
# ============================================================================
class TestCreateNetwork:
    """Test create_network action."""
    
    @patch.object(ForcepointSmc, '_request')
    def test_success(self, mock_request, integration):
        """Test successful network creation."""
        mock_request.return_value = (201, {"uid": "12345", "name": "internal", "subnet": "192.168.0.0", "cidr": 16})
        
        request = RequestBody()
        request.parameters = {"name": "internal", "subnet": "192.168.0.0", "cidr": 16}
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.create_network(request)
        
        assert response.status == "SUCCESS"
        assert response.output["uid"] == "12345"
    
    def test_create_network_missing_subnet(self, integration):
        """Test network creation without subnet."""
        request = RequestBody()
        request.parameters = {"name": "internal"}
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.create_network(request)
        
        assert response.status == "FAILURE"
        assert response.errorCode == "VALIDATION_ERROR"


# ============================================================================
# Test Get Services
# ============================================================================
class TestGetServices:
    """Test get_services action."""
    
    @patch.object(ForcepointSmc, '_request')
    def test_success(self, mock_request, integration):
        """Test successful service retrieval."""
        mock_request.return_value = (200, [
            {"name": "http", "uid": "12345", "protocol": "tcp", "port": "80", "type": "service"}
        ])
        
        request = RequestBody()
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.get_services(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 1


# ============================================================================
# Test Create Service
# ============================================================================
class TestCreateService:
    """Test create_service action."""
    
    @patch.object(ForcepointSmc, '_request')
    def test_success(self, mock_request, integration):
        """Test successful service creation."""
        mock_request.return_value = (201, {"uid": "12345", "name": "custom-service"})
        
        request = RequestBody()
        request.parameters = {"name": "custom-service", "protocol": "tcp", "port": 8080}
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.create_service(request)
        
        assert response.status == "SUCCESS"
        assert response.output["uid"] == "12345"
    
    def test_create_service_missing_port(self, integration):
        """Test service creation without port."""
        request = RequestBody()
        request.parameters = {"name": "custom-service"}
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.create_service(request)
        
        assert response.status == "FAILURE"
        assert response.errorCode == "VALIDATION_ERROR"


# ============================================================================
# Test Get Policies
# ============================================================================
class TestGetPolicies:
    """Test get_policies action."""
    
    @patch.object(ForcepointSmc, '_request')
    def test_success(self, mock_request, integration):
        """Test successful policy retrieval."""
        mock_request.return_value = (200, [
            {"name": "default-policy", "uid": "12345", "type": "security", "engine_count": 2}
        ])
        
        request = RequestBody()
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.get_policies(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 1


# ============================================================================
# Test Get Policy Rules
# ============================================================================
class TestGetPolicyRules:
    """Test get_policy_rules action."""
    
    @patch.object(ForcepointSmc, '_request')
    def test_success(self, mock_request, integration):
        """Test successful rule retrieval."""
        mock_request.return_value = (200, [
            {"name": "allow-web", "uid": "12345", "source": "any", "destination": "web-servers", "service": "http", "action": "accept", "enabled": True}
        ])
        
        request = RequestBody()
        request.parameters = {"uid": "12345"}
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.get_policy_rules(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 1
    
    def test_get_policy_rules_missing_uid(self, integration):
        """Test rule retrieval without UID."""
        request = RequestBody()
        request.parameters = {}
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.get_policy_rules(request)
        
        assert response.status == "FAILURE"
        assert response.errorCode == "VALIDATION_ERROR"


# ============================================================================
# Test Search Unused Elements
# ============================================================================
class TestSearchUnusedElements:
    """Test search_unused_elements action."""
    
    @patch.object(ForcepointSmc, '_request')
    def test_success(self, mock_request, integration):
        """Test successful unused elements search."""
        mock_request.return_value = (200, [
            {"name": "old-host", "uid": "12345", "type": "host"}
        ])
        
        request = RequestBody()
        request.parameters = {"type": "host"}
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.search_unused_elements(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 1


# ============================================================================
# Test Search Duplicate IPs
# ============================================================================
class TestSearchDuplicateIps:
    """Test search_duplicate_ips action."""
    
    @patch.object(ForcepointSmc, '_request')
    def test_success(self, mock_request, integration):
        """Test successful duplicate IP search."""
        mock_request.return_value = (200, [
            {"ip": "192.168.1.10", "count": 2, "elements": ["host1", "host2"]}
        ])
        
        request = RequestBody()
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.search_duplicate_ips(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 1


# ============================================================================
# Test Get System Status
# ============================================================================
class TestGetSystemStatus:
    """Test get_system_status action."""
    
    @patch.object(ForcepointSmc, '_request')
    def test_success(self, mock_request, integration):
        """Test successful status retrieval."""
        mock_request.return_value = (200, {
            "uptime": 123456,
            "version": "7.0.0",
            "engines_connected": 2
        })
        
        request = RequestBody()
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.get_system_status(request)
        
        assert response.status == "SUCCESS"
        assert "status" in response.output


# ============================================================================
# Test Deploy Policy
# ============================================================================
class TestDeployPolicy:
    """Test deploy_policy action."""
    
    @patch.object(ForcepointSmc, '_request')
    def test_success(self, mock_request, integration):
        """Test successful policy deployment."""
        mock_request.return_value = (200, {
            "deployment_id": "abc123",
            "status": "in_progress"
        })
        
        request = RequestBody()
        request.parameters = {"uid": "policy-123", "engine_uids": ["engine-1", "engine-2"]}
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.deploy_policy(request)
        
        assert response.status == "SUCCESS"
        assert response.output["deployment_id"] == "abc123"
    
    def test_deploy_policy_missing_uid(self, integration):
        """Test policy deployment without UID."""
        request = RequestBody()
        request.parameters = {"engine_uids": ["engine-1"]}
        request.connectionParameters = {"api_key": "test_key"}
        
        response = integration.deploy_policy(request)
        
        assert response.status == "FAILURE"
        assert response.errorCode == "VALIDATION_ERROR"
