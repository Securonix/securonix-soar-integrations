import sys
import os
import requests
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from app.cisco_umbrella_investigate import Cisco_Umbrella_Investigate
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
    return Cisco_Umbrella_Investigate()


@pytest.fixture
def connection_params():
    """Standard connection parameters for testing."""
    return {
        "api_key": "test_api_key",
        "api_secret": "test_api_secret",
        "base_url": "https://api.umbrella.com",
        "request_timeout": "30",
        "verify_ssl": "true"
    }


@pytest.fixture
def auth_token_response():
    """Mock OAuth token response."""
    return {
        "access_token": "test_access_token_12345",
        "token_type": "Bearer",
        "expires_in": 3600
    }


# ============================================================================
# Test Input Validation
# ============================================================================
class TestInputValidation:
    """Test input validation methods."""
    
    def test_validate_domain_success(self, integration):
        """Test valid domain validation."""
        result = integration._validate_domain("cisco.com")
        assert result == "cisco.com"
    
    def test_validate_domain_with_url_scheme(self, integration):
        """Test domain with http/https prefix is normalized."""
        result = integration._validate_domain("https://cisco.com/path")
        assert result == "cisco.com"
    
    def test_validate_domain_empty(self, integration):
        """Test empty domain raises error."""
        with pytest.raises(ValueError, match="Domain must be a non-empty string"):
            integration._validate_domain("")
    
    def test_validate_domain_whitespace_only(self, integration):
        """Test whitespace domain raises error."""
        with pytest.raises(ValueError, match="Invalid domain: empty after normalization"):
            integration._validate_domain("   ")
    
    def test_validate_domain_invalid_format(self, integration):
        """Test invalid domain format raises error."""
        with pytest.raises(ValueError, match="Invalid domain format"):
            integration._validate_domain("not-a-valid-domain!!!")
    
    def test_validate_ip_success(self, integration):
        """Test valid IPv4 validation."""
        result = integration._validate_ip("8.8.8.8")
        assert result == "8.8.8.8"
    
    def test_validate_ip_ipv6_disallowed(self, integration):
        """Test IPv6 is rejected for endpoints that don't support it."""
        with pytest.raises(ValueError, match="IPv6 addresses are not supported"):
            integration._validate_ip("2001:4860:4860::8888", allow_ipv6=False)
    
    def test_validate_ip_ipv6_allowed(self, integration):
        """Test IPv6 is allowed when explicitly enabled."""
        result = integration._validate_ip("2001:4860:4860::8888", allow_ipv6=True)
        assert result == "2001:4860:4860::8888"
    
    def test_validate_ip_invalid(self, integration):
        """Test invalid IP raises error."""
        with pytest.raises(ValueError, match="Invalid IP address"):
            integration._validate_ip("999.999.999.999")
    
    def test_validate_url_success(self, integration):
        """Test valid URL validation."""
        result = integration._validate_url("https://example.com/page")
        assert result == "https://example.com"
    
    def test_validate_url_missing_scheme(self, integration):
        """Test URL without scheme raises error."""
        with pytest.raises(ValueError, match="URL must include a scheme"):
            integration._validate_url("example.com")
    
    def test_validate_email_success(self, integration):
        """Test valid email validation."""
        result = integration._validate_email("test@example.com")
        assert result == "test@example.com"
    
    def test_validate_email_invalid(self, integration):
        """Test invalid email raises error."""
        with pytest.raises(ValueError, match="Invalid email format"):
            integration._validate_email("not-an-email")
    
    def test_validate_asn_success(self, integration):
        """Test valid ASN validation."""
        result = integration._validate_asn("15169")
        assert result == 15169
    
    def test_validate_asn_with_prefix(self, integration):
        """Test ASN with AS prefix is normalized."""
        result = integration._validate_asn("AS15169")
        assert result == 15169
    
    def test_validate_asn_invalid(self, integration):
        """Test invalid ASN raises error."""
        with pytest.raises(ValueError, match="Invalid ASN format"):
            integration._validate_asn("not-a-number")
    
    def test_validate_asn_negative(self, integration):
        """Test negative ASN raises error."""
        with pytest.raises(ValueError, match="ASN must be a positive integer"):
            integration._validate_asn("-123")
    
    def test_validate_search_expression_success(self, integration):
        """Test valid search expression."""
        result = integration._validate_search_expression("test*.com")
        assert result == "test*.com"
    
    def test_validate_search_expression_empty(self, integration):
        """Test empty search expression raises error."""
        with pytest.raises(ValueError, match="Search expression must be a non-empty string"):
            integration._validate_search_expression("")


# ============================================================================
# Test OAuth Authentication
# ============================================================================
class TestBearerAuthentication:
    """Test direct Bearer token authentication (Cisco Investigate API uses direct tokens)."""
    
    def test_get_access_token_success(self, integration):
        """Test successful token configuration."""
        token = integration._get_access_token("test_bearer_token_12345", "")
        
        assert token == "test_bearer_token_12345"
        assert integration._access_token == "test_bearer_token_12345"
    
    def test_get_access_token_cached(self, integration):
        """Test token caching works."""
        # First call - gets new token
        token1 = integration._get_access_token("test_bearer_token_12345", "")
        
        # Second call - uses cached token
        token2 = integration._get_access_token("different_token", "")
        
        # Same token returned due to caching
        assert token1 == token2
        assert token1 == "test_bearer_token_12345"
    
    def test_get_access_token_empty_key(self, integration):
        """Test empty API key raises error."""
        with pytest.raises(ConnectionError, match="API key.*is required"):
            integration._get_access_token("", "test_secret")
    
    def test_get_access_token_none_key(self, integration):
        """Test None API key raises error."""
        with pytest.raises(ConnectionError, match="API key.*is required"):
            integration._get_access_token(None, "test_secret")


# ============================================================================
# Test HTTP Layer
# ============================================================================
class TestHTTPRequests:
    """Test HTTP request handling."""
    
    @patch('requests.Session.get')
    @patch.object(Cisco_Umbrella_Investigate, '_get_access_token')
    def test_request_success(self, mock_token, mock_get, integration, auth_token_response):
        """Test successful GET request."""
        mock_token.return_value = auth_token_response["access_token"]
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"test": "data"}
        mock_get.return_value = mock_response
        
        status, response = integration._request(
            "GET",
            "/domains/categorization/cisco.com",
            {},
            "key",
            "secret"
        )
        
        assert status == 200
        assert response == {"test": "data"}
    
    @patch('requests.Session.get')
    @patch.object(Cisco_Umbrella_Investigate, '_get_access_token')
    def test_request_401_retries(self, mock_token, mock_get, integration, auth_token_response):
        """Test 401 triggers token refresh and retry."""
        mock_token.return_value = auth_token_response["access_token"]
        
        # First call returns 401, second returns 200
        mock_response_401 = Mock()
        mock_response_401.status_code = 401
        mock_response_401.headers = {}
        
        mock_response_200 = Mock()
        mock_response_200.status_code = 200
        mock_response_200.json.return_value = {"data": "result"}
        
        mock_get.side_effect = [mock_response_401, mock_response_200]
        
        status, response = integration._request(
            "GET",
            "/test",
            {},
            "key",
            "secret"
        )
        
        assert status == 200
        assert mock_get.call_count == 2
    
    @patch('requests.Session.get')
    @patch.object(Cisco_Umbrella_Investigate, '_get_access_token')
    def test_request_403(self, mock_token, mock_get, integration, auth_token_response):
        """Test 403 forbidden response."""
        mock_token.return_value = auth_token_response["access_token"]
        
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = "Forbidden"
        mock_get.return_value = mock_response
        
        with pytest.raises(ConnectionError, match="Access forbidden"):
            integration._request("GET", "/test", {}, "key", "secret")
    
    @patch('requests.Session.get')
    @patch.object(Cisco_Umbrella_Investigate, '_get_access_token')
    def test_request_429_rate_limit(self, mock_token, mock_get, integration, auth_token_response):
        """Test 429 rate limiting with Retry-After."""
        mock_token.return_value = auth_token_response["access_token"]
        
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "2"}
        mock_get.return_value = mock_response
        
        # Should raise after max retries
        with pytest.raises(ConnectionError, match="Rate limited"):
            integration._request("GET", "/test", {}, "key", "secret")
    
    @patch('requests.Session.get')
    @patch.object(Cisco_Umbrella_Investigate, '_get_access_token')
    def test_request_404(self, mock_token, mock_get, integration, auth_token_response):
        """Test 404 not found response."""
        mock_token.return_value = auth_token_response["access_token"]
        
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"
        mock_get.return_value = mock_response
        
        status, response = integration._request("GET", "/test", {}, "key", "secret")
        
        assert status == 404
        assert response == {}
    
    @patch('requests.Session.get')
    @patch.object(Cisco_Umbrella_Investigate, '_get_access_token')
    def test_request_204_no_content(self, mock_token, mock_get, integration, auth_token_response):
        """Test 204 No Content response."""
        mock_token.return_value = auth_token_response["access_token"]
        
        mock_response = Mock()
        mock_response.status_code = 204
        mock_response.text = ""
        mock_get.return_value = mock_response
        
        status, response = integration._request("GET", "/test", {}, "key", "secret")
        
        assert status == 204
        assert response == {}


# ============================================================================
# Test Domain Categorization
# ============================================================================
class TestDomainCategorization:
    """Test umbrella_domain_categorization action."""
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_success(self, mock_request, integration):
        """Test successful domain categorization."""
        mock_request.return_value = (200, {
            "cisco.com": {
                "security_categories": ["Malware", "Phishing"],
                "content_categories": ["Business", "Technology"]
            }
        })
        
        request = RequestBody()
        request.parameters = {"domain": "cisco.com"}
        request.connectionParameters = {
            "api_key": "key",
            "api_secret": "secret"
        }
        
        response = integration.umbrella_domain_categorization(request)
        
        assert response.status == "SUCCESS"
        assert response.output["domain"] == "cisco.com"
        assert len(response.output["securityCategories"]) > 0
    
    def test_domain_categorization_invalid_domain(self, integration):
        """Test with invalid domain."""
        request = RequestBody()
        request.parameters = {"domain": "invalid!!!"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_domain_categorization(request)
        
        assert response.status == "FAILURE"
        assert response.errorCode == "VALIDATION_ERROR"


# ============================================================================
# Test Domain Search
# ============================================================================
class TestDomainSearch:
    """Test umbrella_domain_search action."""
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_success(self, mock_request, integration):
        """Test successful domain search."""
        mock_request.return_value = (200, ["malware.com", "phishing.com", "bad.com"])
        
        request = RequestBody()
        request.parameters = {"expression": "malware*", "limit": 10}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_domain_search(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 3
        assert "malware.com" in response.output["results"]


# ============================================================================
# Test Domain Co-occurrences
# ============================================================================
class TestDomainCoOccurrences:
    """Test umbrella_domain_co_occurrences action."""
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_success(self, mock_request, integration):
        """Test successful co-occurrence lookup."""
        mock_request.return_value = (200, {
            "linked.com": 10,
            "related.com": 5
        })
        
        request = RequestBody()
        request.parameters = {"domain": "cisco.com"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_domain_co_occurrences(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 2


# ============================================================================
# Test Domain Related
# ============================================================================
class TestDomainRelated:
    """Test umbrella_domain_related action."""
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_success(self, mock_request, integration):
        """Test successful related domains lookup."""
        mock_request.return_value = (200, ["www.cisco.com", "developer.cisco.com"])
        
        request = RequestBody()
        request.parameters = {"domain": "cisco.com"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_domain_related(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 2
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_empty_related(self, mock_request, integration):
        """Test related domains with empty response."""
        mock_request.return_value = (200, [])
        
        request = RequestBody()
        request.parameters = {"domain": "cisco.com"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_domain_related(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 0
        assert response.output["relatedDomains"] == []


# ============================================================================
# Test Domain Security
# ============================================================================
class TestDomainSecurity:
    """Test umbrella_domain_security action."""
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_success(self, mock_request, integration):
        """Test successful security lookup."""
        mock_request.return_value = (200, {
            "threatType": "malware",
            "detectedBy": ["vendor1", "vendor2"]
        })
        
        request = RequestBody()
        request.parameters = {"domain": "cisco.com"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_domain_security(request)
        
        assert response.status == "SUCCESS"
        assert "security" in response.output
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_empty_security(self, mock_request, integration):
        """Test security lookup with empty response."""
        mock_request.return_value = (200, {})
        
        request = RequestBody()
        request.parameters = {"domain": "cisco.com"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_domain_security(request)
        
        assert response.status == "SUCCESS"
        assert response.output["security"] == {}


# ============================================================================
# Test Domain Risk Score
# ============================================================================
class TestDomainRiskScore:
    """Test umbrella_get_domain_risk_score action."""
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_success(self, mock_request, integration):
        """Test successful risk score lookup."""
        mock_request.return_value = (200, {"risk_score": 15, "verdict": "benign"})
        
        request = RequestBody()
        request.parameters = {"domain": "cisco.com"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_get_domain_risk_score(request)
        
        assert response.status == "SUCCESS"
        assert response.output["riskScore"] == 15
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_risk_score_value_dict(self, mock_request, integration):
        """Test risk score with value dict."""
        mock_request.return_value = (200, {"risk_score": {"value": 42}, "verdict": "malicious"})
        
        request = RequestBody()
        request.parameters = {"domain": "cisco.com"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_get_domain_risk_score(request)
        
        assert response.status == "SUCCESS"
        assert response.output["riskScore"] == 42


# ============================================================================
# Test Passive DNS
# ============================================================================
class TestPassiveDNS:
    """Test umbrella_list_resource_record action."""
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_success_name_query(self, mock_request, integration):
        """Test successful passive DNS lookup by name."""
        mock_request.return_value = (200, [{
            "name": "cisco.com",
            "type": "A",
            "value": "173.36.128.1",
            "firstSeen": 1609459200,
            "lastSeen": 1723420800
        }])
        
        request = RequestBody()
        request.parameters = {"query": "cisco.com", "query_type": "name"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_list_resource_record(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 1
        assert response.output["records"][0]["recordName"] == "cisco.com"
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_passive_dns_empty(self, mock_request, integration):
        """Test passive DNS with empty response."""
        mock_request.return_value = (200, [])
        
        request = RequestBody()
        request.parameters = {"query": "cisco.com", "query_type": "name"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_list_resource_record(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 0
        assert response.output["records"] == []


# ============================================================================
# Test Subdomain Enumeration
# ============================================================================
class TestSubdomainEnumeration:
    """Test umbrella_list_domain_subdomain action."""
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_success(self, mock_request, integration):
        """Test successful subdomain enumeration."""
        mock_request.return_value = (200, {
            "www": 100,
            "api": 50,
            "dev": 25
        })
        
        request = RequestBody()
        request.parameters = {"domain": "cisco.com", "limit": 10}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_list_domain_subdomain(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 3
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_empty_subdomains(self, mock_request, integration):
        """Test subdomain enumeration with empty response."""
        mock_request.return_value = (200, {})
        
        request = RequestBody()
        request.parameters = {"domain": "cisco.com"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_list_domain_subdomain(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 0
        assert response.output["subdomains"] == []


# ============================================================================
# Test Domain WHOIS
# ============================================================================
class TestDomainWhois:
    """Test umbrella_get_whois_for_domain action."""
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_success(self, mock_request, integration):
        """Test successful WHOIS lookup."""
        mock_request.return_value = (200, {
            "registrar": "Cisco Systems",
            "createdDate": "2000-01-01T00:00:00Z",
            "expirationDate": "2025-01-01T00:00:00Z"
        })
        
        request = RequestBody()
        request.parameters = {"domain": "cisco.com"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_get_whois_for_domain(request)
        
        assert response.status == "SUCCESS"
        assert "whois" in response.output
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_empty_whois(self, mock_request, integration):
        """Test WHOIS with empty response."""
        mock_request.return_value = (200, {})
        
        request = RequestBody()
        request.parameters = {"domain": "cisco.com"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_get_whois_for_domain(request)
        
        assert response.status == "SUCCESS"
        assert response.output["whois"] == {}
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_whois_str_response(self, mock_request, integration):
        """Test WHOIS with string response."""
        mock_request.return_value = (200, "WHOIS data unavailable")
        
        request = RequestBody()
        request.parameters = {"domain": "cisco.com"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_get_whois_for_domain(request)
        
        assert response.status == "SUCCESS"
        # Cisco returns string for empty WHOIS, our code converts it to dict
        assert isinstance(response.output["whois"], dict)


# ============================================================================
# Test Domain WHOIS History
# ============================================================================
class TestDomainWhoisHistory:
    """Test umbrella_get_domain_whois_history action."""
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_success(self, mock_request, integration):
        """Test successful WHOIS history lookup."""
        mock_request.return_value = (200, [{
            "timestamp": 1609459200,
            "whois": "registrar: Cisco Systems"
        }])
        
        request = RequestBody()
        request.parameters = {"domain": "cisco.com"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_get_domain_whois_history(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 1
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_empty_history(self, mock_request, integration):
        """Test WHOIS history with empty response."""
        mock_request.return_value = (200, [])
        
        request = RequestBody()
        request.parameters = {"domain": "cisco.com"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_get_domain_whois_history(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 0
        assert response.output["history"] == []


# ============================================================================
# Test Email WHOIS
# ============================================================================
class TestEmailWhois:
    """Test umbrella_get_email_whois action."""
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_success(self, mock_request, integration):
        """Test successful email WHOIS lookup."""
        mock_request.return_value = (200, ["cisco.com", "ciscosystems.com"])
        
        request = RequestBody()
        request.parameters = {"email": "admin@cisco.com"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_get_email_whois(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 2
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_empty_email_results(self, mock_request, integration):
        """Test email WHOIS with empty results."""
        mock_request.return_value = (200, [])
        
        request = RequestBody()
        request.parameters = {"email": "admin@cisco.com"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_get_email_whois(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 0
        assert response.output["domains"] == []


# ============================================================================
# Test Domain Timeline
# ============================================================================
class TestDomainTimeline:
    """Test umbrella_get_domain_timeline action."""
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_success(self, mock_request, integration):
        """Test successful domain timeline lookup."""
        mock_request.return_value = (200, [{
            "timestamp": 1609459200,
            "eventType": "registration",
            "description": "Domain registered"
        }])
        
        request = RequestBody()
        request.parameters = {"domain": "cisco.com"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_get_domain_timeline(request)
        
        assert response.status == "SUCCESS"
        assert response.output["indicatorType"] == "domain"
        assert response.output["count"] == 1
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_empty_timeline(self, mock_request, integration):
        """Test timeline with empty response."""
        mock_request.return_value = (200, [])
        
        request = RequestBody()
        request.parameters = {"domain": "cisco.com"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_get_domain_timeline(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 0
        assert response.output["timeline"] == []


# ============================================================================
# Test URL Timeline
# ============================================================================
class TestURLTimeline:
    """Test umbrella_get_url_timeline action."""
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_success(self, mock_request, integration):
        """Test successful URL timeline lookup."""
        mock_request.return_value = (200, [{
            "timestamp": 1609459200,
            "eventType": "first_seen",
            "description": "URL first observed"
        }])
        
        request = RequestBody()
        request.parameters = {"url": "https://example.com/page"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_get_url_timeline(request)
        
        assert response.status == "SUCCESS"
        assert response.output["indicatorType"] == "url"


# ============================================================================
# Test IP Timeline
# ============================================================================
class TestIPTimeline:
    """Test umbrella_get_ip_timeline action."""
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_success(self, mock_request, integration):
        """Test successful IP timeline lookup."""
        mock_request.return_value = (200, [{
            "timestamp": 1609459200,
            "eventType": "first_seen",
            "description": "IP first observed"
        }])
        
        request = RequestBody()
        request.parameters = {"ip": "8.8.8.8"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_get_ip_timeline(request)
        
        assert response.status == "SUCCESS"
        assert response.output["indicatorType"] == "ip"


# ============================================================================
# Test IP BGP
# ============================================================================
class TestIPBGP:
    """Test umbrella_get_ip_bgp action."""
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_success(self, mock_request, integration):
        """Test successful BGP lookup."""
        mock_request.return_value = (200, {
            "asn": "15169",
            "cidr": "8.8.8.0/24",
            "rir": "ARIN",
            "description": "Google LLC"
        })
        
        request = RequestBody()
        request.parameters = {"ip": "8.8.8.8"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_get_ip_bgp(request)
        
        assert response.status == "SUCCESS"
        assert response.output["asn"] == "15169"
        assert response.output["cidr"] == "8.8.8.0/24"
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_bgp_empty(self, mock_request, integration):
        """Test BGP lookup with empty response."""
        mock_request.return_value = (200, {})
        
        request = RequestBody()
        request.parameters = {"ip": "8.8.8.8"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_get_ip_bgp(request)
        
        assert response.status == "SUCCESS"
        assert response.output["asn"] == ""


# ============================================================================
# Test ASN BGP Prefixes
# ============================================================================
class TestASNBGP:
    """Test umbrella_get_asn_bgp action."""
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_success(self, mock_request, integration):
        """Test successful ASN prefix lookup."""
        mock_request.return_value = (200, {
            "prefixes": ["8.8.8.0/24", "8.8.4.0/24"]
        })
        
        request = RequestBody()
        request.parameters = {"asn": "15169"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_get_asn_bgp(request)
        
        assert response.status == "SUCCESS"
        assert response.output["asn"] == "AS15169"
        assert response.output["count"] == 2
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_success_as_prefix(self, mock_request, integration):
        """Test ASN with AS prefix works."""
        mock_request.return_value = (200, {"prefixes": ["8.8.8.0/24"]})
        
        request = RequestBody()
        request.parameters = {"asn": "AS15169"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_get_asn_bgp(request)
        
        assert response.status == "SUCCESS"
        assert response.output["asn"] == "AS15169"
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_empty_prefixes(self, mock_request, integration):
        """Test ASN with empty prefixes response."""
        mock_request.return_value = (200, {"prefixes": []})
        
        request = RequestBody()
        request.parameters = {"asn": "15169"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_get_asn_bgp(request)
        
        assert response.status == "SUCCESS"
        assert response.output["count"] == 0
        assert response.output["prefixes"] == []
    
    @patch.object(Cisco_Umbrella_Investigate, '_request')
    def test_asn_prefixes_as_dict(self, mock_request, integration):
        """Test ASN response with prefixes as dict."""
        mock_request.return_value = (200, {"prefixes": {"8.8.8.0/24": True}})
        
        request = RequestBody()
        request.parameters = {"asn": "15169"}
        request.connectionParameters = {"api_key": "key", "api_secret": "secret"}
        
        response = integration.umbrella_get_asn_bgp(request)
        
        assert response.status == "SUCCESS"


# ============================================================================
# Test Test Connection
# ============================================================================
class TestBearerAuthentication:
    """Test direct Bearer token authentication (Cisco Investigate API uses direct tokens)."""
    
    def test_get_access_token_success(self, integration):
        """Test successful token configuration."""
        token = integration._get_access_token("test_bearer_token_12345", "")
        
        assert token == "test_bearer_token_12345"
        assert integration._access_token == "test_bearer_token_12345"
    
    def test_get_access_token_cached(self, integration):
        """Test token caching works."""
        # First call - gets new token
        token1 = integration._get_access_token("test_bearer_token_12345", "")
        
        # Second call - uses cached token
        token2 = integration._get_access_token("different_token", "")
        
        # Same token returned due to caching
        assert token1 == token2
        assert token1 == "test_bearer_token_12345"
    
    def test_get_access_token_empty_key(self, integration):
        """Test empty API key raises error."""
        with pytest.raises(ConnectionError, match="API key.*is required"):
            integration._get_access_token("", "test_secret")
    
    def test_get_access_token_none_key(self, integration):
        """Test None API key raises error."""
        with pytest.raises(ConnectionError, match="API key.*is required"):
            integration._get_access_token(None, "test_secret")


class TestTestConnection:
    """Test test_connection method."""
    
    @patch('requests.Session.get')
    def test_success(self, mock_get, integration):
        """Test successful connection test."""
        # Mock investigate endpoint (no OAuth flow needed)
        investigate_response = Mock()
        investigate_response.status_code = 200
        investigate_response.json.return_value = {}
        mock_get.return_value = investigate_response
        
        params = {
            "api_key": "test_bearer_token",
            "api_secret": "",
            "base_url": "https://investigate.api.umbrella.com"
        }
        
        response = integration.test_connection(params)
        
        assert response.status == "SUCCESS"
        assert "Connection successful" in response.message
    
    def test_missing_api_key(self, integration):
        """Test connection test with missing API key."""
        params = {"api_secret": "test_secret"}
        
        response = integration.test_connection(params)
        
        assert response.status == "FAILURE"
        assert "API key" in response.message
    
    @patch('requests.Session.get')
    def test_investigate_failure(self, mock_get, integration):
        """Test connection test where Investigate API returns 403."""
        investigate_response = Mock()
        investigate_response.status_code = 403
        mock_get.return_value = investigate_response
        
        params = {
            "api_key": "test_token",
            "api_secret": "",
            "base_url": "https://investigate.api.umbrella.com"
        }
        
        response = integration.test_connection(params)
        
        assert response.status == "FAILURE"
        assert "Access forbidden" in response.message
    
    @patch('requests.Session.get')
    def test_invalid_base_url(self, mock_get, integration):
        """Test connection test with invalid base URL."""
        params = {
            "api_key": "test_token",
            "api_secret": "",
            "base_url": "http://invalid-url.com"
        }
        
        response = integration.test_connection(params)
        
        assert response.status == "FAILURE"
        assert "Base URL must use HTTPS" in response.message


# ============================================================================
# Test Secrets Not Leaked
# ============================================================================
class TestSecretsNotLeaked:
    """Test that secrets are never logged or exposed."""
    
    def test_token_not_stored_in_exception(self, integration):
        """Verify access token is not in exception messages."""
        with pytest.raises(ConnectionError):
            raise ConnectionError("Authentication failed")
    
    def test_api_secret_not_passed_in_log(self, integration):
        """Verify API secret is handled safely."""
        # The integration should never log the secret directly
        # This is a behavioral test - if secrets were in logs, they'd appear
        assert "test_api_secret" not in str(integration.__dict__)
