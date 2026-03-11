import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.model.request_body import RequestBody
from pykson import Pykson
import json
from unittest.mock import patch, MagicMock
import unittest
from app.skyboxsecurity import Skyboxsecurity


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

BASE_URL = "https://skybox.example.com"
USERNAME = "admin"
PASSWORD = "password123"
MOCK_TOKEN = "mock-auth-token"

CONNECTION_PARAMS = {
    "base_url": BASE_URL,
    "username": USERNAME,
    "password": PASSWORD
}


def make_request(parameters: dict):
    """Build a mock RequestBody with connectionParameters and parameters."""
    req = MagicMock()
    req.connectionParameters = CONNECTION_PARAMS
    req.parameters = parameters
    return req


def mock_login_response():
    """Return a mock successful login response."""
    resp = MagicMock()
    resp.json.return_value = {"token": MOCK_TOKEN}
    resp.raise_for_status = MagicMock()
    return resp


def mock_api_response(data: dict):
    """Return a mock successful API response."""
    resp = MagicMock()
    resp.json.return_value = data
    resp.raise_for_status = MagicMock()
    return resp


# -------------------------------------------------------------------
# Test Class
# -------------------------------------------------------------------

class TestSkyboxsecurity(unittest.TestCase):

    def setUp(self):
        self.connector = Skyboxsecurity()

    # -------------------------------------------------------------------
    # test_connection
    # -------------------------------------------------------------------

    @patch("app.skyboxsecurity.requests.post")
    def test_connection_success(self, mock_post):
        mock_post.return_value = mock_login_response()

        result = self.connector.test_connection(CONNECTION_PARAMS)

        self.assertEqual(result["status"], "success")
        self.assertIn("Connected to Skybox Security successfully", result["message"])

    @patch("app.skyboxsecurity.requests.post")
    def test_connection_no_token(self, mock_post):
        resp = MagicMock()
        resp.json.return_value = {}  # no token in response
        resp.raise_for_status = MagicMock()
        mock_post.return_value = resp

        with self.assertRaises(Exception) as ctx:
            self.connector.test_connection(CONNECTION_PARAMS)
        self.assertIn("Failed to retrieve auth token", str(ctx.exception))

    @patch("app.skyboxsecurity.requests.post")
    def test_connection_http_error(self, mock_post):
        mock_post.side_effect = Exception("Connection refused")

        with self.assertRaises(Exception) as ctx:
            self.connector.test_connection(CONNECTION_PARAMS)
        self.assertIn("Connection refused", str(ctx.exception))

    # -------------------------------------------------------------------
    # get_threat_alerts
    # -------------------------------------------------------------------

    @patch("app.skyboxsecurity.requests.get")
    @patch("app.skyboxsecurity.requests.post")
    def test_get_threat_alerts_success(self, mock_post, mock_get):
        mock_post.return_value = mock_login_response()
        alerts = [{"id": 1, "severity": "HIGH", "description": "Threat detected"}]
        mock_get.return_value = mock_api_response(alerts)

        request = make_request({"severity": "HIGH", "limit": 10})
        result = self.connector.get_threat_alerts(request)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"], alerts)

    @patch("app.skyboxsecurity.requests.get")
    @patch("app.skyboxsecurity.requests.post")
    def test_get_threat_alerts_no_filters(self, mock_post, mock_get):
        mock_post.return_value = mock_login_response()
        mock_get.return_value = mock_api_response([])

        request = make_request({})
        result = self.connector.get_threat_alerts(request)

        self.assertEqual(result["status"], "success")

    @patch("app.skyboxsecurity.requests.post")
    def test_get_threat_alerts_login_failure(self, mock_post):
        mock_post.side_effect = Exception("Auth failed")

        request = make_request({"severity": "HIGH"})
        with self.assertRaises(Exception) as ctx:
            self.connector.get_threat_alerts(request)
        self.assertIn("Auth failed", str(ctx.exception))

    # -------------------------------------------------------------------
    # get_vulnerabilities
    # -------------------------------------------------------------------

    @patch("app.skyboxsecurity.requests.get")
    @patch("app.skyboxsecurity.requests.post")
    def test_get_vulnerabilities_success(self, mock_post, mock_get):
        mock_post.return_value = mock_login_response()
        vulns = [{"cve": "CVE-2024-1234", "severity": "CRITICAL"}]
        mock_get.return_value = mock_api_response(vulns)

        request = make_request({"asset_ip": "192.168.1.10", "severity": "CRITICAL"})
        result = self.connector.get_vulnerabilities(request)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"], vulns)

    @patch("app.skyboxsecurity.requests.get")
    @patch("app.skyboxsecurity.requests.post")
    def test_get_vulnerabilities_no_filters(self, mock_post, mock_get):
        mock_post.return_value = mock_login_response()
        mock_get.return_value = mock_api_response([])

        request = make_request({})
        result = self.connector.get_vulnerabilities(request)

        self.assertEqual(result["status"], "success")

    @patch("app.skyboxsecurity.requests.post")
    def test_get_vulnerabilities_api_error(self, mock_post):
        mock_post.side_effect = Exception("API error")

        request = make_request({"asset_ip": "10.0.0.1"})
        with self.assertRaises(Exception) as ctx:
            self.connector.get_vulnerabilities(request)
        self.assertIn("API error", str(ctx.exception))

    # -------------------------------------------------------------------
    # get_exposed_vulnerabilities
    # -------------------------------------------------------------------

    @patch("app.skyboxsecurity.requests.get")
    @patch("app.skyboxsecurity.requests.post")
    def test_get_exposed_vulnerabilities_success(self, mock_post, mock_get):
        mock_post.return_value = mock_login_response()
        exposed = [{"cve": "CVE-2024-5678", "exposed": True}]
        mock_get.return_value = mock_api_response(exposed)

        request = make_request({"asset_ip": "10.0.0.5", "limit": 50})
        result = self.connector.get_exposed_vulnerabilities(request)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"], exposed)

    @patch("app.skyboxsecurity.requests.post")
    def test_get_exposed_vulnerabilities_missing_asset_ip(self, mock_post):
        mock_post.return_value = mock_login_response()

        request = make_request({})  # asset_ip is required
        with self.assertRaises(KeyError):
            self.connector.get_exposed_vulnerabilities(request)

    # -------------------------------------------------------------------
    # get_network_access_rules
    # -------------------------------------------------------------------

    @patch("app.skyboxsecurity.requests.get")
    @patch("app.skyboxsecurity.requests.post")
    def test_get_network_access_rules_success(self, mock_post, mock_get):
        mock_post.return_value = mock_login_response()
        rules = [{"rule": "allow", "source": "10.0.0.1", "destination": "10.0.0.2"}]
        mock_get.return_value = mock_api_response(rules)

        request = make_request({
            "firewall_name": "FW-01",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2"
        })
        result = self.connector.get_network_access_rules(request)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"], rules)

    @patch("app.skyboxsecurity.requests.get")
    @patch("app.skyboxsecurity.requests.post")
    def test_get_network_access_rules_no_filters(self, mock_post, mock_get):
        mock_post.return_value = mock_login_response()
        mock_get.return_value = mock_api_response([])

        request = make_request({})
        result = self.connector.get_network_access_rules(request)

        self.assertEqual(result["status"], "success")

    # -------------------------------------------------------------------
    # run_attack_simulation
    # -------------------------------------------------------------------

    @patch("app.skyboxsecurity.requests.post")
    def test_run_attack_simulation_success(self, mock_post):
        mock_post.side_effect = [
            mock_login_response(),
            mock_api_response({"reachable": True, "path": ["router1", "fw1"]})
        ]

        request = make_request({
            "source_ip": "10.0.0.1",
            "destination_ip": "192.168.1.100",
            "port": "443",
            "protocol": "TCP"
        })
        result = self.connector.run_attack_simulation(request)

        self.assertEqual(result["status"], "success")
        self.assertTrue(result["results"]["reachable"])

    @patch("app.skyboxsecurity.requests.post")
    def test_run_attack_simulation_default_protocol(self, mock_post):
        mock_post.side_effect = [
            mock_login_response(),
            mock_api_response({"reachable": False})
        ]

        request = make_request({
            "source_ip": "10.0.0.1",
            "destination_ip": "192.168.1.100"
        })
        result = self.connector.run_attack_simulation(request)

        self.assertEqual(result["status"], "success")

    @patch("app.skyboxsecurity.requests.post")
    def test_run_attack_simulation_missing_required_params(self, mock_post):
        mock_post.return_value = mock_login_response()

        request = make_request({"source_ip": "10.0.0.1"})  # destination_ip missing
        with self.assertRaises(KeyError):
            self.connector.run_attack_simulation(request)

    # -------------------------------------------------------------------
    # get_security_policy_violations
    # -------------------------------------------------------------------

    @patch("app.skyboxsecurity.requests.get")
    @patch("app.skyboxsecurity.requests.post")
    def test_get_security_policy_violations_success(self, mock_post, mock_get):
        mock_post.return_value = mock_login_response()
        violations = [{"policy": "PCI-DSS", "severity": "HIGH", "asset": "10.0.0.5"}]
        mock_get.return_value = mock_api_response(violations)

        request = make_request({"policy_name": "PCI-DSS", "severity": "HIGH"})
        result = self.connector.get_security_policy_violations(request)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"], violations)

    @patch("app.skyboxsecurity.requests.get")
    @patch("app.skyboxsecurity.requests.post")
    def test_get_security_policy_violations_no_filters(self, mock_post, mock_get):
        mock_post.return_value = mock_login_response()
        mock_get.return_value = mock_api_response([])

        request = make_request({})
        result = self.connector.get_security_policy_violations(request)

        self.assertEqual(result["status"], "success")

    # -------------------------------------------------------------------
    # get_asset_risk_score
    # -------------------------------------------------------------------

    @patch("app.skyboxsecurity.requests.get")
    @patch("app.skyboxsecurity.requests.post")
    def test_get_asset_risk_score_success(self, mock_post, mock_get):
        mock_post.return_value = mock_login_response()
        risk = {"assetIp": "10.0.0.5", "riskScore": 87, "riskLevel": "HIGH"}
        mock_get.return_value = mock_api_response(risk)

        request = make_request({"asset_ip": "10.0.0.5"})
        result = self.connector.get_asset_risk_score(request)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["riskScore"], 87)

    @patch("app.skyboxsecurity.requests.post")
    def test_get_asset_risk_score_missing_asset_ip(self, mock_post):
        mock_post.return_value = mock_login_response()

        request = make_request({})  # asset_ip is required
        with self.assertRaises(KeyError):
            self.connector.get_asset_risk_score(request)

    # -------------------------------------------------------------------
    # get_threat_intelligence
    # -------------------------------------------------------------------

    @patch("app.skyboxsecurity.requests.get")
    @patch("app.skyboxsecurity.requests.post")
    def test_get_threat_intelligence_ip_success(self, mock_post, mock_get):
        mock_post.return_value = mock_login_response()
        intel = {"indicator": "1.2.3.4", "type": "ip", "malicious": True}
        mock_get.return_value = mock_api_response(intel)

        request = make_request({"indicator": "1.2.3.4", "indicator_type": "ip"})
        result = self.connector.get_threat_intelligence(request)

        self.assertEqual(result["status"], "success")
        self.assertTrue(result["results"]["malicious"])

    @patch("app.skyboxsecurity.requests.get")
    @patch("app.skyboxsecurity.requests.post")
    def test_get_threat_intelligence_cve_success(self, mock_post, mock_get):
        mock_post.return_value = mock_login_response()
        intel = {"indicator": "CVE-2024-1234", "type": "cve", "cvss": 9.8}
        mock_get.return_value = mock_api_response(intel)

        request = make_request({"indicator": "CVE-2024-1234", "indicator_type": "cve"})
        result = self.connector.get_threat_intelligence(request)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["cvss"], 9.8)

    @patch("app.skyboxsecurity.requests.post")
    def test_get_threat_intelligence_missing_params(self, mock_post):
        mock_post.return_value = mock_login_response()

        request = make_request({"indicator": "1.2.3.4"})  # indicator_type missing
        with self.assertRaises(KeyError):
            self.connector.get_threat_intelligence(request)

    # -------------------------------------------------------------------
    # block_ip_on_firewall
    # -------------------------------------------------------------------

    @patch("app.skyboxsecurity.requests.post")
    def test_block_ip_on_firewall_success(self, mock_post):
        mock_post.side_effect = [
            mock_login_response(),
            mock_api_response({"status": "blocked", "ip": "1.2.3.4"})
        ]

        request = make_request({
            "firewall_name": "FW-01",
            "ip_to_block": "1.2.3.4",
            "reason": "Malicious activity"
        })
        result = self.connector.block_ip_on_firewall(request)

        self.assertEqual(result["status"], "success")

    @patch("app.skyboxsecurity.requests.post")
    def test_block_ip_on_firewall_default_reason(self, mock_post):
        mock_post.side_effect = [
            mock_login_response(),
            mock_api_response({"status": "blocked"})
        ]

        request = make_request({
            "firewall_name": "FW-01",
            "ip_to_block": "5.6.7.8"
            # reason not provided — should default
        })
        result = self.connector.block_ip_on_firewall(request)

        self.assertEqual(result["status"], "success")

    @patch("app.skyboxsecurity.requests.post")
    def test_block_ip_on_firewall_missing_required_params(self, mock_post):
        mock_post.return_value = mock_login_response()

        request = make_request({"firewall_name": "FW-01"})  # ip_to_block missing
        with self.assertRaises(KeyError):
            self.connector.block_ip_on_firewall(request)

    # -------------------------------------------------------------------
    # get_change_requests
    # -------------------------------------------------------------------

    @patch("app.skyboxsecurity.requests.get")
    @patch("app.skyboxsecurity.requests.post")
    def test_get_change_requests_success(self, mock_post, mock_get):
        mock_post.return_value = mock_login_response()
        changes = [{"id": "CR-001", "status": "open", "firewall": "FW-01"}]
        mock_get.return_value = mock_api_response(changes)

        request = make_request({"status": "open", "limit": 50})
        result = self.connector.get_change_requests(request)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"], changes)

    @patch("app.skyboxsecurity.requests.get")
    @patch("app.skyboxsecurity.requests.post")
    def test_get_change_requests_no_filters(self, mock_post, mock_get):
        mock_post.return_value = mock_login_response()
        mock_get.return_value = mock_api_response([])

        request = make_request({})
        result = self.connector.get_change_requests(request)

        self.assertEqual(result["status"], "success")

    @patch("app.skyboxsecurity.requests.post")
    def test_get_change_requests_api_error(self, mock_post):
        mock_post.side_effect = Exception("Service unavailable")

        request = make_request({"status": "open"})
        with self.assertRaises(Exception) as ctx:
            self.connector.get_change_requests(request)
        self.assertIn("Service unavailable", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()