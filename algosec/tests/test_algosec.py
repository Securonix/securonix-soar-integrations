import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import unittest
from unittest.mock import patch, MagicMock

from app.algosec import Algosec


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

BASE_URL = "https://algosec.example.com"
USERNAME = "admin"
PASSWORD = "algosec"

CONNECTION_PARAMS = {
    "base_url": BASE_URL,
    "username": USERNAME,
    "password": PASSWORD,
    "verify_ssl": "false"
}


def make_request(parameters: dict):
    """Build a mock RequestBody with connectionParameters and parameters."""
    req = MagicMock()
    req.connectionParameters = CONNECTION_PARAMS
    req.parameters = parameters
    return req


def mock_afa_login():
    """AFA login: response has a sessionId (top-level)."""
    resp = MagicMock()
    resp.json.return_value = {"sessionId": "afa-session-123"}
    resp.raise_for_status = MagicMock()
    return resp


def mock_fireflow_login():
    """FireFlow login: response has data.sessionId."""
    resp = MagicMock()
    resp.json.return_value = {
        "status": "Success",
        "data": {"sessionId": "ff-session-abc"}
    }
    resp.raise_for_status = MagicMock()
    return resp


def mock_appviz_login():
    """AppViz login: response has jsessionid."""
    resp = MagicMock()
    resp.json.return_value = {"jsessionid": "av-session-xyz"}
    resp.raise_for_status = MagicMock()
    return resp


def mock_api_response(data):
    """A generic successful API response."""
    resp = MagicMock()
    resp.json.return_value = data
    resp.raise_for_status = MagicMock()
    return resp


# -------------------------------------------------------------------
# Test Class
# -------------------------------------------------------------------

class TestAlgosec(unittest.TestCase):

    def setUp(self):
        self.connector = Algosec()

    # ---------------------------------------------------------------
    # test_connection (uses FireFlow login)
    # ---------------------------------------------------------------

    @patch("app.algosec.requests.post")
    def test_connection_success(self, mock_post):
        mock_post.return_value = mock_fireflow_login()

        result = self.connector.test_connection(CONNECTION_PARAMS)

        self.assertEqual(result["status"], "success")
        self.assertIn("Connected to AlgoSec successfully", result["message"])

    @patch("app.algosec.requests.post")
    def test_connection_no_session(self, mock_post):
        resp = MagicMock()
        resp.json.return_value = {"status": "Failure", "data": None}
        resp.raise_for_status = MagicMock()
        mock_post.return_value = resp

        with self.assertRaises(Exception) as ctx:
            self.connector.test_connection(CONNECTION_PARAMS)
        self.assertIn("Failed to retrieve FireFlow sessionId", str(ctx.exception))

    @patch("app.algosec.requests.post")
    def test_connection_http_error(self, mock_post):
        mock_post.side_effect = Exception("Connection refused")

        with self.assertRaises(Exception) as ctx:
            self.connector.test_connection(CONNECTION_PARAMS)
        self.assertIn("Connection refused", str(ctx.exception))

    # ---------------------------------------------------------------
    # AFA reads (login via post, action via get)
    # ---------------------------------------------------------------

    @patch("app.algosec.requests.get")
    @patch("app.algosec.requests.post")
    def test_get_devices_success(self, mock_post, mock_get):
        mock_post.return_value = mock_afa_login()
        devices = [{"name": "fw_root_1", "vendor": "cisco"}]
        mock_get.return_value = mock_api_response(devices)

        result = self.connector.get_devices(make_request({}))

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"], devices)

    @patch("app.algosec.requests.get")
    @patch("app.algosec.requests.post")
    def test_get_devices_with_policy_success(self, mock_post, mock_get):
        mock_post.return_value = mock_afa_login()
        mock_get.return_value = mock_api_response([{"name": "fw1", "policy": {}}])

        result = self.connector.get_devices_with_policy(make_request({}))
        self.assertEqual(result["status"], "success")

    @patch("app.algosec.requests.get")
    @patch("app.algosec.requests.post")
    def test_get_device_rules_success(self, mock_post, mock_get):
        mock_post.return_value = mock_afa_login()
        rules = [{"id": 1, "action": "allow"}]
        mock_get.return_value = mock_api_response(rules)

        result = self.connector.get_device_rules(make_request({"device_name": "fw_root_1"}))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"], rules)

    @patch("app.algosec.requests.post")
    def test_get_device_rules_missing_device(self, mock_post):
        mock_post.return_value = mock_afa_login()
        with self.assertRaises(KeyError):
            self.connector.get_device_rules(make_request({}))

    @patch("app.algosec.requests.get")
    @patch("app.algosec.requests.post")
    def test_get_risky_rules_success(self, mock_post, mock_get):
        mock_post.return_value = mock_afa_login()
        mock_get.return_value = mock_api_response([{"id": 5, "risk": "HIGH"}])

        result = self.connector.get_risky_rules(make_request({"device_name": "fw1"}))
        self.assertEqual(result["status"], "success")

    @patch("app.algosec.requests.post")
    def test_get_risky_rules_missing_device(self, mock_post):
        mock_post.return_value = mock_afa_login()
        with self.assertRaises(KeyError):
            self.connector.get_risky_rules(make_request({}))

    @patch("app.algosec.requests.get")
    @patch("app.algosec.requests.post")
    def test_get_nat_rules_success(self, mock_post, mock_get):
        mock_post.return_value = mock_afa_login()
        mock_get.return_value = mock_api_response([{"nat": "static"}])

        result = self.connector.get_nat_rules(make_request({"device_name": "fw1"}))
        self.assertEqual(result["status"], "success")

    @patch("app.algosec.requests.post")
    def test_get_nat_rules_missing_device(self, mock_post):
        mock_post.return_value = mock_afa_login()
        with self.assertRaises(KeyError):
            self.connector.get_nat_rules(make_request({}))

    @patch("app.algosec.requests.get")
    @patch("app.algosec.requests.post")
    def test_get_network_objects_success(self, mock_post, mock_get):
        mock_post.return_value = mock_afa_login()
        mock_get.return_value = mock_api_response([{"name": "obj1", "ip": "10.0.0.1"}])

        result = self.connector.get_network_objects(make_request({"device_name": "fw1"}))
        self.assertEqual(result["status"], "success")

    @patch("app.algosec.requests.get")
    @patch("app.algosec.requests.post")
    def test_get_network_objects_no_filter(self, mock_post, mock_get):
        mock_post.return_value = mock_afa_login()
        mock_get.return_value = mock_api_response([])

        result = self.connector.get_network_objects(make_request({}))
        self.assertEqual(result["status"], "success")

    @patch("app.algosec.requests.get")
    @patch("app.algosec.requests.post")
    def test_get_service_objects_success(self, mock_post, mock_get):
        mock_post.return_value = mock_afa_login()
        mock_get.return_value = mock_api_response([{"name": "https", "port": 443}])

        result = self.connector.get_service_objects(make_request({"device_name": "fw1"}))
        self.assertEqual(result["status"], "success")

    @patch("app.algosec.requests.post")
    def test_get_service_objects_missing_device(self, mock_post):
        mock_post.return_value = mock_afa_login()
        with self.assertRaises(KeyError):
            self.connector.get_service_objects(make_request({}))

    @patch("app.algosec.requests.get")
    @patch("app.algosec.requests.post")
    def test_get_reports_for_device(self, mock_post, mock_get):
        mock_post.return_value = mock_afa_login()
        mock_get.return_value = mock_api_response([{"report_id": 101, "status": "completed"}])

        result = self.connector.get_reports(make_request({"device_name": "fw1"}))
        self.assertEqual(result["status"], "success")

    @patch("app.algosec.requests.get")
    @patch("app.algosec.requests.post")
    def test_get_reports_with_from_date(self, mock_post, mock_get):
        mock_post.return_value = mock_afa_login()
        mock_get.return_value = mock_api_response([{"report_id": 102}])

        result = self.connector.get_reports(make_request({"device_name": "fw1", "from_date": "2026-01-01"}))
        self.assertEqual(result["status"], "success")

    @patch("app.algosec.requests.post")
    def test_get_reports_missing_device(self, mock_post):
        mock_post.return_value = mock_afa_login()
        with self.assertRaises(KeyError):
            self.connector.get_reports(make_request({}))

    # ---------------------------------------------------------------
    # AppViz read
    # ---------------------------------------------------------------

    @patch("app.algosec.requests.get")
    @patch("app.algosec.requests.post")
    def test_get_applications_success(self, mock_post, mock_get):
        mock_post.return_value = mock_appviz_login()
        apps = [{"id": 1, "name": "Payroll"}]
        mock_get.return_value = mock_api_response(apps)

        result = self.connector.get_applications(make_request({"page_number": 1}))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"], apps)

    @patch("app.algosec.requests.post")
    def test_get_applications_login_failure(self, mock_post):
        resp = MagicMock()
        resp.json.return_value = {}  # no jsessionid
        resp.raise_for_status = MagicMock()
        mock_post.return_value = resp

        with self.assertRaises(Exception) as ctx:
            self.connector.get_applications(make_request({}))
        self.assertIn("Failed to retrieve AppViz jsessionid", str(ctx.exception))

    # ---------------------------------------------------------------
    # AFA analyze
    # ---------------------------------------------------------------

    @patch("app.algosec.requests.post")
    def test_run_traffic_simulation_success(self, mock_post):
        # login (post) then action (post)
        mock_post.side_effect = [
            mock_afa_login(),
            mock_api_response({"allowed": True})
        ]
        request = make_request({
            "source": "10.0.0.1",
            "destination": "10.0.0.2",
            "service": "tcp/443"
        })
        result = self.connector.run_traffic_simulation(request)
        self.assertEqual(result["status"], "success")
        self.assertTrue(result["results"]["allowed"])

    @patch("app.algosec.requests.post")
    def test_run_traffic_simulation_missing_required(self, mock_post):
        mock_post.return_value = mock_afa_login()
        request = make_request({"source": "10.0.0.1"})  # destination missing
        with self.assertRaises(KeyError):
            self.connector.run_traffic_simulation(request)

    @patch("app.algosec.requests.post")
    def test_find_route_success(self, mock_post):
        # find_route logs in (post) then calls POST /query/routing (post)
        mock_post.side_effect = [
            mock_afa_login(),
            mock_api_response({"path": ["r1", "fw1"]})
        ]
        request = make_request({"source": "10.0.0.1", "destination": "10.0.0.2"})
        result = self.connector.find_route(request)
        self.assertEqual(result["status"], "success")

    @patch("app.algosec.requests.post")
    def test_find_route_missing_required(self, mock_post):
        mock_post.return_value = mock_afa_login()
        with self.assertRaises(KeyError):
            self.connector.find_route(make_request({"source": "10.0.0.1"}))

    @patch("app.algosec.requests.get")
    @patch("app.algosec.requests.post")
    def test_get_risk_profiles_success(self, mock_post, mock_get):
        mock_post.return_value = mock_afa_login()
        mock_get.return_value = mock_api_response([{"name": "PCI"}])

        result = self.connector.get_risk_profiles(make_request({}))
        self.assertEqual(result["status"], "success")

    @patch("app.algosec.requests.post")
    def test_run_risk_check_success(self, mock_post):
        mock_post.side_effect = [
            mock_afa_login(),
            mock_api_response({"risky": False})
        ]
        request = make_request({
            "source": "10.0.0.1",
            "destination": "10.0.0.2",
            "service": "tcp/22",
            "risk_profile": "PCI"
        })
        result = self.connector.run_risk_check(request)
        self.assertEqual(result["status"], "success")

    @patch("app.algosec.requests.post")
    def test_run_risk_check_missing_required(self, mock_post):
        mock_post.return_value = mock_afa_login()
        with self.assertRaises(KeyError):
            self.connector.run_risk_check(make_request({"source": "10.0.0.1"}))

    # ---------------------------------------------------------------
    # FireFlow remediation
    # ---------------------------------------------------------------

    @patch("app.algosec.requests.post")
    def test_create_traffic_change_request_success(self, mock_post):
        mock_post.side_effect = [
            mock_fireflow_login(),
            mock_api_response({"status": "Success", "data": {"id": 4595}})
        ]
        request = make_request({
            "template": "Basic Change Traffic Request",
            "source": "1.1.1.1",
            "destination": "2.2.2.2",
            "service": "tcp/443",
            "action": "Allow"
        })
        result = self.connector.create_traffic_change_request(request)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["data"]["id"], 4595)

    @patch("app.algosec.requests.post")
    def test_create_traffic_change_request_default_action(self, mock_post):
        mock_post.side_effect = [
            mock_fireflow_login(),
            mock_api_response({"status": "Success"})
        ]
        request = make_request({
            "template": "T",
            "source": "1.1.1.1",
            "destination": "2.2.2.2",
            "service": "tcp/80"
            # action defaults to Allow
        })
        result = self.connector.create_traffic_change_request(request)
        self.assertEqual(result["status"], "success")

    @patch("app.algosec.requests.post")
    def test_create_traffic_change_request_missing_required(self, mock_post):
        mock_post.return_value = mock_fireflow_login()
        request = make_request({"template": "T", "source": "1.1.1.1"})  # destination/service missing
        with self.assertRaises(KeyError):
            self.connector.create_traffic_change_request(request)

    @patch("app.algosec.requests.post")
    def test_create_object_change_request_success(self, mock_post):
        mock_post.side_effect = [
            mock_fireflow_login(),
            mock_api_response({"status": "Success", "data": {"id": 500}})
        ]
        request = make_request({
            "template": "Object Request",
            "object_name": "BadHost",
            "content": "6.6.6.6",
            "object_type": "Host",
            "devices": "fw1, fw2"
        })
        result = self.connector.create_object_change_request(request)
        self.assertEqual(result["status"], "success")

    @patch("app.algosec.requests.post")
    def test_create_object_change_request_missing_required(self, mock_post):
        mock_post.return_value = mock_fireflow_login()
        request = make_request({"template": "T", "object_name": "X"})  # content missing
        with self.assertRaises(KeyError):
            self.connector.create_object_change_request(request)

    @patch("app.algosec.requests.get")
    @patch("app.algosec.requests.post")
    def test_get_change_request_status_success(self, mock_post, mock_get):
        mock_post.return_value = mock_fireflow_login()
        mock_get.return_value = mock_api_response({
            "status": "Success",
            "data": {"id": 24, "fields": [{"name": "status", "values": ["implement"]}]}
        })
        result = self.connector.get_change_request_status(make_request({"change_request_id": "24"}))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["data"]["id"], 24)

    @patch("app.algosec.requests.post")
    def test_get_change_request_status_missing_id(self, mock_post):
        mock_post.return_value = mock_fireflow_login()
        with self.assertRaises(KeyError):
            self.connector.get_change_request_status(make_request({}))

    # ---------------------------------------------------------------
    # error propagation
    # ---------------------------------------------------------------

    @patch("app.algosec.requests.post")
    def test_get_devices_login_failure(self, mock_post):
        mock_post.side_effect = Exception("Auth failed")
        with self.assertRaises(Exception) as ctx:
            self.connector.get_devices(make_request({}))
        self.assertIn("Auth failed", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
