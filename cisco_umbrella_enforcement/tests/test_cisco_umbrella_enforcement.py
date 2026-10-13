import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import unittest
from unittest.mock import patch, MagicMock

from app.cisco_umbrella_enforcement import CiscoUmbrellaEnforcement


CONNECTION_PARAMS = {
    "customer_key": "ck-123",
    "base_url": "https://s-platform.api.opendns.com/1.0",
    "timeout": "30",
    "verify_ssl": "true",
}


def make_request(parameters: dict):
    req = MagicMock()
    req.connectionParameters = CONNECTION_PARAMS
    req.parameters = parameters
    return req


def mock_response(data=None, status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = b"x" if data else b""
    resp.json.return_value = data if data is not None else {}
    return resp


class TestCiscoUmbrellaEnforcement(unittest.TestCase):

    def setUp(self):
        self.connector = CiscoUmbrellaEnforcement()

    # ---------------------------------------------------------------
    # test_connection
    # ---------------------------------------------------------------

    @patch("app.cisco_umbrella_enforcement.requests.request")
    def test_connection_success(self, mock_req):
        mock_req.return_value = mock_response({"data": []}, 200)
        result = self.connector.test_connection(CONNECTION_PARAMS)
        self.assertEqual(result["status"], "success")
        self.assertIn("Connected to Cisco Umbrella Enforcement", result["message"])
        # customerKey must be sent as a query param
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["params"]["customerKey"], "ck-123")

    @patch("app.cisco_umbrella_enforcement.requests.request")
    def test_connection_auth_failure(self, mock_req):
        mock_req.return_value = mock_response(None, 403)
        with self.assertRaises(Exception) as ctx:
            self.connector.test_connection(CONNECTION_PARAMS)
        self.assertIn("customer_key", str(ctx.exception))

    def test_connection_missing_customer_key(self):
        with self.assertRaises(Exception) as ctx:
            self.connector.test_connection({"base_url": "https://s-platform.api.opendns.com/1.0"})
        self.assertIn("customer_key is required", str(ctx.exception))

    # ---------------------------------------------------------------
    # add_domain_event
    # ---------------------------------------------------------------

    @patch("app.cisco_umbrella_enforcement.requests.request")
    def test_add_domain_event_success(self, mock_req):
        mock_req.return_value = mock_response({"id": "abc-123"}, 202)
        result = self.connector.add_domain_event(make_request({
            "dst_domain": "internetbadguys.com",
            "dst_url": "https://internetbadguys.com/a-bad-url",
            "event_severity": "high",
        }))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["id"], "abc-123")

        # verify method/path and that the body is an array with required fixed fields
        args, kwargs = mock_req.call_args
        self.assertEqual(args[0], "POST")
        self.assertTrue(args[1].endswith("/events"))
        body = kwargs["json"]
        self.assertIsInstance(body, list)
        event = body[0]
        self.assertEqual(event["protocolVersion"], "1.0a")
        self.assertEqual(event["providerName"], "Security Platform")
        self.assertEqual(event["dstDomain"], "internetbadguys.com")
        self.assertIn("alertTime", event)
        self.assertIn("eventTime", event)
        self.assertIn("deviceId", event)
        self.assertEqual(event["eventSeverity"], "high")

    @patch("app.cisco_umbrella_enforcement.requests.request")
    def test_add_domain_event_disable_safeguards(self, mock_req):
        mock_req.return_value = mock_response({"id": "x"}, 202)
        self.connector.add_domain_event(make_request({
            "dst_domain": "bad.com",
            "dst_url": "https://bad.com",
            "disable_dst_safeguards": "true",
        }))
        _, kwargs = mock_req.call_args
        self.assertTrue(kwargs["json"][0]["disableDstSafeguards"])

    @patch("app.cisco_umbrella_enforcement.requests.request")
    def test_add_domain_event_fixed_provider_and_protocol(self, mock_req):
        # providerName and protocolVersion are fixed values per Cisco docs
        mock_req.return_value = mock_response({"id": "x"}, 202)
        self.connector.add_domain_event(make_request({
            "dst_domain": "bad.com",
            "dst_url": "https://bad.com",
        }))
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["json"][0]["providerName"], "Security Platform")
        self.assertEqual(kwargs["json"][0]["protocolVersion"], "1.0a")

    def test_add_domain_event_missing_domain(self):
        with self.assertRaises(KeyError):
            self.connector.add_domain_event(make_request({"dst_url": "https://bad.com"}))

    def test_add_domain_event_missing_url(self):
        with self.assertRaises(KeyError):
            self.connector.add_domain_event(make_request({"dst_domain": "bad.com"}))

    def test_add_domain_event_invalid_domain(self):
        with self.assertRaises(Exception) as ctx:
            self.connector.add_domain_event(make_request({
                "dst_domain": "not a domain",
                "dst_url": "https://bad.com",
            }))
        self.assertIn("not a valid domain", str(ctx.exception))

    # ---------------------------------------------------------------
    # list_blocked_domains
    # ---------------------------------------------------------------

    @patch("app.cisco_umbrella_enforcement.requests.request")
    def test_list_blocked_domains_success(self, mock_req):
        payload = {"data": [{"id": 30916, "name": "internetbadguys.com", "lastSeenAt": 1625759735}]}
        mock_req.return_value = mock_response(payload, 200)
        result = self.connector.list_blocked_domains(make_request({"limit": 50}))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"], payload)
        args, kwargs = mock_req.call_args
        self.assertEqual(args[0], "GET")
        self.assertTrue(args[1].endswith("/domains"))
        self.assertEqual(kwargs["params"]["limit"], 50)

    @patch("app.cisco_umbrella_enforcement.requests.request")
    def test_list_blocked_domains_no_params(self, mock_req):
        mock_req.return_value = mock_response({"data": []}, 200)
        result = self.connector.list_blocked_domains(make_request({}))
        self.assertEqual(result["status"], "success")

    def test_list_blocked_domains_invalid_limit(self):
        with self.assertRaises(Exception) as ctx:
            self.connector.list_blocked_domains(make_request({"limit": "abc"}))
        self.assertIn("limit must be a positive integer", str(ctx.exception))

    # ---------------------------------------------------------------
    # delete_blocked_domain
    # ---------------------------------------------------------------

    @patch("app.cisco_umbrella_enforcement.requests.request")
    def test_delete_blocked_domain_by_id(self, mock_req):
        mock_req.return_value = mock_response(None, 204)
        result = self.connector.delete_blocked_domain(make_request({"domain": "30916"}))
        self.assertEqual(result["status"], "success")
        self.assertIn("removed", result["results"]["message"])
        args, _ = mock_req.call_args
        self.assertEqual(args[0], "DELETE")
        self.assertTrue(args[1].endswith("/domains/30916"))

    @patch("app.cisco_umbrella_enforcement.requests.request")
    def test_delete_blocked_domain_by_name(self, mock_req):
        mock_req.return_value = mock_response(None, 204)
        result = self.connector.delete_blocked_domain(make_request({"domain": "internetbadguys.com"}))
        self.assertEqual(result["status"], "success")
        args, _ = mock_req.call_args
        # domain name is URL-encoded into the path
        self.assertTrue(args[1].endswith("/domains/internetbadguys.com"))

    def test_delete_blocked_domain_missing(self):
        with self.assertRaises(KeyError):
            self.connector.delete_blocked_domain(make_request({}))

    # ---------------------------------------------------------------
    # error handling
    # ---------------------------------------------------------------

    @patch("app.cisco_umbrella_enforcement.requests.request")
    def test_rate_limit_error(self, mock_req):
        mock_req.return_value = mock_response(None, 429)
        with self.assertRaises(Exception) as ctx:
            self.connector.list_blocked_domains(make_request({}))
        self.assertIn("rate limit", str(ctx.exception).lower())

    @patch("app.cisco_umbrella_enforcement.requests.request")
    def test_server_error(self, mock_req):
        mock_req.return_value = mock_response(None, 500)
        with self.assertRaises(Exception) as ctx:
            self.connector.list_blocked_domains(make_request({}))
        self.assertIn("server error", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
