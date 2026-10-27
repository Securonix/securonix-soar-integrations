import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import unittest
from unittest.mock import patch, MagicMock

from app.imperva_waf import ImpervaWaf


CONNECTION_PARAMS = {
    "api_id": "12345",
    "api_key": "secret-key",
    "base_url": "https://my.imperva.com/api/prov/v1",
    "verify_ssl": "true",
}


def make_request(parameters: dict):
    req = MagicMock()
    req.connectionParameters = CONNECTION_PARAMS
    req.parameters = parameters
    return req


def prov_ok(extra=None):
    """prov/v1 success -> res == 0."""
    body = {"res": 0, "res_message": "OK"}
    if extra:
        body.update(extra)
    resp = MagicMock()
    resp.status_code = 200
    resp.content = b"x"
    resp.json.return_value = body
    return resp


def prov_err(res=1, message="Operation failed"):
    resp = MagicMock()
    resp.status_code = 200
    resp.content = b"x"
    resp.json.return_value = {"res": res, "res_message": message}
    return resp


def http_resp(data, status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = b"x" if data else b""
    resp.json.return_value = data
    return resp


class TestImpervaWaf(unittest.TestCase):

    def setUp(self):
        self.connector = ImpervaWaf()

    # ---------------------------------------------------------------
    # test_connection
    # ---------------------------------------------------------------

    @patch("app.imperva_waf.requests.post")
    def test_connection_success(self, mock_post):
        mock_post.return_value = prov_ok({"sites": []})
        result = self.connector.test_connection(CONNECTION_PARAMS)
        self.assertEqual(result["status"], "success")
        self.assertIn("Connected to Imperva Cloud WAF", result["message"])
        # confirm auth headers + endpoint
        args, kwargs = mock_post.call_args
        self.assertEqual(kwargs["headers"]["x-API-Id"], "12345")
        self.assertEqual(kwargs["headers"]["x-API-Key"], "secret-key")
        self.assertTrue(args[0].endswith("/sites/list"))

    @patch("app.imperva_waf.requests.post")
    def test_connection_auth_401(self, mock_post):
        mock_post.return_value = http_resp({}, status_code=401)
        with self.assertRaises(Exception) as ctx:
            self.connector.test_connection(CONNECTION_PARAMS)
        self.assertIn("Authentication failed", str(ctx.exception))

    @patch("app.imperva_waf.requests.post")
    def test_connection_res_error(self, mock_post):
        mock_post.return_value = prov_err(res=9403, message="Unknown API key")
        with self.assertRaises(Exception) as ctx:
            self.connector.test_connection(CONNECTION_PARAMS)
        self.assertIn("Unknown API key", str(ctx.exception))

    def test_connection_missing_api_id(self):
        with self.assertRaises(Exception) as ctx:
            self.connector.test_connection({"api_key": "k"})
        self.assertIn("Missing required connection parameter: api_id", str(ctx.exception))

    # ---------------------------------------------------------------
    # block / unblock / allowlist / country
    # ---------------------------------------------------------------

    @patch("app.imperva_waf.requests.post")
    def test_block_ip_success(self, mock_post):
        mock_post.return_value = prov_ok()
        result = self.connector.block_ip(make_request({"site_id": "123", "ips": "1.2.3.4"}))
        self.assertEqual(result["status"], "success")
        args, kwargs = mock_post.call_args
        self.assertTrue(args[0].endswith("/sites/configure/acl"))
        self.assertEqual(kwargs["data"]["rule_id"], "api.acl.blacklisted_ips")
        self.assertEqual(kwargs["data"]["site_id"], "123")
        self.assertEqual(kwargs["data"]["ips"], "1.2.3.4")
        # form-encoded content type
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/x-www-form-urlencoded")

    @patch("app.imperva_waf.requests.post")
    def test_block_ip_missing_ips(self, mock_post):
        mock_post.return_value = prov_ok()
        with self.assertRaises(Exception) as ctx:
            self.connector.block_ip(make_request({"site_id": "123"}))
        self.assertIn("Missing required parameter: ips", str(ctx.exception))

    @patch("app.imperva_waf.requests.post")
    def test_block_ip_missing_site(self, mock_post):
        mock_post.return_value = prov_ok()
        with self.assertRaises(Exception) as ctx:
            self.connector.block_ip(make_request({"ips": "1.2.3.4"}))
        self.assertIn("Missing required parameter: site_id", str(ctx.exception))

    @patch("app.imperva_waf.requests.post")
    def test_unblock_ip_empty_clears(self, mock_post):
        mock_post.return_value = prov_ok()
        result = self.connector.unblock_ip(make_request({"site_id": "123"}))
        self.assertEqual(result["status"], "success")
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["data"]["rule_id"], "api.acl.blacklisted_ips")
        self.assertEqual(kwargs["data"]["ips"], "")

    @patch("app.imperva_waf.requests.post")
    def test_allowlist_ip_success(self, mock_post):
        mock_post.return_value = prov_ok()
        result = self.connector.allowlist_ip(make_request({"site_id": "123", "ips": "5.6.7.8"}))
        self.assertEqual(result["status"], "success")
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["data"]["rule_id"], "api.acl.whitelisted_ips")

    @patch("app.imperva_waf.requests.post")
    def test_block_country_success(self, mock_post):
        mock_post.return_value = prov_ok()
        result = self.connector.block_country(make_request({"site_id": "123", "countries": "CN,RU"}))
        self.assertEqual(result["status"], "success")
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["data"]["rule_id"], "api.acl.blacklisted_countries")
        self.assertEqual(kwargs["data"]["countries"], "CN,RU")

    @patch("app.imperva_waf.requests.post")
    def test_block_country_missing(self, mock_post):
        mock_post.return_value = prov_ok()
        with self.assertRaises(Exception) as ctx:
            self.connector.block_country(make_request({"site_id": "123"}))
        self.assertIn("Missing required parameter: countries", str(ctx.exception))

    # ---------------------------------------------------------------
    # add security rule
    # ---------------------------------------------------------------

    @patch("app.imperva_waf.requests.post")
    def test_add_security_rule_success(self, mock_post):
        mock_post.return_value = prov_ok({"rule_id": 55})
        result = self.connector.add_security_rule(make_request({
            "site_id": "123", "name": "Block bad IP",
            "action": "RULE_ACTION_BLOCK_IP", "filter": "ClientIP == 1.2.3.4",
        }))
        self.assertEqual(result["status"], "success")
        args, kwargs = mock_post.call_args
        self.assertTrue(args[0].endswith("/sites/incapRules/add"))
        self.assertEqual(kwargs["data"]["action"], "RULE_ACTION_BLOCK_IP")
        self.assertEqual(kwargs["data"]["filter"], "ClientIP == 1.2.3.4")

    @patch("app.imperva_waf.requests.post")
    def test_add_security_rule_missing_filter(self, mock_post):
        mock_post.return_value = prov_ok()
        with self.assertRaises(Exception) as ctx:
            self.connector.add_security_rule(make_request({
                "site_id": "123", "name": "r", "action": "RULE_ACTION_BLOCK_IP",
            }))
        self.assertIn("Missing required parameter: filter", str(ctx.exception))

    # ---------------------------------------------------------------
    # list sites / site status
    # ---------------------------------------------------------------

    @patch("app.imperva_waf.requests.post")
    def test_list_sites_success(self, mock_post):
        mock_post.return_value = prov_ok({"sites": [{"site_id": 123}]})
        result = self.connector.list_sites(make_request({"page_size": 10}))
        self.assertEqual(result["status"], "success")
        args, kwargs = mock_post.call_args
        self.assertTrue(args[0].endswith("/sites/list"))
        self.assertEqual(kwargs["data"]["page_size"], 10)

    @patch("app.imperva_waf.requests.post")
    def test_list_sites_no_params(self, mock_post):
        mock_post.return_value = prov_ok({"sites": []})
        result = self.connector.list_sites(make_request({}))
        self.assertEqual(result["status"], "success")

    @patch("app.imperva_waf.requests.post")
    def test_get_site_status_success(self, mock_post):
        mock_post.return_value = prov_ok({"site_id": 123, "status": "fully-configured"})
        result = self.connector.get_site_status(make_request({"site_id": "123", "tests": "dns"}))
        self.assertEqual(result["status"], "success")
        args, kwargs = mock_post.call_args
        self.assertTrue(args[0].endswith("/sites/status"))
        self.assertEqual(kwargs["data"]["site_id"], "123")
        self.assertEqual(kwargs["data"]["tests"], "dns")

    @patch("app.imperva_waf.requests.post")
    def test_get_site_status_missing_site(self, mock_post):
        mock_post.return_value = prov_ok()
        with self.assertRaises(Exception) as ctx:
            self.connector.get_site_status(make_request({}))
        self.assertIn("Missing required parameter: site_id", str(ctx.exception))

    # ---------------------------------------------------------------
    # audit events (GET, different base URL)
    # ---------------------------------------------------------------

    @patch("app.imperva_waf.requests.get")
    def test_get_audit_events_success(self, mock_get):
        mock_get.return_value = http_resp({"elements": [{"type_description": "Login"}]})
        result = self.connector.get_audit_events(make_request({"start": "1700000000000", "page_size": 50}))
        self.assertEqual(result["status"], "success")
        args, kwargs = mock_get.call_args
        self.assertTrue(args[0].endswith("/audit-trail/v2/events"))
        self.assertEqual(kwargs["params"]["start"], "1700000000000")
        self.assertEqual(kwargs["headers"]["x-API-Id"], "12345")

    @patch("app.imperva_waf.requests.get")
    def test_get_audit_events_no_params(self, mock_get):
        mock_get.return_value = http_resp({"elements": []})
        result = self.connector.get_audit_events(make_request({}))
        self.assertEqual(result["status"], "success")

    @patch("app.imperva_waf.requests.get")
    def test_get_audit_events_401(self, mock_get):
        mock_get.return_value = http_resp({}, status_code=401)
        with self.assertRaises(Exception) as ctx:
            self.connector.get_audit_events(make_request({}))
        self.assertIn("Authentication failed", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
