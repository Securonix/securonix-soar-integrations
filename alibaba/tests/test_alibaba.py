import sys
import os
import types
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import unittest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# The connector lazily imports the Alibaba Cloud SDK inside its methods:
#   from alibabacloud_cloudfw20171207 import models as m
#   from alibabacloud_sas20181203 import models as m
#   from alibabacloud_cloudfw20171207.client import Client
#   from alibabacloud_sas20181203.client import Client
#   from alibabacloud_tea_openapi import models as open_api_models
# These packages aren't installed in the unit-test environment, so we register
# lightweight stand-ins in sys.modules. Each request model is a permissive stub
# that accepts arbitrary kwargs/attributes.
# ---------------------------------------------------------------------------

class _StubModel:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


def _make_models_module(name):
    mod = types.ModuleType(name)
    # Any attribute access returns the permissive _StubModel class.
    mod.__getattr__ = lambda attr: _StubModel  # type: ignore[attr-defined]
    return mod


def _make_client_module(name):
    mod = types.ModuleType(name)
    mod.Client = MagicMock(name=f"{name}.Client")
    return mod


def _install_sdk_stubs():
    cloudfw_pkg = types.ModuleType("alibabacloud_cloudfw20171207")
    cloudfw_pkg.models = _make_models_module("alibabacloud_cloudfw20171207.models")
    sys.modules["alibabacloud_cloudfw20171207"] = cloudfw_pkg
    sys.modules["alibabacloud_cloudfw20171207.models"] = cloudfw_pkg.models
    sys.modules["alibabacloud_cloudfw20171207.client"] = _make_client_module(
        "alibabacloud_cloudfw20171207.client")

    sas_pkg = types.ModuleType("alibabacloud_sas20181203")
    sas_pkg.models = _make_models_module("alibabacloud_sas20181203.models")
    sys.modules["alibabacloud_sas20181203"] = sas_pkg
    sys.modules["alibabacloud_sas20181203.models"] = sas_pkg.models
    sys.modules["alibabacloud_sas20181203.client"] = _make_client_module(
        "alibabacloud_sas20181203.client")

    tea = types.ModuleType("alibabacloud_tea_openapi")
    tea.models = _make_models_module("alibabacloud_tea_openapi.models")
    sys.modules["alibabacloud_tea_openapi"] = tea
    sys.modules["alibabacloud_tea_openapi.models"] = tea.models


_install_sdk_stubs()

from app.alibaba import Alibaba  # noqa: E402


CONNECTION_PARAMS = {
    "access_key_id": "akid",
    "access_key_secret": "aksecret",
    "region_id": "cn-hangzhou",
}


def make_request(parameters: dict):
    req = MagicMock()
    req.connectionParameters = CONNECTION_PARAMS
    req.parameters = parameters
    return req


def mock_resp(data: dict):
    """A mock SDK response whose .body.to_map() yields the given dict."""
    resp = MagicMock()
    resp.body.to_map.return_value = data
    return resp


class TestAlibaba(unittest.TestCase):

    def setUp(self):
        self.connector = Alibaba()

    # ---------------------------------------------------------------
    # test_connection
    # ---------------------------------------------------------------

    @patch("app.alibaba._build_cloudfw_client")
    def test_connection_success(self, mock_build):
        client = MagicMock()
        client.describe_control_policy.return_value = mock_resp({"TotalCount": 0})
        mock_build.return_value = client
        result = self.connector.test_connection(CONNECTION_PARAMS)
        self.assertEqual(result["status"], "success")
        self.assertIn("Connected to Alibaba Cloud successfully", result["message"])

    @patch("app.alibaba._build_cloudfw_client")
    def test_connection_failure(self, mock_build):
        mock_build.side_effect = Exception("InvalidAccessKeyId")
        with self.assertRaises(Exception) as ctx:
            self.connector.test_connection(CONNECTION_PARAMS)
        self.assertIn("InvalidAccessKeyId", str(ctx.exception))

    def test_connection_missing_credential(self):
        with self.assertRaises(Exception) as ctx:
            # Missing access_key_secret and region_id -> builder raises before SDK use
            from app.alibaba import _get_credentials
            _get_credentials({"access_key_id": "x"})
        self.assertIn("Missing required connection parameter", str(ctx.exception))

    # ---------------------------------------------------------------
    # Cloud Firewall — remediate
    # ---------------------------------------------------------------

    @patch("app.alibaba._build_cloudfw_client")
    def test_add_control_policy_success(self, mock_build):
        client = MagicMock()
        client.add_control_policy.return_value = mock_resp({"AclUuid": "uuid-1"})
        mock_build.return_value = client
        result = self.connector.add_control_policy(make_request({
            "acl_action": "drop", "direction": "in",
            "source": "1.2.3.4/32", "source_type": "net",
            "destination": "0.0.0.0/0", "destination_type": "net",
            "proto": "ANY", "description": "block bad ip", "new_order": "-1",
        }))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["AclUuid"], "uuid-1")
        client.add_control_policy.assert_called_once()

    @patch("app.alibaba._build_cloudfw_client")
    def test_add_control_policy_missing_required(self, mock_build):
        mock_build.return_value = MagicMock()
        with self.assertRaises(Exception) as ctx:
            self.connector.add_control_policy(make_request({
                "acl_action": "drop", "direction": "in",
            }))
        self.assertIn("Missing required parameter", str(ctx.exception))

    @patch("app.alibaba._build_cloudfw_client")
    def test_modify_control_policy_success(self, mock_build):
        client = MagicMock()
        client.modify_control_policy.return_value = mock_resp({"RequestId": "r1"})
        mock_build.return_value = client
        result = self.connector.modify_control_policy(make_request({
            "acl_uuid": "uuid-1", "direction": "in", "acl_action": "accept",
        }))
        self.assertEqual(result["status"], "success")

    @patch("app.alibaba._build_cloudfw_client")
    def test_modify_control_policy_missing_uuid(self, mock_build):
        mock_build.return_value = MagicMock()
        with self.assertRaises(Exception) as ctx:
            self.connector.modify_control_policy(make_request({"direction": "in"}))
        self.assertIn("Missing required parameter: acl_uuid", str(ctx.exception))

    @patch("app.alibaba._build_cloudfw_client")
    def test_delete_control_policy_success(self, mock_build):
        client = MagicMock()
        client.delete_control_policy.return_value = mock_resp({"RequestId": "r1"})
        mock_build.return_value = client
        result = self.connector.delete_control_policy(make_request({
            "acl_uuid": "uuid-1", "direction": "in",
        }))
        self.assertEqual(result["status"], "success")

    @patch("app.alibaba._build_cloudfw_client")
    def test_delete_control_policy_missing(self, mock_build):
        mock_build.return_value = MagicMock()
        with self.assertRaises(Exception) as ctx:
            self.connector.delete_control_policy(make_request({"acl_uuid": "u"}))
        self.assertIn("Missing required parameter: direction", str(ctx.exception))

    @patch("app.alibaba._build_cloudfw_client")
    def test_add_address_book_success(self, mock_build):
        client = MagicMock()
        client.add_address_book.return_value = mock_resp({"GroupUuid": "g1"})
        mock_build.return_value = client
        result = self.connector.add_address_book(make_request({
            "group_type": "ip", "group_name": "bad-ips",
            "description": "known bad", "address_list": "1.1.1.1,2.2.2.2",
        }))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["GroupUuid"], "g1")

    @patch("app.alibaba._build_cloudfw_client")
    def test_add_address_book_missing(self, mock_build):
        mock_build.return_value = MagicMock()
        with self.assertRaises(Exception) as ctx:
            self.connector.add_address_book(make_request({
                "group_type": "ip", "group_name": "x",
            }))
        self.assertIn("Missing required parameter", str(ctx.exception))

    # ---------------------------------------------------------------
    # Cloud Firewall — investigate
    # ---------------------------------------------------------------

    @patch("app.alibaba._build_cloudfw_client")
    def test_describe_control_policy_success(self, mock_build):
        client = MagicMock()
        client.describe_control_policy.return_value = mock_resp({"Policys": [], "TotalCount": 0})
        mock_build.return_value = client
        result = self.connector.describe_control_policy(make_request({"direction": "in"}))
        self.assertEqual(result["status"], "success")

    @patch("app.alibaba._build_cloudfw_client")
    def test_describe_control_policy_missing_direction(self, mock_build):
        mock_build.return_value = MagicMock()
        with self.assertRaises(Exception) as ctx:
            self.connector.describe_control_policy(make_request({}))
        self.assertIn("Missing required parameter: direction", str(ctx.exception))

    @patch("app.alibaba._build_cloudfw_client")
    def test_describe_address_book_success(self, mock_build):
        client = MagicMock()
        client.describe_address_book.return_value = mock_resp({"Acls": []})
        mock_build.return_value = client
        result = self.connector.describe_address_book(make_request({"group_type": "ip"}))
        self.assertEqual(result["status"], "success")

    @patch("app.alibaba._build_cloudfw_client")
    def test_describe_address_book_no_params(self, mock_build):
        client = MagicMock()
        client.describe_address_book.return_value = mock_resp({"Acls": []})
        mock_build.return_value = client
        result = self.connector.describe_address_book(make_request({}))
        self.assertEqual(result["status"], "success")

    # ---------------------------------------------------------------
    # Security Center — investigate
    # ---------------------------------------------------------------

    @patch("app.alibaba._build_sas_client")
    def test_describe_alarm_events_success(self, mock_build):
        client = MagicMock()
        client.describe_susp_events.return_value = mock_resp({"PageInfo": {}, "SuspEvents": []})
        mock_build.return_value = client
        result = self.connector.describe_alarm_events(make_request({"levels": "serious"}))
        self.assertEqual(result["status"], "success")
        client.describe_susp_events.assert_called_once()

    @patch("app.alibaba._build_sas_client")
    def test_describe_alarm_events_no_params(self, mock_build):
        client = MagicMock()
        client.describe_susp_events.return_value = mock_resp({"SuspEvents": []})
        mock_build.return_value = client
        result = self.connector.describe_alarm_events(make_request({}))
        self.assertEqual(result["status"], "success")

    @patch("app.alibaba._build_sas_client")
    def test_describe_alarm_event_detail_success(self, mock_build):
        client = MagicMock()
        client.describe_alarm_event_detail.return_value = mock_resp({"AlarmEvent": {"id": 1}})
        mock_build.return_value = client
        result = self.connector.describe_alarm_event_detail(make_request({
            "alarm_unique_info": "abc123",
        }))
        self.assertEqual(result["status"], "success")

    @patch("app.alibaba._build_sas_client")
    def test_describe_alarm_event_detail_missing(self, mock_build):
        mock_build.return_value = MagicMock()
        with self.assertRaises(Exception) as ctx:
            self.connector.describe_alarm_event_detail(make_request({}))
        self.assertIn("Missing required parameter: alarm_unique_info", str(ctx.exception))

    # ---------------------------------------------------------------
    # Cloud Firewall — modify / delete address book
    # ---------------------------------------------------------------

    @patch("app.alibaba._build_cloudfw_client")
    def test_modify_address_book_success(self, mock_build):
        client = MagicMock()
        client.modify_address_book.return_value = mock_resp({"GroupUuid": "g1"})
        mock_build.return_value = client
        result = self.connector.modify_address_book(make_request({
            "group_uuid": "g1", "address_list": "1.1.1.1,2.2.2.2", "modify_mode": "Append",
        }))
        self.assertEqual(result["status"], "success")
        client.modify_address_book.assert_called_once()

    @patch("app.alibaba._build_cloudfw_client")
    def test_modify_address_book_missing(self, mock_build):
        mock_build.return_value = MagicMock()
        with self.assertRaises(Exception) as ctx:
            self.connector.modify_address_book(make_request({"group_uuid": "g1"}))
        self.assertIn("Missing required parameter: address_list", str(ctx.exception))

    @patch("app.alibaba._build_cloudfw_client")
    def test_delete_address_book_success(self, mock_build):
        client = MagicMock()
        client.delete_address_book.return_value = mock_resp({"RequestId": "r1"})
        mock_build.return_value = client
        result = self.connector.delete_address_book(make_request({"group_uuid": "g1"}))
        self.assertEqual(result["status"], "success")

    @patch("app.alibaba._build_cloudfw_client")
    def test_delete_address_book_missing(self, mock_build):
        mock_build.return_value = MagicMock()
        with self.assertRaises(Exception) as ctx:
            self.connector.delete_address_book(make_request({}))
        self.assertIn("Missing required parameter: group_uuid", str(ctx.exception))

    # ---------------------------------------------------------------
    # Security Center — handle security events (remediate)
    # ---------------------------------------------------------------

    @patch("app.alibaba._build_sas_client")
    def test_handle_security_events_success(self, mock_build):
        client = MagicMock()
        client.handle_security_events.return_value = mock_resp({"RequestId": "r1"})
        mock_build.return_value = client
        result = self.connector.handle_security_events(make_request({
            "security_event_ids": "101,102", "operation_code": "ignore",
        }))
        self.assertEqual(result["status"], "success")
        # confirm the comma-separated IDs were converted to a list for the SDK
        args, _ = client.handle_security_events.call_args
        self.assertEqual(args[0].security_event_ids, ["101", "102"])

    @patch("app.alibaba._build_sas_client")
    def test_handle_security_events_missing_code(self, mock_build):
        mock_build.return_value = MagicMock()
        with self.assertRaises(Exception) as ctx:
            self.connector.handle_security_events(make_request({"security_event_ids": "101"}))
        self.assertIn("Missing required parameter: operation_code", str(ctx.exception))

    @patch("app.alibaba._build_sas_client")
    def test_handle_security_events_missing_ids(self, mock_build):
        mock_build.return_value = MagicMock()
        with self.assertRaises(Exception) as ctx:
            self.connector.handle_security_events(make_request({"operation_code": "ignore"}))
        self.assertIn("Missing required parameter: security_event_ids", str(ctx.exception))

    # ---------------------------------------------------------------
    # error propagation from the SDK call
    # ---------------------------------------------------------------

    @patch("app.alibaba._build_cloudfw_client")
    def test_sdk_error_propagates(self, mock_build):
        client = MagicMock()
        client.describe_control_policy.side_effect = Exception("Throttling.User")
        mock_build.return_value = client
        with self.assertRaises(Exception) as ctx:
            self.connector.describe_control_policy(make_request({"direction": "in"}))
        self.assertIn("Throttling.User", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
