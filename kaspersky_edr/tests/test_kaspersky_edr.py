import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import unittest
from unittest.mock import patch, MagicMock

from app.kaspersky_edr import KasperskyEdr


CONNECTION_PARAMS = {
    "ksc_host": "ksc.example.com",
    "ksc_port": "13299",
    "ksc_user": "soar_user",
    "ksc_password": "secret",
    "verify_ssl": "true",
}


def make_request(parameters: dict):
    req = MagicMock()
    req.connectionParameters = CONNECTION_PARAMS
    req.parameters = parameters
    return req


def mock_json_response(data: dict, status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = b"x" if data else b""
    resp.json.return_value = data
    return resp


def login_ok():
    """login success -> empty JSON object (connection authenticated)."""
    return mock_json_response({})


def addincident_ok(incident_id=4595):
    """AddIncident success -> incident id in PxgRetVal."""
    return mock_json_response({"PxgRetVal": incident_id})


def updateincident_ok():
    """UpdateIncident success -> empty object (no retval)."""
    return mock_json_response({})


def action_posts(incident_id=4595):
    """The 3 session.post responses for an action: login, AddIncident, UpdateIncident."""
    return [login_ok(), addincident_ok(incident_id), updateincident_ok()]


def make_session(post_side_effect=None, post_return=None):
    """
    Build a mock requests.Session whose .post is controllable. The connector
    calls session.post(login) then session.post(method).
    """
    session = MagicMock()
    if post_side_effect is not None:
        session.post.side_effect = post_side_effect
    else:
        session.post.return_value = post_return
    return session


class TestKasperskyEdr(unittest.TestCase):

    def setUp(self):
        self.connector = KasperskyEdr()

    # ---------------------------------------------------------------
    # test_connection
    # ---------------------------------------------------------------

    @patch("app.kaspersky_edr.requests.Session")
    def test_connection_success(self, mock_session_cls):
        session = make_session(post_return=login_ok())
        mock_session_cls.return_value = session
        result = self.connector.test_connection(CONNECTION_PARAMS)
        self.assertEqual(result["status"], "success")
        self.assertIn("Connected to Kaspersky Security Center", result["message"])
        # confirm login called with a KSCBasic auth header
        _, kwargs = session.post.call_args
        self.assertIn("KSCBasic", kwargs["headers"]["Authorization"])

    @patch("app.kaspersky_edr.requests.Session")
    def test_connection_auth_401(self, mock_session_cls):
        mock_session_cls.return_value = make_session(post_return=mock_json_response({}, status_code=401))
        with self.assertRaises(Exception) as ctx:
            self.connector.test_connection(CONNECTION_PARAMS)
        self.assertIn("Authentication failed", str(ctx.exception))

    @patch("app.kaspersky_edr.requests.Session")
    def test_connection_pxgerror(self, mock_session_cls):
        mock_session_cls.return_value = make_session(
            post_return=mock_json_response({"PxgError": {"code": 1234, "message": "Access denied", "module": "KLSTD"}}))
        with self.assertRaises(Exception) as ctx:
            self.connector.test_connection(CONNECTION_PARAMS)
        self.assertIn("Access denied", str(ctx.exception))

    def test_connection_missing_host(self):
        with self.assertRaises(Exception) as ctx:
            self.connector.test_connection({"ksc_user": "u", "ksc_password": "p"})
        self.assertIn("Missing required connection parameter: ksc_host", str(ctx.exception))

    # helper: the AddIncident body from the 2nd session.post call (login is 1st)
    def _incident_body(self, session):
        add_call = session.post.call_args_list[1]
        payload = json.loads(add_call.kwargs["data"])
        return payload, json.loads(payload["pData"]["KLINCDT_BODY"])

    @staticmethod
    def _post_url(call):
        # url is passed positionally: session.post(url, headers=..., data=..., timeout=...)
        return call.args[0] if call.args else call.kwargs.get("url")

    # ---------------------------------------------------------------
    # isolate_host
    # ---------------------------------------------------------------

    @patch("app.kaspersky_edr.requests.Session")
    def test_isolate_host_success(self, mock_session_cls):
        session = make_session(post_side_effect=action_posts(10))
        mock_session_cls.return_value = session
        result = self.connector.isolate_host(make_request({"target_host": "HOST1", "action": "1"}))
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["results"]["incident_id"], 10)
        self.assertEqual(result["results"]["task"], "isolateHost")
        payload, body = self._incident_body(session)
        self.assertEqual(body["task"], "isolateHost")
        self.assertEqual(body["params"]["action"], 1)
        self.assertEqual(body["responseEventIncident"], True)
        self.assertEqual(payload["pData"]["KLHST_WKS_HOSTNAME"], "HOST1")
        self.assertEqual(payload["pData"]["KLINCDT_SEVERITY"], 2)
        self.assertEqual(payload["pData"]["KLINCDT_ADDED"]["type"], "datetime")

    @patch("app.kaspersky_edr.requests.Session")
    def test_action_calls_add_then_update_incident(self, mock_session_cls):
        # Verify the documented AddIncident -> UpdateIncident flow (3 posts total:
        # login, AddIncident, UpdateIncident).
        session = make_session(post_side_effect=action_posts(77))
        mock_session_cls.return_value = session
        self.connector.isolate_host(make_request({"target_host": "HOST1", "action": "0"}))
        self.assertEqual(session.post.call_count, 3)
        add_url = self._post_url(session.post.call_args_list[1])
        upd_call = session.post.call_args_list[2]
        upd_payload = json.loads(upd_call.kwargs["data"])
        self.assertTrue(add_url.endswith("/HostGroup.AddIncident"))
        self.assertTrue(self._post_url(upd_call).endswith("/HostGroup.UpdateIncident"))
        self.assertEqual(upd_payload["nId"], 77)
        self.assertFalse(upd_payload["pData"]["KLINCDT_IS_HANDLED"])
        self.assertEqual(upd_payload["pData"]["KLHST_WKS_HOSTNAME"], "HOST1")

    @patch("app.kaspersky_edr.requests.Session")
    def test_isolate_host_invalid_action(self, mock_session_cls):
        mock_session_cls.return_value = make_session(post_return=login_ok())
        with self.assertRaises(Exception) as ctx:
            self.connector.isolate_host(make_request({"target_host": "HOST1", "action": "5"}))
        self.assertIn("action must be 0", str(ctx.exception))

    @patch("app.kaspersky_edr.requests.Session")
    def test_isolate_host_missing_target(self, mock_session_cls):
        mock_session_cls.return_value = make_session(post_return=login_ok())
        with self.assertRaises(Exception) as ctx:
            self.connector.isolate_host(make_request({"action": "1"}))
        self.assertIn("Missing required parameter: target_host", str(ctx.exception))

    # ---------------------------------------------------------------
    # prevent_execution
    # ---------------------------------------------------------------

    @patch("app.kaspersky_edr.requests.Session")
    def test_prevent_execution_success(self, mock_session_cls):
        session = make_session(post_side_effect=action_posts())
        mock_session_cls.return_value = session
        result = self.connector.prevent_execution(make_request({
            "target_host": "HOST1", "hash": "d41d8cd98f00b204e9800998ecf8427e",
            "path": "C:\\bad.exe", "case_sensitive": "false",
        }))
        self.assertEqual(result["status"], "success")
        _, body = self._incident_body(session)
        self.assertEqual(body["task"], "preventExecution")
        self.assertFalse(body["params"]["caseSensitive"])

    @patch("app.kaspersky_edr.requests.Session")
    def test_prevent_execution_missing_hash(self, mock_session_cls):
        mock_session_cls.return_value = make_session(post_return=login_ok())
        with self.assertRaises(Exception) as ctx:
            self.connector.prevent_execution(make_request({"target_host": "HOST1", "path": "C:\\x"}))
        self.assertIn("Missing required parameter: hash", str(ctx.exception))

    # ---------------------------------------------------------------
    # quarantine / delete / get file
    # ---------------------------------------------------------------

    @patch("app.kaspersky_edr.requests.Session")
    def test_quarantine_file_success(self, mock_session_cls):
        session = make_session(post_side_effect=action_posts())
        mock_session_cls.return_value = session
        result = self.connector.quarantine_file(make_request({"target_host": "H", "path": "C:\\m.exe"}))
        self.assertEqual(result["status"], "success")
        _, body = self._incident_body(session)
        self.assertEqual(body["task"], "quarantineFile")

    @patch("app.kaspersky_edr.requests.Session")
    def test_delete_file_with_subfolders(self, mock_session_cls):
        session = make_session(post_side_effect=action_posts())
        mock_session_cls.return_value = session
        result = self.connector.delete_file(make_request({
            "target_host": "H", "path": "C:\\m.exe", "search_in_subfolders": "true",
        }))
        self.assertEqual(result["status"], "success")
        _, body = self._incident_body(session)
        self.assertEqual(body["task"], "deleteFile")
        self.assertTrue(body["params"]["searchInSubfolders"])

    @patch("app.kaspersky_edr.requests.Session")
    def test_delete_file_missing_path(self, mock_session_cls):
        mock_session_cls.return_value = make_session(post_return=login_ok())
        with self.assertRaises(Exception) as ctx:
            self.connector.delete_file(make_request({"target_host": "H"}))
        self.assertIn("Missing required parameter: path", str(ctx.exception))

    @patch("app.kaspersky_edr.requests.Session")
    def test_get_file_success(self, mock_session_cls):
        session = make_session(post_side_effect=action_posts())
        mock_session_cls.return_value = session
        result = self.connector.get_file(make_request({"target_host": "H", "path": "C:\\f.txt"}))
        self.assertEqual(result["status"], "success")
        _, body = self._incident_body(session)
        self.assertEqual(body["task"], "getFile")

    # ---------------------------------------------------------------
    # terminate / start process
    # ---------------------------------------------------------------

    @patch("app.kaspersky_edr.requests.Session")
    def test_terminate_process_success(self, mock_session_cls):
        session = make_session(post_side_effect=action_posts())
        mock_session_cls.return_value = session
        result = self.connector.terminate_process(make_request({"target_host": "H", "path": "C:\\p.exe"}))
        self.assertEqual(result["status"], "success")
        _, body = self._incident_body(session)
        self.assertEqual(body["task"], "terminateProcess")

    @patch("app.kaspersky_edr.requests.Session")
    def test_start_process_success(self, mock_session_cls):
        session = make_session(post_side_effect=action_posts())
        mock_session_cls.return_value = session
        result = self.connector.start_process(make_request({
            "target_host": "H", "executable_path": "C:\\tool.exe", "arguments": "-scan",
        }))
        self.assertEqual(result["status"], "success")
        _, body = self._incident_body(session)
        self.assertEqual(body["task"], "startProcess")
        self.assertEqual(body["params"]["arguments"], "-scan")

    @patch("app.kaspersky_edr.requests.Session")
    def test_start_process_missing_exec(self, mock_session_cls):
        mock_session_cls.return_value = make_session(post_return=login_ok())
        with self.assertRaises(Exception) as ctx:
            self.connector.start_process(make_request({"target_host": "H"}))
        self.assertIn("Missing required parameter: executable_path", str(ctx.exception))

    # ---------------------------------------------------------------
    # ioc scan / malware scan
    # ---------------------------------------------------------------

    @patch("app.kaspersky_edr.requests.Session")
    def test_ioc_scan_success(self, mock_session_cls):
        session = make_session(post_side_effect=action_posts())
        mock_session_cls.return_value = session
        result = self.connector.ioc_scan(make_request({
            "target_host": "H", "ioc": "base64zip==", "isolate_host": "true",
        }))
        self.assertEqual(result["status"], "success")
        _, body = self._incident_body(session)
        self.assertEqual(body["task"], "iocScan")
        self.assertTrue(body["params"]["isolateHost"])

    @patch("app.kaspersky_edr.requests.Session")
    def test_on_demand_scan_by_name(self, mock_session_cls):
        session = make_session(post_side_effect=action_posts())
        mock_session_cls.return_value = session
        result = self.connector.on_demand_scan(make_request({
            "target_host": "H", "path": "C:\\dir", "scan_type": "Folder", "recursive": "true",
        }))
        self.assertEqual(result["status"], "success")
        _, body = self._incident_body(session)
        self.assertEqual(body["task"], "onDemandScan")
        # params is an array; Folder -> 22
        self.assertEqual(body["params"][0]["type"], 22)
        self.assertTrue(body["params"][0]["recursive"])

    @patch("app.kaspersky_edr.requests.Session")
    def test_on_demand_scan_by_int(self, mock_session_cls):
        session = make_session(post_side_effect=action_posts())
        mock_session_cls.return_value = session
        result = self.connector.on_demand_scan(make_request({
            "target_host": "H", "path": "C:\\dir", "scan_type": "14",
        }))
        self.assertEqual(result["status"], "success")
        _, body = self._incident_body(session)
        self.assertEqual(body["params"][0]["type"], 14)

    @patch("app.kaspersky_edr.requests.Session")
    def test_on_demand_scan_invalid_type(self, mock_session_cls):
        mock_session_cls.return_value = make_session(post_return=login_ok())
        with self.assertRaises(Exception) as ctx:
            self.connector.on_demand_scan(make_request({
                "target_host": "H", "path": "C:\\dir", "scan_type": "Nonsense",
            }))
        self.assertIn("scan_type must be", str(ctx.exception))

    # ---------------------------------------------------------------
    # AddIncident returning PxgError (HTTP 200)
    # ---------------------------------------------------------------

    @patch("app.kaspersky_edr.requests.Session")
    def test_addincident_pxgerror(self, mock_session_cls):
        mock_session_cls.return_value = make_session(post_side_effect=[
            login_ok(),
            mock_json_response({"PxgError": {"code": 1681, "module": "KLFT", "message": "Bad request"}}),
        ])
        with self.assertRaises(Exception) as ctx:
            self.connector.isolate_host(make_request({"target_host": "H", "action": "1"}))
        self.assertIn("Bad request", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
