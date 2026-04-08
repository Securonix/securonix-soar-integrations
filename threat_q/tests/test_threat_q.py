import unittest
from unittest.mock import patch, MagicMock, call
from app.threat_q import ThreatQ


def mock_auth_response():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"access_token": "test_token"}
    mock_resp.raise_for_status = MagicMock()
    return mock_resp


def mock_api_response(data, status_code=200):
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.text = str(data)
    mock_resp.json.return_value = data
    return mock_resp


def make_request(conn_params, parameters=None):
    req = MagicMock()
    req.connectionParameters = conn_params
    req.parameters = parameters or {}
    return req


class TestThreatQConnection(unittest.TestCase):

    def setUp(self):
        self.tq = ThreatQ()
        self.conn_params = {
            "base_url": "https://threatq.example.com",
            "client_id": "test_client_id",
            "email": "[email]",
            "password": "[password]"
        }

    @patch('app.threat_q.requests.post')
    def test_connection_success(self, mock_post):
        mock_post.return_value = mock_auth_response()
        result = self.tq.test_connection(self.conn_params)
        self.assertEqual(result['status'], 'success')

    @patch('app.threat_q.requests.post')
    def test_connection_failure(self, mock_post):
        mock_post.side_effect = Exception("Connection refused")
        with self.assertRaises(Exception):
            self.tq.test_connection(self.conn_params)

    @patch('app.threat_q.requests.post')
    def test_connection_no_token(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp
        with self.assertRaises(Exception) as ctx:
            self.tq.test_connection(self.conn_params)
        self.assertIn("Failed to obtain access token", str(ctx.exception))


class TestThreatQRequest(unittest.TestCase):

    def setUp(self):
        self.tq = ThreatQ()
        self.conn_params = {
            "base_url": "https://threatq.example.com",
            "client_id": "test_client_id",
            "email": "[email]",
            "password": "[password]"
        }
        self.tq._base_url = "https://threatq.example.com"
        self.tq._access_token = "test_token"

    @patch('app.threat_q.requests.request')
    def test_request_401_error(self, mock_request):
        mock_request.return_value = mock_api_response({}, 401)
        with self.assertRaises(Exception) as ctx:
            self.tq._request("GET", "/indicators")
        self.assertIn("Authentication failed", str(ctx.exception))

    @patch('app.threat_q.requests.request')
    def test_request_404_error(self, mock_request):
        mock_request.return_value = mock_api_response({}, 404)
        with self.assertRaises(Exception) as ctx:
            self.tq._request("GET", "/indicators/999")
        self.assertIn("Object not found", str(ctx.exception))

    @patch('app.threat_q.requests.request')
    def test_request_400_error(self, mock_request):
        mock_resp = mock_api_response({}, 400)
        mock_resp.text = "Bad request details"
        mock_request.return_value = mock_resp
        with self.assertRaises(Exception) as ctx:
            self.tq._request("POST", "/indicators")
        self.assertIn("Bad request", str(ctx.exception))

    @patch('app.threat_q.requests.request')
    def test_request_500_error(self, mock_request):
        mock_request.return_value = mock_api_response({}, 500)
        with self.assertRaises(Exception) as ctx:
            self.tq._request("GET", "/indicators")
        self.assertIn("server error", str(ctx.exception))

    @patch('app.threat_q.requests.request')
    def test_request_204_returns_empty(self, mock_request):
        mock_request.return_value = mock_api_response({}, 204)
        result = self.tq._request("DELETE", "/indicators/1")
        self.assertEqual(result, {})

    @patch('app.threat_q.requests.request')
    def test_request_timeout(self, mock_request):
        import requests
        mock_request.side_effect = requests.exceptions.Timeout()
        with self.assertRaises(Exception) as ctx:
            self.tq._request("GET", "/indicators")
        self.assertIn("timed out", str(ctx.exception))

    @patch('app.threat_q.requests.request')
    def test_request_connection_error(self, mock_request):
        import requests
        mock_request.side_effect = requests.exceptions.ConnectionError()
        with self.assertRaises(Exception) as ctx:
            self.tq._request("GET", "/indicators")
        self.assertIn("Failed to connect", str(ctx.exception))

    def test_get_obj_endpoint_valid(self):
        self.assertEqual(self.tq._get_obj_endpoint("indicator"), "indicators")
        self.assertEqual(self.tq._get_obj_endpoint("event"), "events")
        self.assertEqual(self.tq._get_obj_endpoint("adversary"), "adversaries")
        self.assertEqual(self.tq._get_obj_endpoint("attachment"), "attachments")

    def test_get_obj_endpoint_invalid(self):
        with self.assertRaises(Exception) as ctx:
            self.tq._get_obj_endpoint("invalid_type")
        self.assertIn("Invalid object type", str(ctx.exception))


class TestThreatQSearchActions(unittest.TestCase):

    def setUp(self):
        self.tq = ThreatQ()
        self.conn_params = {
            "base_url": "https://threatq.example.com",
            "client_id": "test_client_id",
            "email": "[email]",
            "password": "[password]"
        }

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_search_by_name_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": [{"value": "test_indicator", "id": 1}]
        })
        req = make_request(self.conn_params, {"name": "test", "limit": 10})
        result = self.tq.search_by_name(req)
        self.assertEqual(result['status'], 'success')

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_search_by_name_no_results(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({"data": []})
        req = make_request(self.conn_params, {"name": "nonexistent"})
        result = self.tq.search_by_name(req)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['results'], [])

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_search_by_id_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": {"id": 1, "value": "192.168.1.1"}
        })
        req = make_request(self.conn_params, {"obj_type": "indicator", "obj_id": "1"})
        result = self.tq.search_by_id(req)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['result']['id'], 1)

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_search_by_id_invalid_type(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        req = make_request(self.conn_params, {"obj_type": "invalid", "obj_id": "1"})
        with self.assertRaises(Exception):
            self.tq.search_by_id(req)


class TestThreatQReputationActions(unittest.TestCase):

    def setUp(self):
        self.tq = ThreatQ()
        self.conn_params = {
            "base_url": "https://threatq.example.com",
            "client_id": "test_client_id",
            "email": "[email]",
            "password": "[password]"
        }

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_ip_reputation_found(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": [{"id": 1, "value": "192.168.1.1", "status": "Active"}]
        })
        req = make_request(self.conn_params, {"ip": "192.168.1.1"})
        result = self.tq.ip_reputation(req)
        self.assertEqual(result['status'], 'success')
        self.assertNotEqual(result['result'], "No results found")

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_ip_reputation_not_found(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({"data": []})
        req = make_request(self.conn_params, {"ip": "10.0.0.1"})
        result = self.tq.ip_reputation(req)
        self.assertEqual(result['result'], "No results found")

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_url_reputation_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": [{"id": 2, "value": "http://malicious.com"}]
        })
        req = make_request(self.conn_params, {"url": "http://malicious.com"})
        result = self.tq.url_reputation(req)
        self.assertEqual(result['status'], 'success')

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_domain_reputation_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": [{"id": 3, "value": "malicious.com"}]
        })
        req = make_request(self.conn_params, {"domain": "malicious.com"})
        result = self.tq.domain_reputation(req)
        self.assertEqual(result['status'], 'success')

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_file_reputation_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": [{"id": 4, "value": "abc123hash"}]
        })
        req = make_request(self.conn_params, {"file": "abc123hash"})
        result = self.tq.file_reputation(req)
        self.assertEqual(result['status'], 'success')

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_email_reputation_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": [{"id": 5, "value": "[email]"}]
        })
        req = make_request(self.conn_params, {"email": "[email]"})
        result = self.tq.email_reputation(req)
        self.assertEqual(result['status'], 'success')


class TestThreatQIndicatorActions(unittest.TestCase):

    def setUp(self):
        self.tq = ThreatQ()
        self.conn_params = {
            "base_url": "https://threatq.example.com",
            "client_id": "test_client_id",
            "email": "[email]",
            "password": "[password]"
        }

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_create_indicator_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.side_effect = [
            mock_api_response({"data": [{"name": "IP Address", "id": 1}]}),
            mock_api_response({"data": {"id": 100, "value": "10.0.0.1"}})
        ]
        req = make_request(self.conn_params, {
            "type": "IP Address", "status": "Active",
            "value": "10.0.0.1", "sources": "TestSource",
            "attributes_names": "attr1", "attributes_values": "val1"
        })
        result = self.tq.create_indicator(req)
        self.assertEqual(result['status'], 'success')

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_create_indicator_invalid_status(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": [{"name": "IP Address", "id": 1}]
        })
        req = make_request(self.conn_params, {
            "type": "IP Address", "status": "InvalidStatus", "value": "10.0.0.1"
        })
        with self.assertRaises(Exception) as ctx:
            self.tq.create_indicator(req)
        self.assertIn("Invalid status", str(ctx.exception))

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_edit_indicator_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": {"id": 100, "value": "updated_value"}
        })
        req = make_request(self.conn_params, {
            "id": "100", "value": "updated_value", "description": "test desc"
        })
        result = self.tq.edit_indicator(req)
        self.assertEqual(result['status'], 'success')

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_update_status_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": {"id": 100, "status": "Whitelisted"}
        })
        req = make_request(self.conn_params, {"id": "100", "status": "Whitelisted"})
        result = self.tq.update_status(req)
        self.assertEqual(result['status'], 'success')

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_update_status_invalid(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        req = make_request(self.conn_params, {"id": "100", "status": "BadStatus"})
        with self.assertRaises(Exception) as ctx:
            self.tq.update_status(req)
        self.assertIn("Invalid status", str(ctx.exception))

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_update_score_manual(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": {"id": 100, "manual_score": 5}
        })
        req = make_request(self.conn_params, {"id": "100", "score": "5"})
        result = self.tq.update_score(req)
        self.assertEqual(result['status'], 'success')

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_update_score_generated(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": {"id": 100, "manual_score": None}
        })
        req = make_request(self.conn_params, {"id": "100", "score": "Generated Score"})
        result = self.tq.update_score(req)
        self.assertEqual(result['status'], 'success')

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_get_all_indicators_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": [{"id": 1}, {"id": 2}], "total": 2
        })
        req = make_request(self.conn_params, {"page": "0", "limit": "50"})
        result = self.tq.get_all_indicators(req)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(len(result['indicators']), 2)
        self.assertEqual(result['total'], 2)


class TestThreatQAdversaryActions(unittest.TestCase):

    def setUp(self):
        self.tq = ThreatQ()
        self.conn_params = {
            "base_url": "https://threatq.example.com",
            "client_id": "test_client_id",
            "email": "[email]",
            "password": "[password]"
        }

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_create_adversary_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": {"id": 10, "name": "APT29"}
        })
        req = make_request(self.conn_params, {"name": "APT29", "sources": "Intel,OSINT"})
        result = self.tq.create_adversary(req)
        self.assertEqual(result['status'], 'success')

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_edit_adversary_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": {"id": 10, "name": "APT29 Updated"}
        })
        req = make_request(self.conn_params, {"id": "10", "name": "APT29 Updated"})
        result = self.tq.edit_adversary(req)
        self.assertEqual(result['status'], 'success')

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_get_all_adversaries_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": [{"id": 1, "name": "APT29"}], "total": 1
        })
        req = make_request(self.conn_params, {"page": "0", "limit": "50"})
        result = self.tq.get_all_adversaries(req)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(len(result['adversaries']), 1)


class TestThreatQEventActions(unittest.TestCase):

    def setUp(self):
        self.tq = ThreatQ()
        self.conn_params = {
            "base_url": "https://threatq.example.com",
            "client_id": "test_client_id",
            "email": "[email]",
            "password": "[password]"
        }

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_create_event_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": {"id": 20, "title": "Incident"}
        })
        req = make_request(self.conn_params, {
            "title": "Incident", "type": "Malware",
            "date": "2025-01-01 00:00:00", "sources": "Intel"
        })
        result = self.tq.create_event(req)
        self.assertEqual(result['status'], 'success')

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_edit_event_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.side_effect = [
            mock_api_response({"data": [{"name": "Malware", "id": 1}]}),
            mock_api_response({"data": {"id": 20, "title": "Updated"}})
        ]
        req = make_request(self.conn_params, {
            "id": "20", "title": "Updated", "type": "Malware",
            "date": "2025-02-01", "description": "Updated desc"
        })
        result = self.tq.edit_event(req)
        self.assertEqual(result['status'], 'success')

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_get_all_events_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": [{"id": 1, "title": "Event1"}], "total": 1
        })
        req = make_request(self.conn_params, {"page": "0", "limit": "50"})
        result = self.tq.get_all_events(req)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(len(result['events']), 1)


class TestThreatQAttributeActions(unittest.TestCase):

    def setUp(self):
        self.tq = ThreatQ()
        self.conn_params = {
            "base_url": "https://threatq.example.com",
            "client_id": "test_client_id",
            "email": "[email]",
            "password": "[password]"
        }

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_add_attribute_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": {"id": 50, "name": "attr1", "value": "val1"}
        })
        req = make_request(self.conn_params, {
            "obj_type": "indicator", "obj_id": "100",
            "name": "attr1", "value": "val1"
        })
        result = self.tq.add_attribute(req)
        self.assertEqual(result['status'], 'success')

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_modify_attribute_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": {"id": 50, "value": "new_val"}
        })
        req = make_request(self.conn_params, {
            "obj_type": "indicator", "obj_id": "100",
            "attribute_id": "50", "attribute_value": "new_val"
        })
        result = self.tq.modify_attribute(req)
        self.assertEqual(result['status'], 'success')

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_delete_attribute_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_resp.text = ""
        mock_resp.json.return_value = {}
        mock_request.return_value = mock_resp
        req = make_request(self.conn_params, {
            "obj_type": "indicator", "obj_id": "100", "attribute_id": "50"
        })
        result = self.tq.delete_attribute(req)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['result'], "Attribute deleted")


class TestThreatQSourceActions(unittest.TestCase):

    def setUp(self):
        self.tq = ThreatQ()
        self.conn_params = {
            "base_url": "https://threatq.example.com",
            "client_id": "test_client_id",
            "email": "[email]",
            "password": "[password]"
        }

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_add_source_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": {"id": 60, "name": "AlienVault"}
        })
        req = make_request(self.conn_params, {
            "obj_type": "indicator", "obj_id": "100", "source": "AlienVault"
        })
        result = self.tq.add_source(req)
        self.assertEqual(result['status'], 'success')

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_delete_source_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_resp.text = ""
        mock_resp.json.return_value = {}
        mock_request.return_value = mock_resp
        req = make_request(self.conn_params, {
            "obj_type": "indicator", "obj_id": "100", "source_id": "60"
        })
        result = self.tq.delete_source(req)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['result'], "Source deleted")


class TestThreatQLinkActions(unittest.TestCase):

    def setUp(self):
        self.tq = ThreatQ()
        self.conn_params = {
            "base_url": "https://threatq.example.com",
            "client_id": "test_client_id",
            "email": "[email]",
            "password": "[password]"
        }

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_link_objects_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": {"id": 1}
        })
        req = make_request(self.conn_params, {
            "obj1_type": "indicator", "obj1_id": "100",
            "obj2_type": "adversary", "obj2_id": "10"
        })
        result = self.tq.link_objects(req)
        self.assertEqual(result['status'], 'success')

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_unlink_objects_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.side_effect = [
            mock_api_response({
                "data": [{"id": 10, "pivot": {"id": 999}}]
            }),
            mock_api_response({}, 204)
        ]
        req = make_request(self.conn_params, {
            "obj1_type": "indicator", "obj1_id": "100",
            "obj2_type": "adversary", "obj2_id": "10"
        })
        result = self.tq.unlink_objects(req)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['result'], "Objects unlinked")

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_unlink_objects_not_found(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({"data": []})
        req = make_request(self.conn_params, {
            "obj1_type": "indicator", "obj1_id": "100",
            "obj2_type": "adversary", "obj2_id": "999"
        })
        with self.assertRaises(Exception) as ctx:
            self.tq.unlink_objects(req)
        self.assertIn("Link not found", str(ctx.exception))


class TestThreatQDeleteAndRelatedActions(unittest.TestCase):

    def setUp(self):
        self.tq = ThreatQ()
        self.conn_params = {
            "base_url": "https://threatq.example.com",
            "client_id": "test_client_id",
            "email": "[email]",
            "password": "[password]"
        }

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_delete_object_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_resp.text = ""
        mock_resp.json.return_value = {}
        mock_request.return_value = mock_resp
        req = make_request(self.conn_params, {"obj_type": "event", "obj_id": "20"})
        result = self.tq.delete_object(req)
        self.assertEqual(result['status'], 'success')
        self.assertIn("deleted", result['result'])

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_get_related_indicators_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": [{"id": 1, "value": "10.0.0.1"}]
        })
        req = make_request(self.conn_params, {"obj_type": "adversary", "obj_id": "10"})
        result = self.tq.get_related_indicators(req)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(len(result['indicators']), 1)

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_get_related_events_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": [{"id": 20, "title": "Incident"}]
        })
        req = make_request(self.conn_params, {"obj_type": "indicator", "obj_id": "100"})
        result = self.tq.get_related_events(req)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(len(result['events']), 1)

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_get_related_adversaries_success(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "data": [{"id": 10, "name": "APT29"}]
        })
        req = make_request(self.conn_params, {"obj_type": "event", "obj_id": "20"})
        result = self.tq.get_related_adversaries(req)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(len(result['adversaries']), 1)


if __name__ == '__main__':
    unittest.main()
