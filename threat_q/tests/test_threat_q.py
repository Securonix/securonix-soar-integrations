import json
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
        self.base_url = "https://threatq.example.com"
        self.access_token = "test_token"

    @patch('app.threat_q.requests.request')
    def test_request_401_error(self, mock_request):
        mock_request.return_value = mock_api_response({}, 401)
        with self.assertRaises(Exception) as ctx:
            self.tq._request(self.base_url, self.access_token, "GET", "/indicators")
        self.assertIn("Authentication failed", str(ctx.exception))

    @patch('app.threat_q.requests.request')
    def test_request_404_error(self, mock_request):
        mock_request.return_value = mock_api_response({}, 404)
        with self.assertRaises(Exception) as ctx:
            self.tq._request(self.base_url, self.access_token, "GET", "/indicators/999")
        self.assertIn("Object not found", str(ctx.exception))

    @patch('app.threat_q.requests.request')
    def test_request_400_error(self, mock_request):
        mock_resp = mock_api_response({}, 400)
        mock_resp.text = "Bad request details"
        mock_request.return_value = mock_resp
        with self.assertRaises(Exception) as ctx:
            self.tq._request(self.base_url, self.access_token, "POST", "/indicators")
        self.assertIn("Bad request", str(ctx.exception))

    @patch('app.threat_q.requests.request')
    def test_request_500_error(self, mock_request):
        mock_request.return_value = mock_api_response({}, 500)
        with self.assertRaises(Exception) as ctx:
            self.tq._request(self.base_url, self.access_token, "GET", "/indicators")
        self.assertIn("server error", str(ctx.exception))

    @patch('app.threat_q.requests.request')
    def test_request_204_returns_empty(self, mock_request):
        mock_request.return_value = mock_api_response({}, 204)
        result = self.tq._request(self.base_url, self.access_token, "DELETE", "/indicators/1")
        self.assertEqual(result, {})

    @patch('app.threat_q.requests.request')
    def test_request_timeout(self, mock_request):
        import requests
        mock_request.side_effect = requests.exceptions.Timeout()
        with self.assertRaises(Exception) as ctx:
            self.tq._request(self.base_url, self.access_token, "GET", "/indicators")
        self.assertIn("timed out", str(ctx.exception))

    @patch('app.threat_q.requests.request')
    def test_request_connection_error(self, mock_request):
        import requests
        mock_request.side_effect = requests.exceptions.ConnectionError()
        with self.assertRaises(Exception) as ctx:
            self.tq._request(self.base_url, self.access_token, "GET", "/indicators")
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
        self.assertEqual(result['total_count'], 0)

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
        self.assertEqual(result['object_id'], "1")
        self.assertEqual(result['object_type'], "indicator")
        self.assertEqual(result['value'], "192.168.1.1")

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
            "total": 1,
            "data": [{
                "id": 1, "value": "192.168.1.1", "type_id": 10, "status_id": 1, "score": 8,
                "type": {"id": 10, "name": "IP Address"},
                "status": {"id": 1, "name": "Active"},
                "sources": [{"name": "Intel"}],
                "attributes": [{"name": "Confidence", "value": "High"}]
            }]
        })
        req = make_request(self.conn_params, {"ip": "192.168.1.1"})
        result = self.tq.ip_reputation(req)
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['found'])
        self.assertEqual(result['total_count'], 1)
        self.assertEqual(result['indicator_id'], "1")
        self.assertEqual(result['value'], "192.168.1.1")
        self.assertEqual(result['type_id'], 10)
        self.assertEqual(result['type'], "IP Address")
        self.assertEqual(result['status_id'], 1)
        self.assertEqual(result['indicator_status'], "Active")
        self.assertEqual(result['score'], 8)
        self.assertEqual(result['sources'], ["Intel"])
        self.assertEqual(len(result['attributes']), 1)
        self.assertIn('raw_response', result)

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_ip_reputation_not_found(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({"total": 0, "data": []})
        req = make_request(self.conn_params, {"ip": "10.0.0.1"})
        result = self.tq.ip_reputation(req)
        self.assertEqual(result['status'], 'success')
        self.assertFalse(result['found'])
        self.assertEqual(result['total_count'], 0)
        self.assertIsNone(result['indicator_id'])
        self.assertIsNone(result['score'])
        self.assertIsNone(result['indicator_status'])
        self.assertEqual(result['sources'], [])
        self.assertEqual(result['attributes'], [])

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
            # Verified create shape: list wrapper, nested type, only status_id, no score
            mock_api_response({"total": 1, "data": [{
                "id": 100, "value": "10.0.0.1", "type_id": 10, "status_id": 1,
                "type": {"id": 10, "name": "IP Address"},
                "sources": [{"name": "TestSource"}]
            }]})
        ]
        req = make_request(self.conn_params, {
            "type": "IP Address", "status": "Active",
            "value": "10.0.0.1", "sources": "TestSource",
            "attributes_names": "attr1", "attributes_values": "val1"
        })
        result = self.tq.create_indicator(req)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['indicator_id'], "100")
        self.assertEqual(result['value'], "10.0.0.1")
        self.assertEqual(result['type_id'], 10)
        self.assertEqual(result['type'], "IP Address")
        self.assertEqual(result['status_id'], 1)
        # Verified: create response omits nested status + score -> None
        self.assertIsNone(result['indicator_status'])
        self.assertIsNone(result['score'])
        self.assertIn('raw_response', result)

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
            "data": {"id": 100, "status": {"id": 5, "name": "Whitelisted"}}
        })
        req = make_request(self.conn_params, {"id": "100", "status": "Whitelisted"})
        result = self.tq.update_status(req)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['indicator_id'], "100")
        self.assertEqual(result['indicator_status'], "Whitelisted")

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
        # Server reports a larger total than the number of records on this page
        mock_request.return_value = mock_api_response({
            "data": [{"id": 1}, {"id": 2}], "total": 250
        })
        req = make_request(self.conn_params, {"page": "0", "limit": "50"})
        result = self.tq.get_all_indicators(req)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(len(result['indicators']), 2)
        self.assertEqual(result['total_count'], 250)  # server total, NOT len(data)
        self.assertEqual(result['count'], 2)


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
        self.assertEqual(result['adversary_id'], "10")
        self.assertEqual(result['name'], "APT29")

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
        self.assertEqual(result['total_count'], 1)
        self.assertEqual(result['count'], 1)


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
            "data": {"id": 20, "title": "Incident", "type_id": 1,
                     "happened_at": "2025-01-01 00:00:00",
                     "type": {"id": 1, "name": "Spearphish"}}
        })
        req = make_request(self.conn_params, {
            "title": "Incident", "type": "Spearphish",
            "date": "2025-01-01 00:00:00", "sources": "Intel"
        })
        result = self.tq.create_event(req)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['event_id'], "20")
        self.assertEqual(result['title'], "Incident")
        self.assertEqual(result['type_id'], 1)
        self.assertEqual(result['type'], "Spearphish")
        self.assertEqual(result['happened_at'], "2025-01-01 00:00:00")
        self.assertIn('description', result)

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
        self.assertEqual(result['total_count'], 1)
        self.assertEqual(result['count'], 1)


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
            "total": 1,
            "data": [{"id": 50, "indicator_id": 100, "attribute_id": 255,
                      "name": "attr1", "value": "val1"}]
        })
        req = make_request(self.conn_params, {
            "obj_type": "indicator", "obj_id": "100",
            "name": "attr1", "value": "val1"
        })
        result = self.tq.add_attribute(req)
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['succeeded'])
        self.assertEqual(result['object_attribute_id'], "50")
        self.assertEqual(result['attribute_id'], "50")  # deprecated alias == record id
        self.assertEqual(result['attribute_definition_id'], "255")
        self.assertEqual(result['object_id'], "100")
        self.assertEqual(result['attribute_name'], "attr1")
        self.assertEqual(result['attribute_value'], "val1")

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
        self.assertTrue(result['succeeded'])
        self.assertEqual(result['object_attribute_id'], "50")
        self.assertEqual(result['attribute_id'], "50")

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
        self.assertTrue(result['succeeded'])
        self.assertEqual(result['http_status'], 204)
        self.assertEqual(result['message'], "Attribute deleted")


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
            "total": 1,
            "data": [{"id": 60, "source_id": 10, "name": "AlienVault"}]
        })
        req = make_request(self.conn_params, {
            "obj_type": "indicator", "obj_id": "100", "source": "AlienVault"
        })
        result = self.tq.add_source(req)
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['succeeded'])
        self.assertEqual(result['object_source_id'], "60")
        self.assertEqual(result['source_id'], "60")  # deprecated alias == record id
        self.assertEqual(result['threatq_source_id'], "10")
        self.assertEqual(result['source_name'], "AlienVault")

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
        self.assertTrue(result['succeeded'])
        self.assertEqual(result['http_status'], 204)
        self.assertEqual(result['message'], "Source deleted")


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
            "total": 1,
            "data": [{"id": 10, "pivot": {"id": 999}}]
        })
        req = make_request(self.conn_params, {
            "obj1_type": "indicator", "obj1_id": "100",
            "obj2_type": "adversary", "obj2_id": "10"
        })
        result = self.tq.link_objects(req)
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['succeeded'])
        self.assertEqual(result['link_id'], "999")
        self.assertEqual(result['linked_id'], "10")

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
        self.assertTrue(result['succeeded'])
        self.assertEqual(result['http_status'], 204)
        self.assertEqual(result['message'], "Objects unlinked")

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
        self.assertTrue(result['succeeded'])
        self.assertEqual(result['http_status'], 204)
        self.assertIn("deleted", result['message'])

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
        self.assertEqual(result['total_count'], 1)

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
        self.assertEqual(result['total_count'], 1)

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
        self.assertEqual(result['total_count'], 1)


class TestThreatQIdDistinctionAndBC(unittest.TestCase):
    """Critical: object-attribute/object-source record IDs must never be
    swapped with definition/global IDs, and legacy input aliases must keep
    working with object_* taking precedence."""

    def setUp(self):
        self.tq = ThreatQ()
        self.conn_params = {
            "base_url": "https://threatq.example.com",
            "client_id": "c", "email": "[email]", "password": "[password]"
        }

    # ---- Attribute ID distinction (data.id=8, data.attribute_id=7) ----

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_add_attribute_id_not_swapped(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "total": 1,
            "data": [{"id": 8, "attribute_id": 7, "indicator_id": 100,
                      "name": "Confidence", "value": "High"}]
        })
        req = make_request(self.conn_params, {
            "obj_type": "indicator", "obj_id": "100", "name": "Confidence", "value": "High"
        })
        r = self.tq.add_attribute(req)
        self.assertEqual(r['object_attribute_id'], "8")     # record id
        self.assertEqual(r['attribute_id'], "8")            # legacy alias == record id
        self.assertEqual(r['attribute_definition_id'], "7")  # definition id
        self.assertEqual(r['object_id'], "100")

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_modify_attribute_object_attribute_id_precedence(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({"data": {"id": 8}})
        # both supplied -> object_attribute_id (8) wins, legacy attribute_id (999) ignored
        req = make_request(self.conn_params, {
            "obj_type": "indicator", "obj_id": "100",
            "object_attribute_id": "8", "attribute_id": "999", "attribute_value": "x"
        })
        r = self.tq.modify_attribute(req)
        self.assertEqual(r['object_attribute_id'], "8")
        self.assertEqual(r['attribute_id'], "8")
        called_url = mock_request.call_args[0][1]
        self.assertTrue(called_url.endswith("/attributes/8"))

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_modify_attribute_legacy_attribute_id_still_works(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({"data": {"id": 8}})
        req = make_request(self.conn_params, {
            "obj_type": "indicator", "obj_id": "100",
            "attribute_id": "8", "attribute_value": "x"
        })
        r = self.tq.modify_attribute(req)
        self.assertEqual(r['object_attribute_id'], "8")
        called_url = mock_request.call_args[0][1]
        self.assertTrue(called_url.endswith("/attributes/8"))

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_delete_attribute_object_attribute_id_precedence(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({}, 204)
        req = make_request(self.conn_params, {
            "obj_type": "indicator", "obj_id": "100",
            "object_attribute_id": "8", "attribute_id": "999"
        })
        r = self.tq.delete_attribute(req)
        self.assertEqual(r['object_attribute_id'], "8")
        called_url = mock_request.call_args[0][1]
        self.assertTrue(called_url.endswith("/attributes/8"))

    # ---- Source ID distinction (data.id=39, data.source_id=42) ----

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_add_source_id_not_swapped(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "total": 1,
            "data": [{"id": 39, "indicator_id": 100, "source_id": 42, "name": "Intel"}]
        })
        req = make_request(self.conn_params, {
            "obj_type": "indicator", "obj_id": "100", "source": "Intel"
        })
        r = self.tq.add_source(req)
        self.assertEqual(r['object_source_id'], "39")   # relationship record id
        self.assertEqual(r['source_id'], "39")          # legacy alias == record id
        self.assertEqual(r['threatq_source_id'], "42")  # global source id
        self.assertEqual(r['source_name'], "Intel")

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_delete_source_object_source_id_precedence(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({}, 204)
        req = make_request(self.conn_params, {
            "obj_type": "indicator", "obj_id": "100",
            "object_source_id": "39", "source_id": "999"
        })
        r = self.tq.delete_source(req)
        self.assertEqual(r['object_source_id'], "39")
        called_url = mock_request.call_args[0][1]
        self.assertTrue(called_url.endswith("/sources/39"))

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_delete_source_legacy_source_id_still_works(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({}, 204)
        req = make_request(self.conn_params, {
            "obj_type": "indicator", "obj_id": "100", "source_id": "39"
        })
        r = self.tq.delete_source(req)
        self.assertEqual(r['object_source_id'], "39")
        called_url = mock_request.call_args[0][1]
        self.assertTrue(called_url.endswith("/sources/39"))


class TestThreatQEdgeCases(unittest.TestCase):

    def setUp(self):
        self.tq = ThreatQ()
        self.conn_params = {
            "base_url": "https://threatq.example.com",
            "client_id": "c", "email": "[email]", "password": "[password]"
        }

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_reputation_zero_results(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({"total": 0, "data": []})
        req = make_request(self.conn_params, {"domain": "safe.com"})
        r = self.tq.domain_reputation(req)
        self.assertFalse(r['found'])
        self.assertEqual(r['total_count'], 0)
        self.assertIsNone(r['indicator_id'])
        self.assertIsNone(r['type_id'])
        self.assertIsNone(r['status_id'])

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_reputation_multiple_results_uses_first(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "total": 3,
            "data": [{"id": 11, "value": "a.com"}, {"id": 12}, {"id": 13}]
        })
        req = make_request(self.conn_params, {"domain": "a.com"})
        r = self.tq.domain_reputation(req)
        self.assertTrue(r['found'])
        self.assertEqual(r['total_count'], 3)
        self.assertEqual(r['indicator_id'], "11")

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_reputation_missing_relationships(self, mock_post, mock_request):
        # type_id/status_id present but nested type/status relationships absent
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "total": 1,
            "data": [{"id": 5, "value": "x.com", "type_id": 12, "status_id": 1}]
        })
        req = make_request(self.conn_params, {"domain": "x.com"})
        r = self.tq.domain_reputation(req)
        self.assertEqual(r['type_id'], 12)
        self.assertIsNone(r['type'])          # no manufactured name
        self.assertEqual(r['status_id'], 1)
        self.assertIsNone(r['indicator_status'])
        self.assertIsNone(r['score'])         # score absent -> null
        self.assertEqual(r['sources'], [])
        self.assertEqual(r['attributes'], [])

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_event_missing_type_and_description(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        # event with type_id but no nested type, and no description
        mock_request.return_value = mock_api_response({
            "data": {"id": 20, "title": "E", "type_id": 3, "happened_at": "2025-01-01"}
        })
        req = make_request(self.conn_params, {
            "title": "E", "type": "SQL Injection Attack", "date": "2025-01-01"
        })
        r = self.tq.create_event(req)
        self.assertEqual(r['type_id'], 3)
        self.assertIsNone(r['type'])         # relationship absent -> null
        self.assertIsNone(r['description'])  # resilient when absent

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_link_objects_selects_pivot_id_among_many_ids(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        # Multiple distinct nested ids: linked object id=10, pivot.id=999,
        # plus decoy ids that must NOT be chosen as link_id.
        mock_request.return_value = mock_api_response({
            "total": 1,
            "data": [{"id": 10, "type_id": 55,
                      "pivot": {"id": 999, "src_object_id": 100, "dest_object_id": 10}}]
        })
        req = make_request(self.conn_params, {
            "obj1_type": "indicator", "obj1_id": "100",
            "obj2_type": "adversary", "obj2_id": "10"
        })
        r = self.tq.link_objects(req)
        self.assertEqual(r['link_id'], "999")    # pivot.id
        self.assertEqual(r['linked_id'], "10")   # data[0].id

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_delete_object_204_empty_body(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        # HTTP 204, empty body: mock resp.text = "" so .json() is never called
        resp = MagicMock()
        resp.status_code = 204
        resp.text = ""
        resp.json.side_effect = ValueError("no body")  # would raise if called
        mock_request.return_value = resp
        req = make_request(self.conn_params, {"obj_type": "event", "obj_id": "20"})
        r = self.tq.delete_object(req)
        self.assertTrue(r['succeeded'])
        self.assertEqual(r['http_status'], 204)
        self.assertEqual(r['raw_response'], {})

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_search_by_name_raw_response_preserves_per_type(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        ind_resp = {"total": 1, "data": [{"id": 1, "value": "evil.com"}]}
        adv_resp = {"total": 0, "data": []}
        evt_resp = {"total": 0, "data": []}
        mock_request.side_effect = [
            mock_api_response(ind_resp),
            mock_api_response(adv_resp),
            mock_api_response(evt_resp),
        ]
        req = make_request(self.conn_params, {"name": "evil"})
        r = self.tq.search_by_name(req)
        self.assertEqual(r['raw_response']['indicators'], ind_resp)
        self.assertEqual(r['raw_response']['adversaries'], adv_resp)
        self.assertEqual(r['raw_response']['events'], evt_resp)
        self.assertEqual(r['total_count'], 1)
        self.assertEqual(len(r['results']), 1)

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_get_related_indicators_total_and_count(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        mock_request.return_value = mock_api_response({
            "total": 30, "data": [{"id": 1}, {"id": 2}]
        })
        req = make_request(self.conn_params, {"obj_type": "adversary", "obj_id": "10"})
        r = self.tq.get_related_indicators(req)
        self.assertEqual(r['total_count'], 30)   # server total
        self.assertEqual(r['count'], 2)          # this page

    @patch('app.threat_q.requests.request')
    @patch('app.threat_q.requests.post')
    def test_reputation_raw_response_is_unmodified(self, mock_post, mock_request):
        mock_post.return_value = mock_auth_response()
        raw = {"total": 1, "data": [{"id": 1, "value": "x", "extra_field": "kept"}]}
        mock_request.return_value = mock_api_response(raw)
        req = make_request(self.conn_params, {"ip": "1.1.1.1"})
        r = self.tq.ip_reputation(req)
        # raw_response is the exact API response, not a flattened/transformed copy
        self.assertEqual(r['raw_response'], raw)
        self.assertEqual(r['raw_response']['data'][0]['extra_field'], "kept")


class TestThreatQDescriptorParity(unittest.TestCase):
    """Every action's runtime dict keys (minus http_status which is optional
    on non-204 paths) must be declared in the descriptor outParameters, and
    every sampleOutput key must be declared."""

    def test_descriptor_sampleoutput_declared_and_valid(self):
        import os
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(base, "integration_definition.json")) as f:
            defn = json.load(f)
        self.assertEqual(len(defn["functions"]), 29)
        for fn in defn["functions"]:
            declared = {o["name"] for o in fn["outParameters"]}
            # status must be declared for every action (all return it)
            self.assertIn("status", declared, f"{fn['name']} missing status outParam")
            # sampleOutput keys must all be declared
            sample = json.loads(fn["sampleOutput"])
            for key in sample:
                self.assertIn(key, declared,
                              f"{fn['name']} sampleOutput key '{key}' not declared")
            # structured fields must use Object/List (not String)
            for o in fn["outParameters"]:
                if o["name"] in ("raw_response", "result"):
                    self.assertEqual(o["type"], "Object",
                                     f"{fn['name']}.{o['name']} should be Object")
                if o["name"] in ("results", "sources", "attributes",
                                 "indicators", "events", "adversaries"):
                    self.assertEqual(o["type"], "List",
                                     f"{fn['name']}.{o['name']} should be List")


if __name__ == '__main__':
    unittest.main()
