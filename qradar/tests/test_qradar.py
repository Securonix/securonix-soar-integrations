import pytest
from unittest.mock import patch, MagicMock
from app.qradar import Qradar


@pytest.fixture
def qradar():
    return Qradar()


@pytest.fixture
def connection_params():
    return {
        'base_url': 'https://qradar.example.com/api',
        'api_token': 'test-sec-token',
        'timeout': 30,
        'max_retries': 3,
        'api_version': '14.0'
    }


@pytest.fixture
def mock_request(connection_params):
    req = MagicMock()
    req.connectionParameters = connection_params
    req.parameters = {}
    return req


# ---------------------------------------------------------------------------
# Test Connection
# ---------------------------------------------------------------------------
class TestTestConnection:

    @patch('app.qradar.requests.get')
    def test_success(self, mock_get, qradar, connection_params):
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = []
        mock_get.return_value = mock_resp
        result = qradar.test_connection(connection_params)
        assert result['status'] == 'success'
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs['headers']['SEC'] == 'test-sec-token'
        assert call_kwargs['headers']['Range'] == 'items=0-0'

    @patch('app.qradar.requests.get')
    def test_auth_failure(self, mock_get, qradar, connection_params):
        mock_get.return_value = MagicMock(status_code=401)
        with pytest.raises(Exception, match="Authentication failed"):
            qradar.test_connection(connection_params)

    @patch('app.qradar.requests.get')
    def test_server_error(self, mock_get, qradar, connection_params):
        mock_get.return_value = MagicMock(status_code=500)
        with pytest.raises(Exception, match="server error"):
            qradar.test_connection(connection_params)

    def test_missing_base_url(self, qradar):
        with pytest.raises(Exception, match="base_url is required"):
            qradar.test_connection({'base_url': '', 'api_token': 'tok'})

    def test_missing_api_token(self, qradar):
        with pytest.raises(Exception):
            qradar.test_connection({'base_url': 'https://q.com/api', 'api_token': ''})


# ---------------------------------------------------------------------------
# Fetch Offenses
# ---------------------------------------------------------------------------
class TestFetchOffenses:

    @patch('app.qradar.requests.get')
    def test_success(self, mock_get, qradar, mock_request):
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = [
            {"id": 1, "magnitude": 7, "status": "OPEN"},
            {"id": 2, "magnitude": 3, "status": "OPEN"}
        ]
        mock_get.return_value = mock_resp
        result = qradar.fetch_offenses(mock_request)
        assert result['success'] is True
        assert result['data']['count'] == 2
        assert result['summary']['risk_level'] == 'high'
        assert 'items=0-49' in mock_get.call_args[1]['headers']['Range']

    @patch('app.qradar.requests.get')
    def test_with_filter(self, mock_get, qradar, mock_request):
        mock_request.parameters = {'filter': 'status=OPEN'}
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = []
        mock_get.return_value = mock_resp
        result = qradar.fetch_offenses(mock_request)
        assert result['data']['count'] == 0
        assert mock_get.call_args[1]['params']['filter'] == 'status=OPEN'

    def test_invalid_range(self, qradar, mock_request):
        mock_request.parameters = {'range_start': 50, 'range_end': 10}
        with pytest.raises(Exception, match="range_start must be <= range_end"):
            qradar.fetch_offenses(mock_request)

    @patch('app.qradar.requests.get')
    def test_empty_results(self, mock_get, qradar, mock_request):
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = []
        mock_get.return_value = mock_resp
        result = qradar.fetch_offenses(mock_request)
        assert result['success'] is True
        assert result['data']['count'] == 0
        assert result['summary']['risk_level'] == 'low'


# ---------------------------------------------------------------------------
# Get Offense Details
# ---------------------------------------------------------------------------
class TestGetOffenseDetails:

    @patch('app.qradar.requests.get')
    def test_success(self, mock_get, qradar, mock_request):
        mock_request.parameters = {'offense_id': 123}
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "id": 123, "description": "Suspicious login", "magnitude": 9
        }
        mock_get.return_value = mock_resp
        result = qradar.get_offense_details(mock_request)
        assert result['success'] is True
        assert result['indicator'] == 123
        assert result['summary']['risk_level'] == 'critical'

    @patch('app.qradar.requests.get')
    def test_not_found(self, mock_get, qradar, mock_request):
        mock_request.parameters = {'offense_id': 999}
        mock_resp = MagicMock(status_code=404, text="Not found")
        mock_get.return_value = mock_resp
        with pytest.raises(Exception, match="not found"):
            qradar.get_offense_details(mock_request)

    def test_invalid_offense_id(self, qradar, mock_request):
        mock_request.parameters = {'offense_id': 'abc'}
        with pytest.raises(Exception, match="must be a valid integer"):
            qradar.get_offense_details(mock_request)

    def test_empty_offense_id(self, qradar, mock_request):
        mock_request.parameters = {'offense_id': ''}
        with pytest.raises(Exception, match="offense_id is required"):
            qradar.get_offense_details(mock_request)

    def test_negative_offense_id(self, qradar, mock_request):
        mock_request.parameters = {'offense_id': -1}
        with pytest.raises(Exception, match="must be a positive integer"):
            qradar.get_offense_details(mock_request)


# ---------------------------------------------------------------------------
# Update Offense (query params, NOT JSON body)
# ---------------------------------------------------------------------------
class TestUpdateOffense:

    @patch('app.qradar.requests.post')
    def test_success_close(self, mock_post, qradar, mock_request):
        mock_request.parameters = {
            'offense_id': 123, 'status': 'CLOSED', 'closing_reason_id': 1
        }
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {"id": 123, "status": "CLOSED", "magnitude": 5}
        mock_post.return_value = mock_resp
        result = qradar.update_offense(mock_request)
        assert result['success'] is True
        assert result['summary']['verdict'] == "Offense 123 updated"
        # Verify query params used (not JSON body)
        call_kwargs = mock_post.call_args[1]
        assert call_kwargs['params']['status'] == 'CLOSED'
        assert call_kwargs['params']['closing_reason_id'] == 1

    @patch('app.qradar.requests.post')
    def test_assign(self, mock_post, qradar, mock_request):
        mock_request.parameters = {'offense_id': 123, 'assigned_to': 'analyst1'}
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {"id": 123, "assigned_to": "analyst1", "magnitude": 4}
        mock_post.return_value = mock_resp
        result = qradar.update_offense(mock_request)
        assert result['success'] is True
        assert mock_post.call_args[1]['params']['assigned_to'] == 'analyst1'

    def test_no_update_params(self, qradar, mock_request):
        mock_request.parameters = {'offense_id': 123}
        with pytest.raises(Exception, match="At least one update parameter required"):
            qradar.update_offense(mock_request)


# ---------------------------------------------------------------------------
# Get Offense Notes
# ---------------------------------------------------------------------------
class TestGetOffenseNotes:

    @patch('app.qradar.requests.get')
    def test_success(self, mock_get, qradar, mock_request):
        mock_request.parameters = {'offense_id': 123}
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = [
            {"id": 1, "note_text": "First note"},
            {"id": 2, "note_text": "Second note"}
        ]
        mock_get.return_value = mock_resp
        result = qradar.get_offense_notes(mock_request)
        assert result['success'] is True
        assert result['data']['count'] == 2


# ---------------------------------------------------------------------------
# Add Offense Note
# ---------------------------------------------------------------------------
class TestAddOffenseNote:

    @patch('app.qradar.requests.post')
    def test_success(self, mock_post, qradar, mock_request):
        mock_request.parameters = {'offense_id': 123, 'note_text': 'Investigation completed'}
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {"id": 5, "note_text": "Investigation completed"}
        mock_post.return_value = mock_resp
        result = qradar.add_offense_note(mock_request)
        assert result['success'] is True
        assert result['summary']['verdict'] == "Note added successfully"
        assert mock_post.call_args[1]['json'] == {"note_text": "Investigation completed"}

    def test_empty_note(self, qradar, mock_request):
        mock_request.parameters = {'offense_id': 123, 'note_text': ''}
        with pytest.raises(Exception, match="note_text is required"):
            qradar.add_offense_note(mock_request)


# ---------------------------------------------------------------------------
# Get Closing Reasons
# ---------------------------------------------------------------------------
class TestGetClosingReasons:

    @patch('app.qradar.requests.get')
    def test_success(self, mock_get, qradar, mock_request):
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = [
            {"id": 1, "text": "False Positive"},
            {"id": 2, "text": "Non-Issue"}
        ]
        mock_get.return_value = mock_resp
        result = qradar.get_closing_reasons(mock_request)
        assert result['success'] is True
        assert result['data']['count'] == 2


# ---------------------------------------------------------------------------
# Create Search (Ariel) — with polling
# ---------------------------------------------------------------------------
class TestCreateSearch:

    @patch('app.qradar.time.sleep')
    @patch('app.qradar.requests.get')
    @patch('app.qradar.requests.post')
    def test_success_with_polling(self, mock_post, mock_get, mock_sleep, qradar, mock_request):
        mock_request.parameters = {'query_expression': 'SELECT * FROM events WHERE offenseid=123'}
        # POST creates search
        post_resp = MagicMock(status_code=200)
        post_resp.json.return_value = {"search_id": "abc-123", "status": "EXECUTE"}
        mock_post.return_value = post_resp
        # GET polls: first EXECUTE, then COMPLETED, then results
        poll_resp_1 = MagicMock(status_code=200)
        poll_resp_1.json.return_value = {"search_id": "abc-123", "status": "EXECUTE"}
        poll_resp_2 = MagicMock(status_code=200)
        poll_resp_2.json.return_value = {"search_id": "abc-123", "status": "COMPLETED"}
        results_resp = MagicMock(status_code=200)
        results_resp.json.return_value = {"events": [{"sourceip": "1.2.3.4"}]}
        mock_get.side_effect = [poll_resp_1, poll_resp_2, results_resp]
        result = qradar.create_search(mock_request)
        assert result['success'] is True
        assert result['indicator'] == "abc-123"
        assert "completed" in result['summary']['verdict']
        assert 'results' in result['data']
        assert mock_sleep.call_count == 1

    @patch('app.qradar.requests.post')
    def test_without_polling(self, mock_post, qradar, mock_request):
        mock_request.parameters = {
            'query_expression': 'SELECT * FROM events',
            'wait_for_completion': False
        }
        post_resp = MagicMock(status_code=200)
        post_resp.json.return_value = {"search_id": "abc-456", "status": "EXECUTE"}
        mock_post.return_value = post_resp
        result = qradar.create_search(mock_request)
        assert result['success'] is True
        assert result['indicator'] == "abc-456"
        assert "async" in result['summary']['verdict']

    @patch('app.qradar.time.sleep')
    @patch('app.qradar.requests.get')
    @patch('app.qradar.requests.post')
    def test_search_error_status(self, mock_post, mock_get, mock_sleep, qradar, mock_request):
        mock_request.parameters = {'query_expression': 'SELECT * FROM events'}
        post_resp = MagicMock(status_code=200)
        post_resp.json.return_value = {"search_id": "abc-err", "status": "EXECUTE"}
        mock_post.return_value = post_resp
        poll_resp = MagicMock(status_code=200)
        poll_resp.json.return_value = {"search_id": "abc-err", "status": "ERROR"}
        mock_get.return_value = poll_resp
        with pytest.raises(Exception, match="failed with status: ERROR"):
            qradar.create_search(mock_request)

    @patch('app.qradar.time.sleep')
    @patch('app.qradar.requests.get')
    @patch('app.qradar.requests.post')
    def test_search_canceled_status(self, mock_post, mock_get, mock_sleep, qradar, mock_request):
        mock_request.parameters = {'query_expression': 'SELECT * FROM events'}
        post_resp = MagicMock(status_code=200)
        post_resp.json.return_value = {"search_id": "abc-can", "status": "EXECUTE"}
        mock_post.return_value = post_resp
        poll_resp = MagicMock(status_code=200)
        poll_resp.json.return_value = {"search_id": "abc-can", "status": "CANCELED"}
        mock_get.return_value = poll_resp
        with pytest.raises(Exception, match="failed with status: CANCELED"):
            qradar.create_search(mock_request)

    @patch('app.qradar.time.sleep')
    @patch('app.qradar.requests.get')
    @patch('app.qradar.requests.post')
    def test_search_timeout(self, mock_post, mock_get, mock_sleep, qradar, mock_request):
        mock_request.parameters = {
            'query_expression': 'SELECT * FROM events',
            'poll_timeout': 2,
            'poll_interval': 1
        }
        post_resp = MagicMock(status_code=200)
        post_resp.json.return_value = {"search_id": "abc-to", "status": "EXECUTE"}
        mock_post.return_value = post_resp
        # Always returns EXECUTE, never completes
        poll_resp = MagicMock(status_code=200)
        poll_resp.json.return_value = {"search_id": "abc-to", "status": "EXECUTE"}
        mock_get.return_value = poll_resp
        with pytest.raises(Exception, match="timed out"):
            qradar.create_search(mock_request)

    @patch('app.qradar.time.sleep')
    @patch('app.qradar.requests.get')
    @patch('app.qradar.requests.post')
    def test_poll_interval_min_1(self, mock_post, mock_get, mock_sleep, qradar, mock_request):
        mock_request.parameters = {
            'query_expression': 'SELECT * FROM events',
            'poll_interval': 0,
            'poll_timeout': 2
        }
        post_resp = MagicMock(status_code=200)
        post_resp.json.return_value = {"search_id": "abc-pi", "status": "EXECUTE"}
        mock_post.return_value = post_resp
        poll_resp = MagicMock(status_code=200)
        poll_resp.json.return_value = {"search_id": "abc-pi", "status": "EXECUTE"}
        mock_get.return_value = poll_resp
        with pytest.raises(Exception, match="timed out"):
            qradar.create_search(mock_request)
        # sleep called with 1 (min), not 0
        mock_sleep.assert_called_with(1)

    def test_empty_query(self, qradar, mock_request):
        mock_request.parameters = {'query_expression': ''}
        with pytest.raises(Exception, match="query_expression is required"):
            qradar.create_search(mock_request)

    @patch('app.qradar.requests.post')
    def test_no_search_id_returned(self, mock_post, qradar, mock_request):
        mock_request.parameters = {'query_expression': 'SELECT * FROM events'}
        post_resp = MagicMock(status_code=200)
        post_resp.json.return_value = {"status": "EXECUTE"}
        mock_post.return_value = post_resp
        with pytest.raises(Exception, match="no search_id returned"):
            qradar.create_search(mock_request)


# ---------------------------------------------------------------------------
# Get Search Status (Ariel)
# ---------------------------------------------------------------------------
class TestGetSearchStatus:

    @patch('app.qradar.requests.get')
    def test_success(self, mock_get, qradar, mock_request):
        mock_request.parameters = {'search_id': 'abc-123'}
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {"search_id": "abc-123", "status": "COMPLETED"}
        mock_get.return_value = mock_resp
        result = qradar.get_search_status(mock_request)
        assert result['success'] is True
        assert result['summary']['verdict'] == "Search status: COMPLETED"

    def test_empty_search_id(self, qradar, mock_request):
        mock_request.parameters = {'search_id': ''}
        with pytest.raises(Exception, match="search_id is required"):
            qradar.get_search_status(mock_request)


# ---------------------------------------------------------------------------
# Get Search Results (Ariel)
# ---------------------------------------------------------------------------
class TestGetSearchResults:

    @patch('app.qradar.requests.get')
    def test_success_events(self, mock_get, qradar, mock_request):
        mock_request.parameters = {'search_id': 'abc-123'}
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "events": [
                {"sourceip": "1.2.3.4", "username": "admin"},
                {"sourceip": "5.6.7.8", "username": "user1"}
            ]
        }
        mock_get.return_value = mock_resp
        result = qradar.get_search_results(mock_request)
        assert result['success'] is True
        assert result['summary']['verdict'] == "2 results retrieved"
        assert 'items=0-49' in mock_get.call_args[1]['headers']['Range']

    @patch('app.qradar.requests.get')
    def test_success_flows(self, mock_get, qradar, mock_request):
        mock_request.parameters = {'search_id': 'abc-123'}
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "flows": [{"sourceip": "1.2.3.4"}]
        }
        mock_get.return_value = mock_resp
        result = qradar.get_search_results(mock_request)
        assert result['summary']['verdict'] == "1 results retrieved"

    @patch('app.qradar.requests.get')
    def test_no_events_or_flows(self, mock_get, qradar, mock_request):
        mock_request.parameters = {'search_id': 'abc-123'}
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {}
        mock_get.return_value = mock_resp
        result = qradar.get_search_results(mock_request)
        assert result['summary']['verdict'] == "0 results retrieved"

    def test_empty_search_id(self, qradar, mock_request):
        mock_request.parameters = {'search_id': ''}
        with pytest.raises(Exception, match="search_id is required"):
            qradar.get_search_results(mock_request)

    def test_invalid_range(self, qradar, mock_request):
        mock_request.parameters = {'search_id': 'abc', 'range_start': 50, 'range_end': 10}
        with pytest.raises(Exception, match="range_start must be <= range_end"):
            qradar.get_search_results(mock_request)


# ---------------------------------------------------------------------------
# Retry Logic
# ---------------------------------------------------------------------------
class TestRetryLogic:

    @patch('app.qradar.time.sleep')
    @patch('app.qradar.requests.get')
    def test_rate_limit_retry(self, mock_get, mock_sleep, qradar, mock_request):
        mock_request.parameters = {'offense_id': 1}
        rate_resp = MagicMock(status_code=429)
        success_resp = MagicMock(status_code=200)
        success_resp.json.return_value = {"id": 1, "magnitude": 3}
        mock_get.side_effect = [rate_resp, success_resp]
        result = qradar.get_offense_details(mock_request)
        assert result['success'] is True
        mock_sleep.assert_called_once_with(1)

    @patch('app.qradar.time.sleep')
    @patch('app.qradar.requests.get')
    def test_timeout_retry(self, mock_get, mock_sleep, qradar, mock_request):
        import requests as req
        mock_request.parameters = {'offense_id': 1}
        mock_get.side_effect = [
            req.exceptions.Timeout(),
            MagicMock(status_code=200, json=lambda: {"id": 1, "magnitude": 2})
        ]
        result = qradar.get_offense_details(mock_request)
        assert result['success'] is True

    @patch('app.qradar.time.sleep')
    @patch('app.qradar.requests.get')
    def test_connection_error_retry(self, mock_get, mock_sleep, qradar, mock_request):
        import requests as req
        mock_request.parameters = {'offense_id': 1}
        mock_get.side_effect = [
            req.exceptions.ConnectionError(),
            MagicMock(status_code=200, json=lambda: {"id": 1, "magnitude": 1})
        ]
        result = qradar.get_offense_details(mock_request)
        assert result['success'] is True


# ---------------------------------------------------------------------------
# Connection Parameter Defaults
# ---------------------------------------------------------------------------
class TestConnectionDefaults:

    def test_default_timeout(self, qradar):
        params = {'base_url': 'https://q.com/api', 'api_token': 'tok'}
        _, _, timeout, _, _ = qradar._get_connection(params)
        assert timeout == 30

    def test_default_max_retries(self, qradar):
        params = {'base_url': 'https://q.com/api', 'api_token': 'tok'}
        _, _, _, max_retries, _ = qradar._get_connection(params)
        assert max_retries == 3

    def test_default_api_version(self, qradar):
        params = {'base_url': 'https://q.com/api', 'api_token': 'tok'}
        _, _, _, _, api_version = qradar._get_connection(params)
        assert api_version == '14.0'

    def test_null_timeout_uses_default(self, qradar):
        params = {'base_url': 'https://q.com/api', 'api_token': 'tok', 'timeout': None}
        _, _, timeout, _, _ = qradar._get_connection(params)
        assert timeout == 30

    def test_base_url_trailing_slash_stripped(self, qradar):
        params = {'base_url': 'https://q.com/api/', 'api_token': 'tok'}
        base_url, _, _, _, _ = qradar._get_connection(params)
        assert base_url == 'https://q.com/api'


# ---------------------------------------------------------------------------
# Risk Assessment
# ---------------------------------------------------------------------------
class TestRiskAssessment:

    def test_magnitude_0(self, qradar):
        assert qradar._assess_risk(0) == 'low'

    def test_magnitude_3(self, qradar):
        assert qradar._assess_risk(3) == 'low'

    def test_magnitude_4(self, qradar):
        assert qradar._assess_risk(4) == 'medium'

    def test_magnitude_6(self, qradar):
        assert qradar._assess_risk(6) == 'medium'

    def test_magnitude_7(self, qradar):
        assert qradar._assess_risk(7) == 'high'

    def test_magnitude_8(self, qradar):
        assert qradar._assess_risk(8) == 'high'

    def test_magnitude_9(self, qradar):
        assert qradar._assess_risk(9) == 'critical'

    def test_magnitude_10(self, qradar):
        assert qradar._assess_risk(10) == 'critical'

    def test_magnitude_none(self, qradar):
        assert qradar._assess_risk(None) == 'low'

    def test_magnitude_string(self, qradar):
        assert qradar._assess_risk("invalid") == 'low'

    def test_magnitude_string_number(self, qradar):
        assert qradar._assess_risk("9") == 'critical'
