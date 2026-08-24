import pytest
from unittest.mock import patch, MagicMock
from app.any_run import AnyRun
from app.model.request_body import RequestBody
from pykson import Pykson
import json
import base64

pykson = Pykson()
integration_class = AnyRun()

CONNECTION_PARAMS = {
    "api_key": "test_api_key_123",
    "base_url": "https://api.any.run/v1",
}


def _make_request(params=None):
    body = {"connectionParameters": CONNECTION_PARAMS, "parameters": params or {}}
    return pykson.from_json(json.dumps(body), RequestBody, True)


def _mock_response(status_code=200, json_data=None, content=None, headers=None):
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_data if json_data is not None else {}
    mock.content = content or b""
    mock.headers = headers or {"Content-Type": "application/json"}
    return mock


class TestTestConnection:
    @patch("app.any_run.requests.request")
    def test_success(self, mock_request):
        mock_request.return_value = _mock_response(200, {"status": "ok", "user": "test@example.com"})
        result = integration_class.test_connection(CONNECTION_PARAMS)
        assert result["status"] == "success"

    @patch("app.any_run.requests.request")
    def test_auth_failure(self, mock_request):
        mock_request.return_value = _mock_response(401)
        with pytest.raises(Exception, match="Authentication failed"):
            integration_class.test_connection(CONNECTION_PARAMS)

    def test_missing_api_key(self):
        with pytest.raises(Exception, match="api_key is required"):
            integration_class.test_connection({"base_url": "https://api.any.run/v1"})


class TestSubmitFile:
    @patch("app.any_run.requests.request")
    def test_success(self, mock_request):
        mock_request.return_value = _mock_response(200, {"data": {"task_id": "task-abc-123"}})
        file_content = base64.b64encode(b"MZ\x90\x00").decode()
        resp = integration_class.submit_file(_make_request({
            "file_content": file_content,
            "file_name": "malware.exe",
            "os_type": "windows10",
        }))
        assert resp["status"] == "success"
        assert resp["task_id"] == "task-abc-123"

    @patch("app.any_run.requests.request")
    def test_missing_file_content(self, mock_request):
        with pytest.raises(Exception, match="file_content is required"):
            integration_class.submit_file(_make_request({"file_name": "test.exe"}))

    @patch("app.any_run.requests.request")
    def test_missing_file_name(self, mock_request):
        file_content = base64.b64encode(b"test").decode()
        with pytest.raises(Exception, match="file_name is required"):
            integration_class.submit_file(_make_request({"file_content": file_content}))

    @patch("app.any_run.requests.request")
    def test_invalid_base64(self, mock_request):
        with pytest.raises(Exception, match="valid base64"):
            integration_class.submit_file(_make_request({
                "file_content": "not-valid-base64!!!",
                "file_name": "test.exe",
            }))

    @patch("app.any_run.requests.request")
    def test_invalid_os_type(self, mock_request):
        file_content = base64.b64encode(b"test").decode()
        with pytest.raises(Exception, match="os_type must be one of"):
            integration_class.submit_file(_make_request({
                "file_content": file_content,
                "file_name": "test.exe",
                "os_type": "linux",
            }))

    @patch("app.any_run.requests.request")
    def test_file_name_too_long(self, mock_request):
        file_content = base64.b64encode(b"test").decode()
        with pytest.raises(Exception, match="must not exceed 255"):
            integration_class.submit_file(_make_request({
                "file_content": file_content,
                "file_name": "a" * 256,
            }))

    @patch("app.any_run.requests.request")
    def test_invalid_timeout_duration(self, mock_request):
        file_content = base64.b64encode(b"test").decode()
        with pytest.raises(Exception, match="timeout_duration must be a positive integer"):
            integration_class.submit_file(_make_request({
                "file_content": file_content,
                "file_name": "test.exe",
                "timeout_duration": "-5",
            }))


class TestSubmitUrl:
    @patch("app.any_run.requests.request")
    def test_success(self, mock_request):
        mock_request.return_value = _mock_response(200, {"data": {"task_id": "task-url-456"}})
        resp = integration_class.submit_url(_make_request({
            "url": "https://malicious-site.com/payload",
            "os_type": "windows11",
        }))
        assert resp["status"] == "success"
        assert resp["task_id"] == "task-url-456"

    @patch("app.any_run.requests.request")
    def test_missing_url(self, mock_request):
        with pytest.raises(Exception, match="url is required"):
            integration_class.submit_url(_make_request({}))

    @patch("app.any_run.requests.request")
    def test_invalid_url_format(self, mock_request):
        with pytest.raises(Exception, match="valid HTTP or HTTPS URL"):
            integration_class.submit_url(_make_request({"url": "ftp://bad-protocol.com"}))

    @patch("app.any_run.requests.request")
    def test_invalid_os_type(self, mock_request):
        with pytest.raises(Exception, match="os_type must be one of"):
            integration_class.submit_url(_make_request({
                "url": "https://test.com",
                "os_type": "macos",
            }))


class TestGetAnalysisStatus:
    @patch("app.any_run.requests.request")
    def test_success_completed(self, mock_request):
        mock_request.return_value = _mock_response(200, {"data": {"status": "completed"}})
        resp = integration_class.get_analysis_status(_make_request({"task_id": "task-123"}))
        assert resp["status"] == "success"
        assert resp["analysis_status"] == "completed"
        assert resp["task_id"] == "task-123"

    @patch("app.any_run.requests.request")
    def test_success_running(self, mock_request):
        mock_request.return_value = _mock_response(200, {"data": {"status": "running"}})
        resp = integration_class.get_analysis_status(_make_request({"task_id": "task-456"}))
        assert resp["analysis_status"] == "running"

    @patch("app.any_run.requests.request")
    def test_missing_task_id(self, mock_request):
        with pytest.raises(Exception, match="task_id is required"):
            integration_class.get_analysis_status(_make_request({}))


class TestGetAnalysisReport:
    @patch("app.any_run.requests.request")
    def test_success(self, mock_request):
        mock_request.return_value = _mock_response(200, {"data": {
            "verdict": "malicious",
            "score": 95,
            "malware_family": "Emotet",
            "tags": ["trojan", "banker"],
            "process_activity": [{"pid": 1234, "name": "malware.exe", "action": "created"}],
            "network_activity": [{"type": "dns", "domain": "evil.com", "ip": "1.2.3.4"}],
            "mitre_attacks": [{"id": "T1059", "name": "Command and Scripting Interpreter"}],
        }})
        resp = integration_class.get_analysis_report(_make_request({"task_id": "task-789"}))
        assert resp["status"] == "success"
        assert resp["verdict"] == "malicious"
        assert resp["score"] == 95
        assert resp["malware_family"] == "Emotet"
        assert "trojan" in resp["tags"]
        assert len(resp["process_activity"]) == 1
        assert len(resp["network_activity"]) == 1
        assert resp["mitre_attacks"][0]["id"] == "T1059"

    @patch("app.any_run.requests.request")
    def test_missing_task_id(self, mock_request):
        with pytest.raises(Exception, match="task_id is required"):
            integration_class.get_analysis_report(_make_request({}))


class TestExtractIocs:
    @patch("app.any_run.requests.request")
    def test_success(self, mock_request):
        mock_request.return_value = _mock_response(200, {"data": {
            "domains": ["evil.com", "malware.org"],
            "ip_addresses": ["1.2.3.4", "5.6.7.8"],
            "urls": ["https://evil.com/payload.exe"],
            "hashes": [{"md5": "abc123", "sha1": "def456", "sha256": "ghi789"}],
        }})
        resp = integration_class.extract_iocs(_make_request({"task_id": "task-ioc-1"}))
        assert resp["status"] == "success"
        assert len(resp["domains"]) == 2
        assert len(resp["ip_addresses"]) == 2
        assert len(resp["urls"]) == 1
        assert resp["hashes"][0]["md5"] == "abc123"

    @patch("app.any_run.requests.request")
    def test_missing_task_id(self, mock_request):
        with pytest.raises(Exception, match="task_id is required"):
            integration_class.extract_iocs(_make_request({}))


class TestDownloadArtifact:
    @patch("app.any_run.requests.request")
    def test_success_binary_response(self, mock_request):
        pcap_data = b"\xd4\xc3\xb2\xa1" * 100
        mock_request.return_value = _mock_response(
            200, content=pcap_data,
            headers={"Content-Type": "application/octet-stream",
                     "Content-Disposition": 'attachment; filename="capture.pcap"'}
        )
        resp = integration_class.download_artifact(_make_request({
            "task_id": "task-dl-1",
            "artifact_type": "pcap",
        }))
        assert resp["status"] == "success"
        assert resp["artifact_type"] == "pcap"
        assert resp["content"] == base64.b64encode(pcap_data).decode("utf-8")
        assert resp["filename"] == "capture.pcap"

    @patch("app.any_run.requests.request")
    def test_success_json_response(self, mock_request):
        mock_request.return_value = _mock_response(200, {"data": {
            "content": "base64encodedcontent",
            "filename": "screenshot.png",
            "content_type": "image/png",
        }})
        resp = integration_class.download_artifact(_make_request({
            "task_id": "task-dl-2",
            "artifact_type": "screenshot",
        }))
        assert resp["status"] == "success"
        assert resp["content"] == "base64encodedcontent"
        assert resp["filename"] == "screenshot.png"

    @patch("app.any_run.requests.request")
    def test_missing_task_id(self, mock_request):
        with pytest.raises(Exception, match="task_id is required"):
            integration_class.download_artifact(_make_request({"artifact_type": "pcap"}))

    @patch("app.any_run.requests.request")
    def test_missing_artifact_type(self, mock_request):
        with pytest.raises(Exception, match="artifact_type is required"):
            integration_class.download_artifact(_make_request({"task_id": "task-1"}))

    @patch("app.any_run.requests.request")
    def test_invalid_artifact_type(self, mock_request):
        with pytest.raises(Exception, match="artifact_type must be one of"):
            integration_class.download_artifact(_make_request({
                "task_id": "task-1",
                "artifact_type": "invalid",
            }))


class TestErrorHandling:
    @patch("app.any_run.requests.request")
    def test_connection_error(self, mock_request):
        import requests as req
        mock_request.side_effect = req.exceptions.ConnectionError()
        with pytest.raises(Exception, match="Unable to connect"):
            integration_class.test_connection(CONNECTION_PARAMS)

    @patch("app.any_run.requests.request")
    def test_timeout(self, mock_request):
        import requests as req
        mock_request.side_effect = req.exceptions.Timeout()
        with pytest.raises(Exception, match="timed out"):
            integration_class.test_connection(CONNECTION_PARAMS)

    @patch("app.any_run.time.sleep")
    @patch("app.any_run.requests.request")
    def test_429_retry_then_success(self, mock_request, mock_sleep):
        mock_request.side_effect = [
            _mock_response(429),
            _mock_response(200, {"data": {"status": "completed"}}),
        ]
        resp = integration_class.get_analysis_status(_make_request({"task_id": "task-retry"}))
        assert resp["status"] == "success"
        assert mock_sleep.call_count == 1

    @patch("app.any_run.time.sleep")
    @patch("app.any_run.requests.request")
    def test_429_retry_exhausted(self, mock_request, mock_sleep):
        mock_request.side_effect = [
            _mock_response(429),
            _mock_response(429),
            _mock_response(429),
        ]
        with pytest.raises(Exception, match="Rate limit exceeded"):
            integration_class.get_analysis_status(_make_request({"task_id": "task-retry"}))

    @patch("app.any_run.time.sleep")
    @patch("app.any_run.requests.request")
    def test_500_retry_then_success(self, mock_request, mock_sleep):
        mock_request.side_effect = [
            _mock_response(500),
            _mock_response(200, {"data": {"status": "queued"}}),
        ]
        resp = integration_class.get_analysis_status(_make_request({"task_id": "task-500"}))
        assert resp["status"] == "success"
        assert mock_sleep.call_count == 1

    @patch("app.any_run.requests.request")
    def test_404_not_found(self, mock_request):
        mock_request.return_value = _mock_response(404)
        result = integration_class.get_analysis_status(_make_request({"task_id": "nonexistent"}))
        assert result["status"] == "success"
        assert result["message"] == "Task not found."
