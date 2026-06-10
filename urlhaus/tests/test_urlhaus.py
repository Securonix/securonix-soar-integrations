import pytest
from unittest.mock import patch, Mock
from app.urlhaus import Urlhaus


class DummyRequest:
    def __init__(self, connectionParameters, parameters):
        self.connectionParameters = connectionParameters
        self.parameters = parameters


# -------------------------------
# Test Connection
# -------------------------------
@patch("requests.post")
def test_test_connection_success(mock_post):
    mock_response = Mock()
    mock_response.json.return_value = {"query_status": "no_results"}
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    connector = Urlhaus()

    result = connector.test_connection({
        "base_url": "https://urlhaus-api.abuse.ch/v1",
        "api_key": "dummy_key"
    })

    assert result["status"] == "success"
    mock_post.assert_called_once_with(
        "https://urlhaus-api.abuse.ch/v1/url/",
        headers={"Auth-Key": "dummy_key"},
        data={"url": "https://example.com"},
        timeout=30
    )


@patch("requests.post")
def test_test_connection_failure(mock_post):
    mock_post.side_effect = Exception("Connection failed")

    connector = Urlhaus()

    with pytest.raises(Exception):
        connector.test_connection({
            "base_url": "https://urlhaus-api.abuse.ch/v1",
            "api_key": "dummy_key"
        })


@patch("requests.post")
def test_test_connection_no_api_key(mock_post):
    mock_response = Mock()
    mock_response.json.return_value = {"query_status": "no_results"}
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    connector = Urlhaus()

    result = connector.test_connection({
        "base_url": "https://urlhaus-api.abuse.ch/v1"
    })

    assert result["status"] == "success"
    mock_post.assert_called_once_with(
        "https://urlhaus-api.abuse.ch/v1/url/",
        headers={},
        data={"url": "https://example.com"},
        timeout=30
    )


# -------------------------------
# URL Reputation
# -------------------------------
@patch("requests.post")
def test_url_reputation_malicious(mock_post):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"query_status": "ok", "threat": "malware_download"}
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    connector = Urlhaus()
    request = DummyRequest(
        {"base_url": "https://urlhaus-api.abuse.ch/v1", "api_key": "key"},
        {"urls": "http://bad.com"}
    )

    result = connector.url_reputation(request)

    assert result["results"][0]["reputation"] == "malicious"


@patch("requests.post")
def test_url_reputation_unknown(mock_post):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"query_status": "no_results"}
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    connector = Urlhaus()
    request = DummyRequest(
        {"base_url": "https://urlhaus-api.abuse.ch/v1", "api_key": "key"},
        {"urls": "http://clean.com"}
    )

    result = connector.url_reputation(request)

    assert result["results"][0]["reputation"] == "unknown"


@patch("requests.post")
def test_url_reputation_suspicious(mock_post):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"query_status": "ok", "threat": "none", "url_status": "unknown"}
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    connector = Urlhaus()
    request = DummyRequest(
        {"base_url": "https://urlhaus-api.abuse.ch/v1", "api_key": "key"},
        {"urls": "http://maybe.com"}
    )

    result = connector.url_reputation(request)

    assert result["results"][0]["reputation"] == "suspicious"


# -------------------------------
# Host Reputation
# -------------------------------
@patch("requests.post")
def test_host_reputation_malicious(mock_post):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"query_status": "ok", "url_count": 5}
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    connector = Urlhaus()
    request = DummyRequest(
        {"base_url": "https://urlhaus-api.abuse.ch/v1", "api_key": "key"},
        {"hosts": "1.2.3.4"}
    )

    result = connector.host_reputation(request)

    assert result["results"][0]["reputation"] == "malicious"


@patch("requests.post")
def test_host_reputation_unknown(mock_post):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"query_status": "no_results"}
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    connector = Urlhaus()
    request = DummyRequest(
        {"base_url": "https://urlhaus-api.abuse.ch/v1", "api_key": "key"},
        {"hosts": "8.8.8.8"}
    )

    result = connector.host_reputation(request)

    assert result["results"][0]["reputation"] == "unknown"


# -------------------------------
# Domain Reputation (uses /host/ endpoint)
# -------------------------------
@patch("requests.post")
def test_domain_reputation_malicious(mock_post):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"query_status": "ok", "url_count": 3}
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    connector = Urlhaus()
    request = DummyRequest(
        {"base_url": "https://urlhaus-api.abuse.ch/v1", "api_key": "key"},
        {"domains": "evil.com"}
    )

    result = connector.domain_reputation(request)

    assert result["results"][0]["reputation"] == "malicious"


@patch("requests.post")
def test_domain_reputation_unknown(mock_post):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"query_status": "no_results"}
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    connector = Urlhaus()
    request = DummyRequest(
        {"base_url": "https://urlhaus-api.abuse.ch/v1", "api_key": "key"},
        {"domains": "example.com"}
    )

    result = connector.domain_reputation(request)

    assert result["results"][0]["reputation"] == "unknown"


# -------------------------------
# File Reputation
# -------------------------------
@patch("requests.post")
def test_file_reputation_malicious(mock_post):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"query_status": "ok"}
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    connector = Urlhaus()
    request = DummyRequest(
        {"base_url": "https://urlhaus-api.abuse.ch/v1", "api_key": "key"},
        {"sha256_hashes": "a" * 64}
    )

    result = connector.file_reputation(request)

    assert result["results"][0]["reputation"] == "malicious"


@patch("requests.post")
def test_file_reputation_unknown(mock_post):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"query_status": "no_results"}
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    connector = Urlhaus()
    request = DummyRequest(
        {"base_url": "https://urlhaus-api.abuse.ch/v1", "api_key": "key"},
        {"sha256_hashes": "b" * 64}
    )

    result = connector.file_reputation(request)

    assert result["results"][0]["reputation"] == "unknown"
