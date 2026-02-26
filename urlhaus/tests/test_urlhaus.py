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
        "auth_key": "dummy_key"
    })

    assert result["status"] == "success"


@patch("requests.post")
def test_test_connection_failure(mock_post):
    mock_post.side_effect = Exception("Connection failed")

    connector = Urlhaus()

    with pytest.raises(Exception):
        connector.test_connection({
            "base_url": "https://urlhaus-api.abuse.ch/v1",
            "auth_key": "dummy_key"
        })


# -------------------------------
# URL Reputation
# -------------------------------
@patch("requests.post")
def test_url_reputation_malicious(mock_post):
    mock_response = Mock()
    mock_response.json.return_value = {"query_status": "ok"}
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    connector = Urlhaus()
    request = DummyRequest(
        {"base_url": "https://urlhaus-api.abuse.ch/v1", "auth_key": "key"},
        {"urls": "http://bad.com"}
    )

    result = connector.url_reputation(request)

    assert result["results"][0]["reputation"] == "malicious"


@patch("requests.post")
def test_url_reputation_unknown(mock_post):
    mock_response = Mock()
    mock_response.json.return_value = {"query_status": "no_results"}
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    connector = Urlhaus()
    request = DummyRequest(
        {"base_url": "https://urlhaus-api.abuse.ch/v1", "auth_key": "key"},
        {"urls": "http://clean.com"}
    )

    result = connector.url_reputation(request)

    assert result["results"][0]["reputation"] == "unknown"


# -------------------------------
# Host Reputation
# -------------------------------
@patch("requests.post")
def test_host_reputation(mock_post):
    mock_response = Mock()
    mock_response.json.return_value = {"query_status": "ok"}
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    connector = Urlhaus()
    request = DummyRequest(
        {"base_url": "https://urlhaus-api.abuse.ch/v1", "auth_key": "key"},
        {"hosts": "1.2.3.4"}
    )

    result = connector.host_reputation(request)

    assert result["results"][0]["reputation"] == "malicious"


# -------------------------------
# Domain Reputation
# -------------------------------
@patch("requests.post")
def test_domain_reputation(mock_post):
    mock_response = Mock()
    mock_response.json.return_value = {"query_status": "no_results"}
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    connector = Urlhaus()
    request = DummyRequest(
        {"base_url": "https://urlhaus-api.abuse.ch/v1", "auth_key": "key"},
        {"domains": "example.com"}
    )

    result = connector.domain_reputation(request)

    assert result["results"][0]["reputation"] == "unknown"


# -------------------------------
# File Reputation
# -------------------------------
@patch("requests.post")
def test_file_reputation(mock_post):
    mock_response = Mock()
    mock_response.json.return_value = {"query_status": "ok"}
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    connector = Urlhaus()
    request = DummyRequest(
        {"base_url": "https://urlhaus-api.abuse.ch/v1", "auth_key": "key"},
        {"sha256_hashes": "dummyhash"}
    )

    result = connector.file_reputation(request)

    assert result["results"][0]["reputation"] == "malicious"
