from unittest.mock import patch, MagicMock
from app.mimecast import Mimecast
from app.model.request_body import RequestBody
from pykson import Pykson

pykson = Pykson()
integration_class = Mimecast()

CONN = {
    "connectionParameters": {
        "base_url": "https://us-api.mimecast.com",
        "access_key": "samplevalue",
        "secret_key": "c2FtcGxldmFsdWU=",
        "app_id": "samplevalue",
        "app_key": "samplevalue"
    }
}


def make_req(parameters: dict) -> RequestBody:
    import json
    body = {**CONN, "parameters": parameters}
    return pykson.from_json(json.dumps(body), RequestBody, True)


def mock_response(json_data, status_code=200):
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_data
    return mock


@patch("app.mimecast.requests.post")
def test_get_threats(mock_post):
    mock_post.return_value = mock_response({
        "data": [{"clickLogs": [{"id": "threat1"}, {"id": "threat2"}]}]
    })
    resp = integration_class.get_threats(make_req({"limit": 2}))
    assert resp["status"] == "success"
    assert len(resp["threats"]) == 2


@patch("app.mimecast.requests.post")
def test_block_sender(mock_post):
    mock_post.return_value = mock_response({"data": [{"result": "blocked"}]})
    resp = integration_class.block_sender(make_req({
        "sender_email": "malicious@example.com",
        "recipient_email": "user@example.com"
    }))
    assert resp["status"] == "success"


@patch("app.mimecast.requests.post")
def test_unblock_sender(mock_post):
    mock_post.return_value = mock_response({"data": [{"result": "permitted"}]})
    resp = integration_class.unblock_sender(make_req({
        "sender_email": "malicious@example.com",
        "recipient_email": "user@example.com"
    }))
    assert resp["status"] == "success"


@patch("app.mimecast.requests.post")
def test_list_blocked_senders(mock_post):
    mock_post.return_value = mock_response({"data": [{"id": "policy1"}]})
    resp = integration_class.list_blocked_senders(make_req({}))
    assert resp["status"] == "success"
    assert len(resp["policies"]) == 1


@patch("app.mimecast.requests.post")
def test_remove_message(mock_post):
    mock_post.return_value = mock_response({"data": []})
    resp = integration_class.remove_message(make_req({"message_id": "sample-message-id"}))
    assert resp["status"] == "success"


@patch("app.mimecast.requests.post")
def test_get_url_reputation(mock_post):
    mock_post.return_value = mock_response({"data": [{"url": "http://malicious.example.com", "verdict": "malicious"}]})
    resp = integration_class.get_url_reputation(make_req({"url": "http://malicious.example.com"}))
    assert resp["status"] == "success"


@patch("app.mimecast.requests.post")
def test_mimecast_test_connection(mock_post):
    mock_post.return_value = mock_response({"data": []})
    resp = integration_class.test_connection(CONN["connectionParameters"])
    assert resp["status"] == "success"
