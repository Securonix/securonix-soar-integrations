import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.telegram import Telegram
from app.model.request_body import RequestBody
from pykson import Pykson
from unittest.mock import patch, MagicMock

pykson = Pykson()
integration_class = Telegram()

connection_params = {
    "bot_token": "mock_bot_token",
    "server_url": "https://api.telegram.org",
    "chat_id": "123456789"
}


def create_request_body(parameters):
    req_json = {
        "connectionParameters": connection_params,
        "parameters": parameters
    }
    return pykson.from_json(req_json, RequestBody, True)


@patch("requests.get")
def test_test_connection(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"ok": True, "result": {"id": 123, "is_bot": True, "first_name": "TestBot"}}
    mock_get.return_value = mock_response

    result = integration_class.test_connection(connection_params)
    assert result["status"] == "success"
    assert "Connected" in result["message"]


@patch("requests.post")
def test_send_message(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"ok": True, "result": {"message_id": 42}}
    mock_post.return_value = mock_response

    req = create_request_body({"message": "Hello from SOAR"})
    resp = integration_class.send_message(req)
    assert resp["status"] == "success"
    assert resp["message_id"] == 42


@patch("requests.post")
def test_send_message_with_parse_mode(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"ok": True, "result": {"message_id": 43}}
    mock_post.return_value = mock_response

    req = create_request_body({"message": "<b>Bold</b>", "parse_mode": "HTML"})
    resp = integration_class.send_message(req)
    assert resp["status"] == "success"
    assert resp["message_id"] == 43

    call_kwargs = mock_post.call_args
    assert call_kwargs[1]["json"]["parse_mode"] == "HTML"


@patch("requests.post")
def test_get_updates(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "ok": True,
        "result": [
            {
                "update_id": 100,
                "message": {
                    "message_id": 1,
                    "from": {"username": "testuser"},
                    "chat": {"id": 123456789},
                    "date": 1700000000,
                    "text": "Hello bot"
                }
            },
            {
                "update_id": 101,
                "message": {
                    "message_id": 2,
                    "from": {"username": "anotheruser"},
                    "chat": {"id": 123456789},
                    "date": 1700000001,
                    "text": "Second message"
                }
            }
        ]
    }
    mock_post.return_value = mock_response

    req = create_request_body({"limit": 10})
    resp = integration_class.get_updates(req)
    assert resp["status"] == "success"
    assert resp["count"] == 2
    assert resp["messages"][0]["text"] == "Hello bot"
    assert resp["messages"][1]["from"] == "anotheruser"


@patch("requests.post")
def test_get_updates_with_offset(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"ok": True, "result": []}
    mock_post.return_value = mock_response

    req = create_request_body({"limit": 5, "offset": "102"})
    resp = integration_class.get_updates(req)
    assert resp["status"] == "success"
    assert resp["count"] == 0
    assert resp["messages"] == []

    call_kwargs = mock_post.call_args
    assert call_kwargs[1]["json"]["offset"] == 102


@patch("requests.post")
def test_get_updates_empty(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"ok": True, "result": []}
    mock_post.return_value = mock_response

    req = create_request_body({})
    resp = integration_class.get_updates(req)
    assert resp["status"] == "success"
    assert resp["count"] == 0


@patch("requests.get")
def test_test_connection_failure(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"ok": False, "description": "Unauthorized"}
    mock_get.return_value = mock_response

    try:
        integration_class.test_connection(connection_params)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Unauthorized" in str(e)


@patch("requests.post")
def test_send_message_failure(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"ok": False, "description": "Bad Request: chat not found"}
    mock_post.return_value = mock_response

    req = create_request_body({"message": "test"})
    try:
        integration_class.send_message(req)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "chat not found" in str(e)
