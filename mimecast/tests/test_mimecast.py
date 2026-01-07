
from app.aws_waf import AwsWaf
from app.model.request_body import RequestBody
from pykson import Pykson
import json
pykson = Pykson()
integration_class = mimecast()


def test_get_threats(mock_post):
    mock_post.return_value = {
        "data": [
            {"id": "threat1"},
            {"id": "threat2"}
        ]
    }

    req = """
    {
        "connectionParameters": {
            "base_url": "https://us-api.mimecast.com",
            "access_key": "samplevalue",
            "secret_key": "samplevalue",
            "app_id": "samplevalue",
            "app_key": "samplevalue"
        },
        "parameters": {
            "limit": 2
        }
    }
    """

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.get_threats(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert len(resp["threats"]) == 2

def test_block_sender(mock_post):
    mock_post.return_value = {"status": "ok"}

    req = """
    {
        "connectionParameters": {
            "base_url": "https://us-api.mimecast.com",
            "access_key": "samplevalue",
            "secret_key": "samplevalue",
            "app_id": "samplevalue",
            "app_key": "samplevalue"
        },
        "parameters": {
            "sender_email": "malicious@example.com"
        }
    }
    """

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.block_sender(req)

    assert resp is not None
    assert resp["status"] == "success"

def test_remove_message(mock_post):
    mock_post.return_value = {"status": "ok"}

    req = """
    {
        "connectionParameters": {
            "base_url": "https://us-api.mimecast.com",
            "access_key": "samplevalue",
            "secret_key": "samplevalue",
            "app_id": "samplevalue",
            "app_key": "samplevalue"
        },
        "parameters": {
            "message_id": "sample-message-id"
        }
    }
    """

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.remove_message(req)

    assert resp is not None
    assert resp["status"] == "success"


def test_get_url_reputation(mock_post):
    mock_post.return_value = {
        "data": [
            {
                "url": "http://malicious.example.com",
                "verdict": "malicious"
            }
        ]
    }

    req = """
    {
        "connectionParameters": {
            "base_url": "https://us-api.mimecast.com",
            "access_key": "samplevalue",
            "secret_key": "samplevalue",
            "app_id": "samplevalue",
            "app_key": "samplevalue"
        },
        "parameters": {
            "url": "http://malicious.example.com"
        }
    }
    """

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.get_url_reputation(req)

    assert resp is not None
    assert resp["status"] == "success"

def test_mimecast_test_connection(mock_post):
    mock_post.return_value = {"data": []}

    conn_params = {
        "base_url": "https://us-api.mimecast.com",
        "access_key": "samplevalue",
        "secret_key": "samplevalue",
        "app_id": "samplevalue",
        "app_key": "samplevalue"
    }

    resp = integration_class.test_connection(conn_params)

    assert resp is not None
    assert resp["status"] == "success"
