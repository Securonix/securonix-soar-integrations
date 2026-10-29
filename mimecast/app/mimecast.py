from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import json
import requests
import hmac
import hashlib
import base64
import time
import uuid


def _init_client(connectionParameters):
    return {
        "base_url": connectionParameters["base_url"],
        "access_key": connectionParameters["access_key"],
        "secret_key": connectionParameters["secret_key"],
        "app_id": connectionParameters["app_id"],
        "app_key": connectionParameters["app_key"],
    }


def _headers(client, uri):
    request_id = str(uuid.uuid4())
    timestamp = str(int(time.time() * 1000))
    data_to_sign = f"{timestamp}:{request_id}:{uri}:{client['app_key']}"
    secret_key_bytes = base64.b64decode(client["secret_key"])
    signature = base64.b64encode(
        hmac.new(
            secret_key_bytes,
            data_to_sign.encode(),
            hashlib.sha1
        ).digest()
    ).decode()
    return {
        "Authorization": f"MC {client['access_key']}:{signature}",
        "x-mc-app-id": client["app_id"],
        "x-mc-date": timestamp,
        "x-mc-req-id": request_id,
        "Content-Type": "application/json"
    }


def _post(client, uri, payload):
    url = f"{client['base_url']}{uri}"
    response = requests.post(url, headers=_headers(client, uri), json=payload, timeout=30)
    if response.status_code >= 300:
        error_body = response.text or "(empty response body)"
        raise Exception(f"HTTP {response.status_code}: {error_body}")
    return response.json()


class Mimecast():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    def test_connection(self, connectionParameters: dict):
        try:
            client = _init_client(connectionParameters)
            resp = _post(client, "/api/audit/get-audit-events", {
                "meta": {"pagination": {"pageSize": 1}},
                "data": []
            })
            self.logger.debug("Mimecast test connection response: %s", json.dumps(resp))
            return {"status": "success", "message": "Connected to Mimecast successfully."}
        except Exception as e:
            self.logger.error("Exception while testing Mimecast connection", exc_info=e)
            raise Exception(str(e))

    def get_threats(self, request: RequestBody) -> ResponseBody:
        try:
            client = _init_client(request.connectionParameters)
            limit = request.parameters.get("limit", 10)
            payload = {"meta": {"pagination": {"pageSize": limit}}, "data": []}
            response = _post(client, "/api/ttp/threat/get-threats", payload)
            return {"status": "success", "threats": response.get("data", [])}
        except Exception as e:
            self.logger.error("error while running action 'get_threats'", exc_info=e)
            raise Exception(str(e))

    def block_sender(self, request: RequestBody) -> ResponseBody:
        try:
            client = _init_client(request.connectionParameters)
            sender = request.parameters["sender_email"]
            recipient = request.parameters["recipient_email"]
            response = _post(client, "/api/managedsender/permit-or-block-sender", {
                "data": [{"sender": sender, "to": recipient, "action": "block"}]
            })
            return {"status": "success", "result": response.get("data", [])}
        except Exception as e:
            self.logger.error("error while running action 'block_sender'", exc_info=e)
            raise Exception(str(e))

    def unblock_sender(self, request: RequestBody) -> ResponseBody:
        """
        Permits the sender for the specified recipient using action 'permit'.
        Note: this does not delete the block policy entry; it creates a permit
        override for the given sender/recipient pair.
        """
        try:
            client = _init_client(request.connectionParameters)
            sender = request.parameters["sender_email"]
            recipient = request.parameters["recipient_email"]
            response = _post(client, "/api/managedsender/permit-or-block-sender", {
                "data": [{"sender": sender, "to": recipient, "action": "permit"}]
            })
            return {"status": "success", "result": response.get("data", [])}
        except Exception as e:
            self.logger.error("error while running action 'unblock_sender'", exc_info=e)
            raise Exception(str(e))

    def list_blocked_senders(self, request: RequestBody) -> ResponseBody:
        """
        Lists blocked sender policies. Requires Gateway | Policies | Read permission.
        Returns policies, not individual managed sender entries.
        """
        try:
            client = _init_client(request.connectionParameters)
            response = _post(client, "/api/policy/blockedsenders/get-policy", {"data": []})
            return {"status": "success", "policies": response.get("data", [])}
        except Exception as e:
            self.logger.error("error while running action 'list_blocked_senders'", exc_info=e)
            raise Exception(str(e))

    def remove_message(self, request: RequestBody) -> ResponseBody:
        try:
            client = _init_client(request.connectionParameters)
            message_id = request.parameters["message_id"]
            payload = {"data": [{"messageId": message_id}]}
            _post(client, "/api/message-finder/remove", payload)
            return {"status": "success", "message": "Message removed successfully."}
        except Exception as e:
            self.logger.error("error while running action 'remove_message'", exc_info=e)
            raise Exception(str(e))

    def get_url_reputation(self, request: RequestBody) -> ResponseBody:
        try:
            client = _init_client(request.connectionParameters)
            url = request.parameters["url"]
            payload = {"data": [{"url": url}]}
            response = _post(client, "/api/ttp/url/get-url", payload)
            return {"status": "success", "result": response.get("data", [])}
        except Exception as e:
            self.logger.error("error while running action 'get_url_reputation'", exc_info=e)
            raise Exception(str(e))
