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


class Mimecast():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    # ---------------------------------------------------------------------
    # Test Connection
    # ---------------------------------------------------------------------
    def test_connection(self, connectionParameters: dict):
        try:
            self._init_client(connectionParameters)
            resp = self._post("/api/audit/get-audit-events", {
                "meta": {"pagination": {"pageSize": 1}},
                "data": []
            })
            self.logger.debug("Mimecast test connection response: %s", json.dumps(resp))
            return {
                "status": "success",
                "message": "Connected to Mimecast successfully."
            }
        except Exception as e:
            self.logger.error("Exception while testing Mimecast connection", exc_info=e)
            raise Exception(str(e))

    # ---------------------------------------------------------------------
    # Get Threats
    # ---------------------------------------------------------------------
    def get_threats(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_client(request.connectionParameters)

            limit = request.parameters.get("limit", 10)

            payload = {
                "meta": {
                    "pagination": {
                        "pageSize": limit
                    }
                },
                "data": []
            }

            response = self._post("/api/ttp/threat/get-threats", payload)

            return {
                "status": "success",
                "threats": response.get("data", [])
            }

        except Exception as e:
            self.logger.error("error while running action 'get_threats'", exc_info=e)
            raise Exception(str(e))

    # ---------------------------------------------------------------------
    # Block Sender
    # ---------------------------------------------------------------------
    def block_sender(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_client(request.connectionParameters)

            sender_email = request.parameters["sender_email"]

            payload = {
                "data": [
                    {
                        "sender": sender_email
                    }
                ]
            }

            self._post("/api/directory/add-blocked-sender", payload)

            return {
                "status": "success",
                "message": f"Sender {sender_email} blocked successfully."
            }

        except Exception as e:
            self.logger.error("error while running action 'block_sender'", exc_info=e)
            raise Exception(str(e))

    # =========================
    # Internal helper methods
    # =========================

    def _init_client(self, connectionParameters):
        self.base_url = connectionParameters["base_url"]
        self.access_key = connectionParameters["access_key"]
        self.secret_key = connectionParameters["secret_key"]
        self.app_id = connectionParameters["app_id"]
        self.app_key = connectionParameters["app_key"]

    def _post(self, uri, payload):
        url = f"{self.base_url}{uri}"
        headers = self._headers(uri)

        response = requests.post(url, headers=headers, json=payload, timeout=30)

        if response.status_code >= 300:
            raise Exception(response.text)

        return response.json()

    def _headers(self, uri):
        request_id = str(uuid.uuid4())
        timestamp = str(int(time.time() * 1000))

        data_to_sign = f"{timestamp}:{request_id}:{uri}:{self.app_key}"

        signature = base64.b64encode(
            hmac.new(
                self.secret_key.encode(),
                data_to_sign.encode(),
                hashlib.sha1
            ).digest()
        ).decode()

        return {
            "Authorization": f"MC {self.access_key}:{signature}",
            "x-mc-app-id": self.app_id,
            "x-mc-date": timestamp,
            "x-mc-req-id": request_id,
            "Content-Type": "application/json"
        }

def remove_message(self, request: RequestBody) -> ResponseBody:
    message_id = request.parameters["message_id"]

    payload = {
        "data": [{"messageId": message_id}]
    }

    self._post("/api/message-finder/remove", payload)

    return {
        "status": "success",
        "message": "Message removed successfully."
    }

def get_url_reputation(self, request: RequestBody) -> ResponseBody:
    url = request.parameters["url"]

    payload = {
        "data": [{"url": url}]
    }

    response = self._post("/api/ttp/url/get-url", payload)

    return {
        "status": "success",
        "result": response.get("data", [])
    }