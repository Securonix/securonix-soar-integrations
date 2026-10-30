from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import binascii
import logging
import json
import requests
import hmac
import hashlib
import base64
import uuid
from datetime import datetime, timedelta, timezone

_PAGE_SIZE_MIN = 1
_PAGE_SIZE_MAX = 500


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
    timestamp = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S UTC")
    secret = str(client["secret_key"]).strip()
    secret += "=" * (-len(secret) % 4)
    try:
        secret_key_bytes = base64.b64decode(secret, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Mimecast secret_key must be a complete Base64-encoded API secret.") from exc
    data_to_sign = f"{timestamp}:{request_id}:{uri}:{client['app_key']}"
    signature = base64.b64encode(
        hmac.new(secret_key_bytes, data_to_sign.encode(), hashlib.sha1).digest()
    ).decode()
    return {
        "Authorization": f"MC {client['access_key']}:{signature}",
        "x-mc-app-id": client["app_id"],
        "x-mc-date": timestamp,
        "x-mc-req-id": request_id,
        "Content-Type": "application/json",
    }


def _post(client, uri, payload):
    url = f"{client['base_url']}{uri}"
    response = requests.post(url, headers=_headers(client, uri), json=payload, timeout=30)
    if response.status_code >= 300:
        raise Exception(f"HTTP {response.status_code}: {response.text or '(empty response body)'}")
    body = response.json()
    fail = body.get("fail")
    meta_status = body.get("meta", {}).get("status")
    if fail or (meta_status is not None and str(meta_status) != "200"):
        errors = (fail or [{}])[0].get("errors", [])
        raise Exception(f"Mimecast API error (status={meta_status}): {errors}")
    return body


def _validated_limit(parameters):
    try:
        limit = int(parameters.get("limit", 100))
    except (TypeError, ValueError):
        raise ValueError("limit must be an integer.")
    if not (_PAGE_SIZE_MIN <= limit <= _PAGE_SIZE_MAX):
        raise ValueError(f"limit must be between {_PAGE_SIZE_MIN} and {_PAGE_SIZE_MAX}.")
    return limit


class Mimecast():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    def test_connection(self, connectionParameters: dict):
        try:
            client = _init_client(connectionParameters)
            now = datetime.now(timezone.utc)
            resp = _post(client, "/api/audit/get-audit-events", {
                "meta": {"pagination": {"pageSize": 1}},
                "data": [{
                    "startDateTime": (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S+0000"),
                    "endDateTime": now.strftime("%Y-%m-%dT%H:%M:%S+0000")
                }]
            })
            self.logger.debug("Mimecast test connection response: %s", json.dumps(resp))
            return {"status": "success", "message": "Connected to Mimecast successfully."}
        except Exception as e:
            self.logger.error("Exception while testing Mimecast connection", exc_info=e)
            raise Exception(str(e))

    def get_threats(self, request: RequestBody) -> ResponseBody:
        """
        Retrieves URL Protection click logs via /api/ttp/url/get-logs.
        Note: this endpoint returns URL Protection logs only, not all threat event types.
        Paginates until all pages are fetched or the limit is reached.
        """
        try:
            client = _init_client(request.connectionParameters)
            limit = _validated_limit(request.parameters)
            now = datetime.now(timezone.utc)
            base_data = {
                "oldestFirst": False,
                "route": "all",
                "scanResult": "all",
                "from": (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S+0000"),
                "to": now.strftime("%Y-%m-%dT%H:%M:%S+0000"),
            }
            click_logs = []
            next_page = None
            while True:
                meta = {"pagination": {"pageSize": min(limit - len(click_logs), _PAGE_SIZE_MAX)}}
                if next_page:
                    meta["pagination"]["pageToken"] = next_page
                response = _post(client, "/api/ttp/url/get-logs", {"meta": meta, "data": [base_data]})
                for entry in response.get("data", []):
                    click_logs.extend(entry.get("clickLogs", []))
                next_page = response.get("meta", {}).get("pagination", {}).get("next")
                if not next_page or len(click_logs) >= limit:
                    break
            return {"status": "success", "threats": click_logs[:limit]}
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
        Creates a permit override for the sender/recipient pair via action 'permit'.
        This does not remove an existing block policy entry; it adds a permit override.
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
        Returns blocked sender policies via /api/policy/blockedsenders/get-policy.
        Returns policy entries, not individual managed sender entries.
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
