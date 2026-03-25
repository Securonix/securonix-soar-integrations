from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import json
import requests


class Telegram():

    DEFAULT_SERVER_URL = "https://api.telegram.org"

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    def _get_base_url(self, connectionParameters: dict) -> str:
        server_url = connectionParameters.get('server_url', self.DEFAULT_SERVER_URL)
        if not server_url:
            server_url = self.DEFAULT_SERVER_URL
        server_url = server_url.rstrip('/')
        bot_token = connectionParameters['bot_token']
        return f"{server_url}/bot{bot_token}"

    def test_connection(self, connectionParameters: dict):
        try:
            base_url = self._get_base_url(connectionParameters)
            resp = requests.get(f"{base_url}/getMe", timeout=30)
            resp.raise_for_status()
            data = resp.json()
            self.logger.debug("Telegram response to getMe is %s", json.dumps(data))
            if data.get("ok"):
                return {'status': 'success', 'message': 'Connected to Telegram Bot API successfully.'}
            else:
                raise Exception(f"Telegram API returned error: {data.get('description', 'Unknown error')}")
        except Exception as e:
            self.logger.error("Exception while testing Telegram connection", exc_info=e)
            raise Exception(str(e))

    def send_message(self, request: RequestBody) -> ResponseBody:
        try:
            base_url = self._get_base_url(request.connectionParameters)
            chat_id = request.connectionParameters['chat_id']
            message = request.parameters['message']
            parse_mode = request.parameters.get('parse_mode')

            payload = {
                "chat_id": chat_id,
                "text": message
            }
            if parse_mode:
                payload["parse_mode"] = parse_mode

            resp = requests.post(f"{base_url}/sendMessage", json=payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            if data.get("ok"):
                result = data.get("result", {})
                return {
                    "status": "success",
                    "message_id": result.get("message_id"),
                    "message": "Message sent successfully."
                }
            else:
                raise Exception(data.get("description", "Failed to send message"))

        except Exception as e:
            self.logger.error("Error while running action 'send_message'", exc_info=e)
            raise Exception(str(e))

    def get_updates(self, request: RequestBody) -> ResponseBody:
        try:
            base_url = self._get_base_url(request.connectionParameters)
            limit = request.parameters.get('limit', 10)
            offset = request.parameters.get('offset')

            payload = {"limit": int(limit)}
            if offset is not None and offset != '':
                payload["offset"] = int(offset)

            resp = requests.post(f"{base_url}/getUpdates", json=payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            if data.get("ok"):
                updates = data.get("result", [])
                messages = []
                for update in updates:
                    msg = update.get("message") or update.get("channel_post", {})
                    if msg:
                        messages.append({
                            "update_id": update.get("update_id"),
                            "message_id": msg.get("message_id"),
                            "from": msg.get("from", {}).get("username", ""),
                            "chat_id": msg.get("chat", {}).get("id"),
                            "date": msg.get("date"),
                            "text": msg.get("text", "")
                        })
                return {
                    "status": "success",
                    "count": len(messages),
                    "messages": messages
                }
            else:
                raise Exception(data.get("description", "Failed to get updates"))

        except Exception as e:
            self.logger.error("Error while running action 'get_updates'", exc_info=e)
            raise Exception(str(e))


