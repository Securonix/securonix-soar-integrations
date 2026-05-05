from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import requests


class Misp():

    SUPPORTED_ATTRIBUTE_TYPES = [
        "ip-src", "ip-dst", "domain", "hostname", "url",
        "md5", "sha1", "sha256",
        "email-src", "email-dst",
        "filename", "mutex", "regkey",
        "malware-sample", "link", "comment", "text",
        "user-agent", "port", "snort", "yara"
    ]

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    @staticmethod
    def _get_headers(api_key):
        return {
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

    @staticmethod
    def _normalize_list(value):
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        raise Exception("Invalid input format")

    @staticmethod
    def _validate_attribute_type(attr_type):
        if attr_type not in Misp.SUPPORTED_ATTRIBUTE_TYPES:
            raise Exception(
                f"Unsupported attribute type: {attr_type}. "
                f"Supported types: {Misp.SUPPORTED_ATTRIBUTE_TYPES}"
            )

    def _get(self, base_url, api_key, endpoint, params=None):
        url = f"{base_url}{endpoint}"
        resp = requests.get(url, headers=self._get_headers(api_key), params=params, timeout=30)
        return self._handle_response(resp)

    def _post(self, base_url, api_key, endpoint, payload):
        url = f"{base_url}{endpoint}"
        resp = requests.post(url, headers=self._get_headers(api_key), json=payload, timeout=30)
        return self._handle_response(resp)

    def _delete(self, base_url, api_key, endpoint):
        url = f"{base_url}{endpoint}"
        resp = requests.delete(url, headers=self._get_headers(api_key), timeout=30)
        return self._handle_response(resp)

    @staticmethod
    def _handle_response(resp):
        if resp.status_code in (401, 403):
            raise Exception("Authentication failed")
        if resp.status_code == 404:
            raise Exception("Resource not found")
        if resp.status_code >= 500:
            raise Exception(f"MISP server error: {resp.status_code}")
        if resp.status_code >= 300:
            raise Exception(f"Unexpected error: {resp.status_code} - {resp.text[:500]}")
        return resp.json()

    def _extract_conn(self, connection_params):
        base_url = connection_params["server_url"].rstrip("/")
        api_key = connection_params["api_key"]
        return base_url, api_key

    # --- Connection ---

    def test_connection(self, connectionParameters: dict):
        try:
            base_url, api_key = self._extract_conn(connectionParameters)
            self._get(base_url, api_key, "/servers/getVersion")
            return {"status": "success", "message": "Connected to MISP successfully."}
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to MISP. Please verify the Server URL.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to MISP timed out.")
        except Exception as e:
            self.logger.error("Exception while testing connection", exc_info=e)
            raise Exception(str(e))

    # --- Event Operations ---

    def search_events(self, request: RequestBody) -> dict:
        try:
            base_url, api_key = self._extract_conn(request.connectionParameters)
            params = request.parameters
            payload = {"returnFormat": "json", "limit": params.get("limit", 50)}
            for key in ("value", "eventid", "type", "category", "tags"):
                if params.get(key) is not None:
                    payload[key] = params[key]
            if params.get("date_from") is not None:
                payload["from"] = params["date_from"]
            if params.get("date_to") is not None:
                payload["to"] = params["date_to"]
            data = self._post(base_url, api_key, "/events/restSearch", payload)
            events = data.get("response", [])
            return {"status": "success", "count": len(events), "events": events}
        except Exception as e:
            self.logger.error("Error in search_events", exc_info=e)
            raise Exception(str(e))

    def create_event(self, request: RequestBody) -> dict:
        try:
            base_url, api_key = self._extract_conn(request.connectionParameters)
            params = request.parameters
            for field in ("info", "distribution", "threat_level_id", "analysis"):
                if params.get(field) is None:
                    raise Exception(f"Missing required parameter: {field}")
            event_body = {
                "info": params["info"],
                "distribution": params["distribution"],
                "threat_level_id": params["threat_level_id"],
                "analysis": params["analysis"]
            }
            if params.get("date") is not None:
                event_body["date"] = params["date"]
            if params.get("published") is not None:
                event_body["published"] = params["published"]
            if params.get("tags") is not None:
                tags = self._normalize_list(params["tags"])
                event_body["Tag"] = [{"name": t} for t in tags]
            data = self._post(base_url, api_key, "/events/add", {"Event": event_body})
            event = data.get("Event", {})
            return {"status": "success", "event_id": event.get("id"), "message": "Event created successfully."}
        except Exception as e:
            self.logger.error("Error in create_event", exc_info=e)
            raise Exception(str(e))

    def get_event(self, request: RequestBody) -> dict:
        try:
            base_url, api_key = self._extract_conn(request.connectionParameters)
            event_id = request.parameters.get("event_id")
            if event_id is None:
                raise Exception("Missing required parameter: event_id")
            data = self._get(base_url, api_key, f"/events/view/{event_id}")
            return {"status": "success", "event": data.get("Event", {})}
        except Exception as e:
            self.logger.error("Error in get_event", exc_info=e)
            raise Exception(str(e))

    # --- Attribute Operations ---

    def add_attribute(self, request: RequestBody) -> dict:
        try:
            base_url, api_key = self._extract_conn(request.connectionParameters)
            params = request.parameters
            event_id = params.get("event_id")
            attr_type = params.get("type")
            value = params.get("value")
            if event_id is None:
                raise Exception("Missing required parameter: event_id")
            if attr_type is None:
                raise Exception("Missing required parameter: type")
            if value is None:
                raise Exception("Missing required parameter: value")
            self._validate_attribute_type(attr_type)
            attr_body = {"type": attr_type, "value": value}
            if params.get("category") is not None:
                attr_body["category"] = params["category"]
            if params.get("to_ids") is not None:
                attr_body["to_ids"] = params["to_ids"]
            if params.get("comment") is not None:
                attr_body["comment"] = params["comment"]
            data = self._post(base_url, api_key, f"/attributes/add/{event_id}", attr_body)
            attr = data.get("Attribute", {})
            return {"status": "success", "attribute_id": attr.get("id"), "message": "Attribute added successfully."}
        except Exception as e:
            self.logger.error("Error in add_attribute", exc_info=e)
            raise Exception(str(e))

    def search_attributes(self, request: RequestBody) -> dict:
        try:
            base_url, api_key = self._extract_conn(request.connectionParameters)
            params = request.parameters
            payload = {"returnFormat": "json", "limit": params.get("limit", 50)}
            value = params.get("value")
            if value is not None and isinstance(value, str) and "," in value:
                payload["value"] = "|".join(v.strip() for v in value.split(",") if v.strip())
            elif value is not None:
                payload["value"] = value
            for key in ("type", "category", "tags"):
                if params.get(key) is not None:
                    payload[key] = params[key]
            if params.get("date_from") is not None:
                payload["from"] = params["date_from"]
            if params.get("date_to") is not None:
                payload["to"] = params["date_to"]
            data = self._post(base_url, api_key, "/attributes/restSearch", payload)
            response = data.get("response", {})
            attributes = response.get("Attribute", []) if isinstance(response, dict) else []
            return {"status": "success", "count": len(attributes), "attributes": attributes}
        except Exception as e:
            self.logger.error("Error in search_attributes", exc_info=e)
            raise Exception(str(e))

    # --- Tag Management ---

    def add_tag(self, request: RequestBody) -> dict:
        try:
            base_url, api_key = self._extract_conn(request.connectionParameters)
            params = request.parameters
            target_type = params.get("target_type")
            target_id = params.get("target_id")
            tag_name = params.get("tag_name")
            if target_type not in ("event", "attribute"):
                raise Exception("target_type must be 'event' or 'attribute'")
            if target_id is None:
                raise Exception("Missing required parameter: target_id")
            if tag_name is None:
                raise Exception("Missing required parameter: tag_name")
            tags_data = self._get(base_url, api_key, "/tags")
            tag_list = tags_data.get("Tag", [])
            matched_tag = None
            for tag in tag_list:
                if tag.get("name", "").lower() == tag_name.lower():
                    matched_tag = tag["name"]
                    break
            if matched_tag is None:
                raise Exception(f"Tag '{tag_name}' does not exist in MISP")
            endpoint = f"/tags/attachTagToObject/{target_id}"
            self._post(base_url, api_key, endpoint, {"tag": matched_tag})
            return {"status": "success", "message": f"Tag '{matched_tag}' added to {target_type} {target_id}."}
        except Exception as e:
            self.logger.error("Error in add_tag", exc_info=e)
            raise Exception(str(e))

    def remove_tag(self, request: RequestBody) -> dict:
        try:
            base_url, api_key = self._extract_conn(request.connectionParameters)
            params = request.parameters
            target_type = params.get("target_type")
            target_id = params.get("target_id")
            tag_name = params.get("tag_name")
            if target_type not in ("event", "attribute"):
                raise Exception("target_type must be 'event' or 'attribute'")
            if target_id is None:
                raise Exception("Missing required parameter: target_id")
            if tag_name is None:
                raise Exception("Missing required parameter: tag_name")
            endpoint = f"/tags/removeTagFromObject/{target_id}"
            self._post(base_url, api_key, endpoint, {"tag": tag_name})
            return {"status": "success", "message": f"Tag '{tag_name}' removed from {target_type} {target_id}."}
        except Exception as e:
            self.logger.error("Error in remove_tag", exc_info=e)
            raise Exception(str(e))

    # --- Sighting Management ---

    def add_sighting(self, request: RequestBody) -> dict:
        try:
            base_url, api_key = self._extract_conn(request.connectionParameters)
            params = request.parameters
            attr_id = params.get("attribute_id")
            attr_value = params.get("attribute_value")
            if attr_id is None and attr_value is None:
                raise Exception("At least one of attribute_id or attribute_value is required")
            sighting_type = params.get("type", 0)
            if sighting_type not in (0, 1, 2):
                raise Exception("Sighting type must be 0 (sighting), 1 (false positive), or 2 (expiration)")
            payload = {"type": sighting_type}
            if attr_id is not None:
                payload["id"] = attr_id
            else:
                payload["value"] = attr_value
            if params.get("source") is not None:
                payload["source"] = params["source"]
            data = self._post(base_url, api_key, "/sightings/add", payload)
            return {"status": "success", "sighting_id": data.get("id"), "message": "Sighting added successfully."}
        except Exception as e:
            self.logger.error("Error in add_sighting", exc_info=e)
            raise Exception(str(e))

    # --- Feed Management ---

    def get_feeds(self, request: RequestBody) -> dict:
        try:
            base_url, api_key = self._extract_conn(request.connectionParameters)
            data = self._get(base_url, api_key, "/feeds")
            feeds = data if isinstance(data, list) else []
            return {"status": "success", "count": len(feeds), "feeds": feeds}
        except Exception as e:
            self.logger.error("Error in get_feeds", exc_info=e)
            raise Exception(str(e))

    def enable_feed(self, request: RequestBody) -> dict:
        try:
            base_url, api_key = self._extract_conn(request.connectionParameters)
            feed_id = request.parameters.get("feed_id")
            if feed_id is None:
                raise Exception("Missing required parameter: feed_id")
            self._post(base_url, api_key, f"/feeds/enable/{feed_id}", {})
            return {"status": "success", "feed_id": feed_id, "message": "Feed enabled successfully."}
        except Exception as e:
            self.logger.error("Error in enable_feed", exc_info=e)
            raise Exception(str(e))

    def disable_feed(self, request: RequestBody) -> dict:
        try:
            base_url, api_key = self._extract_conn(request.connectionParameters)
            feed_id = request.parameters.get("feed_id")
            if feed_id is None:
                raise Exception("Missing required parameter: feed_id")
            self._post(base_url, api_key, f"/feeds/disable/{feed_id}", {})
            return {"status": "success", "feed_id": feed_id, "message": "Feed disabled successfully."}
        except Exception as e:
            self.logger.error("Error in disable_feed", exc_info=e)
            raise Exception(str(e))

    def fetch_feed(self, request: RequestBody) -> dict:
        try:
            base_url, api_key = self._extract_conn(request.connectionParameters)
            feed_id = request.parameters.get("feed_id")
            if feed_id is None:
                raise Exception("Missing required parameter: feed_id")
            self._post(base_url, api_key, f"/feeds/fetch/{feed_id}", {})
            return {"status": "success", "feed_id": feed_id, "message": "Feed fetch triggered."}
        except Exception as e:
            self.logger.error("Error in fetch_feed", exc_info=e)
            raise Exception(str(e))

    # --- Warninglist Lookup ---

    def check_warninglists(self, request: RequestBody) -> dict:
        try:
            base_url, api_key = self._extract_conn(request.connectionParameters)
            value = request.parameters.get("value")
            if value is None:
                raise Exception("Missing required parameter: value")
            data = self._post(base_url, api_key, "/warninglists/checkValue", {"value": value})
            matches = data if isinstance(data, list) else []
            return {"status": "success", "value": value, "matched": len(matches) > 0, "warninglists": matches}
        except Exception as e:
            self.logger.error("Error in check_warninglists", exc_info=e)
            raise Exception(str(e))
