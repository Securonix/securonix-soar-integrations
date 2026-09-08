from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import json
import requests


class ThreatQ():

    OBJ_TYPE_MAP = {
        "indicator": "indicators",
        "event": "events",
        "adversary": "adversaries",
        "attachment": "attachments"
    }

    STATUS_MAP = {
        "Active": 1, "Expired": 2, "Indirect": 3,
        "Review": 4, "Whitelisted": 5
    }

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    # --- Normalizer helpers ---

    @staticmethod
    def _first(data):
        """Return the created object whether ThreatQ wraps it in a list or not.

        Several POST endpoints return {"total": N, "data": [ {...} ]} (a list),
        while others return {"data": {...}} (a single object). This normalizes
        both to a single dict.
        """
        payload = data.get("data") if isinstance(data, dict) else data
        if isinstance(payload, list):
            return payload[0] if payload else {}
        return payload or {}

    @staticmethod
    def _str_id(value):
        return str(value) if value is not None else None

    def _indicator_fields(self, ind: dict) -> dict:
        """Flatten a single indicator object into scalar output fields.

        `type_id`/`status_id` are native ThreatQ scalar fields; `type`/
        `indicator_status` are the human-readable names from the `type`/`status`
        relationships (only present when requested via `with=type,status` and
        actually returned). `score` is best-effort and may be null when the
        endpoint does not include the score relationship.
        """
        ind = ind or {}
        type_obj = ind.get("type") or {}
        status_obj = ind.get("status") or {}
        return {
            "indicator_id": self._str_id(ind.get("id")),
            "value": ind.get("value"),
            "type_id": ind.get("type_id"),
            "type": type_obj.get("name") if type_obj else None,
            "status_id": ind.get("status_id"),
            "indicator_status": status_obj.get("name") if status_obj else None,
            "score": ind.get("score"),
            "sources": [s.get("name") for s in (ind.get("sources") or []) if isinstance(s, dict)],
            "attributes": ind.get("attributes") or [],
        }

    def _event_fields(self, evt: dict) -> dict:
        """Flatten an event object. `type` (name) is only present when the
        `type` relationship is returned; `type_id` is the native scalar.
        Resilient when `type` or `description` is absent."""
        evt = evt or {}
        type_obj = evt.get("type") or {}
        return {
            "event_id": self._str_id(evt.get("id")),
            "title": evt.get("title"),
            "type_id": evt.get("type_id"),
            "type": type_obj.get("name") if type_obj else None,
            "happened_at": evt.get("happened_at"),
            "description": evt.get("description"),
        }

    def _adversary_fields(self, adv: dict) -> dict:
        adv = adv or {}
        return {
            "adversary_id": self._str_id(adv.get("id")),
            "name": adv.get("name"),
        }

    # --- Internal helpers ---

    def _authenticate(self, base_url, cp):
        url = f"{base_url}/api/token"
        payload = {
            "email": cp['email'],
            "password": cp['password'],
            "grant_type": "password",
            "client_id": cp['client_id']
        }
        resp = requests.post(url, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        token = data.get("access_token")
        if not token:
            raise Exception("Failed to obtain access token from ThreatQ")
        return token

    def _connect(self, connectionParameters):
        base_url = connectionParameters['base_url'].rstrip('/')
        access_token = self._authenticate(base_url, connectionParameters)
        return base_url, access_token

    def _headers(self, access_token):
        return {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    def _request(self, base_url, access_token, method, endpoint, params=None, json_data=None):
        url = f"{base_url}/api{endpoint}"
        self.logger.debug("ThreatQ %s %s", method, url)
        try:
            resp = requests.request(method, url, headers=self._headers(access_token),
                                    params=params, json=json_data, timeout=30)
            if resp.status_code == 401:
                raise Exception("Authentication failed")
            if resp.status_code == 404:
                raise Exception("Object not found")
            if resp.status_code == 400:
                raise Exception(f"Bad request: {resp.text[:500]}")
            if resp.status_code >= 500:
                raise Exception(f"ThreatQ server error: {resp.status_code}")
            if resp.status_code == 204:
                return {}
            return resp.json() if resp.text else {}
        except requests.exceptions.Timeout:
            raise Exception("Connection timed out")
        except requests.exceptions.ConnectionError:
            raise Exception("Failed to connect to ThreatQ")

    def _get_obj_endpoint(self, obj_type):
        ep = self.OBJ_TYPE_MAP.get(obj_type)
        if not ep:
            raise Exception(f"Invalid object type: {obj_type}")
        return ep

    def _get_indicator_type_id(self, base_url, access_token, type_name):
        data = self._request(base_url, access_token, "GET", "/indicator/types")
        for t in data.get("data", []):
            if t["name"].lower() == type_name.lower():
                return t["id"]
        raise Exception(f"Unknown indicator type: {type_name}")

    def _get_event_type_id(self, base_url, access_token, type_name):
        data = self._request(base_url, access_token, "GET", "/event/types")
        for t in data.get("data", []):
            if t["name"].lower() == type_name.lower():
                return t["id"]
        raise Exception(f"Unknown event type: {type_name}")

    def _search_indicators_raw(self, base_url, access_token, value):
        return self._request(base_url, access_token, "GET", "/indicators/search",
                             params={"value": value, "with": "sources,attributes,score,status,type"})

    def _reputation(self, request, value_key):
        base_url, access_token = self._connect(request.connectionParameters)
        resp = self._search_indicators_raw(base_url, access_token, request.parameters[value_key])
        data = resp.get("data", []) if isinstance(resp, dict) else []
        first = data[0] if data else {}
        out = {
            "status": "success",
            "found": bool(data),
            "total_count": resp.get("total", len(data)) if isinstance(resp, dict) else len(data),
        }
        out.update(self._indicator_fields(first))
        out["raw_response"] = resp
        return out

    # --- Test Connection ---

    def test_connection(self, connectionParameters: dict):
        try:
            base_url = connectionParameters['base_url'].rstrip('/')
            url = f"{base_url}/api/token"
            payload = {
                "email": connectionParameters['email'],
                "password": connectionParameters['password'],
                "grant_type": "password",
                "client_id": connectionParameters['client_id']
            }
            resp = requests.post(url, json=payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            if not data.get("access_token"):
                raise Exception("Failed to obtain access token from ThreatQ")
            return {'status': 'success', 'message': 'Connected to ThreatQ successfully.'}
        except Exception as e:
            self.logger.error("ThreatQ connection test failed", exc_info=e)
            raise Exception(str(e))

    # --- Search Actions ---

    def search_by_name(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            name = request.parameters['name']
            limit = request.parameters.get('limit', 50)
            results = []
            # search_by_name performs multiple ThreatQ calls; raw_response
            # preserves each actual per-type API response unmodified.
            raw = {}
            for obj_type in ['indicators', 'adversaries', 'events']:
                data = self._request(base_url, access_token, "GET", f"/{obj_type}",
                                     params={"limit": limit, "with": "sources,attributes"})
                raw[obj_type] = data
                for item in data.get("data", []):
                    val = item.get("value") or item.get("name") or item.get("title", "")
                    if name.lower() in val.lower():
                        results.append(item)
            return {"status": "success", "total_count": len(results),
                    "results": results, "raw_response": raw}
        except Exception as e:
            self.logger.error("Error in search_by_name", exc_info=e)
            raise Exception(str(e))

    def search_by_id(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            obj_type = request.parameters['obj_type']
            obj_id = request.parameters['obj_id']
            ep = self._get_obj_endpoint(obj_type)
            data = self._request(base_url, access_token, "GET", f"/{ep}/{obj_id}",
                                 params={"with": "sources,attributes"})
            obj = data.get("data", data) if isinstance(data, dict) else data
            obj = obj if isinstance(obj, dict) else {}
            return {"status": "success", "object_id": self._str_id(obj_id),
                    "object_type": obj_type, "value": obj.get("value"),
                    "name": obj.get("name"), "title": obj.get("title"),
                    "result": obj, "raw_response": data}
        except Exception as e:
            self.logger.error("Error in search_by_id", exc_info=e)
            raise Exception(str(e))

    # --- Reputation Actions ---

    def ip_reputation(self, request: RequestBody) -> ResponseBody:
        try:
            return self._reputation(request, 'ip')
        except Exception as e:
            self.logger.error("Error in ip_reputation", exc_info=e)
            raise Exception(str(e))

    def url_reputation(self, request: RequestBody) -> ResponseBody:
        try:
            return self._reputation(request, 'url')
        except Exception as e:
            self.logger.error("Error in url_reputation", exc_info=e)
            raise Exception(str(e))

    def domain_reputation(self, request: RequestBody) -> ResponseBody:
        try:
            return self._reputation(request, 'domain')
        except Exception as e:
            self.logger.error("Error in domain_reputation", exc_info=e)
            raise Exception(str(e))

    def file_reputation(self, request: RequestBody) -> ResponseBody:
        try:
            return self._reputation(request, 'file')
        except Exception as e:
            self.logger.error("Error in file_reputation", exc_info=e)
            raise Exception(str(e))

    def email_reputation(self, request: RequestBody) -> ResponseBody:
        try:
            return self._reputation(request, 'email')
        except Exception as e:
            self.logger.error("Error in email_reputation", exc_info=e)
            raise Exception(str(e))

    # --- Indicator CRUD ---

    def create_indicator(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            p = request.parameters
            type_id = self._get_indicator_type_id(base_url, access_token, p['type'])
            status_id = self.STATUS_MAP.get(p['status'])
            if not status_id:
                raise Exception(f"Invalid status: {p['status']}")
            payload = {"value": p['value'], "type_id": type_id, "status_id": status_id, "class": "network"}
            sources = p.get('sources')
            if sources:
                payload["sources"] = [{"name": s.strip()} for s in sources.split(',')]
            attrs_names = p.get('attributes_names')
            attrs_values = p.get('attributes_values')
            if attrs_names and attrs_values:
                names = [n.strip() for n in attrs_names.split(',')]
                values = [v.strip() for v in attrs_values.split(',')]
                payload["attributes"] = [{"name": n, "value": v} for n, v in zip(names, values)]
            data = self._request(base_url, access_token, "POST", "/indicators", json_data=[payload])
            ind = self._first(data)
            return {"status": "success", **self._indicator_fields(ind), "raw_response": data}
        except Exception as e:
            self.logger.error("Error in create_indicator", exc_info=e)
            raise Exception(str(e))

    def edit_indicator(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            p = request.parameters
            ind_id = p['id']
            payload = {}
            if p.get('value'):
                payload['value'] = p['value']
            if p.get('type'):
                payload['type_id'] = self._get_indicator_type_id(base_url, access_token, p['type'])
            if p.get('description'):
                payload['description'] = p['description']
            data = self._request(base_url, access_token, "PUT", f"/indicators/{ind_id}",
                                 json_data=payload, params={"with": "sources,attributes,score,status,type"})
            ind = self._first(data)
            return {"status": "success", **self._indicator_fields(ind), "raw_response": data}
        except Exception as e:
            self.logger.error("Error in edit_indicator", exc_info=e)
            raise Exception(str(e))

    def update_status(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            ind_id = request.parameters['id']
            status_id = self.STATUS_MAP.get(request.parameters['status'])
            if not status_id:
                raise Exception(f"Invalid status: {request.parameters['status']}")
            data = self._request(base_url, access_token, "PUT", f"/indicators/{ind_id}",
                                 json_data={"status_id": status_id}, params={"with": "status"})
            obj = self._first(data)
            status_obj = obj.get("status") or {}
            status_name = status_obj.get("name") if status_obj else request.parameters['status']
            return {"status": "success", "indicator_id": self._str_id(ind_id),
                    "indicator_status": status_name, "raw_response": data}
        except Exception as e:
            self.logger.error("Error in update_status", exc_info=e)
            raise Exception(str(e))

    def update_score(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            ind_id = request.parameters['id']
            score = request.parameters['score']
            payload = {"manual_score": None if score == "Generated Score" else int(score)}
            data = self._request(base_url, access_token, "PUT", f"/indicators/{ind_id}",
                                 json_data=payload, params={"with": "score"})
            obj = self._first(data)
            return {"status": "success", "indicator_id": self._str_id(ind_id),
                    "score": obj.get("score"), "raw_response": data}
        except Exception as e:
            self.logger.error("Error in update_score", exc_info=e)
            raise Exception(str(e))

    def get_all_indicators(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            page = int(request.parameters.get('page', 0))
            limit = int(request.parameters.get('limit', 50))
            data = self._request(base_url, access_token, "GET", "/indicators",
                                 params={"limit": limit, "offset": page * limit,
                                         "with": "sources,attributes,score,status,type"})
            items = data.get("data", []) or []
            return {"status": "success", "total_count": data.get("total", len(items)),
                    "count": len(items), "indicators": items, "raw_response": data}
        except Exception as e:
            self.logger.error("Error in get_all_indicators", exc_info=e)
            raise Exception(str(e))

    # --- Adversary CRUD ---

    def create_adversary(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            p = request.parameters
            payload = {"name": p['name']}
            sources = p.get('sources')
            if sources:
                payload["sources"] = [{"name": s.strip()} for s in sources.split(',')]
            data = self._request(base_url, access_token, "POST", "/adversaries", json_data=payload)
            adv = self._first(data)
            return {"status": "success", **self._adversary_fields(adv), "raw_response": data}
        except Exception as e:
            self.logger.error("Error in create_adversary", exc_info=e)
            raise Exception(str(e))

    def edit_adversary(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            adv_id = request.parameters['id']
            data = self._request(base_url, access_token, "PUT", f"/adversaries/{adv_id}",
                                 json_data={"name": request.parameters['name']},
                                 params={"with": "sources,attributes"})
            adv = self._first(data)
            return {"status": "success", **self._adversary_fields(adv), "raw_response": data}
        except Exception as e:
            self.logger.error("Error in edit_adversary", exc_info=e)
            raise Exception(str(e))

    def get_all_adversaries(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            page = int(request.parameters.get('page', 0))
            limit = int(request.parameters.get('limit', 50))
            data = self._request(base_url, access_token, "GET", "/adversaries",
                                 params={"limit": limit, "offset": page * limit,
                                         "with": "sources,attributes"})
            items = data.get("data", []) or []
            return {"status": "success", "total_count": data.get("total", len(items)),
                    "count": len(items), "adversaries": items, "raw_response": data}
        except Exception as e:
            self.logger.error("Error in get_all_adversaries", exc_info=e)
            raise Exception(str(e))

    # --- Event CRUD ---

    def create_event(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            p = request.parameters
            payload = {
                "title": p['title'],
                "type": p['type'],
                "happened_at": p['date']
            }
            sources = p.get('sources')
            if sources:
                payload["sources"] = [{"name": s.strip()} for s in sources.split(',')]
            data = self._request(base_url, access_token, "POST", "/events", json_data=payload)
            evt = self._first(data)
            return {"status": "success", **self._event_fields(evt), "raw_response": data}
        except Exception as e:
            self.logger.error("Error in create_event", exc_info=e)
            raise Exception(str(e))

    def edit_event(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            p = request.parameters
            evt_id = p['id']
            payload = {}
            for field in ['title', 'description']:
                if p.get(field):
                    payload[field] = p[field]
            if p.get('date'):
                payload['happened_at'] = p['date']
            if p.get('type'):
                payload['type_id'] = self._get_event_type_id(base_url, access_token, p['type'])
            data = self._request(base_url, access_token, "PUT", f"/events/{evt_id}",
                                 json_data=payload, params={"with": "sources,attributes,type"})
            evt = self._first(data)
            return {"status": "success", **self._event_fields(evt), "raw_response": data}
        except Exception as e:
            self.logger.error("Error in edit_event", exc_info=e)
            raise Exception(str(e))

    def get_all_events(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            page = int(request.parameters.get('page', 0))
            limit = int(request.parameters.get('limit', 50))
            data = self._request(base_url, access_token, "GET", "/events",
                                 params={"limit": limit, "offset": page * limit,
                                         "with": "sources,attributes,type"})
            items = data.get("data", []) or []
            return {"status": "success", "total_count": data.get("total", len(items)),
                    "count": len(items), "events": items, "raw_response": data}
        except Exception as e:
            self.logger.error("Error in get_all_events", exc_info=e)
            raise Exception(str(e))

    # --- Attribute Actions ---

    def add_attribute(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            p = request.parameters
            obj_type = p['obj_type']
            ep = self._get_obj_endpoint(obj_type)
            data = self._request(base_url, access_token, "POST", f"/{ep}/{p['obj_id']}/attributes",
                                 json_data={"name": p['name'], "value": p['value']})
            attr = self._first(data)
            # ThreatQ object-attribute record: `id` is the object-attribute
            # record ID; `attribute_id` is the attribute DEFINITION ID; and
            # `<object_type>_id` (e.g. indicator_id) is the parent object ID.
            record_id = self._str_id(attr.get("id"))
            return {
                "status": "success",
                "succeeded": True,
                "object_attribute_id": record_id,
                # Deprecated legacy alias: historically `attribute_id` returned
                # the object-attribute record ID (data.id). Preserved for BC.
                "attribute_id": record_id,
                "attribute_definition_id": self._str_id(attr.get("attribute_id")),
                "object_id": self._str_id(attr.get(f"{obj_type}_id")),
                "attribute_name": attr.get("name"),
                "attribute_value": attr.get("value"),
                "raw_response": data,
            }
        except Exception as e:
            self.logger.error("Error in add_attribute", exc_info=e)
            raise Exception(str(e))

    def _resolve_object_attribute_id(self, p):
        """Resolve the ThreatQ object-attribute RECORD id from parameters.

        Accepts the precise `object_attribute_id` (preferred) and the legacy
        `attribute_id` input, which has always referred to the same
        object-attribute record ID (used in the URL path). If both are given,
        `object_attribute_id` wins; the legacy `attribute_id` is NEVER
        reinterpreted as the attribute definition ID.
        """
        oaid = p.get('object_attribute_id')
        if oaid is not None and str(oaid) != "":
            return oaid
        legacy = p.get('attribute_id')
        if legacy is not None and str(legacy) != "":
            return legacy
        raise Exception("Missing required parameter: object_attribute_id")

    def modify_attribute(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            p = request.parameters
            ep = self._get_obj_endpoint(p['obj_type'])
            oaid = self._resolve_object_attribute_id(p)
            data = self._request(base_url, access_token, "PUT", f"/{ep}/{p['obj_id']}/attributes/{oaid}",
                                 json_data={"value": p['attribute_value']})
            return {"status": "success", "succeeded": True,
                    "object_attribute_id": self._str_id(oaid),
                    "attribute_id": self._str_id(oaid),  # deprecated legacy alias
                    "raw_response": data}
        except Exception as e:
            self.logger.error("Error in modify_attribute", exc_info=e)
            raise Exception(str(e))

    def delete_attribute(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            p = request.parameters
            ep = self._get_obj_endpoint(p['obj_type'])
            oaid = self._resolve_object_attribute_id(p)
            self._request(base_url, access_token, "DELETE", f"/{ep}/{p['obj_id']}/attributes/{oaid}")
            return {"status": "success", "succeeded": True, "http_status": 204,
                    "object_attribute_id": self._str_id(oaid),
                    "attribute_id": self._str_id(oaid),  # deprecated legacy alias
                    "message": "Attribute deleted", "raw_response": {}}
        except Exception as e:
            self.logger.error("Error in delete_attribute", exc_info=e)
            raise Exception(str(e))

    # --- Source Actions ---

    def add_source(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            p = request.parameters
            ep = self._get_obj_endpoint(p['obj_type'])
            data = self._request(base_url, access_token, "POST", f"/{ep}/{p['obj_id']}/sources",
                                 json_data={"name": p['source']})
            src = self._first(data)
            # ThreatQ object-source record: `id` is the object-source
            # relationship record ID; `source_id` is the GLOBAL ThreatQ source
            # catalog ID. These are not interchangeable.
            record_id = self._str_id(src.get("id"))
            return {
                "status": "success",
                "succeeded": True,
                "object_source_id": record_id,
                # Deprecated legacy alias: historically `source_id` returned the
                # object-source relationship record ID (data.id). Preserved for BC.
                "source_id": record_id,
                "threatq_source_id": self._str_id(src.get("source_id")),
                "source_name": src.get("name"),
                "raw_response": data,
            }
        except Exception as e:
            self.logger.error("Error in add_source", exc_info=e)
            raise Exception(str(e))

    def _resolve_object_source_id(self, p):
        """Resolve the ThreatQ object-source RECORD id (the URL path id).

        Verified against v6.15: DELETE /{obj}/{id}/sources/{object_source_id}
        expects the object-source relationship record ID (data.id), NOT the
        global ThreatQ source_id. Accepts precise `object_source_id`
        (preferred) and legacy `source_id`, which has always meant the same
        record ID. `object_source_id` wins if both supplied.
        """
        osid = p.get('object_source_id')
        if osid is not None and str(osid) != "":
            return osid
        legacy = p.get('source_id')
        if legacy is not None and str(legacy) != "":
            return legacy
        raise Exception("Missing required parameter: object_source_id")

    def delete_source(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            p = request.parameters
            ep = self._get_obj_endpoint(p['obj_type'])
            osid = self._resolve_object_source_id(p)
            self._request(base_url, access_token, "DELETE", f"/{ep}/{p['obj_id']}/sources/{osid}")
            return {"status": "success", "succeeded": True, "http_status": 204,
                    "object_source_id": self._str_id(osid),
                    "source_id": self._str_id(osid),  # deprecated legacy alias
                    "message": "Source deleted", "raw_response": {}}
        except Exception as e:
            self.logger.error("Error in delete_source", exc_info=e)
            raise Exception(str(e))

    # --- Link/Unlink Actions ---

    def link_objects(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            p = request.parameters
            ep1 = self._get_obj_endpoint(p['obj1_type'])
            ep2 = self._get_obj_endpoint(p['obj2_type'])
            data = self._request(base_url, access_token, "POST", f"/{ep1}/{p['obj1_id']}/{ep2}",
                                 json_data=[{"id": int(p['obj2_id'])}])
            link = self._first(data)
            pivot = link.get("pivot") or {}
            return {"status": "success", "succeeded": True,
                    "link_id": self._str_id(pivot.get("id")),
                    "linked_id": self._str_id(link.get("id")), "raw_response": data}
        except Exception as e:
            self.logger.error("Error in link_objects", exc_info=e)
            raise Exception(str(e))

    def unlink_objects(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            p = request.parameters
            ep1 = self._get_obj_endpoint(p['obj1_type'])
            ep2 = self._get_obj_endpoint(p['obj2_type'])
            links = self._request(base_url, access_token, "GET", f"/{ep1}/{p['obj1_id']}/{ep2}")
            link_id = None
            for item in links.get("data", []):
                if str(item.get("id")) == str(p['obj2_id']):
                    link_id = item.get("pivot", {}).get("id")
                    break
            if not link_id:
                raise Exception("Link not found between the two objects")
            self._request(base_url, access_token, "DELETE", f"/{ep1}/{p['obj1_id']}/{ep2}/{link_id}")
            return {"status": "success", "succeeded": True, "http_status": 204,
                    "message": "Objects unlinked", "raw_response": {}}
        except Exception as e:
            self.logger.error("Error in unlink_objects", exc_info=e)
            raise Exception(str(e))

    # --- Delete Object ---

    def delete_object(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            p = request.parameters
            ep = self._get_obj_endpoint(p['obj_type'])
            self._request(base_url, access_token, "DELETE", f"/{ep}/{p['obj_id']}")
            return {"status": "success", "succeeded": True, "http_status": 204,
                    "message": f"{p['obj_type']} deleted", "raw_response": {}}
        except Exception as e:
            self.logger.error("Error in delete_object", exc_info=e)
            raise Exception(str(e))

    # --- Related Objects ---

    def get_related_indicators(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            p = request.parameters
            ep = self._get_obj_endpoint(p['obj_type'])
            data = self._request(base_url, access_token, "GET", f"/{ep}/{p['obj_id']}/indicators",
                                 params={"with": "sources,attributes,score,status,type"})
            items = data.get("data", []) or []
            return {"status": "success", "total_count": data.get("total", len(items)),
                    "count": len(items), "indicators": items, "raw_response": data}
        except Exception as e:
            self.logger.error("Error in get_related_indicators", exc_info=e)
            raise Exception(str(e))

    def get_related_events(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            p = request.parameters
            ep = self._get_obj_endpoint(p['obj_type'])
            data = self._request(base_url, access_token, "GET", f"/{ep}/{p['obj_id']}/events",
                                 params={"with": "sources,type"})
            items = data.get("data", []) or []
            return {"status": "success", "total_count": data.get("total", len(items)),
                    "count": len(items), "events": items, "raw_response": data}
        except Exception as e:
            self.logger.error("Error in get_related_events", exc_info=e)
            raise Exception(str(e))

    def get_related_adversaries(self, request: RequestBody) -> ResponseBody:
        try:
            base_url, access_token = self._connect(request.connectionParameters)
            p = request.parameters
            ep = self._get_obj_endpoint(p['obj_type'])
            data = self._request(base_url, access_token, "GET", f"/{ep}/{p['obj_id']}/adversaries",
                                 params={"with": "sources,attributes"})
            items = data.get("data", []) or []
            return {"status": "success", "total_count": data.get("total", len(items)),
                    "count": len(items), "adversaries": items, "raw_response": data}
        except Exception as e:
            self.logger.error("Error in get_related_adversaries", exc_info=e)
            raise Exception(str(e))
