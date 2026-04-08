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
        self._base_url = None
        self._access_token = None

    # --- Internal helpers ---

    def _init_connection(self, cp: dict):
        self._base_url = cp['base_url'].rstrip('/')
        self._authenticate(cp)

    def _authenticate(self, cp: dict):
        url = f"{self._base_url}/api/token"
        payload = {
            "email": cp['email'],
            "password": cp['password'],
            "grant_type": "password",
            "client_id": cp['client_id']
        }
        resp = requests.post(url, data=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        self._access_token = data.get("access_token")
        if not self._access_token:
            raise Exception("Failed to obtain access token from ThreatQ")

    def _headers(self):
        return {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    def _request(self, method, endpoint, params=None, json_data=None):
        url = f"{self._base_url}/api{endpoint}"
        self.logger.debug("ThreatQ %s %s", method, url)
        try:
            resp = requests.request(method, url, headers=self._headers(),
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

    def _get_indicator_type_id(self, type_name):
        data = self._request("GET", "/indicator/types")
        for t in data.get("data", []):
            if t["name"].lower() == type_name.lower():
                return t["id"]
        raise Exception(f"Unknown indicator type: {type_name}")

    def _get_event_type_id(self, type_name):
        data = self._request("GET", "/event/types")
        for t in data.get("data", []):
            if t["name"].lower() == type_name.lower():
                return t["id"]
        raise Exception(f"Unknown event type: {type_name}")

    def _search_indicator(self, value):
        data = self._request("GET", "/indicators/search",
                             params={"value": value, "with": "sources,attributes,score,status,type"})
        results = data.get("data", [])
        if not results:
            return None
        return results[0] if len(results) == 1 else results

    # --- Test Connection ---

    def test_connection(self, connectionParameters: dict):
        try:
            self._init_connection(connectionParameters)
            return {'status': 'success', 'message': 'Connected to ThreatQ successfully.'}
        except Exception as e:
            self.logger.error("ThreatQ connection test failed", exc_info=e)
            raise Exception(str(e))

    # --- Search Actions ---

    def search_by_name(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            name = request.parameters['name']
            limit = request.parameters.get('limit', 50)
            results = []
            for obj_type in ['indicators', 'adversaries', 'events']:
                data = self._request("GET", f"/{obj_type}",
                                     params={"limit": limit, "with": "sources,attributes"})
                for item in data.get("data", []):
                    val = item.get("value") or item.get("name") or item.get("title", "")
                    if name.lower() in val.lower():
                        results.append(item)
            return {"status": "success", "results": results}
        except Exception as e:
            self.logger.error("Error in search_by_name", exc_info=e)
            raise Exception(str(e))

    def search_by_id(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            obj_type = request.parameters['obj_type']
            obj_id = request.parameters['obj_id']
            ep = self._get_obj_endpoint(obj_type)
            data = self._request("GET", f"/{ep}/{obj_id}",
                                 params={"with": "sources,attributes"})
            return {"status": "success", "result": data.get("data", data)}
        except Exception as e:
            self.logger.error("Error in search_by_id", exc_info=e)
            raise Exception(str(e))

    # --- Reputation Actions ---

    def ip_reputation(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            result = self._search_indicator(request.parameters['ip'])
            return {"status": "success", "result": result or "No results found"}
        except Exception as e:
            self.logger.error("Error in ip_reputation", exc_info=e)
            raise Exception(str(e))

    def url_reputation(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            result = self._search_indicator(request.parameters['url'])
            return {"status": "success", "result": result or "No results found"}
        except Exception as e:
            self.logger.error("Error in url_reputation", exc_info=e)
            raise Exception(str(e))

    def domain_reputation(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            result = self._search_indicator(request.parameters['domain'])
            return {"status": "success", "result": result or "No results found"}
        except Exception as e:
            self.logger.error("Error in domain_reputation", exc_info=e)
            raise Exception(str(e))

    def file_reputation(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            result = self._search_indicator(request.parameters['file'])
            return {"status": "success", "result": result or "No results found"}
        except Exception as e:
            self.logger.error("Error in file_reputation", exc_info=e)
            raise Exception(str(e))

    def email_reputation(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            result = self._search_indicator(request.parameters['email'])
            return {"status": "success", "result": result or "No results found"}
        except Exception as e:
            self.logger.error("Error in email_reputation", exc_info=e)
            raise Exception(str(e))

    # --- Indicator CRUD ---

    def create_indicator(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            p = request.parameters
            type_id = self._get_indicator_type_id(p['type'])
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
            data = self._request("POST", "/indicators", json_data=[payload])
            return {"status": "success", "indicator": data.get("data", data)}
        except Exception as e:
            self.logger.error("Error in create_indicator", exc_info=e)
            raise Exception(str(e))

    def edit_indicator(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            p = request.parameters
            ind_id = p['id']
            payload = {}
            if p.get('value'):
                payload['value'] = p['value']
            if p.get('type'):
                payload['type_id'] = self._get_indicator_type_id(p['type'])
            if p.get('description'):
                payload['description'] = p['description']
            data = self._request("PUT", f"/indicators/{ind_id}",
                                 json_data=payload, params={"with": "sources,attributes,status,type"})
            return {"status": "success", "indicator": data.get("data", data)}
        except Exception as e:
            self.logger.error("Error in edit_indicator", exc_info=e)
            raise Exception(str(e))

    def update_status(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            ind_id = request.parameters['id']
            status_id = self.STATUS_MAP.get(request.parameters['status'])
            if not status_id:
                raise Exception(f"Invalid status: {request.parameters['status']}")
            data = self._request("PUT", f"/indicators/{ind_id}",
                                 json_data={"status_id": status_id},
                                 params={"with": "status"})
            return {"status": "success", "result": data.get("data", data)}
        except Exception as e:
            self.logger.error("Error in update_status", exc_info=e)
            raise Exception(str(e))

    def update_score(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            ind_id = request.parameters['id']
            score = request.parameters['score']
            payload = {"manual_score": None if score == "Generated Score" else int(score)}
            data = self._request("PUT", f"/indicators/{ind_id}",
                                 json_data=payload, params={"with": "score"})
            return {"status": "success", "result": data.get("data", data)}
        except Exception as e:
            self.logger.error("Error in update_score", exc_info=e)
            raise Exception(str(e))

    def get_all_indicators(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            page = int(request.parameters.get('page', 0))
            limit = int(request.parameters.get('limit', 50))
            data = self._request("GET", "/indicators",
                                 params={"limit": limit, "offset": page * limit,
                                         "with": "sources,attributes,score,status,type"})
            return {"status": "success", "indicators": data.get("data", []),
                    "total": data.get("total", 0)}
        except Exception as e:
            self.logger.error("Error in get_all_indicators", exc_info=e)
            raise Exception(str(e))

    # --- Adversary CRUD ---

    def create_adversary(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            p = request.parameters
            payload = {"name": p['name']}
            sources = p.get('sources')
            if sources:
                payload["sources"] = [{"name": s.strip()} for s in sources.split(',')]
            data = self._request("POST", "/adversaries", json_data=payload)
            return {"status": "success", "adversary": data.get("data", data)}
        except Exception as e:
            self.logger.error("Error in create_adversary", exc_info=e)
            raise Exception(str(e))

    def edit_adversary(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            adv_id = request.parameters['id']
            data = self._request("PUT", f"/adversaries/{adv_id}",
                                 json_data={"name": request.parameters['name']},
                                 params={"with": "sources,attributes"})
            return {"status": "success", "adversary": data.get("data", data)}
        except Exception as e:
            self.logger.error("Error in edit_adversary", exc_info=e)
            raise Exception(str(e))

    def get_all_adversaries(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            page = int(request.parameters.get('page', 0))
            limit = int(request.parameters.get('limit', 50))
            data = self._request("GET", "/adversaries",
                                 params={"limit": limit, "offset": page * limit,
                                         "with": "sources,attributes"})
            return {"status": "success", "adversaries": data.get("data", []),
                    "total": data.get("total", 0)}
        except Exception as e:
            self.logger.error("Error in get_all_adversaries", exc_info=e)
            raise Exception(str(e))

    # --- Event CRUD ---

    def create_event(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            p = request.parameters
            payload = {
                "title": p['title'],
                "type": p['type'],
                "happened_at": p['date']
            }
            sources = p.get('sources')
            if sources:
                payload["sources"] = [{"name": s.strip()} for s in sources.split(',')]
            data = self._request("POST", "/events", json_data=payload)
            return {"status": "success", "event": data.get("data", data)}
        except Exception as e:
            self.logger.error("Error in create_event", exc_info=e)
            raise Exception(str(e))

    def edit_event(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            p = request.parameters
            evt_id = p['id']
            payload = {}
            for field in ['title', 'description']:
                if p.get(field):
                    payload[field] = p[field]
            if p.get('date'):
                payload['happened_at'] = p['date']
            if p.get('type'):
                payload['type_id'] = self._get_event_type_id(p['type'])
            data = self._request("PUT", f"/events/{evt_id}",
                                 json_data=payload, params={"with": "sources,attributes,type"})
            return {"status": "success", "event": data.get("data", data)}
        except Exception as e:
            self.logger.error("Error in edit_event", exc_info=e)
            raise Exception(str(e))

    def get_all_events(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            page = int(request.parameters.get('page', 0))
            limit = int(request.parameters.get('limit', 50))
            data = self._request("GET", "/events",
                                 params={"limit": limit, "offset": page * limit,
                                         "with": "sources,attributes,type"})
            return {"status": "success", "events": data.get("data", []),
                    "total": data.get("total", 0)}
        except Exception as e:
            self.logger.error("Error in get_all_events", exc_info=e)
            raise Exception(str(e))

    # --- Attribute Actions ---

    def add_attribute(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            p = request.parameters
            ep = self._get_obj_endpoint(p['obj_type'])
            data = self._request("POST", f"/{ep}/{p['obj_id']}/attributes",
                                 json_data={"name": p['name'], "value": p['value']})
            return {"status": "success", "result": data.get("data", data)}
        except Exception as e:
            self.logger.error("Error in add_attribute", exc_info=e)
            raise Exception(str(e))

    def modify_attribute(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            p = request.parameters
            ep = self._get_obj_endpoint(p['obj_type'])
            data = self._request("PUT", f"/{ep}/{p['obj_id']}/attributes/{p['attribute_id']}",
                                 json_data={"value": p['attribute_value']})
            return {"status": "success", "result": data.get("data", data)}
        except Exception as e:
            self.logger.error("Error in modify_attribute", exc_info=e)
            raise Exception(str(e))

    def delete_attribute(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            p = request.parameters
            ep = self._get_obj_endpoint(p['obj_type'])
            self._request("DELETE", f"/{ep}/{p['obj_id']}/attributes/{p['attribute_id']}")
            return {"status": "success", "result": "Attribute deleted"}
        except Exception as e:
            self.logger.error("Error in delete_attribute", exc_info=e)
            raise Exception(str(e))

    # --- Source Actions ---

    def add_source(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            p = request.parameters
            ep = self._get_obj_endpoint(p['obj_type'])
            data = self._request("POST", f"/{ep}/{p['obj_id']}/sources",
                                 json_data={"name": p['source']})
            return {"status": "success", "result": data.get("data", data)}
        except Exception as e:
            self.logger.error("Error in add_source", exc_info=e)
            raise Exception(str(e))

    def delete_source(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            p = request.parameters
            ep = self._get_obj_endpoint(p['obj_type'])
            self._request("DELETE", f"/{ep}/{p['obj_id']}/sources/{p['source_id']}")
            return {"status": "success", "result": "Source deleted"}
        except Exception as e:
            self.logger.error("Error in delete_source", exc_info=e)
            raise Exception(str(e))

    # --- Link/Unlink Actions ---

    def link_objects(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            p = request.parameters
            ep1 = self._get_obj_endpoint(p['obj1_type'])
            ep2 = self._get_obj_endpoint(p['obj2_type'])
            data = self._request("POST", f"/{ep1}/{p['obj1_id']}/{ep2}",
                                 json_data=[{"id": int(p['obj2_id'])}])
            return {"status": "success", "result": data.get("data", data)}
        except Exception as e:
            self.logger.error("Error in link_objects", exc_info=e)
            raise Exception(str(e))

    def unlink_objects(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            p = request.parameters
            ep1 = self._get_obj_endpoint(p['obj1_type'])
            ep2 = self._get_obj_endpoint(p['obj2_type'])
            links = self._request("GET", f"/{ep1}/{p['obj1_id']}/{ep2}")
            link_id = None
            for item in links.get("data", []):
                if str(item.get("id")) == str(p['obj2_id']):
                    link_id = item.get("pivot", {}).get("id")
                    break
            if not link_id:
                raise Exception("Link not found between the two objects")
            self._request("DELETE", f"/{ep1}/{p['obj1_id']}/{ep2}/{link_id}")
            return {"status": "success", "result": "Objects unlinked"}
        except Exception as e:
            self.logger.error("Error in unlink_objects", exc_info=e)
            raise Exception(str(e))

    # --- Delete Object ---

    def delete_object(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            p = request.parameters
            ep = self._get_obj_endpoint(p['obj_type'])
            self._request("DELETE", f"/{ep}/{p['obj_id']}")
            return {"status": "success", "result": f"{p['obj_type']} deleted"}
        except Exception as e:
            self.logger.error("Error in delete_object", exc_info=e)
            raise Exception(str(e))

    # --- Related Objects ---

    def get_related_indicators(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            p = request.parameters
            ep = self._get_obj_endpoint(p['obj_type'])
            data = self._request("GET", f"/{ep}/{p['obj_id']}/indicators",
                                 params={"with": "sources,attributes,score,status,type"})
            return {"status": "success", "indicators": data.get("data", [])}
        except Exception as e:
            self.logger.error("Error in get_related_indicators", exc_info=e)
            raise Exception(str(e))

    def get_related_events(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            p = request.parameters
            ep = self._get_obj_endpoint(p['obj_type'])
            data = self._request("GET", f"/{ep}/{p['obj_id']}/events",
                                 params={"with": "sources,type"})
            return {"status": "success", "events": data.get("data", [])}
        except Exception as e:
            self.logger.error("Error in get_related_events", exc_info=e)
            raise Exception(str(e))

    def get_related_adversaries(self, request: RequestBody) -> ResponseBody:
        try:
            self._init_connection(request.connectionParameters)
            p = request.parameters
            ep = self._get_obj_endpoint(p['obj_type'])
            data = self._request("GET", f"/{ep}/{p['obj_id']}/adversaries",
                                 params={"with": "sources,attributes"})
            return {"status": "success", "adversaries": data.get("data", [])}
        except Exception as e:
            self.logger.error("Error in get_related_adversaries", exc_info=e)
            raise Exception(str(e))


