from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import time
import requests
from urllib.parse import urljoin


BASE_URL = "https://attack-taxii.mitre.org"
TAXII_ACCEPT = "application/taxii+json;version=2.1"
USER_AGENT = "SecuronixSOAR-MitreAttack/1.0"
SUPPORTED_DOMAINS = ("enterprise-attack", "mobile-attack", "ics-attack")
DOMAIN_TITLES = {
    "enterprise-attack": "Enterprise ATT&CK",
    "mobile-attack": "Mobile ATT&CK",
    "ics-attack": "ICS ATT&CK",
}


def _get_config(connection_params: dict) -> dict:
    base_url = (connection_params.get("base_url") or BASE_URL).rstrip("/")

    raw_timeout = connection_params.get("timeout")
    if raw_timeout is not None and str(raw_timeout).strip():
        try:
            timeout = int(raw_timeout)
            if timeout < 1:
                raise ValueError()
        except (ValueError, TypeError):
            raise Exception("timeout must be a positive integer.")
    else:
        timeout = 30

    verify_ssl = connection_params.get("verify_ssl", True)
    if isinstance(verify_ssl, str):
        normalized = verify_ssl.strip().lower()
        if normalized in ("true", "1", "yes"):
            verify_ssl = True
        elif normalized in ("false", "0", "no"):
            verify_ssl = False
        else:
            raise ValueError(f"verify_ssl has an unrecognized value: '{verify_ssl}'. Use true or false.")
    elif not isinstance(verify_ssl, bool):
        raise ValueError("verify_ssl must be a boolean value.")

    proxy = connection_params.get("proxy")
    proxies = {"http": proxy, "https": proxy} if proxy else None

    return {
        "base_url": base_url,
        "headers": {
            "Accept": TAXII_ACCEPT,
            "User-Agent": USER_AGENT,
        },
        "timeout": timeout,
        "verify": verify_ssl,
        "proxies": proxies,
    }


def _taxii_get(config: dict, url: str, params: dict = None) -> dict:
    for attempt in range(3):
        try:
            resp = requests.get(
                url,
                headers=config["headers"],
                params=params,
                timeout=config["timeout"],
                verify=config["verify"],
                proxies=config["proxies"],
            )
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to MITRE ATT&CK TAXII server. Check base_url and network.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to MITRE ATT&CK TAXII server timed out.")

        if resp.status_code == 429:
            raise Exception("Rate limit exceeded. Please wait before retrying.")
        if resp.status_code in (401, 403):
            raise Exception("Authentication error accessing MITRE ATT&CK TAXII server.")
        if resp.status_code == 404:
            raise LookupError("Resource not found on MITRE ATT&CK TAXII server.")
        if resp.status_code >= 500:
            if attempt < 2:
                time.sleep(2 ** (attempt + 1))
                continue
            raise Exception(f"MITRE ATT&CK TAXII server error (HTTP {resp.status_code}).")
        if resp.status_code >= 400:
            raise Exception(f"Request failed (HTTP {resp.status_code}).")
        return resp.json()
    raise Exception("Max retries exceeded.")


def _fetch_all_objects(config: dict, collection_id: str, root_url: str) -> list:
    objects = []
    params = {}
    while True:
        resp = _taxii_get(config, f"{root_url}/collections/{collection_id}/objects/", params=params or None)
        objects.extend(resp.get("objects", []))
        if resp.get("more"):
            params = {"next": resp["next"]}
        else:
            break
    return objects


def _discover_collection(config: dict, domain: str) -> tuple:
    """Returns (collection_id, root_url) for the given domain."""
    target_title = DOMAIN_TITLES[domain]
    base_url = config["base_url"]
    roots_resp = _taxii_get(config, f"{base_url}/taxii2/")
    api_roots = roots_resp.get("api_roots", [])
    if not api_roots:
        raise Exception("No API roots returned by TAXII server.")
    for raw_root in api_roots:
        root_url = urljoin(base_url + "/", raw_root.lstrip("/")).rstrip("/")
        try:
            colls_resp = _taxii_get(config, f"{root_url}/collections/")
        except LookupError:
            continue
        for coll in colls_resp.get("collections", []):
            if coll.get("title") == target_title:
                return coll["id"], root_url
    raise Exception(f"Collection not found for domain: {domain}")


def _load_domain(instance, config: dict, domain: str) -> list:
    if domain not in SUPPORTED_DOMAINS:
        raise Exception(f"Invalid domain: {domain}. Must be one of: {', '.join(SUPPORTED_DOMAINS)}")
    if domain not in instance._cache:
        collection_id, root_url = _discover_collection(config, domain)
        raw = _fetch_all_objects(config, collection_id, root_url)
        instance._cache[domain] = [
            obj for obj in raw
            if not obj.get("x_mitre_deprecated") and not obj.get("revoked")
        ]
    return instance._cache[domain]


def _extract_attack_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _extract_url(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def _to_technique_summary(obj: dict) -> dict:
    return {
        "technique_id": _extract_attack_id(obj),
        "name": obj.get("name", ""),
        "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
        "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
    }


def _to_technique_full(obj: dict) -> dict:
    result = {
        "id": obj.get("id", ""),
        "technique_id": _extract_attack_id(obj),
        "name": obj.get("name", ""),
        "description": obj.get("description", ""),
        "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
        "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
        "platforms": obj.get("x_mitre_platforms", []),
        "url": _extract_url(obj),
        "created": obj.get("created", ""),
        "modified": obj.get("modified", ""),
    }
    if "x_mitre_data_sources" in obj:
        result["data_sources"] = obj["x_mitre_data_sources"]
    if "x_mitre_detection" in obj:
        result["detection"] = obj["x_mitre_detection"]
    return result


def _find_technique(objects: list, technique_id: str) -> dict:
    technique_id = technique_id.strip().upper()
    for obj in objects:
        if obj.get("type") == "attack-pattern":
            if _extract_attack_id(obj).upper() == technique_id:
                return obj
    raise Exception(f"Technique not found: {technique_id}")


def _validate_domain(domain: str) -> str:
    domain = (domain or "enterprise-attack").strip().lower()
    if domain not in SUPPORTED_DOMAINS:
        raise Exception(f"Invalid domain: {domain}. Must be one of: {', '.join(SUPPORTED_DOMAINS)}")
    return domain


class MitreAttack:

    def __init__(self) -> None:
        self.logger = logging.getLogger()
        self._cache: dict = {}

    def test_connection(self, connectionParameters: dict):
        try:
            config = _get_config(connectionParameters)
            resp = _taxii_get(config, f"{config['base_url']}/taxii2/")
            api_roots = resp.get("api_roots")
            if not isinstance(api_roots, list) or not api_roots:
                raise Exception("Invalid TAXII discovery response: api_roots is missing or empty.")
            return {"status": "success", "message": "Connected to MITRE ATT&CK TAXII server successfully."}
        except Exception as e:
            self.logger.error("Error in test_connection", exc_info=e)
            raise Exception(str(e))

    def search_techniques(self, request: RequestBody) -> ResponseBody:
        try:
            config = _get_config(request.connectionParameters)
            params = request.parameters

            query = (params.get("query") or "").strip()
            if not query:
                raise Exception("query is required.")

            domain = _validate_domain(params.get("domain"))

            raw_limit = params.get("limit")
            if raw_limit is not None and str(raw_limit).strip():
                try:
                    limit = int(raw_limit)
                    if limit < 1:
                        raise ValueError()
                except (ValueError, TypeError):
                    raise Exception("limit must be a positive integer.")
            else:
                limit = 50

            objects = _load_domain(self, config, domain)
            q = query.lower()
            matches = []
            for obj in objects:
                if obj.get("type") != "attack-pattern":
                    continue
                tactics = [p["phase_name"].lower() for p in obj.get("kill_chain_phases", [])]
                if (
                    q in _extract_attack_id(obj).lower()
                    or q in obj.get("name", "").lower()
                    or q in obj.get("description", "").lower()
                    or any(q in t for t in tactics)
                ):
                    matches.append({
                        "id": obj.get("id", ""),
                        "technique_id": _extract_attack_id(obj),
                        "name": obj.get("name", ""),
                        "description": obj.get("description", ""),
                        "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
                        "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                        "platforms": obj.get("x_mitre_platforms", []),
                        "url": _extract_url(obj),
                    })
                    if len(matches) >= limit:
                        break

            result = {"status": "success", "domain": domain, "query": query, "count": len(matches), "techniques": matches}
            self.logger.info("search_techniques: domain=%s query=%s count=%d", domain, query, len(matches))
            return result
        except Exception as e:
            self.logger.error("Error in search_techniques", exc_info=e)
            raise Exception(str(e))

    def get_technique_details(self, request: RequestBody) -> ResponseBody:
        try:
            config = _get_config(request.connectionParameters)
            params = request.parameters

            technique_id = (params.get("technique_id") or "").strip()
            if not technique_id:
                raise Exception("technique_id is required.")

            domain = _validate_domain(params.get("domain"))
            objects = _load_domain(self, config, domain)
            obj = _find_technique(objects, technique_id)
            result = {"status": "success", "technique": _to_technique_full(obj)}
            self.logger.info("get_technique_details: technique_id=%s domain=%s", technique_id, domain)
            return result
        except Exception as e:
            self.logger.error("Error in get_technique_details", exc_info=e)
            raise Exception(str(e))

    def get_mitigations_for_technique(self, request: RequestBody) -> ResponseBody:
        try:
            config = _get_config(request.connectionParameters)
            params = request.parameters

            technique_id = (params.get("technique_id") or "").strip()
            if not technique_id:
                raise Exception("technique_id is required.")

            domain = _validate_domain(params.get("domain"))
            objects = _load_domain(self, config, domain)
            technique = _find_technique(objects, technique_id)
            technique_stix_id = technique["id"]

            by_id = {obj["id"]: obj for obj in objects}
            mitigations = []
            for obj in objects:
                if (
                    obj.get("type") == "relationship"
                    and obj.get("relationship_type") == "mitigates"
                    and obj.get("target_ref") == technique_stix_id
                ):
                    source = by_id.get(obj["source_ref"])
                    if source and source.get("type") == "course-of-action":
                        mitigations.append({
                            "id": source.get("id", ""),
                            "mitigation_id": _extract_attack_id(source),
                            "name": source.get("name", ""),
                            "description": source.get("description", ""),
                            "url": _extract_url(source),
                        })

            result = {"status": "success", "technique_id": technique_id.upper(), "count": len(mitigations), "mitigations": mitigations}
            self.logger.info("get_mitigations_for_technique: technique_id=%s count=%d", technique_id, len(mitigations))
            return result
        except Exception as e:
            self.logger.error("Error in get_mitigations_for_technique", exc_info=e)
            raise Exception(str(e))

    def get_groups_for_technique(self, request: RequestBody) -> ResponseBody:
        try:
            config = _get_config(request.connectionParameters)
            params = request.parameters

            technique_id = (params.get("technique_id") or "").strip()
            if not technique_id:
                raise Exception("technique_id is required.")

            domain = _validate_domain(params.get("domain"))
            objects = _load_domain(self, config, domain)
            technique = _find_technique(objects, technique_id)
            technique_stix_id = technique["id"]

            by_id = {obj["id"]: obj for obj in objects}
            groups = []
            for obj in objects:
                if (
                    obj.get("type") == "relationship"
                    and obj.get("relationship_type") == "uses"
                    and obj.get("target_ref") == technique_stix_id
                ):
                    source = by_id.get(obj["source_ref"])
                    if source and source.get("type") == "intrusion-set":
                        groups.append({
                            "id": source.get("id", ""),
                            "group_id": _extract_attack_id(source),
                            "name": source.get("name", ""),
                            "aliases": source.get("aliases", []),
                            "description": source.get("description", ""),
                            "url": _extract_url(source),
                        })

            result = {"status": "success", "technique_id": technique_id.upper(), "count": len(groups), "groups": groups}
            self.logger.info("get_groups_for_technique: technique_id=%s count=%d", technique_id, len(groups))
            return result
        except Exception as e:
            self.logger.error("Error in get_groups_for_technique", exc_info=e)
            raise Exception(str(e))

    def get_software_for_technique(self, request: RequestBody) -> ResponseBody:
        try:
            config = _get_config(request.connectionParameters)
            params = request.parameters

            technique_id = (params.get("technique_id") or "").strip()
            if not technique_id:
                raise Exception("technique_id is required.")

            domain = _validate_domain(params.get("domain"))
            objects = _load_domain(self, config, domain)
            technique = _find_technique(objects, technique_id)
            technique_stix_id = technique["id"]

            by_id = {obj["id"]: obj for obj in objects}
            software = []
            for obj in objects:
                if (
                    obj.get("type") == "relationship"
                    and obj.get("relationship_type") == "uses"
                    and obj.get("target_ref") == technique_stix_id
                ):
                    source = by_id.get(obj["source_ref"])
                    if source and source.get("type") in ("malware", "tool"):
                        software.append({
                            "id": source.get("id", ""),
                            "software_id": _extract_attack_id(source),
                            "name": source.get("name", ""),
                            "type": source.get("type", ""),
                            "description": source.get("description", ""),
                            "platforms": source.get("x_mitre_platforms", []),
                            "url": _extract_url(source),
                        })

            result = {"status": "success", "technique_id": technique_id.upper(), "count": len(software), "software": software}
            self.logger.info("get_software_for_technique: technique_id=%s count=%d", technique_id, len(software))
            return result
        except Exception as e:
            self.logger.error("Error in get_software_for_technique", exc_info=e)
            raise Exception(str(e))

    def get_group_details(self, request: RequestBody) -> ResponseBody:
        try:
            config = _get_config(request.connectionParameters)
            params = request.parameters

            group_id = (params.get("group_id") or "").strip().upper()
            if not group_id:
                raise Exception("group_id is required.")

            domain = _validate_domain(params.get("domain"))
            objects = _load_domain(self, config, domain)

            group_obj = None
            for obj in objects:
                if obj.get("type") == "intrusion-set" and _extract_attack_id(obj).upper() == group_id:
                    group_obj = obj
                    break
            if group_obj is None:
                raise Exception(f"Group not found: {group_id}")

            group_stix_id = group_obj["id"]
            by_id = {obj["id"]: obj for obj in objects}
            techniques_used = []
            for obj in objects:
                if (
                    obj.get("type") == "relationship"
                    and obj.get("relationship_type") == "uses"
                    and obj.get("source_ref") == group_stix_id
                ):
                    target = by_id.get(obj["target_ref"])
                    if target and target.get("type") == "attack-pattern":
                        techniques_used.append(_to_technique_summary(target))

            group_data = {
                "id": group_obj.get("id", ""),
                "group_id": _extract_attack_id(group_obj),
                "name": group_obj.get("name", ""),
                "aliases": group_obj.get("aliases", []),
                "description": group_obj.get("description", ""),
                "url": _extract_url(group_obj),
                "created": group_obj.get("created", ""),
                "modified": group_obj.get("modified", ""),
            }
            result = {
                "status": "success",
                "group": group_data,
                "techniques_used": techniques_used,
                "techniques_count": len(techniques_used),
            }
            self.logger.info("get_group_details: group_id=%s techniques_count=%d", group_id, len(techniques_used))
            return result
        except Exception as e:
            self.logger.error("Error in get_group_details", exc_info=e)
            raise Exception(str(e))

    def get_tactics_by_domain(self, request: RequestBody) -> ResponseBody:
        try:
            config = _get_config(request.connectionParameters)
            params = request.parameters

            domain = (params.get("domain") or "").strip().lower()
            if not domain:
                raise Exception("domain is required.")
            domain = _validate_domain(domain)

            objects = _load_domain(self, config, domain)

            technique_ids_by_tactic: dict = {}
            for obj in objects:
                if obj.get("type") == "attack-pattern":
                    tid = _extract_attack_id(obj)
                    for phase in obj.get("kill_chain_phases", []):
                        short = phase["phase_name"]
                        technique_ids_by_tactic.setdefault(short, []).append(tid)

            tactics = []
            for obj in objects:
                if obj.get("type") == "x-mitre-tactic":
                    short_name = obj.get("x_mitre_shortname", "")
                    tactics.append({
                        "id": obj.get("id", ""),
                        "tactic_id": _extract_attack_id(obj),
                        "name": obj.get("name", ""),
                        "short_name": short_name,
                        "description": obj.get("description", ""),
                        "url": _extract_url(obj),
                        "technique_ids": technique_ids_by_tactic.get(short_name, []),
                    })

            result = {"status": "success", "domain": domain, "count": len(tactics), "tactics": tactics}
            self.logger.info("get_tactics_by_domain: domain=%s count=%d", domain, len(tactics))
            return result
        except Exception as e:
            self.logger.error("Error in get_tactics_by_domain", exc_info=e)
            raise Exception(str(e))

    def refresh_dataset(self, request: RequestBody) -> ResponseBody:
        try:
            config = _get_config(request.connectionParameters)
            params = request.parameters

            raw_domain = (params.get("domain") or "").strip().lower()
            if raw_domain:
                if raw_domain not in SUPPORTED_DOMAINS:
                    raise Exception(f"Invalid domain: {raw_domain}. Must be one of: {', '.join(SUPPORTED_DOMAINS)}")
                domains_to_refresh = [raw_domain]
            else:
                domains_to_refresh = list(SUPPORTED_DOMAINS)

            object_counts = {}
            for domain in domains_to_refresh:
                self._cache.pop(domain, None)
                objects = _load_domain(self, config, domain)
                object_counts[domain] = len(objects)

            result = {
                "status": "success",
                "refreshed_domains": domains_to_refresh,
                "object_counts": object_counts,
            }
            self.logger.info("refresh_dataset: domains=%s counts=%s", domains_to_refresh, object_counts)
            return result
        except Exception as e:
            self.logger.error("Error in refresh_dataset", exc_info=e)
            raise Exception(str(e))
