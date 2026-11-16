import pytest
from unittest.mock import patch, MagicMock, call
from app.mitre_attack import (
    MitreAttack,
    _get_config,
    _taxii_get,
    _discover_collection,
    _fetch_all_objects,
    _load_domain,
    _find_technique,
    _extract_attack_id,
    _extract_url,
    _validate_domain,
    BASE_URL,
    SUPPORTED_DOMAINS,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _conn(**kwargs):
    return {"base_url": BASE_URL, **kwargs}


def _req(connection_params=None, parameters=None):
    body = MagicMock()
    body.connectionParameters = connection_params or _conn()
    body.parameters = parameters or {}
    return body


def _technique(tid, name, tactics=None, is_sub=False, deprecated=False, revoked=False):
    return {
        "id": f"attack-pattern--{tid}",
        "type": "attack-pattern",
        "name": name,
        "description": f"Description of {name}",
        "external_references": [{"source_name": "mitre-attack", "external_id": tid, "url": f"https://attack.mitre.org/techniques/{tid}"}],
        "kill_chain_phases": [{"phase_name": t} for t in (tactics or ["execution"])],
        "x_mitre_is_subtechnique": is_sub,
        "x_mitre_platforms": ["Windows"],
        "x_mitre_deprecated": deprecated,
        "revoked": revoked,
    }


def _relationship(rel_type, source_id, target_id):
    return {
        "id": f"relationship--{source_id}-{target_id}",
        "type": "relationship",
        "relationship_type": rel_type,
        "source_ref": source_id,
        "target_ref": target_id,
    }


def _mitigation(mid, name):
    return {
        "id": f"course-of-action--{mid}",
        "type": "course-of-action",
        "name": name,
        "description": f"Desc {name}",
        "external_references": [{"source_name": "mitre-attack", "external_id": mid, "url": f"https://attack.mitre.org/mitigations/{mid}"}],
    }


def _group(gid, name, aliases=None):
    return {
        "id": f"intrusion-set--{gid}",
        "type": "intrusion-set",
        "name": name,
        "aliases": aliases or [],
        "description": f"Desc {name}",
        "external_references": [{"source_name": "mitre-attack", "external_id": gid, "url": f"https://attack.mitre.org/groups/{gid}"}],
        "created": "2020-01-01T00:00:00Z",
        "modified": "2021-01-01T00:00:00Z",
    }


def _software(sid, name, stype="malware"):
    return {
        "id": f"{stype}--{sid}",
        "type": stype,
        "name": name,
        "description": f"Desc {name}",
        "external_references": [{"source_name": "mitre-attack", "external_id": sid, "url": f"https://attack.mitre.org/software/{sid}"}],
        "x_mitre_platforms": ["Windows"],
    }


def _tactic(taid, name, short):
    return {
        "id": f"x-mitre-tactic--{taid}",
        "type": "x-mitre-tactic",
        "name": name,
        "x_mitre_shortname": short,
        "description": f"Desc {name}",
        "external_references": [{"source_name": "mitre-attack", "external_id": taid, "url": f"https://attack.mitre.org/tactics/{taid}"}],
    }


# ---------------------------------------------------------------------------
# _get_config
# ---------------------------------------------------------------------------

class TestGetConfig:

    def test_defaults(self):
        cfg = _get_config({})
        assert cfg["base_url"] == BASE_URL
        assert cfg["timeout"] == 30
        assert cfg["verify"] is True
        assert cfg["proxies"] is None

    def test_custom_base_url_strips_slash(self):
        cfg = _get_config({"base_url": "https://custom.example.com/"})
        assert cfg["base_url"] == "https://custom.example.com"

    def test_invalid_timeout(self):
        with pytest.raises(Exception, match="timeout must be a positive integer"):
            _get_config({"timeout": "abc"})

    def test_zero_timeout(self):
        with pytest.raises(Exception, match="timeout must be a positive integer"):
            _get_config({"timeout": "0"})

    def test_verify_ssl_string_false(self):
        cfg = _get_config({"verify_ssl": "false"})
        assert cfg["verify"] is False

    def test_verify_ssl_string_true(self):
        cfg = _get_config({"verify_ssl": "true"})
        assert cfg["verify"] is True

    def test_verify_ssl_invalid_string_raises(self):
        with pytest.raises((Exception, ValueError), match="unrecognized value"):
            _get_config({"verify_ssl": "maybe"})

    def test_verify_ssl_invalid_type_raises(self):
        with pytest.raises((Exception, ValueError), match="boolean"):
            _get_config({"verify_ssl": 42})

    def test_proxy_set(self):
        cfg = _get_config({"proxy": "http://proxy:8080"})
        assert cfg["proxies"] == {"http": "http://proxy:8080", "https": "http://proxy:8080"}

    def test_user_agent_header(self):
        cfg = _get_config({})
        assert cfg["headers"]["User-Agent"] == "SecuronixSOAR-MitreAttack/1.0"

    def test_accept_header(self):
        cfg = _get_config({})
        assert "taxii" in cfg["headers"]["Accept"]


# ---------------------------------------------------------------------------
# _taxii_get
# ---------------------------------------------------------------------------

class TestTaxiiGet:

    def _cfg(self):
        return _get_config({})

    @patch("app.mitre_attack.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"title": "ok"})
        result = _taxii_get(self._cfg(), "https://example.com/taxii2/")
        assert result == {"title": "ok"}

    @patch("app.mitre_attack.requests.get")
    def test_429_raises_immediately(self, mock_get):
        mock_get.return_value = MagicMock(status_code=429)
        with pytest.raises(Exception, match="Rate limit exceeded"):
            _taxii_get(self._cfg(), "https://example.com/taxii2/")
        assert mock_get.call_count == 1

    @patch("app.mitre_attack.time.sleep")
    @patch("app.mitre_attack.requests.get")
    def test_5xx_retries_then_raises(self, mock_get, mock_sleep):
        mock_get.return_value = MagicMock(status_code=503)
        with pytest.raises(Exception, match="MITRE ATT&CK TAXII server error"):
            _taxii_get(self._cfg(), "https://example.com/taxii2/")
        assert mock_get.call_count == 3

    @patch("app.mitre_attack.time.sleep")
    @patch("app.mitre_attack.requests.get")
    def test_5xx_retry_then_success(self, mock_get, mock_sleep):
        mock_get.side_effect = [
            MagicMock(status_code=500),
            MagicMock(status_code=200, json=lambda: {"ok": True}),
        ]
        result = _taxii_get(self._cfg(), "https://example.com/taxii2/")
        assert result == {"ok": True}

    @patch("app.mitre_attack.requests.get")
    def test_401_raises(self, mock_get):
        mock_get.return_value = MagicMock(status_code=401)
        with pytest.raises(Exception, match="Authentication error"):
            _taxii_get(self._cfg(), "https://example.com/taxii2/")

    @patch("app.mitre_attack.requests.get")
    def test_404_raises_lookup_error(self, mock_get):
        mock_get.return_value = MagicMock(status_code=404)
        with pytest.raises(LookupError, match="Resource not found"):
            _taxii_get(self._cfg(), "https://example.com/taxii2/")

    @patch("app.mitre_attack.requests.get")
    def test_connection_error(self, mock_get):
        import requests as req_lib
        mock_get.side_effect = req_lib.exceptions.ConnectionError()
        with pytest.raises(Exception, match="Unable to connect"):
            _taxii_get(self._cfg(), "https://example.com/taxii2/")

    @patch("app.mitre_attack.requests.get")
    def test_timeout_error(self, mock_get):
        import requests as req_lib
        mock_get.side_effect = req_lib.exceptions.Timeout()
        with pytest.raises(Exception, match="timed out"):
            _taxii_get(self._cfg(), "https://example.com/taxii2/")


# ---------------------------------------------------------------------------
# _discover_collection
# ---------------------------------------------------------------------------

class TestDiscoverCollection:

    def _cfg(self):
        return _get_config({})

    @patch("app.mitre_attack._taxii_get")
    def test_finds_enterprise(self, mock_get):
        mock_get.side_effect = [
            {"api_roots": ["https://attack-taxii.mitre.org/api/v21/"]},
            {"collections": [
                {"id": "col-ent", "title": "Enterprise ATT&CK"},
                {"id": "col-mob", "title": "Mobile ATT&CK"},
            ]},
        ]
        cid, root = _discover_collection(self._cfg(), "enterprise-attack")
        assert cid == "col-ent"

    @patch("app.mitre_attack._taxii_get")
    def test_finds_ics(self, mock_get):
        mock_get.side_effect = [
            {"api_roots": ["https://attack-taxii.mitre.org/api/v21/"]},
            {"collections": [{"id": "col-ics", "title": "ICS ATT&CK"}]},
        ]
        cid, root = _discover_collection(self._cfg(), "ics-attack")
        assert cid == "col-ics"

    @patch("app.mitre_attack._taxii_get")
    def test_relative_root_resolved_against_base_url(self, mock_get):
        mock_get.side_effect = [
            {"api_roots": ["/api/v21/"]},
            {"collections": [{"id": "col-ent", "title": "Enterprise ATT&CK"}]},
        ]
        cid, root = _discover_collection(self._cfg(), "enterprise-attack")
        assert cid == "col-ent"
        second_url = mock_get.call_args_list[1][0][1]
        assert second_url.startswith("https://")

    @patch("app.mitre_attack._taxii_get")
    def test_404_on_root_skipped_other_roots_tried(self, mock_get):
        mock_get.side_effect = [
            {"api_roots": ["/api/v21/", "/api/v22/"]},
            LookupError("Resource not found"),
            {"collections": [{"id": "col-ent", "title": "Enterprise ATT&CK"}]},
        ]
        cid, root = _discover_collection(self._cfg(), "enterprise-attack")
        assert cid == "col-ent"

    @patch("app.mitre_attack._taxii_get")
    def test_rate_limit_propagates(self, mock_get):
        mock_get.side_effect = [
            {"api_roots": ["/api/v21/"]},
            Exception("Rate limit exceeded"),
        ]
        with pytest.raises(Exception, match="Rate limit exceeded"):
            _discover_collection(self._cfg(), "enterprise-attack")

    @patch("app.mitre_attack._taxii_get")
    def test_not_found_raises(self, mock_get):
        mock_get.side_effect = [
            {"api_roots": ["https://attack-taxii.mitre.org/api/v21/"]},
            {"collections": [{"id": "col-x", "title": "Something Else"}]},
        ]
        with pytest.raises(Exception, match="Collection not found for domain"):
            _discover_collection(self._cfg(), "mobile-attack")

    @patch("app.mitre_attack._taxii_get")
    def test_no_api_roots_raises(self, mock_get):
        mock_get.return_value = {"api_roots": []}
        with pytest.raises(Exception, match="No API roots"):
            _discover_collection(self._cfg(), "enterprise-attack")


# ---------------------------------------------------------------------------
# _fetch_all_objects
# ---------------------------------------------------------------------------

class TestFetchAllObjects:

    def _cfg(self):
        return _get_config({})

    @patch("app.mitre_attack._taxii_get")
    def test_single_page(self, mock_get):
        mock_get.return_value = {"objects": [{"id": "obj1"}, {"id": "obj2"}], "more": False}
        result = _fetch_all_objects(self._cfg(), "col-1", "https://root")
        assert len(result) == 2
        assert mock_get.call_count == 1

    @patch("app.mitre_attack._taxii_get")
    def test_multi_page(self, mock_get):
        mock_get.side_effect = [
            {"objects": [{"id": "obj1"}], "more": True, "next": "token-abc"},
            {"objects": [{"id": "obj2"}, {"id": "obj3"}], "more": False},
        ]
        result = _fetch_all_objects(self._cfg(), "col-1", "https://root")
        assert len(result) == 3
        assert mock_get.call_count == 2
        second_call_params = mock_get.call_args_list[1][1].get("params") or mock_get.call_args_list[1][0][2]
        assert second_call_params == {"next": "token-abc"}

    @patch("app.mitre_attack._taxii_get")
    def test_three_pages_accumulated(self, mock_get):
        mock_get.side_effect = [
            {"objects": [{"id": "a"}], "more": True, "next": "t1"},
            {"objects": [{"id": "b"}], "more": True, "next": "t2"},
            {"objects": [{"id": "c"}], "more": False},
        ]
        result = _fetch_all_objects(self._cfg(), "col-1", "https://root")
        assert [o["id"] for o in result] == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# _load_domain
# ---------------------------------------------------------------------------

class TestLoadDomain:

    def _cfg(self):
        return _get_config({})

    @patch("app.mitre_attack._fetch_all_objects")
    @patch("app.mitre_attack._discover_collection")
    def test_cache_miss_fetches(self, mock_disc, mock_fetch):
        mock_disc.return_value = ("col-1", "https://root")
        mock_fetch.return_value = [_technique("T1059", "Command Scripting")]
        inst = MitreAttack()
        result = _load_domain(inst, self._cfg(), "enterprise-attack")
        assert len(result) == 1
        mock_fetch.assert_called_once()

    @patch("app.mitre_attack._fetch_all_objects")
    @patch("app.mitre_attack._discover_collection")
    def test_cache_hit_no_fetch(self, mock_disc, mock_fetch):
        inst = MitreAttack()
        inst._cache["enterprise-attack"] = [_technique("T1059", "Command Scripting")]
        result = _load_domain(inst, self._cfg(), "enterprise-attack")
        mock_fetch.assert_not_called()
        assert len(result) == 1

    @patch("app.mitre_attack._fetch_all_objects")
    @patch("app.mitre_attack._discover_collection")
    def test_deprecated_filtered(self, mock_disc, mock_fetch):
        mock_disc.return_value = ("col-1", "https://root")
        mock_fetch.return_value = [
            _technique("T1059", "Good"),
            _technique("T1060", "Deprecated", deprecated=True),
            _technique("T1061", "Revoked", revoked=True),
        ]
        inst = MitreAttack()
        result = _load_domain(inst, self._cfg(), "enterprise-attack")
        assert len(result) == 1
        assert result[0]["name"] == "Good"

    def test_invalid_domain_raises(self):
        inst = MitreAttack()
        with pytest.raises(Exception, match="Invalid domain"):
            _load_domain(inst, self._cfg(), "bad-domain")


# ---------------------------------------------------------------------------
# test_connection
# ---------------------------------------------------------------------------

class TestTestConnection:

    @patch("app.mitre_attack._taxii_get")
    def test_success(self, mock_get):
        mock_get.return_value = {"title": "MITRE ATT&CK", "api_roots": ["https://root/"]}
        ma = MitreAttack()
        result = ma.test_connection(_conn())
        assert result["status"] == "success"

    @patch("app.mitre_attack._taxii_get")
    def test_missing_api_roots_raises(self, mock_get):
        mock_get.return_value = {"title": "MITRE ATT&CK"}
        ma = MitreAttack()
        with pytest.raises(Exception, match="api_roots is missing or empty"):
            ma.test_connection(_conn())

    @patch("app.mitre_attack._taxii_get")
    def test_empty_api_roots_raises(self, mock_get):
        mock_get.return_value = {"title": "MITRE ATT&CK", "api_roots": []}
        ma = MitreAttack()
        with pytest.raises(Exception, match="api_roots is missing or empty"):
            ma.test_connection(_conn())

    @patch("app.mitre_attack._taxii_get")
    def test_connectivity_failure(self, mock_get):
        mock_get.side_effect = Exception("Unable to connect")
        ma = MitreAttack()
        with pytest.raises(Exception, match="Unable to connect"):
            ma.test_connection(_conn())


# ---------------------------------------------------------------------------
# search_techniques
# ---------------------------------------------------------------------------

class TestSearchTechniques:

    def _objects(self):
        return [
            _technique("T1059", "Command and Scripting Interpreter", tactics=["execution"]),
            _technique("T1059.001", "PowerShell", tactics=["execution"], is_sub=True),
            _technique("T1078", "Valid Accounts", tactics=["persistence", "privilege-escalation"]),
        ]

    @patch("app.mitre_attack._load_domain")
    def test_match_by_id(self, mock_load):
        mock_load.return_value = self._objects()
        ma = MitreAttack()
        result = ma.search_techniques(_req(parameters={"query": "T1059"}))
        assert result["status"] == "success"
        ids = [t["technique_id"] for t in result["techniques"]]
        assert "T1059" in ids
        assert "T1059.001" in ids

    @patch("app.mitre_attack._load_domain")
    def test_match_by_name(self, mock_load):
        mock_load.return_value = self._objects()
        ma = MitreAttack()
        result = ma.search_techniques(_req(parameters={"query": "powershell"}))
        assert any(t["technique_id"] == "T1059.001" for t in result["techniques"])

    @patch("app.mitre_attack._load_domain")
    def test_match_by_tactic(self, mock_load):
        mock_load.return_value = self._objects()
        ma = MitreAttack()
        result = ma.search_techniques(_req(parameters={"query": "privilege-escalation"}))
        assert any(t["technique_id"] == "T1078" for t in result["techniques"])

    @patch("app.mitre_attack._load_domain")
    def test_limit_applied(self, mock_load):
        mock_load.return_value = self._objects()
        ma = MitreAttack()
        result = ma.search_techniques(_req(parameters={"query": "e", "limit": "1"}))
        assert len(result["techniques"]) <= 1

    @patch("app.mitre_attack._load_domain")
    def test_no_match_returns_empty(self, mock_load):
        mock_load.return_value = self._objects()
        ma = MitreAttack()
        result = ma.search_techniques(_req(parameters={"query": "zzznomatch"}))
        assert result["count"] == 0
        assert result["techniques"] == []

    def test_missing_query_raises(self):
        ma = MitreAttack()
        with pytest.raises(Exception, match="query is required"):
            ma.search_techniques(_req(parameters={}))

    def test_invalid_limit_raises(self):
        ma = MitreAttack()
        with pytest.raises(Exception, match="limit must be a positive integer"):
            ma.search_techniques(_req(parameters={"query": "T1059", "limit": "0"}))

    def test_invalid_domain_raises(self):
        ma = MitreAttack()
        with pytest.raises(Exception, match="Invalid domain"):
            ma.search_techniques(_req(parameters={"query": "T1059", "domain": "bad"}))


# ---------------------------------------------------------------------------
# get_technique_details
# ---------------------------------------------------------------------------

class TestGetTechniqueDetails:

    @patch("app.mitre_attack._load_domain")
    def test_found(self, mock_load):
        obj = _technique("T1059", "Command and Scripting Interpreter")
        obj["x_mitre_detection"] = "Monitor process execution"
        mock_load.return_value = [obj]
        ma = MitreAttack()
        result = ma.get_technique_details(_req(parameters={"technique_id": "T1059"}))
        assert result["status"] == "success"
        assert result["technique"]["technique_id"] == "T1059"
        assert result["technique"]["detection"] == "Monitor process execution"

    @patch("app.mitre_attack._load_domain")
    def test_legacy_fields_absent_when_not_present(self, mock_load):
        mock_load.return_value = [_technique("T1059", "Command and Scripting Interpreter")]
        ma = MitreAttack()
        result = ma.get_technique_details(_req(parameters={"technique_id": "T1059"}))
        assert "detection" not in result["technique"]
        assert "data_sources" not in result["technique"]

    @patch("app.mitre_attack._load_domain")
    def test_not_found_raises(self, mock_load):
        mock_load.return_value = [_technique("T1059", "Command and Scripting Interpreter")]
        ma = MitreAttack()
        with pytest.raises(Exception, match="Technique not found"):
            ma.get_technique_details(_req(parameters={"technique_id": "T9999"}))

    def test_missing_technique_id_raises(self):
        ma = MitreAttack()
        with pytest.raises(Exception, match="technique_id is required"):
            ma.get_technique_details(_req(parameters={}))


# ---------------------------------------------------------------------------
# get_mitigations_for_technique
# ---------------------------------------------------------------------------

class TestGetMitigationsForTechnique:

    @patch("app.mitre_attack._load_domain")
    def test_with_mitigations(self, mock_load):
        t = _technique("T1059", "Command Scripting")
        m = _mitigation("M1038", "Execution Prevention")
        rel = _relationship("mitigates", m["id"], t["id"])
        mock_load.return_value = [t, m, rel]
        ma = MitreAttack()
        result = ma.get_mitigations_for_technique(_req(parameters={"technique_id": "T1059"}))
        assert result["status"] == "success"
        assert result["count"] == 1
        assert result["mitigations"][0]["mitigation_id"] == "M1038"

    @patch("app.mitre_attack._load_domain")
    def test_empty_list_when_no_mitigations(self, mock_load):
        mock_load.return_value = [_technique("T1059", "Command Scripting")]
        ma = MitreAttack()
        result = ma.get_mitigations_for_technique(_req(parameters={"technique_id": "T1059"}))
        assert result["mitigations"] == []

    @patch("app.mitre_attack._load_domain")
    def test_technique_not_found_raises(self, mock_load):
        mock_load.return_value = [_technique("T1059", "Command Scripting")]
        ma = MitreAttack()
        with pytest.raises(Exception, match="Technique not found"):
            ma.get_mitigations_for_technique(_req(parameters={"technique_id": "T9999"}))


# ---------------------------------------------------------------------------
# get_groups_for_technique
# ---------------------------------------------------------------------------

class TestGetGroupsForTechnique:

    @patch("app.mitre_attack._load_domain")
    def test_with_groups(self, mock_load):
        t = _technique("T1059", "Command Scripting")
        g = _group("G0016", "APT29", aliases=["Cozy Bear"])
        rel = _relationship("uses", g["id"], t["id"])
        mock_load.return_value = [t, g, rel]
        ma = MitreAttack()
        result = ma.get_groups_for_technique(_req(parameters={"technique_id": "T1059"}))
        assert result["count"] == 1
        assert result["groups"][0]["group_id"] == "G0016"
        assert result["groups"][0]["aliases"] == ["Cozy Bear"]

    @patch("app.mitre_attack._load_domain")
    def test_empty_when_no_groups(self, mock_load):
        mock_load.return_value = [_technique("T1059", "Command Scripting")]
        ma = MitreAttack()
        result = ma.get_groups_for_technique(_req(parameters={"technique_id": "T1059"}))
        assert result["groups"] == []

    @patch("app.mitre_attack._load_domain")
    def test_technique_not_found_raises(self, mock_load):
        mock_load.return_value = []
        ma = MitreAttack()
        with pytest.raises(Exception, match="Technique not found"):
            ma.get_groups_for_technique(_req(parameters={"technique_id": "T9999"}))


# ---------------------------------------------------------------------------
# get_software_for_technique
# ---------------------------------------------------------------------------

class TestGetSoftwareForTechnique:

    @patch("app.mitre_attack._load_domain")
    def test_malware_and_tool(self, mock_load):
        t = _technique("T1059", "Command Scripting")
        mal = _software("S0002", "Mimikatz", stype="malware")
        tool = _software("S0099", "NetCat", stype="tool")
        rel1 = _relationship("uses", mal["id"], t["id"])
        rel2 = _relationship("uses", tool["id"], t["id"])
        mock_load.return_value = [t, mal, tool, rel1, rel2]
        ma = MitreAttack()
        result = ma.get_software_for_technique(_req(parameters={"technique_id": "T1059"}))
        assert result["count"] == 2
        types = {s["type"] for s in result["software"]}
        assert types == {"malware", "tool"}

    @patch("app.mitre_attack._load_domain")
    def test_empty_when_no_software(self, mock_load):
        mock_load.return_value = [_technique("T1059", "Command Scripting")]
        ma = MitreAttack()
        result = ma.get_software_for_technique(_req(parameters={"technique_id": "T1059"}))
        assert result["software"] == []

    @patch("app.mitre_attack._load_domain")
    def test_technique_not_found_raises(self, mock_load):
        mock_load.return_value = []
        ma = MitreAttack()
        with pytest.raises(Exception, match="Technique not found"):
            ma.get_software_for_technique(_req(parameters={"technique_id": "T9999"}))


# ---------------------------------------------------------------------------
# get_group_details
# ---------------------------------------------------------------------------

class TestGetGroupDetails:

    @patch("app.mitre_attack._load_domain")
    def test_found_with_techniques(self, mock_load):
        g = _group("G0016", "APT29")
        t = _technique("T1059", "Command Scripting")
        rel = _relationship("uses", g["id"], t["id"])
        mock_load.return_value = [g, t, rel]
        ma = MitreAttack()
        result = ma.get_group_details(_req(parameters={"group_id": "G0016"}))
        assert result["status"] == "success"
        assert result["group"]["group_id"] == "G0016"
        assert result["techniques_count"] == 1
        assert result["techniques_used"][0]["technique_id"] == "T1059"

    @patch("app.mitre_attack._load_domain")
    def test_group_not_found_raises(self, mock_load):
        mock_load.return_value = [_group("G0016", "APT29")]
        ma = MitreAttack()
        with pytest.raises(Exception, match="Group not found"):
            ma.get_group_details(_req(parameters={"group_id": "G9999"}))

    def test_missing_group_id_raises(self):
        ma = MitreAttack()
        with pytest.raises(Exception, match="group_id is required"):
            ma.get_group_details(_req(parameters={}))


# ---------------------------------------------------------------------------
# get_tactics_by_domain
# ---------------------------------------------------------------------------

class TestGetTacticsByDomain:

    @patch("app.mitre_attack._load_domain")
    def test_returns_tactics_with_technique_ids(self, mock_load):
        tac = _tactic("TA0002", "Execution", "execution")
        t1 = _technique("T1059", "Command Scripting", tactics=["execution"])
        t2 = _technique("T1059.001", "PowerShell", tactics=["execution"], is_sub=True)
        mock_load.return_value = [tac, t1, t2]
        ma = MitreAttack()
        result = ma.get_tactics_by_domain(_req(parameters={"domain": "enterprise-attack"}))
        assert result["status"] == "success"
        assert result["count"] == 1
        tactic = result["tactics"][0]
        assert tactic["tactic_id"] == "TA0002"
        assert "T1059" in tactic["technique_ids"]
        assert "T1059.001" in tactic["technique_ids"]

    def test_missing_domain_raises(self):
        ma = MitreAttack()
        with pytest.raises(Exception, match="domain is required"):
            ma.get_tactics_by_domain(_req(parameters={}))

    def test_invalid_domain_raises(self):
        ma = MitreAttack()
        with pytest.raises(Exception, match="Invalid domain"):
            ma.get_tactics_by_domain(_req(parameters={"domain": "bad-domain"}))


# ---------------------------------------------------------------------------
# refresh_dataset
# ---------------------------------------------------------------------------

class TestRefreshDataset:

    @patch("app.mitre_attack._load_domain")
    def test_specific_domain(self, mock_load):
        mock_load.return_value = [_technique("T1059", "Command Scripting")] * 5
        ma = MitreAttack()
        ma._cache["enterprise-attack"] = ["stale"]
        result = ma.refresh_dataset(_req(parameters={"domain": "enterprise-attack"}))
        assert result["status"] == "success"
        assert result["refreshed_domains"] == ["enterprise-attack"]
        assert result["object_counts"]["enterprise-attack"] == 5

    @patch("app.mitre_attack._load_domain")
    def test_all_domains_when_omitted(self, mock_load):
        mock_load.return_value = [_technique("T1059", "Command Scripting")] * 3
        ma = MitreAttack()
        result = ma.refresh_dataset(_req(parameters={}))
        assert set(result["refreshed_domains"]) == set(SUPPORTED_DOMAINS)
        assert len(result["object_counts"]) == 3

    @patch("app.mitre_attack._load_domain")
    def test_clears_cache_before_reload(self, mock_load):
        mock_load.return_value = [_technique("T1059", "Fresh")]
        ma = MitreAttack()
        ma._cache["enterprise-attack"] = [{"stale": True}]
        ma.refresh_dataset(_req(parameters={"domain": "enterprise-attack"}))
        assert "enterprise-attack" not in ma._cache or ma._cache["enterprise-attack"][0].get("stale") is None

    def test_invalid_domain_raises(self):
        ma = MitreAttack()
        with pytest.raises(Exception, match="Invalid domain"):
            ma.refresh_dataset(_req(parameters={"domain": "bad-domain"}))
