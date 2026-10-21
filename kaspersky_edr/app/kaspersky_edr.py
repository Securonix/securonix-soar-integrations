from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import base64
import datetime
import json
import logging
import requests


DEFAULT_PORT = "13299"
DEFAULT_TIMEOUT = 30
DEFAULT_INCIDENT_AREA = "Securonix SOAR"
DEFAULT_INCIDENT_SEVERITY = 2

# ScanObjectType enum for the onDemandScan task (from Kaspersky docs).
SCAN_OBJECT_TYPES = {
    "SystemMemory": 14,
    "StartupObjectsAndRunningProcesses": 15,
    "DiskBootSectors": 16,
    "SystemBackupStorage": 17,
    "Email": 18,
    "Folder": 22,
    "AllRemovableDrives": 23,
    "AllNetworkDrives": 24,
    "AllFixedDrives": 25,
}


# ----------------------------------------------------------------------
# Connection-parameter helpers
# ----------------------------------------------------------------------
def _require_conn(connection_params: dict, name: str) -> str:
    value = connection_params.get(name)
    if not value or (isinstance(value, str) and not value.strip()):
        raise Exception(f"Missing required connection parameter: {name}")
    return value.strip() if isinstance(value, str) else value


def _get_port(connection_params: dict) -> str:
    port = connection_params.get("ksc_port")
    if not port or str(port).strip() in ("", "None", "null"):
        return DEFAULT_PORT
    return str(port).strip()


def _get_verify_ssl(connection_params: dict):
    v = connection_params.get("verify_ssl", True)
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes")
    return bool(v)


def _get_timeout(connection_params: dict) -> int:
    t = connection_params.get("timeout", "")
    if not t or str(t) in ("None", "null"):
        return DEFAULT_TIMEOUT
    try:
        n = int(t)
    except (ValueError, TypeError):
        raise Exception(f"timeout must be a positive integer (seconds), got: {t!r}")
    if n <= 0:
        raise Exception(f"timeout must be a positive integer (seconds), got: {n}")
    return n


def _param(parameters: dict, name: str):
    """Required action parameter (raises if missing)."""
    value = parameters.get(name)
    if value is None or (isinstance(value, str) and not value.strip()):
        raise Exception(f"Missing required parameter: {name}")
    return value.strip() if isinstance(value, str) else value


def _to_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes")


def _now_iso() -> str:
    """UTC time in the ISO 8601 form KSC expects (e.g. 2016-09-19T15:22:35Z)."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class KasperskyEdr:
    """
    Kaspersky EDR (Threat Response) SOAR connector.

    Response actions are delivered through the Kaspersky Security Center (KSC)
    Open API method HostGroup.AddIncident. Each action builds a JSON "task" and
    submits it as the incident body (KLINCDT_BODY); Kaspersky Endpoint Security
    then executes the response on the target host.

    Transport: direct HTTPS/JSON to the KSC Open API (no KlAkOAPI dependency).
    Auth: two-step session — Session.StartSession (KSCBasic) returns a session id
    used on subsequent calls.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    # ------------------------------------------------------------------
    # Low-level KSC Open API plumbing
    # ------------------------------------------------------------------
    def _base_url(self, connection_params: dict) -> str:
        host = _require_conn(connection_params, "ksc_host")
        port = _get_port(connection_params)
        return f"https://{host}:{port}/api/v1.0"

    def _connect(self, connection_params: dict):
        """
        Authenticate the connection and return an authenticated requests.Session.

        Matches the KSC Open API / KlAkOAPI model: the client authenticates the
        connection by calling the `login` method with a KSCBasic Authorization
        header (user/pass base64-encoded), then reuses the same session for all
        subsequent method calls. There is no per-request session-id header.
        """
        user = _require_conn(connection_params, "ksc_user")
        password = _require_conn(connection_params, "ksc_password")
        verify = _get_verify_ssl(connection_params)
        timeout = _get_timeout(connection_params)

        user_b64 = base64.b64encode(user.encode()).decode()
        pass_b64 = base64.b64encode(password.encode()).decode()
        auth_header = (
            f'KSCBasic user="{user_b64}", pass="{pass_b64}", domain="", internal="0"'
        )

        session = requests.Session()
        session.verify = verify
        # Keep a single pooled connection for the authenticated session.
        adapter = requests.adapters.HTTPAdapter(pool_connections=1, pool_maxsize=1)
        session.mount("https://", adapter)

        url = f"{self._base_url(connection_params)}/login"
        headers = {"Authorization": auth_header, "Content-Type": "application/json"}
        try:
            resp = session.post(url, headers=headers, data="{}", timeout=timeout)
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Kaspersky Security Center. Please verify ksc_host/ksc_port and connectivity.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Kaspersky Security Center timed out.")

        if resp.status_code == 401:
            raise Exception("Authentication failed. Please verify ksc_user and ksc_password.")
        if resp.status_code != 200:
            raise Exception(f"Kaspersky Security Center authentication failed: HTTP {resp.status_code}")

        data = resp.json() if resp.content else {}
        if isinstance(data, dict) and "PxgError" in data:
            err = data["PxgError"]
            raise Exception(f"KSC authentication error {err.get('code')}: {err.get('message')}")
        return session

    def _call_on(self, connection_params: dict, session, method: str, payload: dict) -> dict:
        """Call a KSC Open API method on an already-authenticated session."""
        timeout = _get_timeout(connection_params)
        headers = {"Content-Type": "application/json"}
        url = f"{self._base_url(connection_params)}/{method}"
        try:
            resp = session.post(url, headers=headers, data=json.dumps(payload), timeout=timeout)
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Kaspersky Security Center. Please verify ksc_host/ksc_port and connectivity.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Kaspersky Security Center timed out.")

        if resp.status_code != 200:
            raise Exception(f"Kaspersky Security Center returned HTTP {resp.status_code} for {method}.")

        data = resp.json() if resp.content else {}
        # KSC returns errors inside an HTTP 200 as PxgError.
        if isinstance(data, dict) and "PxgError" in data:
            err = data["PxgError"]
            raise Exception(f"KSC error {err.get('code')} ({err.get('module')}): {err.get('message')}")
        return data

    def _add_incident(self, connection_params: dict, parameters: dict,
                      task: str, task_params: dict) -> dict:
        """
        Build the EDR task body and submit it via HostGroup.AddIncident.
        `targetHost` (required) and `responseEventIncidentArea` (optional) come
        from the action parameters.
        """
        target_host = _param(parameters, "target_host")
        area = parameters.get("response_event_incident_area") or DEFAULT_INCIDENT_AREA
        severity = parameters.get("severity")
        try:
            severity = int(severity) if severity not in (None, "") else DEFAULT_INCIDENT_SEVERITY
        except (ValueError, TypeError):
            raise Exception(f"severity must be an integer, got: {severity!r}")

        body = {
            "task": task,
            "targetHost": target_host,
            "params": task_params,
            "responseEventIncident": True,
            "responseEventIncidentArea": area,
        }
        add_payload = {
            "pData": {
                "KLINCDT_SEVERITY": severity,
                "KLINCDT_ADDED": {"type": "datetime", "value": _now_iso()},
                "KLINCDT_BODY": json.dumps(body),
                "KLHST_WKS_HOSTNAME": target_host,
            }
        }
        # Per Kaspersky's documented flow, AddIncident is followed by UpdateIncident
        # setting KLINCDT_IS_HANDLED=False for the same host. Both calls reuse the
        # same authenticated session.
        session = self._connect(connection_params)
        add_resp = self._call_on(connection_params, session, "HostGroup.AddIncident", add_payload)
        incident_id = add_resp.get("PxgRetVal")
        self.logger.debug("Kaspersky AddIncident (%s) response: %s", task, add_resp)

        update_payload = {
            "nId": incident_id,
            "pData": {
                "KLINCDT_IS_HANDLED": False,
                "KLHST_WKS_HOSTNAME": target_host,
            },
        }
        self._call_on(connection_params, session, "HostGroup.UpdateIncident", update_payload)
        return {"status": "success", "results": {"incident_id": incident_id, "task": task}}

    # ------------------------------------------------------------------
    # Test Connection
    # ------------------------------------------------------------------
    def test_connection(self, connectionParameters: dict):
        try:
            self._connect(connectionParameters)
            return {"status": "success", "message": "Connected to Kaspersky Security Center successfully."}
        except Exception as e:
            self.logger.error("Exception while testing Kaspersky EDR connection", exc_info=e)
            raise Exception(str(e))

    # ------------------------------------------------------------------
    # EDR response actions
    # ------------------------------------------------------------------
    def isolate_host(self, request: RequestBody) -> ResponseBody:
        """
        Isolate (or de-isolate) a host from the network.
        Required: target_host, action (0 = turn off isolation, 1 = turn on).
        """
        p = request.parameters
        try:
            action = int(_param(p, "action"))
        except (ValueError, TypeError):
            raise Exception("action must be an integer: 0 (off) or 1 (on).")
        if action not in (0, 1):
            raise Exception("action must be 0 (turn off isolation) or 1 (turn on isolation).")
        try:
            return self._add_incident(request.connectionParameters, p, "isolateHost", {"action": action})
        except Exception as e:
            self.logger.error("Exception in isolate_host", exc_info=e)
            raise Exception(str(e))

    def prevent_execution(self, request: RequestBody) -> ResponseBody:
        """
        Prevent a file from running on a host.
        Required: target_host, hash (MD5), path. Optional: case_sensitive (bool).
        """
        p = request.parameters
        try:
            task_params = {
                "hash": _param(p, "hash"),
                "path": _param(p, "path"),
                "caseSensitive": _to_bool(p.get("case_sensitive", False)),
            }
            return self._add_incident(request.connectionParameters, p, "preventExecution", task_params)
        except Exception as e:
            self.logger.error("Exception in prevent_execution", exc_info=e)
            raise Exception(str(e))

    def quarantine_file(self, request: RequestBody) -> ResponseBody:
        """
        Move a file to Quarantine on a host.
        Required: target_host, path. Optional: md5hash, sha256hash.
        """
        p = request.parameters
        try:
            task_params = {
                "md5hash": p.get("md5hash", ""),
                "sha256hash": p.get("sha256hash", ""),
                "path": _param(p, "path"),
            }
            return self._add_incident(request.connectionParameters, p, "quarantineFile", task_params)
        except Exception as e:
            self.logger.error("Exception in quarantine_file", exc_info=e)
            raise Exception(str(e))

    def delete_file(self, request: RequestBody) -> ResponseBody:
        """
        Delete a file on a host.
        Required: target_host, path. Optional: md5hash, sha256hash, search_in_subfolders (bool).
        """
        p = request.parameters
        try:
            task_params = {
                "md5hash": p.get("md5hash", ""),
                "sha256hash": p.get("sha256hash", ""),
                "path": _param(p, "path"),
            }
            if p.get("search_in_subfolders") is not None and str(p.get("search_in_subfolders")) != "":
                task_params["searchInSubfolders"] = _to_bool(p["search_in_subfolders"])
            return self._add_incident(request.connectionParameters, p, "deleteFile", task_params)
        except Exception as e:
            self.logger.error("Exception in delete_file", exc_info=e)
            raise Exception(str(e))

    def get_file(self, request: RequestBody) -> ResponseBody:
        """
        Retrieve a file from a host.
        Required: target_host, path. Optional: md5hash, sha256hash.
        """
        p = request.parameters
        try:
            task_params = {
                "md5hash": p.get("md5hash", ""),
                "sha256hash": p.get("sha256hash", ""),
                "path": _param(p, "path"),
            }
            return self._add_incident(request.connectionParameters, p, "getFile", task_params)
        except Exception as e:
            self.logger.error("Exception in get_file", exc_info=e)
            raise Exception(str(e))

    def terminate_process(self, request: RequestBody) -> ResponseBody:
        """
        Terminate the process of a file on a host.
        Required: target_host, path. Optional: md5hash, sha256hash, case_sensitive (bool).
        """
        p = request.parameters
        try:
            task_params = {
                "md5hash": p.get("md5hash", ""),
                "sha256hash": p.get("sha256hash", ""),
                "path": _param(p, "path"),
                "caseSensitive": _to_bool(p.get("case_sensitive", False)),
            }
            return self._add_incident(request.connectionParameters, p, "terminateProcess", task_params)
        except Exception as e:
            self.logger.error("Exception in terminate_process", exc_info=e)
            raise Exception(str(e))

    def start_process(self, request: RequestBody) -> ResponseBody:
        """
        Start a process on a host.
        Required: target_host, executable_path. Optional: arguments, working_folder.
        """
        p = request.parameters
        try:
            task_params = {"executablePath": _param(p, "executable_path")}
            if p.get("arguments"):
                task_params["arguments"] = p["arguments"]
            if p.get("working_folder"):
                task_params["workingFolder"] = p["working_folder"]
            return self._add_incident(request.connectionParameters, p, "startProcess", task_params)
        except Exception as e:
            self.logger.error("Exception in start_process", exc_info=e)
            raise Exception(str(e))

    def ioc_scan(self, request: RequestBody) -> ResponseBody:
        """
        Run an IOC scan on a host.
        Required: target_host, ioc (base64 zip of IOC files).
        Optional: isolate_host, scan_critical_areas, quarantine_object (bools).
        """
        p = request.parameters
        try:
            task_params = {
                "ioc": _param(p, "ioc"),
                "isolateHost": _to_bool(p.get("isolate_host", False)),
                "scanCriticalAreas": _to_bool(p.get("scan_critical_areas", False)),
                "quarantineObject": _to_bool(p.get("quarantine_object", False)),
            }
            return self._add_incident(request.connectionParameters, p, "iocScan", task_params)
        except Exception as e:
            self.logger.error("Exception in ioc_scan", exc_info=e)
            raise Exception(str(e))

    def on_demand_scan(self, request: RequestBody) -> ResponseBody:
        """
        Run a Malware (on-demand) scan on a host.
        Required: target_host, path (space-delimited files/folders), scan_type
            (one of the ScanObjectType names or its integer id).
        Optional: recursive (bool).
        """
        p = request.parameters
        try:
            path = _param(p, "path")
            scan_type_raw = _param(p, "scan_type")
            # Accept either the enum name or the integer id.
            if str(scan_type_raw).isdigit():
                scan_type = int(scan_type_raw)
            elif scan_type_raw in SCAN_OBJECT_TYPES:
                scan_type = SCAN_OBJECT_TYPES[scan_type_raw]
            else:
                raise Exception(
                    f"scan_type must be an integer or one of {sorted(SCAN_OBJECT_TYPES)}, got: {scan_type_raw!r}"
                )
            recursive = _to_bool(p.get("recursive", False))
            # onDemandScan params is an array of scan-object descriptors.
            task_params = [{
                "enabled": True,
                "path": path,
                "recursive": recursive,
                "type": scan_type,
            }]
            return self._add_incident(request.connectionParameters, p, "onDemandScan", task_params)
        except Exception as e:
            self.logger.error("Exception in on_demand_scan", exc_info=e)
            raise Exception(str(e))
