from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import time
import base64
import re
import requests


AUTH_HEADER_NAME = "Authorization"
AUTH_HEADER_PREFIX = ""

BASE_URL_DEFAULT = "https://api.any.run/v1"
ENDPOINT_ENVIRONMENT = "/environment"
ENDPOINT_SUBMIT_FILE = "/analysis/file"
ENDPOINT_SUBMIT_URL = "/analysis/url"
ENDPOINT_TASK_STATUS = "/analysis/{task_id}"
ENDPOINT_TASK_REPORT = "/analysis/{task_id}/report"
ENDPOINT_TASK_IOCS = "/analysis/{task_id}/iocs"
ENDPOINT_TASK_ARTIFACT = "/analysis/{task_id}/artifact/{artifact_type}"

DEFAULT_TIMEOUT = 60
MAX_RETRIES = 3
BACKOFF_FACTOR = 2

VALID_OS_TYPES = ("windows7", "windows10", "windows11")
VALID_ARTIFACT_TYPES = ("pcap", "screenshot", "dropped_file")
URL_PATTERN = re.compile(r"^https?://.+", re.IGNORECASE)


def _get_connection(connection_params: dict):
    api_key = connection_params.get("api_key")
    if not api_key:
        raise Exception("api_key is required.")

    base_url = connection_params.get("base_url", BASE_URL_DEFAULT) or BASE_URL_DEFAULT
    base_url = base_url.rstrip("/")

    timeout = DEFAULT_TIMEOUT
    try:
        t = connection_params.get("timeout")
        if t:
            timeout = max(1, int(t))
    except (ValueError, TypeError):
        pass

    verify_ssl = connection_params.get("verify_ssl", True)
    if isinstance(verify_ssl, str):
        verify_ssl = verify_ssl.lower() in ("true", "1", "yes")

    proxy = connection_params.get("proxy")
    proxies = {"https": proxy, "http": proxy} if proxy else None

    return api_key, base_url, timeout, verify_ssl, proxies


def _extract_filename(resp) -> str:
    cd = resp.headers.get("Content-Disposition", "")
    if "filename=" in cd:
        return cd.split("filename=")[-1].strip('" ')
    return "artifact"


def _make_request(method: str, url: str, api_key: str, timeout: int,
                  verify_ssl: bool, proxies: dict, json_data: dict = None,
                  files: dict = None, data: dict = None) -> dict:
    logger = logging.getLogger(__name__)
    headers = {AUTH_HEADER_NAME: f"{AUTH_HEADER_PREFIX}{api_key}"}
    if not files:
        headers["Content-Type"] = "application/json"

    last_exception = None
    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.request(
                method,
                url,
                headers=headers,
                json=json_data if not files else None,
                files=files,
                data=data,
                timeout=timeout,
                verify=verify_ssl,
                proxies=proxies,
            )
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Any.Run API.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Any.Run API timed out.")

        if resp.status_code == 200:
            content_type = resp.headers.get("Content-Type", "")
            if "application/json" in content_type:
                return resp.json()
            return {"_raw_content": base64.b64encode(resp.content).decode("utf-8"),
                    "_content_type": content_type,
                    "_filename": _extract_filename(resp)}

        if resp.status_code in (401, 403):
            raise Exception("Authentication failed. Verify api_key.")

        if resp.status_code == 404:
            raise Exception("NOT_FOUND")

        if resp.status_code == 429:
            if attempt < MAX_RETRIES - 1:
                wait = BACKOFF_FACTOR ** (attempt + 1)
                logger.warning("Rate limited (429). Retrying in %ds...", wait)
                time.sleep(wait)
                last_exception = Exception("Rate limit exceeded. Please try again later.")
                continue
            raise Exception("Rate limit exceeded. Please try again later.")

        if resp.status_code >= 500:
            if attempt < MAX_RETRIES - 1:
                wait = BACKOFF_FACTOR ** (attempt + 1)
                logger.warning("Server error (%d). Retrying in %ds...", resp.status_code, wait)
                time.sleep(wait)
                last_exception = Exception(f"Any.Run server error (HTTP {resp.status_code}).")
                continue
            raise Exception(f"Any.Run server error (HTTP {resp.status_code}).")

        raise Exception(f"Any.Run API error (HTTP {resp.status_code}).")

    if last_exception:
        raise last_exception


def _validate_required(value, field_name: str) -> str:
    if not value or (isinstance(value, str) and not value.strip()):
        raise Exception(f"{field_name} is required and cannot be empty.")
    return value.strip() if isinstance(value, str) else value


class AnyRun:

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)

    def test_connection(self, connectionParameters: dict):
        try:
            api_key, base_url, timeout, verify_ssl, proxies = \
                _get_connection(connectionParameters)
            url = f"{base_url}{ENDPOINT_ENVIRONMENT}"
            result = _make_request("GET", url, api_key, timeout, verify_ssl, proxies)
            return {"status": "success", "message": "Connected to Any.Run successfully.", "data": result}
        except Exception as e:
            self.logger.error("Exception while testing connection", exc_info=e)
            raise Exception(str(e))

    def submit_file(self, request: RequestBody) -> dict:
        try:
            api_key, base_url, timeout, verify_ssl, proxies = \
                _get_connection(request.connectionParameters)
            params = request.parameters or {}

            file_content = _validate_required(params.get("file_content"), "file_content")
            file_name = _validate_required(params.get("file_name"), "file_name")
            if len(file_name) > 255:
                raise Exception("file_name must not exceed 255 characters.")

            try:
                file_bytes = base64.b64decode(file_content)
            except Exception:
                raise Exception("file_content must be valid base64-encoded data.")

            os_type = params.get("os_type", "windows10") or "windows10"
            if os_type not in VALID_OS_TYPES:
                raise Exception(f"os_type must be one of: {', '.join(VALID_OS_TYPES)}")

            timeout_duration = params.get("timeout_duration")
            form_data = {"os_type": os_type}
            if timeout_duration:
                try:
                    td = int(timeout_duration)
                    if td <= 0:
                        raise ValueError()
                    form_data["timeout"] = str(td)
                except (ValueError, TypeError):
                    raise Exception("timeout_duration must be a positive integer.")

            files = {"file": (file_name, file_bytes)}
            url = f"{base_url}{ENDPOINT_SUBMIT_FILE}"
            result = _make_request("POST", url, api_key, timeout, verify_ssl, proxies,
                                   files=files, data=form_data)
            task_id = result.get("data", {}).get("task_id") or result.get("task_id", "")
            return {"status": "success", "task_id": task_id, "raw_response": result}
        except Exception as e:
            self.logger.error("Exception in submit_file", exc_info=e)
            raise Exception(str(e))

    def submit_url(self, request: RequestBody) -> dict:
        try:
            api_key, base_url, timeout, verify_ssl, proxies = \
                _get_connection(request.connectionParameters)
            params = request.parameters or {}

            url_to_analyze = _validate_required(params.get("url"), "url")
            if not URL_PATTERN.match(url_to_analyze):
                raise Exception("url must be a valid HTTP or HTTPS URL.")

            os_type = params.get("os_type", "windows10") or "windows10"
            if os_type not in VALID_OS_TYPES:
                raise Exception(f"os_type must be one of: {', '.join(VALID_OS_TYPES)}")

            payload = {"url": url_to_analyze, "os_type": os_type}

            timeout_duration = params.get("timeout_duration")
            if timeout_duration:
                try:
                    td = int(timeout_duration)
                    if td <= 0:
                        raise ValueError()
                    payload["timeout"] = td
                except (ValueError, TypeError):
                    raise Exception("timeout_duration must be a positive integer.")

            endpoint = f"{base_url}{ENDPOINT_SUBMIT_URL}"
            result = _make_request("POST", endpoint, api_key, timeout, verify_ssl, proxies,
                                   json_data=payload)
            task_id = result.get("data", {}).get("task_id") or result.get("task_id", "")
            return {"status": "success", "task_id": task_id, "raw_response": result}
        except Exception as e:
            self.logger.error("Exception in submit_url", exc_info=e)
            raise Exception(str(e))

    def get_analysis_status(self, request: RequestBody) -> dict:
        try:
            api_key, base_url, timeout, verify_ssl, proxies = \
                _get_connection(request.connectionParameters)
            params = request.parameters or {}

            task_id = _validate_required(params.get("task_id"), "task_id")

            url = f"{base_url}{ENDPOINT_TASK_STATUS.format(task_id=task_id)}"
            result = _make_request("GET", url, api_key, timeout, verify_ssl, proxies)

            status = result.get("data", {}).get("status") or result.get("status", "unknown")
            return {"status": "success", "task_id": task_id, "analysis_status": status,
                    "raw_response": result}
        except Exception as e:
            if "NOT_FOUND" in str(e):
                return {"status": "success", "task_id": task_id, "results": [], "message": "Task not found."}
            self.logger.error("Exception in get_analysis_status", exc_info=e)
            raise Exception(str(e))

    def get_analysis_report(self, request: RequestBody) -> dict:
        try:
            api_key, base_url, timeout, verify_ssl, proxies = \
                _get_connection(request.connectionParameters)
            params = request.parameters or {}

            task_id = _validate_required(params.get("task_id"), "task_id")

            url = f"{base_url}{ENDPOINT_TASK_REPORT.format(task_id=task_id)}"
            result = _make_request("GET", url, api_key, timeout, verify_ssl, proxies)

            data = result.get("data", result)
            return {
                "status": "success",
                "task_id": task_id,
                "verdict": data.get("verdict", "unknown"),
                "score": data.get("score", 0),
                "malware_family": data.get("malware_family"),
                "tags": data.get("tags", []),
                "process_activity": data.get("process_activity", []),
                "network_activity": data.get("network_activity", []),
                "mitre_attacks": data.get("mitre_attacks", []),
                "raw_response": result,
            }
        except Exception as e:
            if "NOT_FOUND" in str(e):
                return {"status": "success", "task_id": task_id, "results": [], "message": "Task not found."}
            self.logger.error("Exception in get_analysis_report", exc_info=e)
            raise Exception(str(e))

    def extract_iocs(self, request: RequestBody) -> dict:
        try:
            api_key, base_url, timeout, verify_ssl, proxies = \
                _get_connection(request.connectionParameters)
            params = request.parameters or {}

            task_id = _validate_required(params.get("task_id"), "task_id")

            url = f"{base_url}{ENDPOINT_TASK_IOCS.format(task_id=task_id)}"
            result = _make_request("GET", url, api_key, timeout, verify_ssl, proxies)

            data = result.get("data", result)
            return {
                "status": "success",
                "task_id": task_id,
                "domains": data.get("domains", []),
                "ip_addresses": data.get("ip_addresses", []),
                "urls": data.get("urls", []),
                "hashes": data.get("hashes", []),
                "raw_response": result,
            }
        except Exception as e:
            if "NOT_FOUND" in str(e):
                return {"status": "success", "task_id": task_id, "results": [], "message": "Task not found."}
            self.logger.error("Exception in extract_iocs", exc_info=e)
            raise Exception(str(e))

    def download_artifact(self, request: RequestBody) -> dict:
        try:
            api_key, base_url, timeout, verify_ssl, proxies = \
                _get_connection(request.connectionParameters)
            params = request.parameters or {}

            task_id = _validate_required(params.get("task_id"), "task_id")
            artifact_type = _validate_required(params.get("artifact_type"), "artifact_type")
            if artifact_type not in VALID_ARTIFACT_TYPES:
                raise Exception(f"artifact_type must be one of: {', '.join(VALID_ARTIFACT_TYPES)}")

            url = f"{base_url}{ENDPOINT_TASK_ARTIFACT.format(task_id=task_id, artifact_type=artifact_type)}"

            artifact_id = params.get("artifact_id")
            if artifact_id:
                url = f"{url}?artifact_id={artifact_id}"

            result = _make_request("GET", url, api_key, timeout, verify_ssl, proxies)

            if "_raw_content" in result:
                return {
                    "status": "success",
                    "task_id": task_id,
                    "artifact_type": artifact_type,
                    "content": result["_raw_content"],
                    "filename": result.get("_filename", "artifact"),
                    "content_type": result.get("_content_type", "application/octet-stream"),
                }

            content = result.get("data", {}).get("content") or result.get("content", "")
            filename = result.get("data", {}).get("filename") or result.get("filename", "artifact")
            content_type = result.get("data", {}).get("content_type") or result.get("content_type", "application/octet-stream")
            return {
                "status": "success",
                "task_id": task_id,
                "artifact_type": artifact_type,
                "content": content,
                "filename": filename,
                "content_type": content_type,
            }
        except Exception as e:
            if "NOT_FOUND" in str(e):
                return {"status": "success", "task_id": task_id, "results": [], "message": "Task not found."}
            self.logger.error("Exception in download_artifact", exc_info=e)
            raise Exception(str(e))
