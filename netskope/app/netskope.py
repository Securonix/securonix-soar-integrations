from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import time
import requests


VALID_EVENT_TYPES = {"application", "page", "network", "audit", "infrastructure", "incident"}
VALID_ALERT_TYPES = {
    "dlp", "malware", "policy", "security_assessment",
    "compromised_credential", "watchlist", "quarantine", "remediation", "uba",
}
VALID_URL_ACTIONS = {"append", "replace"}

MAX_RETRIES = 3
BACKOFF_FACTOR = 2
USER_AGENT = "SecuronixSOAR-Netskope/1.0"


class Netskope():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    def _get_config(self, connection_params: dict) -> dict:
        tenant_hostname = (connection_params.get("tenant_hostname") or "").strip()
        if not tenant_hostname:
            raise Exception("tenant_hostname is required.")
        api_token = connection_params.get("api_token", "")
        if not api_token or not str(api_token).strip():
            raise Exception("api_token is required.")
        api_token = str(api_token).strip()

        raw_timeout = connection_params.get("timeout")
        if raw_timeout is not None:
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
            verify_ssl = verify_ssl.lower() in ("true", "1", "yes")
        elif not isinstance(verify_ssl, bool):
            raise Exception("verify_ssl must be a boolean value.")

        proxy = connection_params.get("proxy")
        proxies = {"http": proxy, "https": proxy} if proxy else None

        return {
            "base_url": f"https://{tenant_hostname}",
            "headers": {
                "Netskope-API-Token": api_token,
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
            "timeout": timeout,
            "verify": verify_ssl,
            "proxies": proxies,
        }

    def _make_request(self, config: dict, method: str, endpoint: str, json_body=None, params=None):
        url = f"{config['base_url']}{endpoint}"
        for attempt in range(MAX_RETRIES):
            try:
                resp = requests.request(
                    method=method,
                    url=url,
                    headers=config["headers"],
                    json=json_body,
                    params=params,
                    timeout=config["timeout"],
                    verify=config["verify"],
                    proxies=config["proxies"],
                )
                if resp.status_code in (401, 403):
                    raise Exception("Authentication failed. Verify tenant_hostname and api_token.")
                if resp.status_code == 404:
                    raise Exception("Resource not found.")
                if resp.status_code == 422:
                    error_detail = ""
                    try:
                        err = resp.json()
                        error_detail = str(err.get("error", "") or err.get("message", ""))
                    except Exception:
                        pass
                    raise Exception(f"Validation error: {error_detail}" if error_detail else "Validation error.")
                if resp.status_code == 429:
                    if attempt < MAX_RETRIES - 1:
                        retry_after = resp.headers.get("Retry-After")
                        wait = int(retry_after) if retry_after else BACKOFF_FACTOR ** (attempt + 1)
                        time.sleep(wait)
                        continue
                    raise Exception("Rate limit exceeded. Please try again later.")
                if resp.status_code >= 500:
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(BACKOFF_FACTOR ** (attempt + 1))
                        continue
                    raise Exception(f"Netskope server error (HTTP {resp.status_code}).")
                if resp.status_code == 204:
                    return {}
                return resp.json()
            except requests.exceptions.ConnectionError:
                raise Exception("Unable to connect to Netskope. Check tenant_hostname and network.")
            except requests.exceptions.Timeout:
                raise Exception("Connection to Netskope timed out.")
        raise Exception("Max retries exceeded.")

    def test_connection(self, connectionParameters: dict):
        try:
            config = self._get_config(connectionParameters)
            self._make_request(config, "GET", "/api/v2/events/datasearch/alert", params={"limit": 1})
            return {"status": "success", "message": "Connected to Netskope tenant successfully."}
        except Exception as e:
            self.logger.error("Exception while testing connection", exc_info=e)
            raise Exception(str(e))

    def get_alerts(self, request: RequestBody) -> ResponseBody:
        try:
            config = self._get_config(request.connectionParameters)
            params = request.parameters

            query_params = {}

            alert_type = (params.get("alert_type") or "").strip().lower()
            if alert_type:
                if alert_type not in VALID_ALERT_TYPES:
                    raise Exception(f"alert_type must be one of: {', '.join(sorted(VALID_ALERT_TYPES))}")
                query_params["alert_type"] = alert_type

            time_period = params.get("time_period")
            if time_period:
                try:
                    time_period = int(time_period)
                    if time_period < 1:
                        raise ValueError()
                    query_params["timeperiod"] = time_period
                except (ValueError, TypeError):
                    raise Exception("time_period must be a positive integer (hours).")
            else:
                query_params["timeperiod"] = 24

            user = (params.get("user") or "").strip()
            if user:
                query_params["user"] = user

            severity = (params.get("severity") or "").strip()
            if severity:
                query_params["severity"] = severity

            query = (params.get("query") or "").strip()
            if query:
                query_params["query"] = query

            limit = params.get("limit")
            if limit:
                try:
                    limit = int(limit)
                    if limit < 1:
                        raise ValueError()
                    query_params["limit"] = limit
                except (ValueError, TypeError):
                    raise Exception("limit must be a positive integer.")
            else:
                query_params["limit"] = 100

            data = self._make_request(config, "GET", "/api/v2/events/datasearch/alert", params=query_params)
            return {"status": "success", "alerts": data.get("result", data.get("data", []))}
        except Exception as e:
            self.logger.error("Error in get_alerts", exc_info=e)
            raise Exception(str(e))

    def get_events(self, request: RequestBody) -> ResponseBody:
        try:
            config = self._get_config(request.connectionParameters)
            params = request.parameters

            event_type = (params.get("event_type") or "").strip().lower()
            if not event_type:
                raise Exception("event_type is required.")
            if event_type not in VALID_EVENT_TYPES:
                raise Exception(f"event_type must be one of: {', '.join(sorted(VALID_EVENT_TYPES))}")

            query_params = {}

            time_period = params.get("time_period")
            if time_period:
                try:
                    time_period = int(time_period)
                    if time_period < 1:
                        raise ValueError()
                    query_params["timeperiod"] = time_period
                except (ValueError, TypeError):
                    raise Exception("time_period must be a positive integer (hours).")
            else:
                query_params["timeperiod"] = 24

            user = (params.get("user") or "").strip()
            if user:
                query_params["user"] = user

            query = (params.get("query") or "").strip()
            if query:
                query_params["query"] = query

            limit = params.get("limit")
            if limit:
                try:
                    limit = int(limit)
                    if limit < 1:
                        raise ValueError()
                    query_params["limit"] = limit
                except (ValueError, TypeError):
                    raise Exception("limit must be a positive integer.")
            else:
                query_params["limit"] = 100

            data = self._make_request(config, "GET", f"/api/v2/events/datasearch/{event_type}", params=query_params)
            return {"status": "success", "events": data.get("result", data.get("data", []))}
        except Exception as e:
            self.logger.error("Error in get_events", exc_info=e)
            raise Exception(str(e))

    def get_incidents(self, request: RequestBody) -> ResponseBody:
        try:
            config = self._get_config(request.connectionParameters)
            params = request.parameters

            query_params = {}

            status = (params.get("status") or "").strip().lower()
            if status:
                query_params["status"] = status

            time_period = params.get("time_period")
            if time_period:
                try:
                    time_period = int(time_period)
                    if time_period < 1:
                        raise ValueError()
                    query_params["timeperiod"] = time_period
                except (ValueError, TypeError):
                    raise Exception("time_period must be a positive integer (hours).")
            else:
                query_params["timeperiod"] = 24

            query = (params.get("query") or "").strip()
            if query:
                query_params["query"] = query

            limit = params.get("limit")
            if limit:
                try:
                    limit = int(limit)
                    if limit < 1:
                        raise ValueError()
                    query_params["limit"] = limit
                except (ValueError, TypeError):
                    raise Exception("limit must be a positive integer.")
            else:
                query_params["limit"] = 100

            data = self._make_request(config, "GET", "/api/v2/events/datasearch/incident", params=query_params)
            return {"status": "success", "incidents": data.get("result", data.get("data", []))}
        except Exception as e:
            self.logger.error("Error in get_incidents", exc_info=e)
            raise Exception(str(e))

    def get_alert_details(self, request: RequestBody) -> ResponseBody:
        try:
            config = self._get_config(request.connectionParameters)
            params = request.parameters

            alert_id = (params.get("alert_id") or "").strip()
            if not alert_id:
                raise Exception("alert_id is required.")
            if len(alert_id) > 256:
                raise Exception("alert_id exceeds maximum length of 256 characters.")

            query_params = {"query": f"alert_id eq {alert_id}", "limit": 1}

            data = self._make_request(config, "GET", "/api/v2/events/datasearch/alert", params=query_params)
            results = data.get("result", data.get("data", []))
            if not results:
                raise Exception(f"Alert not found for alert_id: {alert_id}")
            return {"status": "success", "alert": results[0] if isinstance(results, list) else results}
        except Exception as e:
            self.logger.error("Error in get_alert_details", exc_info=e)
            raise Exception(str(e))

    def update_url_list(self, request: RequestBody) -> ResponseBody:
        try:
            config = self._get_config(request.connectionParameters)
            params = request.parameters

            list_id = (params.get("list_id") or "").strip()
            if not list_id:
                raise Exception("list_id is required.")

            action = (params.get("action") or "").strip().lower()
            if not action:
                raise Exception("action is required.")
            if action not in VALID_URL_ACTIONS:
                raise Exception(f"action must be one of: {', '.join(sorted(VALID_URL_ACTIONS))}")

            urls = (params.get("urls") or "").strip()
            if not urls:
                raise Exception("urls is required.")
            url_list = [u.strip() for u in urls.split(",") if u.strip()]
            if not url_list:
                raise Exception("urls must contain at least one valid URL.")

            endpoint = f"/api/v2/policy/urllist/{list_id}/{action}"
            body = {"urls": url_list}

            data = self._make_request(config, "PATCH", endpoint, json_body=body)
            return {"status": "success", "result": data}
        except Exception as e:
            self.logger.error("Error in update_url_list", exc_info=e)
            raise Exception(str(e))
