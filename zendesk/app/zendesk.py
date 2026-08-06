from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import time
from datetime import datetime
import requests
from base64 import b64encode


VALID_WRITABLE_STATUSES = {"new", "open", "pending", "solved"}
VALID_SEARCH_STATUSES = {"new", "open", "pending", "solved", "closed"}
VALID_PRIORITIES = {"low", "normal", "high", "urgent"}
VALID_TYPES = {"problem", "incident", "question", "task"}

MAX_RETRIES = 3
BACKOFF_FACTOR = 2
USER_AGENT = "SecuronixSOAR-Zendesk/1.0"


def _get_config(connection_params: dict) -> dict:
    subdomain = (connection_params.get("subdomain") or "").strip()
    if not subdomain:
        raise Exception("subdomain is required.")
    email = (connection_params.get("email") or "").strip()
    if not email:
        raise Exception("email is required.")
    api_token = connection_params.get("api_token", "")
    if not api_token or not str(api_token).strip():
        raise Exception("api_token is required.")
    api_token = str(api_token).strip()

    raw_timeout = connection_params.get("timeout")
    if raw_timeout is not None and str(raw_timeout).strip() != "":
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

    credentials = b64encode(f"{email}/token:{api_token}".encode()).decode()

    return {
        "base_url": f"https://{subdomain}.zendesk.com",
        "headers": {
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
        "timeout": timeout,
        "verify": verify_ssl,
        "proxies": proxies,
    }


def _make_request(config: dict, method: str, endpoint: str, json_body=None, params=None):
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
                raise Exception("Authentication failed. Verify subdomain, email, and api_token.")
            if resp.status_code == 404:
                raise Exception("Resource not found.")
            if resp.status_code == 422:
                error_detail = ""
                try:
                    err = resp.json()
                    error_detail = str(err.get("error", "") or err.get("description", ""))
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
                raise Exception(f"Zendesk server error (HTTP {resp.status_code}).")
            if resp.status_code == 204:
                return {}
            return resp.json()
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to Zendesk. Check subdomain and network.")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Zendesk timed out.")
    raise Exception("Max retries exceeded.")


def _resolve_user_id(config: dict, email: str) -> int:
    data = _make_request(config, "GET", "/api/v2/users/search.json", params={"query": email})
    users = data.get("users", [])
    if not users:
        raise Exception(f"User not found for email: {email}")
    for user in users:
        if user.get("email", "").lower() == email.lower():
            return user["id"]
    return users[0]["id"]


class Zendesk():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    def test_connection(self, connectionParameters: dict):
        try:
            config = _get_config(connectionParameters)
            data = _make_request(config, "GET", "/api/v2/users/me.json")
            user = data.get("user", {})
            return {"status": "success", "message": f"Connected as {user.get('name', 'unknown')} ({user.get('email', '')})."}
        except Exception as e:
            self.logger.error("Exception while testing connection", exc_info=e)
            raise Exception(str(e))

    def create_ticket(self, request: RequestBody) -> ResponseBody:
        try:
            config = _get_config(request.connectionParameters)
            params = request.parameters

            subject = (params.get("subject") or "").strip()
            if not subject:
                raise Exception("subject is required.")
            if len(subject) > 150:
                raise Exception("subject exceeds maximum length of 150 characters.")

            description = (params.get("description") or "").strip()
            if not description:
                raise Exception("description is required.")

            ticket = {"subject": subject, "comment": {"body": description}}

            priority = (params.get("priority") or "").strip().lower()
            if priority:
                if priority not in VALID_PRIORITIES:
                    raise Exception(f"priority must be one of: {', '.join(sorted(VALID_PRIORITIES))}")
                ticket["priority"] = priority

            ticket_type = (params.get("type") or "").strip().lower()
            if ticket_type:
                if ticket_type not in VALID_TYPES:
                    raise Exception(f"type must be one of: {', '.join(sorted(VALID_TYPES))}")
                ticket["type"] = ticket_type

            status = (params.get("status") or "").strip().lower()
            if status:
                if status not in VALID_WRITABLE_STATUSES:
                    raise Exception(f"status must be one of: {', '.join(sorted(VALID_WRITABLE_STATUSES))}")
                ticket["status"] = status

            tags = (params.get("tags") or "").strip()
            if tags:
                ticket["tags"] = [t.strip() for t in tags.split(",") if t.strip()]

            assignee_email = (params.get("assignee_email") or "").strip()
            if assignee_email:
                ticket["assignee_id"] = _resolve_user_id(config, assignee_email)

            requester_email = (params.get("requester_email") or "").strip()
            if requester_email:
                ticket["requester_id"] = _resolve_user_id(config, requester_email)

            data = _make_request(config, "POST", "/api/v2/tickets.json", json_body={"ticket": ticket})
            return {"status": "success", "ticket": data.get("ticket", {})}
        except Exception as e:
            self.logger.error("Error in create_ticket", exc_info=e)
            raise Exception(str(e))

    def get_ticket_details(self, request: RequestBody) -> ResponseBody:
        try:
            config = _get_config(request.connectionParameters)
            ticket_id = request.parameters.get("ticket_id")
            if not ticket_id:
                raise Exception("ticket_id is required.")
            try:
                ticket_id = int(ticket_id)
                if ticket_id < 1:
                    raise ValueError()
            except (ValueError, TypeError):
                raise Exception("ticket_id must be a positive integer.")

            data = _make_request(config, "GET", f"/api/v2/tickets/{ticket_id}.json")
            return {"status": "success", "ticket": data.get("ticket", {})}
        except Exception as e:
            if "Resource not found" in str(e):
                return {"status": "success", "ticket": {}, "message": f"Ticket {ticket_id} not found."}
            self.logger.error("Error in get_ticket_details", exc_info=e)
            raise Exception(str(e))

    def update_ticket(self, request: RequestBody) -> ResponseBody:
        try:
            config = _get_config(request.connectionParameters)
            params = request.parameters

            ticket_id = params.get("ticket_id")
            if not ticket_id:
                raise Exception("ticket_id is required.")
            try:
                ticket_id = int(ticket_id)
                if ticket_id < 1:
                    raise ValueError()
            except (ValueError, TypeError):
                raise Exception("ticket_id must be a positive integer.")

            ticket = {}

            subject = (params.get("subject") or "").strip()
            if subject:
                if len(subject) > 150:
                    raise Exception("subject exceeds maximum length of 150 characters.")
                ticket["subject"] = subject

            priority = (params.get("priority") or "").strip().lower()
            if priority:
                if priority not in VALID_PRIORITIES:
                    raise Exception(f"priority must be one of: {', '.join(sorted(VALID_PRIORITIES))}")
                ticket["priority"] = priority

            ticket_type = (params.get("type") or "").strip().lower()
            if ticket_type:
                if ticket_type not in VALID_TYPES:
                    raise Exception(f"type must be one of: {', '.join(sorted(VALID_TYPES))}")
                ticket["type"] = ticket_type

            status = (params.get("status") or "").strip().lower()
            if status:
                if status not in VALID_WRITABLE_STATUSES:
                    raise Exception(f"status must be one of: {', '.join(sorted(VALID_WRITABLE_STATUSES))}")
                ticket["status"] = status

            tags = (params.get("tags") or "").strip()
            if tags:
                ticket["tags"] = [t.strip() for t in tags.split(",") if t.strip()]

            assignee_email = (params.get("assignee_email") or "").strip()
            if assignee_email:
                ticket["assignee_id"] = _resolve_user_id(config, assignee_email)

            if not ticket:
                raise Exception("At least one field to update is required.")

            data = _make_request(config, "PUT", f"/api/v2/tickets/{ticket_id}.json", json_body={"ticket": ticket})
            return {"status": "success", "ticket": data.get("ticket", {})}
        except Exception as e:
            self.logger.error("Error in update_ticket", exc_info=e)
            raise Exception(str(e))

    def add_comment(self, request: RequestBody) -> ResponseBody:
        try:
            config = _get_config(request.connectionParameters)
            params = request.parameters

            ticket_id = params.get("ticket_id")
            if not ticket_id:
                raise Exception("ticket_id is required.")
            try:
                ticket_id = int(ticket_id)
                if ticket_id < 1:
                    raise ValueError()
            except (ValueError, TypeError):
                raise Exception("ticket_id must be a positive integer.")

            comment_body = (params.get("comment_body") or "").strip()
            if not comment_body:
                raise Exception("comment_body is required.")

            public = params.get("public", True)
            if isinstance(public, str):
                public = public.lower() in ("true", "1", "yes")

            ticket = {"comment": {"body": comment_body, "public": public}}
            data = _make_request(config, "PUT", f"/api/v2/tickets/{ticket_id}.json", json_body={"ticket": ticket})
            return {"status": "success", "ticket": data.get("ticket", {})}
        except Exception as e:
            self.logger.error("Error in add_comment", exc_info=e)
            raise Exception(str(e))

    def search_tickets(self, request: RequestBody) -> ResponseBody:
        try:
            config = _get_config(request.connectionParameters)
            params = request.parameters

            query_parts = ["type:ticket"]

            query = (params.get("query") or "").strip()
            if query:
                query_parts.append(query)

            status = (params.get("status") or "").strip().lower()
            if status:
                if status not in VALID_SEARCH_STATUSES:
                    raise Exception(f"status must be one of: {', '.join(sorted(VALID_SEARCH_STATUSES))}")
                query_parts.append(f"status:{status}")

            assignee_email = (params.get("assignee_email") or params.get("assignee") or "").strip()
            if assignee_email:
                query_parts.append(f"assignee:{assignee_email}")

            requester_email = (params.get("requester_email") or params.get("requester") or "").strip()
            if requester_email:
                query_parts.append(f"requester:{requester_email}")

            tags = (params.get("tags") or "").strip()
            if tags:
                for tag in tags.split(","):
                    tag = tag.strip()
                    if tag:
                        query_parts.append(f"tags:{tag}")

            created_after = (params.get("created_after") or "").strip()
            if created_after:
                try:
                    datetime.strptime(created_after, "%Y-%m-%d")
                except ValueError:
                    raise Exception("created_after must be a valid ISO date (YYYY-MM-DD).")
                query_parts.append(f"created>{created_after}")

            created_before = (params.get("created_before") or "").strip()
            if created_before:
                try:
                    datetime.strptime(created_before, "%Y-%m-%d")
                except ValueError:
                    raise Exception("created_before must be a valid ISO date (YYYY-MM-DD).")
                query_parts.append(f"created<{created_before}")

            page_size = 25
            raw_page_size = params.get("page_size")
            if raw_page_size is not None:
                try:
                    page_size = int(raw_page_size)
                    if page_size < 1 or page_size > 100:
                        raise Exception("page_size must be between 1 and 100.")
                except (ValueError, TypeError):
                    raise Exception("page_size must be a valid integer.")

            search_query = " ".join(query_parts)
            api_params = {"query": search_query, "per_page": page_size}

            data = _make_request(config, "GET", "/api/v2/search.json", params=api_params)
            return {
                "status": "success",
                "tickets": data.get("results", []),
                "count": data.get("count", 0),
                "has_more": data.get("next_page") is not None,
                "next_page": data.get("next_page"),
            }
        except Exception as e:
            self.logger.error("Error in search_tickets", exc_info=e)
            raise Exception(str(e))

    def search_users(self, request: RequestBody) -> ResponseBody:
        try:
            config = _get_config(request.connectionParameters)
            params = request.parameters

            query = (params.get("query") or "").strip()
            if not query:
                raise Exception("query is required.")

            page_size = 25
            raw_page_size = params.get("page_size")
            if raw_page_size is not None:
                try:
                    page_size = int(raw_page_size)
                    if page_size < 1 or page_size > 100:
                        raise Exception("page_size must be between 1 and 100.")
                except (ValueError, TypeError):
                    raise Exception("page_size must be a valid integer.")

            api_params = {"query": query, "per_page": page_size}
            data = _make_request(config, "GET", "/api/v2/users/search.json", params=api_params)
            return {
                "status": "success",
                "users": data.get("users", []),
                "count": data.get("count", 0),
                "has_more": data.get("next_page") is not None,
                "next_page": data.get("next_page"),
            }
        except Exception as e:
            self.logger.error("Error in search_users", exc_info=e)
            raise Exception(str(e))

    def change_ticket_status(self, request: RequestBody) -> ResponseBody:
        try:
            config = _get_config(request.connectionParameters)
            params = request.parameters

            ticket_id = params.get("ticket_id")
            if not ticket_id:
                raise Exception("ticket_id is required.")
            try:
                ticket_id = int(ticket_id)
                if ticket_id < 1:
                    raise ValueError()
            except (ValueError, TypeError):
                raise Exception("ticket_id must be a positive integer.")

            status = (params.get("status") or "").strip().lower()
            if not status:
                raise Exception("status is required.")
            if status not in VALID_WRITABLE_STATUSES:
                raise Exception(f"status must be one of: {', '.join(sorted(VALID_WRITABLE_STATUSES))}")

            data = _make_request(config, "PUT", f"/api/v2/tickets/{ticket_id}.json", json_body={"ticket": {"status": status}})
            return {"status": "success", "ticket": data.get("ticket", {})}
        except Exception as e:
            self.logger.error("Error in change_ticket_status", exc_info=e)
            raise Exception(str(e))

    def get_ticket_comments(self, request: RequestBody) -> ResponseBody:
        try:
            config = _get_config(request.connectionParameters)
            params = request.parameters

            ticket_id = params.get("ticket_id")
            if not ticket_id:
                raise Exception("ticket_id is required.")
            try:
                ticket_id = int(ticket_id)
                if ticket_id < 1:
                    raise ValueError()
            except (ValueError, TypeError):
                raise Exception("ticket_id must be a positive integer.")

            page_size = 25
            raw_page_size = params.get("page_size")
            if raw_page_size is not None:
                try:
                    page_size = int(raw_page_size)
                    if page_size < 1 or page_size > 100:
                        raise Exception("page_size must be between 1 and 100.")
                except (ValueError, TypeError):
                    raise Exception("page_size must be a valid integer.")

            api_params = {"per_page": page_size}
            data = _make_request(config, "GET", f"/api/v2/tickets/{ticket_id}/comments.json", params=api_params)
            return {
                "status": "success",
                "comments": data.get("comments", []),
                "count": data.get("count", 0),
                "has_more": data.get("next_page") is not None,
                "next_page": data.get("next_page"),
            }
        except Exception as e:
            if "Resource not found" in str(e):
                return {"status": "success", "comments": [], "count": 0, "message": f"Ticket {ticket_id} not found."}
            self.logger.error("Error in get_ticket_comments", exc_info=e)
            raise Exception(str(e))

    def list_ticket_attachments(self, request: RequestBody) -> ResponseBody:
        try:
            config = _get_config(request.connectionParameters)
            params = request.parameters

            ticket_id = params.get("ticket_id")
            if not ticket_id:
                raise Exception("ticket_id is required.")
            try:
                ticket_id = int(ticket_id)
                if ticket_id < 1:
                    raise ValueError()
            except (ValueError, TypeError):
                raise Exception("ticket_id must be a positive integer.")

            data = _make_request(config, "GET", f"/api/v2/tickets/{ticket_id}/comments.json")
            comments = data.get("comments", [])
            attachments = []
            for comment in comments:
                for attachment in comment.get("attachments", []):
                    attachments.append({
                        "id": attachment.get("id"),
                        "filename": attachment.get("file_name"),
                        "content_url": attachment.get("content_url"),
                        "content_type": attachment.get("content_type"),
                        "size": attachment.get("size"),
                    })
            return {"status": "success", "attachments": attachments, "count": len(attachments)}
        except Exception as e:
            self.logger.error("Error in list_ticket_attachments", exc_info=e)
            raise Exception(str(e))
