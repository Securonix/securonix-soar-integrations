from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging


# Default regional endpoints; overridable by passing a full endpoint if needed.
# Alibaba Cloud Firewall and Security Center expose region-specific endpoints.
CLOUDFW_ENDPOINT_TMPL = "cloudfw.{region}.aliyuncs.com"
CLOUDFW_CN_ENDPOINT = "cloudfw.cn-hangzhou.aliyuncs.com"
SAS_ENDPOINT_TMPL = "tds.{region}.aliyuncs.com"
SAS_CN_ENDPOINT = "sas.cn-hangzhou.aliyuncs.com"


def _require(connection_params: dict, name: str) -> str:
    value = connection_params.get(name)
    if not value or (isinstance(value, str) and not value.strip()):
        raise Exception(f"Missing required connection parameter: {name}")
    return value.strip() if isinstance(value, str) else value


def _get_credentials(connection_params: dict):
    access_key_id = _require(connection_params, "access_key_id")
    access_key_secret = _require(connection_params, "access_key_secret")
    region_id = _require(connection_params, "region_id")
    return access_key_id, access_key_secret, region_id


def _param(parameters: dict, name: str):
    """Required action parameter (raises if missing)."""
    value = parameters.get(name)
    if value is None or (isinstance(value, str) and not value.strip()):
        raise Exception(f"Missing required parameter: {name}")
    return value.strip() if isinstance(value, str) else value


def _build_cloudfw_client(connection_params: dict):
    """
    Build a Cloud Firewall OpenAPI client. The SDK is imported lazily so the
    module can be imported (and unit-tested with mocks) without the SDK present.
    """
    from alibabacloud_cloudfw20171207.client import Client as CloudfwClient
    from alibabacloud_tea_openapi import models as open_api_models

    access_key_id, access_key_secret, region_id = _get_credentials(connection_params)
    endpoint = (connection_params.get("cloudfw_endpoint") or "").strip() or CLOUDFW_CN_ENDPOINT
    config = open_api_models.Config(
        access_key_id=access_key_id,
        access_key_secret=access_key_secret,
        region_id=region_id,
        endpoint=endpoint,
    )
    return CloudfwClient(config)


def _build_sas_client(connection_params: dict):
    """Build a Security Center (Sas) OpenAPI client (lazy SDK import)."""
    from alibabacloud_sas20181203.client import Client as SasClient
    from alibabacloud_tea_openapi import models as open_api_models

    access_key_id, access_key_secret, region_id = _get_credentials(connection_params)
    endpoint = (connection_params.get("sas_endpoint") or "").strip() or SAS_CN_ENDPOINT
    config = open_api_models.Config(
        access_key_id=access_key_id,
        access_key_secret=access_key_secret,
        region_id=region_id,
        endpoint=endpoint,
    )
    return SasClient(config)


def _to_dict(resp):
    """Normalize an SDK response object to a plain dict."""
    if resp is None:
        return {}
    body = getattr(resp, "body", None)
    if body is not None and hasattr(body, "to_map"):
        return body.to_map()
    if hasattr(resp, "to_map"):
        return resp.to_map()
    if isinstance(resp, dict):
        return resp
    return {"response": str(resp)}


class Alibaba:
    """
    Alibaba Cloud (Aliyun) SOAR connector.

    Covers SOAR-relevant security operations:
      - Cloud Firewall (Cloudfw 2017-12-07): access-control policies and
        address books (block/allow/monitor traffic, audit).
      - Security Center (Sas 2018-12-03): alert (alarm) event investigation.

    Authentication is via an AccessKey pair (AccessKey ID + Secret) with request
    signing handled by the official Alibaba Cloud SDK — consistent with how the
    AWS connectors use boto3.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    # ------------------------------------------------------------------
    # Test Connection
    # ------------------------------------------------------------------
    def test_connection(self, connectionParameters: dict):
        try:
            from alibabacloud_cloudfw20171207 import models as cloudfw_models
            client = _build_cloudfw_client(connectionParameters)
            # A lightweight, read-only call to validate credentials.
            req = cloudfw_models.DescribeControlPolicyRequest(direction="in", current_page="1", page_size=1)
            client.describe_control_policy(req)
            return {"status": "success", "message": "Connected to Alibaba Cloud successfully."}
        except Exception as e:
            self.logger.error("Exception while testing Alibaba Cloud connection", exc_info=e)
            raise Exception(str(e))

    # ==================================================================
    # Cloud Firewall — Remediate
    # ==================================================================

    def add_control_policy(self, request: RequestBody) -> ResponseBody:
        """
        Create a Cloud Firewall access-control policy (block/allow/monitor).
        Required: acl_action (accept/drop/log), direction (in/out), source,
            source_type, destination, destination_type, proto, description, new_order.
        """
        from alibabacloud_cloudfw20171207 import models as m
        p = request.parameters
        try:
            client = _build_cloudfw_client(request.connectionParameters)
            req = m.AddControlPolicyRequest(
                acl_action=_param(p, "acl_action"),
                direction=_param(p, "direction"),
                source=_param(p, "source"),
                source_type=_param(p, "source_type"),
                destination=_param(p, "destination"),
                destination_type=_param(p, "destination_type"),
                proto=_param(p, "proto"),
                description=_param(p, "description"),
                new_order=str(_param(p, "new_order")),
            )
            if p.get("application_name"):
                req.application_name = p["application_name"]
            if p.get("dest_port"):
                req.dest_port = p["dest_port"]
            resp = client.add_control_policy(req)
            data = _to_dict(resp)
            self.logger.debug("Alibaba add_control_policy response: %s", data)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in add_control_policy", exc_info=e)
            raise Exception(str(e))

    def modify_control_policy(self, request: RequestBody) -> ResponseBody:
        """
        Modify a Cloud Firewall access-control policy.
        Required: acl_uuid, direction. Optional: acl_action, source, source_type,
            destination, destination_type, proto, description, application_name, dest_port.
        """
        from alibabacloud_cloudfw20171207 import models as m
        p = request.parameters
        try:
            client = _build_cloudfw_client(request.connectionParameters)
            req = m.ModifyControlPolicyRequest(
                acl_uuid=_param(p, "acl_uuid"),
                direction=_param(p, "direction"),
            )
            for field, key in [
                ("acl_action", "acl_action"), ("source", "source"),
                ("source_type", "source_type"), ("destination", "destination"),
                ("destination_type", "destination_type"), ("proto", "proto"),
                ("description", "description"), ("application_name", "application_name"),
                ("dest_port", "dest_port"),
            ]:
                if p.get(key) is not None and str(p.get(key)) != "":
                    setattr(req, field, p[key])
            resp = client.modify_control_policy(req)
            data = _to_dict(resp)
            self.logger.debug("Alibaba modify_control_policy response: %s", data)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in modify_control_policy", exc_info=e)
            raise Exception(str(e))

    def delete_control_policy(self, request: RequestBody) -> ResponseBody:
        """
        Delete a Cloud Firewall access-control policy.
        Required: acl_uuid, direction.
        """
        from alibabacloud_cloudfw20171207 import models as m
        p = request.parameters
        try:
            client = _build_cloudfw_client(request.connectionParameters)
            req = m.DeleteControlPolicyRequest(
                acl_uuid=_param(p, "acl_uuid"),
                direction=_param(p, "direction"),
            )
            resp = client.delete_control_policy(req)
            data = _to_dict(resp)
            self.logger.debug("Alibaba delete_control_policy response: %s", data)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in delete_control_policy", exc_info=e)
            raise Exception(str(e))

    def add_address_book(self, request: RequestBody) -> ResponseBody:
        """
        Create a Cloud Firewall address book (group of IPs/domains/ports).
        Required: group_type, group_name, description, address_list (comma-separated).
        """
        from alibabacloud_cloudfw20171207 import models as m
        p = request.parameters
        try:
            client = _build_cloudfw_client(request.connectionParameters)
            req = m.AddAddressBookRequest(
                group_type=_param(p, "group_type"),
                group_name=_param(p, "group_name"),
                description=_param(p, "description"),
                address_list=_param(p, "address_list"),
            )
            if p.get("auto_add_tag_ecs") is not None and str(p.get("auto_add_tag_ecs")) != "":
                req.auto_add_tag_ecs = str(p["auto_add_tag_ecs"])
            resp = client.add_address_book(req)
            data = _to_dict(resp)
            self.logger.debug("Alibaba add_address_book response: %s", data)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in add_address_book", exc_info=e)
            raise Exception(str(e))

    def modify_address_book(self, request: RequestBody) -> ResponseBody:
        """
        Modify a Cloud Firewall address book (e.g., update its address list).
        Required: group_uuid, address_list (comma-separated).
        Optional: group_name, description, modify_mode (Cover/Append/Delete).
        """
        from alibabacloud_cloudfw20171207 import models as m
        p = request.parameters
        try:
            client = _build_cloudfw_client(request.connectionParameters)
            req = m.ModifyAddressBookRequest(
                group_uuid=_param(p, "group_uuid"),
                address_list=_param(p, "address_list"),
            )
            if p.get("group_name"):
                req.group_name = p["group_name"]
            if p.get("description"):
                req.description = p["description"]
            if p.get("modify_mode"):
                req.modify_mode = p["modify_mode"]
            resp = client.modify_address_book(req)
            data = _to_dict(resp)
            self.logger.debug("Alibaba modify_address_book response: %s", data)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in modify_address_book", exc_info=e)
            raise Exception(str(e))

    def delete_address_book(self, request: RequestBody) -> ResponseBody:
        """
        Delete a Cloud Firewall address book.
        Required: group_uuid.
        """
        from alibabacloud_cloudfw20171207 import models as m
        p = request.parameters
        try:
            client = _build_cloudfw_client(request.connectionParameters)
            req = m.DeleteAddressBookRequest(
                group_uuid=_param(p, "group_uuid"),
            )
            resp = client.delete_address_book(req)
            data = _to_dict(resp)
            self.logger.debug("Alibaba delete_address_book response: %s", data)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in delete_address_book", exc_info=e)
            raise Exception(str(e))

    # ==================================================================
    # Cloud Firewall — Investigate
    # ==================================================================

    def describe_control_policy(self, request: RequestBody) -> ResponseBody:
        """
        List Cloud Firewall access-control policies.
        Required: direction (in/out). Optional: source, destination,
            current_page, page_size.
        """
        from alibabacloud_cloudfw20171207 import models as m
        p = request.parameters
        try:
            client = _build_cloudfw_client(request.connectionParameters)
            req = m.DescribeControlPolicyRequest(
                direction=_param(p, "direction"),
                current_page=str(p.get("current_page", "1")),
                page_size=str(p.get("page_size", "10")),
            )
            if p.get("source"):
                req.source = p["source"]
            if p.get("destination"):
                req.destination = p["destination"]
            resp = client.describe_control_policy(req)
            data = _to_dict(resp)
            self.logger.debug("Alibaba describe_control_policy response: %s", data)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in describe_control_policy", exc_info=e)
            raise Exception(str(e))

    def describe_address_book(self, request: RequestBody) -> ResponseBody:
        """
        List Cloud Firewall address books.
        Optional: group_type, current_page, page_size.
        """
        from alibabacloud_cloudfw20171207 import models as m
        p = request.parameters
        try:
            client = _build_cloudfw_client(request.connectionParameters)
            req = m.DescribeAddressBookRequest(
                current_page=str(p.get("current_page", "1")),
                page_size=str(p.get("page_size", "10")),
            )
            if p.get("group_type"):
                req.group_type = p["group_type"]
            resp = client.describe_address_book(req)
            data = _to_dict(resp)
            self.logger.debug("Alibaba describe_address_book response: %s", data)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in describe_address_book", exc_info=e)
            raise Exception(str(e))

    # ==================================================================
    # Security Center — Investigate
    # ==================================================================

    def describe_alarm_events(self, request: RequestBody) -> ResponseBody:
        """
        List Security Center suspicious (alert) events via the DescribeSuspEvents
        operation.
        Optional: name (event name filter), dealed (Y/N),
            levels (serious/suspicious/remind), current_page, page_size, lang.
        """
        from alibabacloud_sas20181203 import models as m
        p = request.parameters
        try:
            client = _build_sas_client(request.connectionParameters)
            req = m.DescribeSuspEventsRequest(
                current_page=int(p.get("current_page", 1)),
                page_size=int(p.get("page_size", 20)),
            )
            if p.get("name"):
                req.name = p["name"]
            if p.get("dealed"):
                req.dealed = p["dealed"]
            if p.get("levels"):
                req.levels = p["levels"]
            if p.get("lang"):
                req.lang = p["lang"]
            resp = client.describe_susp_events(req)
            data = _to_dict(resp)
            self.logger.debug("Alibaba describe_alarm_events response: %s", data)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in describe_alarm_events", exc_info=e)
            raise Exception(str(e))

    def describe_alarm_event_detail(self, request: RequestBody) -> ResponseBody:
        """
        Get the details of a Security Center alarm (alert) event.
        Required: alarm_unique_info.
        """
        from alibabacloud_sas20181203 import models as m
        p = request.parameters
        try:
            client = _build_sas_client(request.connectionParameters)
            req = m.DescribeAlarmEventDetailRequest(
                alarm_unique_info=_param(p, "alarm_unique_info"),
            )
            if p.get("lang"):
                req.lang = p["lang"]
            resp = client.describe_alarm_event_detail(req)
            data = _to_dict(resp)
            self.logger.debug("Alibaba describe_alarm_event_detail response: %s", data)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in describe_alarm_event_detail", exc_info=e)
            raise Exception(str(e))

    # ==================================================================
    # Security Center — Remediate
    # ==================================================================

    def handle_security_events(self, request: RequestBody) -> ResponseBody:
        """
        Handle (dispose of) one or more Security Center security/alert events.
        Required: security_event_ids (comma-separated IDs), operation_code
            (the handling operation, e.g. block, kill_process, ignore).
        Optional: operation_params, remark, mark_batch (true/false).
        """
        from alibabacloud_sas20181203 import models as m
        p = request.parameters
        try:
            client = _build_sas_client(request.connectionParameters)
            # security_event_ids is a List[str] in the SDK; accept a comma-separated
            # string or an already-provided list.
            raw_ids = _param(p, "security_event_ids")
            if isinstance(raw_ids, list):
                event_ids = [str(x).strip() for x in raw_ids if str(x).strip()]
            else:
                event_ids = [x.strip() for x in str(raw_ids).split(",") if x.strip()]
            req = m.HandleSecurityEventsRequest(
                security_event_ids=event_ids,
                operation_code=_param(p, "operation_code"),
            )
            if p.get("operation_params"):
                req.operation_params = p["operation_params"]
            if p.get("remark"):
                req.remark = p["remark"]
            if p.get("mark_batch") is not None and str(p.get("mark_batch")) != "":
                req.mark_batch = str(p["mark_batch"])
            resp = client.handle_security_events(req)
            data = _to_dict(resp)
            self.logger.debug("Alibaba handle_security_events response: %s", data)
            return {"status": "success", "results": data}
        except Exception as e:
            self.logger.error("Exception in handle_security_events", exc_info=e)
            raise Exception(str(e))
