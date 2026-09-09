import logging
from datetime import datetime

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from app.model.request_body import RequestBody

VALID_SEVERITY_LABELS = ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")
VALID_WORKFLOW_STATUSES = ("NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED")
VALID_RECORD_STATES = ("ACTIVE", "ARCHIVED")


def _get_client(connection_params: dict):
    access_key = connection_params.get("access_key")
    secret_key = connection_params.get("secret_key")
    region = connection_params.get("region")

    if not access_key:
        raise Exception("Missing required connection parameter: access_key")
    if not secret_key:
        raise Exception("Missing required connection parameter: secret_key")
    if not region:
        raise Exception("Missing required connection parameter: region")

    return boto3.client(
        "securityhub",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )


def _validate_required(value, field_name: str):
    if not value or (isinstance(value, str) and not value.strip()):
        raise Exception(f"Missing required parameter: {field_name}")
    return value.strip() if isinstance(value, str) else value


def _validate_max_results(value, default: int = 100) -> int:
    if value is None:
        return default
    try:
        n = int(value)
    except (ValueError, TypeError):
        raise Exception("max_results must be an integer between 1 and 100")
    if not 1 <= n <= 100:
        raise Exception("max_results must be an integer between 1 and 100")
    return n


class AwsSecurityHub:

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    def test_connection(self, connectionParameters: dict):
        try:
            client = _get_client(connectionParameters)
            client.get_findings(MaxResults=1)
            return {"status": "success", "message": "Connected to AWS Security Hub successfully."}
        except ClientError as e:
            self.logger.error("Exception while testing connection", exc_info=e)
            raise Exception(e.response["Error"]["Message"])
        except EndpointConnectionError as e:
            self.logger.error("Exception while testing connection", exc_info=e)
            raise Exception("Unable to connect to AWS Security Hub endpoint.")
        except Exception as e:
            self.logger.error("Exception while testing connection", exc_info=e)
            raise Exception(str(e))

    def list_findings(self, request: RequestBody) -> dict:
        try:
            client = _get_client(request.connectionParameters)
            params = request.parameters or {}

            max_results = _validate_max_results(params.get("max_results"))
            filters = {}

            severity_label = params.get("severity_label")
            if severity_label:
                if severity_label not in VALID_SEVERITY_LABELS:
                    raise Exception(f"severity_label must be one of: {', '.join(VALID_SEVERITY_LABELS)}")
                filters["SeverityLabel"] = [{"Value": severity_label, "Comparison": "EQUALS"}]

            workflow_status = params.get("workflow_status")
            if workflow_status:
                if workflow_status not in VALID_WORKFLOW_STATUSES:
                    raise Exception(f"workflow_status must be one of: {', '.join(VALID_WORKFLOW_STATUSES)}")
                filters["WorkflowStatus"] = [{"Value": workflow_status, "Comparison": "EQUALS"}]

            record_state = params.get("record_state")
            if record_state:
                if record_state not in VALID_RECORD_STATES:
                    raise Exception(f"record_state must be one of: {', '.join(VALID_RECORD_STATES)}")
                filters["RecordState"] = [{"Value": record_state, "Comparison": "EQUALS"}]

            product_name = params.get("product_name")
            if product_name:
                # Security Hub applies ProductName filtering against ProductFields, not the top-level ProductName field
                filters["ProductFields"] = [{"Key": "ProductName", "Value": product_name, "Comparison": "EQUALS"}]

            kwargs = {"MaxResults": max_results}
            if filters:
                kwargs["Filters"] = filters

            next_token = params.get("next_token")
            if next_token:
                kwargs["NextToken"] = next_token

            response = client.get_findings(**kwargs)
            findings = response.get("Findings", [])
            result = {
                "status": "success",
                "findings": findings,
                "count": len(findings),
            }
            if response.get("NextToken"):
                result["next_token"] = response["NextToken"]
            return result

        except ClientError as e:
            self.logger.error("Error in list_findings", exc_info=e)
            raise Exception(e.response["Error"]["Message"])
        except EndpointConnectionError as e:
            self.logger.error("Error in list_findings", exc_info=e)
            raise Exception("Unable to connect to AWS Security Hub endpoint.")
        except Exception as e:
            self.logger.error("Error in list_findings", exc_info=e)
            raise Exception(str(e))

    def get_finding_details(self, request: RequestBody) -> dict:
        try:
            client = _get_client(request.connectionParameters)
            params = request.parameters or {}

            finding_id = _validate_required(params.get("finding_id"), "finding_id")
            product_arn = _validate_required(params.get("product_arn"), "product_arn")

            response = client.get_findings(
                Filters={
                    "Id": [{"Value": finding_id, "Comparison": "EQUALS"}],
                    "ProductArn": [{"Value": product_arn, "Comparison": "EQUALS"}],
                },
                MaxResults=1,
            )
            findings = response.get("Findings", [])
            if not findings:
                raise Exception("Finding not found.")

            return {"status": "success", "finding": findings[0]}

        except ClientError as e:
            self.logger.error("Error in get_finding_details", exc_info=e)
            raise Exception(e.response["Error"]["Message"])
        except EndpointConnectionError as e:
            self.logger.error("Error in get_finding_details", exc_info=e)
            raise Exception("Unable to connect to AWS Security Hub endpoint.")
        except Exception as e:
            self.logger.error("Error in get_finding_details", exc_info=e)
            raise Exception(str(e))

    def update_finding_workflow_status(self, request: RequestBody) -> dict:
        try:
            client = _get_client(request.connectionParameters)
            params = request.parameters or {}

            finding_id = _validate_required(params.get("finding_id"), "finding_id")
            product_arn = _validate_required(params.get("product_arn"), "product_arn")
            workflow_status = _validate_required(params.get("workflow_status"), "workflow_status")

            if workflow_status not in VALID_WORKFLOW_STATUSES:
                raise Exception(f"workflow_status must be one of: {', '.join(VALID_WORKFLOW_STATUSES)}")

            response = client.batch_update_findings(
                FindingIdentifiers=[{"Id": finding_id, "ProductArn": product_arn}],
                Workflow={"Status": workflow_status},
            )
            return {
                "status": "success",
                "message": f"Workflow status updated to '{workflow_status}' successfully.",
                "processed_findings": response.get("ProcessedFindings", []),
                "unprocessed_findings": response.get("UnprocessedFindings", []),
            }

        except ClientError as e:
            self.logger.error("Error in update_finding_workflow_status", exc_info=e)
            raise Exception(e.response["Error"]["Message"])
        except EndpointConnectionError as e:
            self.logger.error("Error in update_finding_workflow_status", exc_info=e)
            raise Exception("Unable to connect to AWS Security Hub endpoint.")
        except Exception as e:
            self.logger.error("Error in update_finding_workflow_status", exc_info=e)
            raise Exception(str(e))

    def update_finding_severity(self, request: RequestBody) -> dict:
        try:
            client = _get_client(request.connectionParameters)
            params = request.parameters or {}

            finding_id = _validate_required(params.get("finding_id"), "finding_id")
            product_arn = _validate_required(params.get("product_arn"), "product_arn")
            severity_label = _validate_required(params.get("severity_label"), "severity_label")

            if severity_label not in VALID_SEVERITY_LABELS:
                raise Exception(f"severity_label must be one of: {', '.join(VALID_SEVERITY_LABELS)}")

            response = client.batch_update_findings(
                FindingIdentifiers=[{"Id": finding_id, "ProductArn": product_arn}],
                Severity={"Label": severity_label},
            )
            return {
                "status": "success",
                "message": f"Severity updated to '{severity_label}' successfully.",
                "processed_findings": response.get("ProcessedFindings", []),
                "unprocessed_findings": response.get("UnprocessedFindings", []),
            }

        except ClientError as e:
            self.logger.error("Error in update_finding_severity", exc_info=e)
            raise Exception(e.response["Error"]["Message"])
        except EndpointConnectionError as e:
            self.logger.error("Error in update_finding_severity", exc_info=e)
            raise Exception("Unable to connect to AWS Security Hub endpoint.")
        except Exception as e:
            self.logger.error("Error in update_finding_severity", exc_info=e)
            raise Exception(str(e))

    def add_update_finding_note(self, request: RequestBody) -> dict:
        try:
            client = _get_client(request.connectionParameters)
            params = request.parameters or {}

            finding_id = _validate_required(params.get("finding_id"), "finding_id")
            product_arn = _validate_required(params.get("product_arn"), "product_arn")
            note_text = _validate_required(params.get("note_text"), "note_text")
            note_updated_by = _validate_required(params.get("note_updated_by"), "note_updated_by")

            response = client.batch_update_findings(
                FindingIdentifiers=[{"Id": finding_id, "ProductArn": product_arn}],
                Note={"Text": note_text, "UpdatedBy": note_updated_by},
            )
            return {
                "status": "success",
                "message": "Finding note updated successfully.",
                "processed_findings": response.get("ProcessedFindings", []),
                "unprocessed_findings": response.get("UnprocessedFindings", []),
            }

        except ClientError as e:
            self.logger.error("Error in add_update_finding_note", exc_info=e)
            raise Exception(e.response["Error"]["Message"])
        except EndpointConnectionError as e:
            self.logger.error("Error in add_update_finding_note", exc_info=e)
            raise Exception("Unable to connect to AWS Security Hub endpoint.")
        except Exception as e:
            self.logger.error("Error in add_update_finding_note", exc_info=e)
            raise Exception(str(e))

    def get_finding_history(self, request: RequestBody) -> dict:
        try:
            client = _get_client(request.connectionParameters)
            params = request.parameters or {}

            finding_id = _validate_required(params.get("finding_id"), "finding_id")
            product_arn = _validate_required(params.get("product_arn"), "product_arn")
            max_results = _validate_max_results(params.get("max_results"))

            kwargs = {
                "FindingIdentifier": {"Id": finding_id, "ProductArn": product_arn},
                "MaxResults": max_results,
            }
            if params.get("start_time"):
                kwargs["StartTime"] = datetime.fromisoformat(params["start_time"].replace("Z", "+00:00"))
            if params.get("end_time"):
                kwargs["EndTime"] = datetime.fromisoformat(params["end_time"].replace("Z", "+00:00"))
            if params.get("next_token"):
                kwargs["NextToken"] = params["next_token"]

            response = client.get_finding_history(**kwargs)
            records = response.get("Records", [])
            result = {
                "status": "success",
                "records": records,
                "count": len(records),
            }
            if response.get("NextToken"):
                result["next_token"] = response["NextToken"]
            return result

        except ClientError as e:
            self.logger.error("Error in get_finding_history", exc_info=e)
            raise Exception(e.response["Error"]["Message"])
        except EndpointConnectionError as e:
            self.logger.error("Error in get_finding_history", exc_info=e)
            raise Exception("Unable to connect to AWS Security Hub endpoint.")
        except Exception as e:
            self.logger.error("Error in get_finding_history", exc_info=e)
            raise Exception(str(e))

    def get_insight_results(self, request: RequestBody) -> dict:
        try:
            client = _get_client(request.connectionParameters)
            params = request.parameters or {}

            insight_arn = _validate_required(params.get("insight_arn"), "insight_arn")

            response = client.get_insight_results(InsightArn=insight_arn)
            results = response.get("InsightResults", {}).get("ResultValues", [])
            return {
                "status": "success",
                "insight_arn": insight_arn,
                "insight_results": results,
                "count": len(results),
            }

        except ClientError as e:
            self.logger.error("Error in get_insight_results", exc_info=e)
            raise Exception(e.response["Error"]["Message"])
        except EndpointConnectionError as e:
            self.logger.error("Error in get_insight_results", exc_info=e)
            raise Exception("Unable to connect to AWS Security Hub endpoint.")
        except Exception as e:
            self.logger.error("Error in get_insight_results", exc_info=e)
            raise Exception(str(e))
