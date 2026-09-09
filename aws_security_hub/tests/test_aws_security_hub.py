import json
import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError, EndpointConnectionError

from pykson import Pykson
from app.aws_security_hub import AwsSecurityHub
from app.model.request_body import RequestBody

pykson = Pykson()
integration_class = AwsSecurityHub()

CONNECTION_PARAMS = {
    "access_key": "AKIAIOSFODNN7EXAMPLE",
    "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "region": "us-east-1",
}

FINDING_ID = "arn:aws:securityhub:us-east-1:123456789012:finding/test-finding-id"
PRODUCT_ARN = "arn:aws:securityhub:us-east-1::product/aws/guardduty"

SAMPLE_FINDING = {
    "Id": FINDING_ID,
    "ProductArn": PRODUCT_ARN,
    "Title": "Test Finding",
    "Severity": {"Label": "HIGH"},
    "Workflow": {"Status": "NEW"},
}


def _make_request(params=None):
    body = {"connectionParameters": CONNECTION_PARAMS, "parameters": params or {}}
    return pykson.from_json(json.dumps(body), RequestBody, True)


def _client_error(code="AccessDeniedException", message="Access denied"):
    error = {"Error": {"Code": code, "Message": message}}
    return ClientError(error, "operation")


def _endpoint_error():
    return EndpointConnectionError(endpoint_url="https://securityhub.us-east-1.amazonaws.com")


class TestTestConnection:
    @patch("app.aws_security_hub.boto3.client")
    def test_success(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_findings.return_value = {"Findings": []}
        result = integration_class.test_connection(CONNECTION_PARAMS)
        assert result["status"] == "success"
        mock_client.get_findings.assert_called_once_with(MaxResults=1)

    @patch("app.aws_security_hub.boto3.client")
    def test_client_error(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_findings.side_effect = _client_error(message="Access denied")
        with pytest.raises(Exception, match="Access denied"):
            integration_class.test_connection(CONNECTION_PARAMS)

    @patch("app.aws_security_hub.boto3.client")
    def test_endpoint_error(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_findings.side_effect = _endpoint_error()
        with pytest.raises(Exception, match="Unable to connect"):
            integration_class.test_connection(CONNECTION_PARAMS)

    def test_missing_access_key(self):
        with pytest.raises(Exception, match="access_key"):
            integration_class.test_connection({"secret_key": "s", "region": "us-east-1"})

    def test_missing_secret_key(self):
        with pytest.raises(Exception, match="secret_key"):
            integration_class.test_connection({"access_key": "a", "region": "us-east-1"})

    def test_missing_region(self):
        with pytest.raises(Exception, match="region"):
            integration_class.test_connection({"access_key": "a", "secret_key": "s"})


class TestListFindings:
    @patch("app.aws_security_hub.boto3.client")
    def test_success_no_filters(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_findings.return_value = {"Findings": [SAMPLE_FINDING]}
        result = integration_class.list_findings(_make_request())
        assert result["status"] == "success"
        assert result["count"] == 1
        assert result["findings"][0]["Id"] == FINDING_ID

    @patch("app.aws_security_hub.boto3.client")
    def test_success_with_filters(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_findings.return_value = {"Findings": [SAMPLE_FINDING]}
        result = integration_class.list_findings(_make_request({
            "severity_label": "HIGH",
            "workflow_status": "NEW",
            "record_state": "ACTIVE",
            "max_results": 50,
        }))
        assert result["status"] == "success"
        call_kwargs = mock_client.get_findings.call_args[1]
        assert call_kwargs["MaxResults"] == 50
        assert "SeverityLabel" in call_kwargs["Filters"]
        assert "WorkflowStatus" in call_kwargs["Filters"]
        assert "RecordState" in call_kwargs["Filters"]

    @patch("app.aws_security_hub.boto3.client")
    def test_product_name_filter_uses_product_fields(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_findings.return_value = {"Findings": []}
        integration_class.list_findings(_make_request({"product_name": "GuardDuty"}))
        call_kwargs = mock_client.get_findings.call_args[1]
        assert "ProductFields" in call_kwargs["Filters"]
        assert call_kwargs["Filters"]["ProductFields"][0]["Key"] == "ProductName"
        assert call_kwargs["Filters"]["ProductFields"][0]["Value"] == "GuardDuty"

    @patch("app.aws_security_hub.boto3.client")
    def test_pagination_next_token_returned(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_findings.return_value = {"Findings": [SAMPLE_FINDING], "NextToken": "token-abc"}
        result = integration_class.list_findings(_make_request())
        assert result["next_token"] == "token-abc"

    @patch("app.aws_security_hub.boto3.client")
    def test_no_next_token_when_last_page(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_findings.return_value = {"Findings": [SAMPLE_FINDING]}
        result = integration_class.list_findings(_make_request())
        assert "next_token" not in result

    @patch("app.aws_security_hub.boto3.client")
    def test_empty_next_token_not_returned(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_findings.return_value = {"Findings": [], "NextToken": ""}
        result = integration_class.list_findings(_make_request())
        assert "next_token" not in result

    @patch("app.aws_security_hub.boto3.client")
    def test_pagination_next_token_passed(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_findings.return_value = {"Findings": []}
        integration_class.list_findings(_make_request({"next_token": "token-abc"}))
        call_kwargs = mock_client.get_findings.call_args[1]
        assert call_kwargs["NextToken"] == "token-abc"

    def test_invalid_severity_label(self):
        with pytest.raises(Exception, match="severity_label must be one of"):
            integration_class.list_findings(_make_request({"severity_label": "EXTREME"}))

    def test_invalid_workflow_status(self):
        with pytest.raises(Exception, match="workflow_status must be one of"):
            integration_class.list_findings(_make_request({"workflow_status": "CLOSED"}))

    def test_invalid_record_state(self):
        with pytest.raises(Exception, match="record_state must be one of"):
            integration_class.list_findings(_make_request({"record_state": "DELETED"}))

    def test_max_results_too_high(self):
        with pytest.raises(Exception, match="max_results must be an integer between 1 and 100"):
            integration_class.list_findings(_make_request({"max_results": 101}))

    def test_max_results_zero(self):
        with pytest.raises(Exception, match="max_results must be an integer between 1 and 100"):
            integration_class.list_findings(_make_request({"max_results": 0}))

    def test_max_results_invalid_type(self):
        with pytest.raises(Exception, match="max_results must be an integer between 1 and 100"):
            integration_class.list_findings(_make_request({"max_results": "abc"}))

    @patch("app.aws_security_hub.boto3.client")
    def test_max_results_default_100(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_findings.return_value = {"Findings": []}
        integration_class.list_findings(_make_request())
        call_kwargs = mock_client.get_findings.call_args[1]
        assert call_kwargs["MaxResults"] == 100

    @patch("app.aws_security_hub.boto3.client")
    def test_client_error(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_findings.side_effect = _client_error(message="Access denied")
        with pytest.raises(Exception, match="Access denied"):
            integration_class.list_findings(_make_request())

    @patch("app.aws_security_hub.boto3.client")
    def test_endpoint_error(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_findings.side_effect = _endpoint_error()
        with pytest.raises(Exception, match="Unable to connect"):
            integration_class.list_findings(_make_request())


class TestGetFindingDetails:
    @patch("app.aws_security_hub.boto3.client")
    def test_success(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_findings.return_value = {"Findings": [SAMPLE_FINDING]}
        result = integration_class.get_finding_details(_make_request({
            "finding_id": FINDING_ID,
            "product_arn": PRODUCT_ARN,
        }))
        assert result["status"] == "success"
        assert result["finding"]["Id"] == FINDING_ID

    @patch("app.aws_security_hub.boto3.client")
    def test_not_found_raises(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_findings.return_value = {"Findings": []}
        with pytest.raises(Exception, match="Finding not found."):
            integration_class.get_finding_details(_make_request({
                "finding_id": FINDING_ID,
                "product_arn": PRODUCT_ARN,
            }))

    def test_missing_finding_id(self):
        with pytest.raises(Exception, match="finding_id"):
            integration_class.get_finding_details(_make_request({"product_arn": PRODUCT_ARN}))

    def test_missing_product_arn(self):
        with pytest.raises(Exception, match="product_arn"):
            integration_class.get_finding_details(_make_request({"finding_id": FINDING_ID}))

    @patch("app.aws_security_hub.boto3.client")
    def test_filters_applied_correctly(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_findings.return_value = {"Findings": [SAMPLE_FINDING]}
        integration_class.get_finding_details(_make_request({
            "finding_id": FINDING_ID,
            "product_arn": PRODUCT_ARN,
        }))
        call_kwargs = mock_client.get_findings.call_args[1]
        assert call_kwargs["Filters"]["Id"][0]["Value"] == FINDING_ID
        assert call_kwargs["Filters"]["ProductArn"][0]["Value"] == PRODUCT_ARN
        assert call_kwargs["MaxResults"] == 1


class TestUpdateFindingWorkflowStatus:
    @patch("app.aws_security_hub.boto3.client")
    def test_success(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.batch_update_findings.return_value = {
            "ProcessedFindings": [{"Id": FINDING_ID, "ProductArn": PRODUCT_ARN}],
            "UnprocessedFindings": [],
        }
        result = integration_class.update_finding_workflow_status(_make_request({
            "finding_id": FINDING_ID,
            "product_arn": PRODUCT_ARN,
            "workflow_status": "RESOLVED",
        }))
        assert result["status"] == "success"
        assert "RESOLVED" in result["message"]
        assert len(result["processed_findings"]) == 1

    def test_missing_finding_id(self):
        with pytest.raises(Exception, match="finding_id"):
            integration_class.update_finding_workflow_status(_make_request({
                "product_arn": PRODUCT_ARN, "workflow_status": "NEW"
            }))

    def test_missing_product_arn(self):
        with pytest.raises(Exception, match="product_arn"):
            integration_class.update_finding_workflow_status(_make_request({
                "finding_id": FINDING_ID, "workflow_status": "NEW"
            }))

    def test_missing_workflow_status(self):
        with pytest.raises(Exception, match="workflow_status"):
            integration_class.update_finding_workflow_status(_make_request({
                "finding_id": FINDING_ID, "product_arn": PRODUCT_ARN
            }))

    def test_invalid_workflow_status(self):
        with pytest.raises(Exception, match="workflow_status must be one of"):
            integration_class.update_finding_workflow_status(_make_request({
                "finding_id": FINDING_ID, "product_arn": PRODUCT_ARN, "workflow_status": "CLOSED"
            }))

    @patch("app.aws_security_hub.boto3.client")
    def test_client_error(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.batch_update_findings.side_effect = _client_error(message="Invalid finding")
        with pytest.raises(Exception, match="Invalid finding"):
            integration_class.update_finding_workflow_status(_make_request({
                "finding_id": FINDING_ID, "product_arn": PRODUCT_ARN, "workflow_status": "NEW"
            }))


class TestUpdateFindingSeverity:
    @patch("app.aws_security_hub.boto3.client")
    def test_success(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.batch_update_findings.return_value = {
            "ProcessedFindings": [{"Id": FINDING_ID, "ProductArn": PRODUCT_ARN}],
            "UnprocessedFindings": [],
        }
        result = integration_class.update_finding_severity(_make_request({
            "finding_id": FINDING_ID,
            "product_arn": PRODUCT_ARN,
            "severity_label": "CRITICAL",
        }))
        assert result["status"] == "success"
        assert "CRITICAL" in result["message"]

    def test_invalid_severity_label(self):
        with pytest.raises(Exception, match="severity_label must be one of"):
            integration_class.update_finding_severity(_make_request({
                "finding_id": FINDING_ID, "product_arn": PRODUCT_ARN, "severity_label": "EXTREME"
            }))

    def test_missing_severity_label(self):
        with pytest.raises(Exception, match="severity_label"):
            integration_class.update_finding_severity(_make_request({
                "finding_id": FINDING_ID, "product_arn": PRODUCT_ARN
            }))

    @patch("app.aws_security_hub.boto3.client")
    def test_severity_passed_to_api(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.batch_update_findings.return_value = {"ProcessedFindings": [], "UnprocessedFindings": []}
        integration_class.update_finding_severity(_make_request({
            "finding_id": FINDING_ID, "product_arn": PRODUCT_ARN, "severity_label": "LOW"
        }))
        call_kwargs = mock_client.batch_update_findings.call_args[1]
        assert call_kwargs["Severity"] == {"Label": "LOW"}


class TestAddUpdateFindingNote:
    @patch("app.aws_security_hub.boto3.client")
    def test_success(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.batch_update_findings.return_value = {
            "ProcessedFindings": [{"Id": FINDING_ID, "ProductArn": PRODUCT_ARN}],
            "UnprocessedFindings": [],
        }
        result = integration_class.add_update_finding_note(_make_request({
            "finding_id": FINDING_ID,
            "product_arn": PRODUCT_ARN,
            "note_text": "Investigated and confirmed false positive.",
            "note_updated_by": "analyst@example.com",
        }))
        assert result["status"] == "success"
        assert len(result["processed_findings"]) == 1

    def test_missing_note_text(self):
        with pytest.raises(Exception, match="note_text"):
            integration_class.add_update_finding_note(_make_request({
                "finding_id": FINDING_ID, "product_arn": PRODUCT_ARN, "note_updated_by": "analyst"
            }))

    def test_missing_note_updated_by(self):
        with pytest.raises(Exception, match="note_updated_by"):
            integration_class.add_update_finding_note(_make_request({
                "finding_id": FINDING_ID, "product_arn": PRODUCT_ARN, "note_text": "some note"
            }))

    @patch("app.aws_security_hub.boto3.client")
    def test_note_passed_to_api(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.batch_update_findings.return_value = {"ProcessedFindings": [], "UnprocessedFindings": []}
        integration_class.add_update_finding_note(_make_request({
            "finding_id": FINDING_ID, "product_arn": PRODUCT_ARN,
            "note_text": "Test note", "note_updated_by": "analyst",
        }))
        call_kwargs = mock_client.batch_update_findings.call_args[1]
        assert call_kwargs["Note"] == {"Text": "Test note", "UpdatedBy": "analyst"}


class TestGetFindingHistory:
    @patch("app.aws_security_hub.boto3.client")
    def test_success(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_finding_history.return_value = {
            "Records": [{"FindingIdentifier": {"Id": FINDING_ID}, "UpdateTime": "2024-01-01T00:00:00Z"}]
        }
        result = integration_class.get_finding_history(_make_request({
            "finding_id": FINDING_ID,
            "product_arn": PRODUCT_ARN,
        }))
        assert result["status"] == "success"
        assert result["count"] == 1

    @patch("app.aws_security_hub.boto3.client")
    def test_pagination_next_token(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_finding_history.return_value = {"Records": [], "NextToken": "hist-token"}
        result = integration_class.get_finding_history(_make_request({
            "finding_id": FINDING_ID, "product_arn": PRODUCT_ARN
        }))
        assert result["next_token"] == "hist-token"

    @patch("app.aws_security_hub.boto3.client")
    def test_no_next_token_when_last_page(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_finding_history.return_value = {"Records": []}
        result = integration_class.get_finding_history(_make_request({
            "finding_id": FINDING_ID, "product_arn": PRODUCT_ARN
        }))
        assert "next_token" not in result

    def test_missing_finding_id(self):
        with pytest.raises(Exception, match="finding_id"):
            integration_class.get_finding_history(_make_request({"product_arn": PRODUCT_ARN}))

    def test_missing_product_arn(self):
        with pytest.raises(Exception, match="product_arn"):
            integration_class.get_finding_history(_make_request({"finding_id": FINDING_ID}))

    def test_max_results_validation(self):
        with pytest.raises(Exception, match="max_results must be an integer between 1 and 100"):
            integration_class.get_finding_history(_make_request({
                "finding_id": FINDING_ID, "product_arn": PRODUCT_ARN, "max_results": 200
            }))

    @patch("app.aws_security_hub.boto3.client")
    def test_optional_time_range_passed(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_finding_history.return_value = {"Records": []}
        integration_class.get_finding_history(_make_request({
            "finding_id": FINDING_ID, "product_arn": PRODUCT_ARN,
            "start_time": "2024-01-01T00:00:00Z", "end_time": "2024-01-31T00:00:00Z",
        }))
        call_kwargs = mock_client.get_finding_history.call_args[1]
        from datetime import datetime, timezone
        assert call_kwargs["StartTime"] == datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert call_kwargs["EndTime"] == datetime(2024, 1, 31, 0, 0, 0, tzinfo=timezone.utc)


class TestGetInsightResults:
    @patch("app.aws_security_hub.boto3.client")
    def test_success(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_insight_results.return_value = {
            "InsightResults": {
                "InsightArn": "arn:aws:securityhub:::insight/aws/securityhub/1",
                "GroupByAttribute": "SeverityLabel",
                "ResultValues": [
                    {"GroupByAttributeValue": "HIGH", "Count": 5},
                    {"GroupByAttributeValue": "MEDIUM", "Count": 3},
                ],
            }
        }
        result = integration_class.get_insight_results(_make_request({
            "insight_arn": "arn:aws:securityhub:::insight/aws/securityhub/1"
        }))
        assert result["status"] == "success"
        assert result["count"] == 2
        assert result["insight_results"][0]["GroupByAttributeValue"] == "HIGH"

    def test_missing_insight_arn(self):
        with pytest.raises(Exception, match="insight_arn"):
            integration_class.get_insight_results(_make_request({}))

    @patch("app.aws_security_hub.boto3.client")
    def test_client_error(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_insight_results.side_effect = _client_error(message="Insight not found")
        with pytest.raises(Exception, match="Insight not found"):
            integration_class.get_insight_results(_make_request({
                "insight_arn": "arn:aws:securityhub:::insight/aws/securityhub/1"
            }))

    @patch("app.aws_security_hub.boto3.client")
    def test_endpoint_error(self, mock_boto):
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        mock_client.get_insight_results.side_effect = _endpoint_error()
        with pytest.raises(Exception, match="Unable to connect"):
            integration_class.get_insight_results(_make_request({
                "insight_arn": "arn:aws:securityhub:::insight/aws/securityhub/1"
            }))
