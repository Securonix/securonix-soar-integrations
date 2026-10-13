# Vectra AI SOAR Connector - Development Guide

## Overview

This document provides comprehensive guidance for developing and maintaining the Vectra AI SOAR connector. Vectra AI is a breach detection system that identifies and prioritizes threats in real-time using behavioral analysis and machine learning.

## API Documentation

**Current Version**: v3.4 and v3.5 (Public Preview)

**Base URL**: `https://{apiBaseUrl}/api`

**Authentication**: OAuth2 (Client Credentials Grant)

**API Reference**: `/Users/pkamble/Downloads/vectraai-rest-api.yaml`

### OAuth2 Authentication

The connector uses OAuth2 with the `client_credentials` grant type:

```
POST /oauth2/token
Authorization: Basic <base64(client_id:client_secret)>
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
```

**Response**:
```json
{
  "access_token": "eyJhbG...",
  "expires_in": 3600,
  "refresh_expires_in": 86400,
  "refresh_token": "eyJhbG...",
  "token_type": "Bearer"
}
```

## Connector Architecture

### Folder Structure

```
vectra_ai/
├── app/
│   ├── __init__.py
│   ├── vectra_ai.py          # Main connector class
│   └── model/
│       ├── __init__.py
│       ├── request_body.py   # RequestBody model
│       └── response_body.py  # ResponseBody model
├── tests/
│   ├── __init__.py
│   └── test_vectra_ai.py     # Unit tests
├── __init__.py
├── integration_definition.json
├── integration_meta.json
├── integration_meta_schema.json
├── requirements.txt
└── DEV_GUIDE.md              # This file
```

### Action Hierarchy

| Category | Actions | Purpose |
|----------|---------|---------|
| **Investigate** | `get_detections`, `get_detection_by_id`, `get_accounts`, `get_account_by_id`, `get_hosts`, `get_host_by_id`, `get_entities`, `get_entity_by_id`, `get_findings`, `get_finding_by_id`, `get_host_findings`, `get_assignments`, `get_assignment_by_id`, `get_assignment_outcomes`, `get_detection_events` | Retrieve security events, entities, findings, and assignments |
| **Analyze** | `search_detections_by_criteria` | Advanced detection filtering and analysis |
| **Remediate** | `mark_detection_fixed`, `close_account`, `set_host_as_key_asset`, `create_assignment_outcome` | Take corrective actions on detected threats |

## SOAR Functions

### Investigate Functions

#### 1. get_detections
**Description**: Retrieve a paginated list of detections with optional filtering

**Parameters**:
- `ordering` (String): Field to order results by (e.g., `last_timestamp`, `-threat`)
- `page` (Number): Page number for pagination
- `page_size` (Number): Number of results per page
- `detection_category` (String): Filter by category (command, botnet, reconnaissance, lateral, exfiltration, info)
- `state` (String): Filter by state (active, closed)
- `threat` (Number): Minimum threat score
- `certainty` (Number): Minimum certainty score
- `is_targeting_key_asset` (Boolean): Filter for key asset targets
- `is_triaged` (Boolean): Filter for triaged detections
- `created_timestamp_gte` (String): ISO8601 start date
- `created_timestamp_lte` (String): ISO8601 end date
- `fields` (String): Comma-separated list of fields to include
- `exclude_fields` (String): Comma-separated list of fields to exclude
- `size` (String): Response tier (small, regular, detailed)

**Output**: Paginated list of detection objects

#### 2. get_detection_by_id
**Description**: Retrieve a single detection by ID

**Parameters**:
- `detection_id` (Number): Detection ID

**Output**: Detailed detection object

#### 3. get_accounts
**Description**: Retrieve a paginated list of accounts

**Parameters**:
- `ordering` (String): Field to order results by
- `page` (Number): Page number
- `page_size` (Number): Results per page
- `state` (String): Filter by state (active, closed)
- `threat` (Number): Minimum threat score
- `fields` (String): Fields to include
- `exclude_fields` (String): Fields to exclude
- `size` (String): Response tier

**Output**: Paginated list of account objects

#### 4. get_account_by_id
**Description**: Retrieve a single account by ID

**Parameters**:
- `account_id` (Number): Account ID

**Output**: Detailed account object

#### 5. get_hosts
**Description**: Retrieve a paginated list of hosts

**Parameters**:
- `ordering` (String): Field to order results by
- `page` (Number): Page number
- `page_size` (Number): Results per page
- `state` (String): Filter by state (active, closed)
- `threat` (Number): Minimum threat score
- `fields` (String): Fields to include
- `exclude_fields` (String): Fields to exclude
- `size` (String): Response tier

**Output**: Paginated list of host objects

#### 6. get_host_by_id
**Description**: Retrieve a single host by ID

**Parameters**:
- `host_id` (Number): Host ID

**Output**: Detailed host object

#### 7. get_entities
**Description**: Retrieve a paginated list of entities (hosts and accounts)

**Parameters**:
- `ordering` (String): Field to order results by
- `page` (Number): Page number
- `page_size` (Number): Results per page
- `type` (String): Filter by type (host, account)
- `fields` (String): Fields to include
- `exclude_fields` (String): Fields to exclude

**Output**: Paginated list of entity objects

#### 8. get_entity_by_id
**Description**: Retrieve a single entity by ID

**Parameters**:
- `entity_id` (Number): Entity ID
- `type` (String): Entity type (host or account)

**Output**: Detailed entity object

### Analyze Functions

#### 9. search_detections_by_criteria
**Description**: Advanced detection search with multiple filter criteria

**Parameters**:
- `src_ip` (String): Source IP address
- `src_account` (String): Source account name
- `detection_category` (String): Detection category
- `threat_gte` (Number): Minimum threat score
- `created_timestamp_gte` (String): Start date
- `is_targeting_key_asset` (Boolean): Key asset filter
- `tags` (String): Tag filter
- `external_reference_id` (String): External ticket ID

**Output**: List of matching detections

### Remediate Functions

#### 10. mark_detection_fixed
**Description**: Mark one or more detections as fixed

**Parameters**:
- `detection_id_list` (Array): List of detection IDs to mark as fixed
- `external_reference_id` (String): Optional external ticket reference
- `investigation_status` (String): Status (open, acknowledged, escalated, paused, closed, expired)

**Output**: Success message with list of updated detections

#### 11. close_account
**Description**: Close an account and its associated detections

**Parameters**:
- `account_id` (Number): Account ID
- `reason` (String): Close reason (remediated, benign)

**Output**: Success message with list of closed detections

#### 12. set_host_as_key_asset
**Description**: Mark a host as a key asset

**Parameters**:
- `host_id` (Number): Host ID
- `key_asset` (Boolean): Set to true to mark as key asset

**Output**: Success message

## Implementation Details

### Request/Response Models

All requests use the `RequestBody` model with:
- `connectionParameters`: API credentials (host, client_id, client_secret)
- `parameters`: Action-specific parameters

All responses use the `ResponseBody` model with:
- `status`: success/error
- `results`: Response data
- `message`: Human-readable message

### Error Handling

Standard error responses:
- `401`: Authentication error (invalid credentials)
- `403`: Authorization error (insufficient permissions)
- `404`: Not found
- `429`: Rate limit exceeded
- `500`: Internal server error
- `503`: Service unavailable
- `504`: Gateway timeout

### Pagination

All list endpoints support pagination via:
- `page` and `page_size` query parameters
- `next` and `previous` URLs in response

### Field Selection

Supports `fields` and `exclude_fields` query parameters to control response size.


### Test Categories

1. **Authentication Tests**: Verify OAuth2 token acquisition and expiration handling
2. **Investigation Tests**: Test all read operations with various filters
3. **Remediation Tests**: Test action operations with valid and invalid inputs
4. **Error Handling Tests**: Verify proper error responses
5. **Pagination Tests**: Verify pagination works correctly

### Running Tests

```bash
cd vectra_ai
pytest tests/test_vectra_ai.py -v
coverage run -m pytest tests/test_vectra_ai.py
coverage report -m
```

### Integration Configuration

### Connection Parameters

| Parameter | Type | Required | Encrypted | Description |
|-----------|------|----------|-----------|-------------|
| `api_host` | String | Yes | No | Vectra brain FQDN or IP address |
| `client_id` | String | Yes | Yes | OAuth2 client ID |
| `client_secret` | String | Yes | Yes | OAuth2 client secret |
| `verify_ssl` | Boolean | No | No | Verify SSL certificate |

### Sample Connection Parameters

```json
{
  "api_host": "https://vectra.mycompany.com",
  "client_id": "my_client_id",
  "client_secret": "my_client_secret",
  "verify_ssl": true
}
```

### Deployment Checklist

- [ ] OAuth2 credentials obtained from Vectra admin
- [ ] API host URL configured
- [ ] SSL verification settings determined
- [ ] Test connection parameters
- [ ] Verify detection listing works
- [ ] Verify remediation actions work
- [ ] Configure error notifications

### Known Limitations

1. **API Versioning**: Connector supports both v3.4 and v3.5 APIs. v3.5 features are marked as "unreleased"
2. **Pagination**: Large result sets may require multiple API calls
3. **Rate Limiting**: API has rate limits (429 responses). Implement exponential backoff for production use.
4. **Token Expiration**: Access tokens expire after 1 hour. Implement token refresh logic.

### Future Enhancements

- [ ] Add event stream polling for real-time detection updates
- [ ] Add bulk remediation operations
- [ ] Add detection correlation across multiple Vectra instances
- [ ] Add custom field mapping for external ticketing systems
- [ ] Add health check endpoint status monitoring

### Support

For API questions or issues, contact Vectra support at support@vectra.ai

### Additional SOAR Functions

#### 21. get_detection_by_id_patch
**Description**: Retrieve a single detection by ID using the PATCH method (alternative endpoint)

**Parameters**:
- `detection_id` (Number): Detection ID
- `fields` (String): Fields to include
- `exclude_fields` (String): Fields to exclude

**Output**: Detailed detection object

#### 22. patch_single_entity
**Description**: Update a single entity (host or account) with new values

**Parameters**:
- `entity_id` (Number): Entity ID
- `type` (String): Entity type (host, account)
- `mark_as_fixed` (Boolean): Mark detection as fixed
- `threat` (Number): New threat score
- `certainty` (Number): New certainty score
- `state` (String): New state (active, closed)
- `detection_tags` (Array): Array of tags to add
- `detection_category` (String): Detection category
- `detection_notes` (String): Detection notes

**Output**: Updated entity object

#### 23. delete_assignment_outcome
**Description**: Delete an assignment outcome by ID

**Parameters**:
- `outcome_id` (Number): Assignment outcome ID

**Output**: Success message

#### 24. update_assignment_outcome
**Description**: Update an existing assignment outcome

**Parameters**:
- `outcome_id` (Number): Assignment outcome ID
- `title` (String): Updated title
- `category` (String): Updated category
- `description` (String): Updated description

**Output**: Updated assignment outcome object

#### 25. get_assignment_outcome_by_id
**Description**: Get a single assignment outcome by its ID

**Parameters**:
- `outcome_id` (Number): Assignment outcome ID

**Output**: Detailed assignment outcome object

#### 26. get_rules
**Description**: Get a paginated list of rules for detection configuration

**Parameters**:
- `page` (Number): Page number
- `page_size` (Number): Results per page
- `ordering` (String): Order by field
- `name` (String): Filter by rule name
- `category` (String): Filter by category
- `severity` (String): Filter by severity
- `enabled` (Boolean): Filter by enabled status

**Output**: Paginated list of rule objects

#### 27. create_rules
**Description**: Create a new rule for detection configuration

**Parameters**:
- `name` (String): Rule name
- `category` (String): Rule category
- `severity` (String): Rule severity
- `enabled` (Boolean): Enable rule
- `detection_parameters` (Object): Detection parameters
- `description` (String): Rule description

**Output**: Created rule object

#### 28. update_rules
**Description**: Update an existing rule

**Parameters**:
- `rule_id` (Number): Rule ID
- `name` (String): Updated rule name
- `category` (String): Updated category
- `severity` (String): Updated severity
- `enabled` (Boolean): Updated enabled status
- `detection_parameters` (Object): Updated detection parameters
- `description` (String): Updated description

**Output**: Updated rule object

#### 29. delete_rules
**Description**: Delete a rule by ID

**Parameters**:
- `rule_id` (Number): Rule ID

**Output**: Success message

#### 30. get_rules_by_id
**Description**: Get a single rule by its ID

**Parameters**:
- `rule_id` (Number): Rule ID

**Output**: Detailed rule object

#### 31. create_assignment
**Description**: Create a new assignment for analyst workflow management

**Parameters**:
- `title` (String): Assignment title
- `description` (String): Assignment description
- `accounts` (Array): Array of account IDs
- `hosts` (Array): Array of host IDs
- `assignees` (Array): Array of assignee usernames
- `resolution` (String): Initial resolution status

**Output**: Created assignment object

#### 32. update_assignment
**Description**: Update an existing assignment

**Parameters**:
- `assignment_id` (Number): Assignment ID
- `title` (String): Updated title
- `description` (String): Updated description
- `accounts` (Array): Updated array of account IDs
- `hosts` (Array): Updated array of host IDs
- `assignees` (Array): Updated array of assignee usernames
- `resolution` (String): Updated resolution status

**Output**: Updated assignment object

#### 33. delete_assignment
**Description**: Delete an assignment by ID

**Parameters**:
- `assignment_id` (Number): Assignment ID

**Output**: Success message

#### 34. get_single_detection_events
**Description**: Get detection events for a single detection

**Parameters**:
- `detection_id` (Number): Detection ID
- `from` (Number): Checkpoint ID to start from
- `event_timestamp_gte` (String): Start date (ISO8601 format)
- `event_timestamp_lte` (String): End date (ISO8601 format)
- `id` (Number): Filter by event ID
- `limit` (Number): Max results per page
- `ordering` (String): Order by field
- `type` (String): Event type
- `size` (String): Response tier

**Output**: Detection events list
