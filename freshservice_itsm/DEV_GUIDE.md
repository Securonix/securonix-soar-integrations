# Freshservice ITSM SOAR Connector - Development Guide

## Overview

This document provides comprehensive guidance for developing and maintaining the Freshservice ITSM SOAR connector. Freshservice is a cloud-based IT Service Management (ITSM) solution that enables IT teams to streamline service delivery within their organization, improve user experience, and enhance employee satisfaction.

## API Documentation

**Current Version**: v2.0

**Base URL**: `https://{domain}.freshservice.com/api/v2/`

**Authentication**: HTTP Basic Auth with API Key

**API Reference**: `/Users/pkamble/Downloads/Freshservice_Complete_Offline_API_Reference.docx`

### HTTP Basic Authentication

The connector uses HTTP Basic Authentication with the API key:

```
Authorization: Basic {base64(api_key:X)}
Content-Type: application/json
Accept: application/json
```

The API key is encoded with "X" as the password (standard for Freshservice API keys).

## Connector Architecture

### Folder Structure

```
freshservice_itsm/
├── app/
│   ├── __init__.py
│   ├── freshservice_itsm.py          # Main connector class
│   └── model/
│       ├── __init__.py
│       ├── request_body.py   # RequestBody model
│       └── response_body.py  # ResponseBody model
├── tests/
│   ├── __init__.py
│   └── test_freshservice_itsm.py     # Unit tests
├── __init__.py
├── integration_definition.json
├── integration_meta.json
├── integration_meta_schema.json
├── logo.svg
├── requirements.txt
└── DEV_GUIDE.md                      # This file
```

### Action Hierarchy

| Category | Actions | Purpose |
|----------|---------|---------|
| **Investigate (12)** | test_connection, get_tickets, get_ticket_by_id, search_tickets_by_criteria, get_agents, get_agent_by_id, get_requesters, get_requester_by_id, get_assets, get_asset_by_id, get_locations, get_location_by_id | Retrieve tickets, agents, requesters, assets, and locations |
| **Remediate (5)** | create_ticket, update_ticket, close_ticket, resolve_ticket, delete_ticket | Create, update, close, resolve, and delete tickets |

## SOAR Functions

### Investigate Functions

#### 1. test_connection
**Description**: Test connection to Freshservice API and verify API key validity

**Parameters**: None

**Output**: 
- `status`: success or error
- `results`: Sample ticket data from the API

#### 2. get_tickets
**Description**: Retrieve a paginated list of tickets with optional filtering

**Parameters**:
- `page` (Number): Page number for pagination
- `per_page` (Number): Number of results per page (max 100)
- `filter` (String): Filter name (new_and_my_open, watching, spam, deleted)
- `query` (String): Advanced query string
- `requester_id` (Number): Filter by requester ID
- `email` (String): Filter by requester email
- `updated_since` (String): Filter by last updated timestamp (ISO8601)
- `type` (String): Filter by ticket type (Incident, Service Request, Problem, Change)
- `workspace_id` (Number): Filter by workspace ID
- `include` (String): Comma-separated list of includes (requester, stats, tags, conversations, assets, etc.)
- `order_type` (String): Sort order (asc/desc)

**Output**: Paginated list of ticket objects

#### 3. get_ticket_by_id
**Description**: Retrieve a single ticket by ID with optional embedded resources

**Parameters**:
- `ticket_id` (Number): Ticket ID
- `include` (String): Comma-separated list of includes

**Output**: Detailed ticket object

#### 4. search_tickets_by_criteria
**Description**: Search tickets using Freshservice's advanced query syntax

**Parameters**:
- `query` (String): Query string using Freshservice field names (e.g., "priority: 1 AND status: 2 OR urgency: 3")
- `page` (Number): Page number for pagination
- `per_page` (Number): Number of results per page

**Output**: List of matching ticket objects

#### 5. get_agents
**Description**: Retrieve a paginated list of agents

**Parameters**:
- `page` (Number): Page number for pagination
- `per_page` (Number): Number of results per page
- `filter` (String): Filter by email, mobile_phone_number, work_phone_number, or active status
- `state` (String): Filter by state (fulltime, occasional)
- `query` (String): Advanced query string

**Output**: Paginated list of agent objects

#### 6. get_agent_by_id
**Description**: Retrieve a single agent by ID

**Parameters**:
- `agent_id` (Number): Agent ID

**Output**: Detailed agent object

#### 7. get_requesters
**Description**: Retrieve a paginated list of requesters (contacts)

**Parameters**:
- `page` (Number): Page number for pagination
- `per_page` (Number): Number of results per page
- `email` (String): Filter by email
- `mobile_phone_number` (String): Filter by mobile phone number
- `work_phone_number` (String): Filter by work phone number
- `query` (String): Advanced query string

**Output**: Paginated list of requester objects

#### 8. get_requester_by_id
**Description**: Retrieve a single requester by ID

**Parameters**:
- `requester_id` (Number): Requester ID

**Output**: Detailed requester object

#### 9. get_assets
**Description**: Retrieve a paginated list of assets

**Parameters**:
- `page` (Number): Page number for pagination
- `per_page` (Number): Number of results per page
- `order_by` (String): Order by field (created_at, updated_at)
- `order_type` (String): Order type (asc/desc)
- `include` (String): Include type_fields for asset-specific fields
- `trashed` (Boolean): Include trashed assets
- `workspace_id` (Number): Filter by workspace ID
- `query` (String): Advanced query string

**Output**: Paginated list of asset objects

#### 10. get_asset_by_id
**Description**: Retrieve a single asset by display ID

**Parameters**:
- `display_id` (String): Asset display ID
- `include` (String): Include type_fields for asset-specific fields

**Output**: Detailed asset object

#### 11. get_locations
**Description**: Retrieve a paginated list of locations

**Parameters**:
- `page` (Number): Page number for pagination
- `per_page` (Number): Number of results per page
- `query` (String): Advanced query string

**Output**: Paginated list of location objects

#### 12. get_location_by_id
**Description**: Retrieve a single location by ID

**Parameters**:
- `location_id` (Number): Location ID

**Output**: Detailed location object

### Remediate Functions

#### 13. create_ticket
**Description**: Create a new ticket in Freshservice

**Parameters**:
- `subject` (String): Ticket subject
- `description` (String): Ticket description
- `requester_id` (Number): Requester ID (for existing requesters)
- `requester` (String): Requester email (creates new requester if not exists)
- `type` (String): Ticket type (Incident, Service Request, Problem, Change)
- `priority` (Number): Priority (1=Low, 2=Medium, 3=High, 4=Urgent)
- `status` (Number): Status (1=Open, 2=Pending, 3=Resolved, 4=Closed)
- `group_id` (Number): Group ID to assign ticket to
- `agent_id` (Number): Agent ID to assign ticket to
- `due_by` (String): Due date (ISO8601 format)
- `fr_due_by` (String): First response due date (ISO8601 format)
- `tags` (String): Comma-separated tags
- `custom_fields` (String): JSON object for custom field values

**Output**: Created ticket object with ID

#### 14. update_ticket
**Description**: Update an existing ticket

**Parameters**:
- `ticket_id` (Number): Ticket ID
- `subject` (String): Ticket subject
- `description` (String): Ticket description
- `requester_id` (Number): Requester ID
- `type` (String): Ticket type
- `priority` (Number): Priority
- `status` (Number): Status
- `group_id` (Number): Group ID
- `agent_id` (Number): Agent ID to assign ticket to
- `due_by` (String): Due date (ISO8601 format)
- `tags` (String): Comma-separated tags

**Output**: Updated ticket object

#### 15. close_ticket
**Description**: Close a ticket (sets status to Closed)

**Parameters**:
- `ticket_id` (Number): Ticket ID
- `resolution` (String): Resolution description

**Output**: Closed ticket object

#### 16. resolve_ticket
**Description**: Resolve a ticket (sets status to Resolved)

**Parameters**:
- `ticket_id` (Number): Ticket ID
- `resolution` (String): Resolution description

**Output**: Resolved ticket object

#### 17. delete_ticket
**Description**: Soft delete a ticket

**Parameters**:
- `ticket_id` (Number): Ticket ID

**Output**: Delete confirmation message

## Implementation Details

### Request/Response Models

All requests use the `RequestBody` model with:
- `connectionParameters`: API credentials (api_host, api_key, verify_ssl)
- `parameters`: Action-specific parameters

All responses use the `ResponseBody` model with:
- `status`: success/error
- `results`: Response data
- `message`: Human-readable message (optional)

### Error Handling

Standard error responses:
- `401`: Authentication error (invalid API key)
- `403`: Authorization error (insufficient permissions)
- `404`: Not found (resource ID not valid)
- `409`: Conflict (duplicate resource or invalid operation)
- `422`: Validation error (missing required fields)
- `429`: Rate limit exceeded (too many requests)
- `500`: Internal server error (Freshservice API internal error)
- `503`: Service unavailable (Freshservice API temporarily unavailable)
- `504`: Gateway timeout (Freshservice API response timeout)

### Pagination

All list endpoints support pagination via query parameters:
- `page` (number): Page number for pagination
- `per_page` (number): Number of results per page (default: 20, max: 100)

### Embedding Resources

Freshservice v2 API supports embedding additional resources using the `include` parameter:
- `requester`: Requester details
- `stats`: Ticket statistics (closed_at, resolved_at, first_responded_at)
- `tags`: Tags associated with the ticket
- `conversations`: Up to 10 conversations
- `assets`: Associated assets
- `related_tickets`: Related tickets metadata
- `department`: Department details

### Query Format

Freshservice uses a custom query syntax:
- String fields: Enclosed in single quotes ('')
- Number fields: Given as number without quotes
- Date fields: Enclosed in single quotes ('yyyy-mm-dd')
- Operators: `:>` (greater than), `:<` (less than)
- Logical operators: AND, OR, parentheses

Example: `"priority: 1 AND status: 2 OR urgency: 3"`

### API Versioning

Connector supports Freshservice API v2.0:
- All endpoints use `/api/v2/` prefix
- v1.0 APIs are deprecated

### Authentication Flow

The connector implements HTTP Basic Authentication:
1. Base64 encode `api_key:X` (X is the password placeholder)
2. Include in Authorization header
3. All requests include the Authorization header

### Rate Limits

Freshservice accounts created on or after 01-Sep-2020 use minute-level rate limiting:
- Growth plan: 200 requests per minute
- Pro plan: 400 requests per minute
- Enterprise plan: 500 requests per minute

Check response headers `X-Ratelimit-Total`, `X-Ratelimit-Remaining`, `Retry-After` for rate limit status.

## Testing Strategy

### Test Categories

1. **Authentication Tests**: Verify API key authentication and error handling
2. **Investigation Tests**: Test all read operations with various filters
3. **Remediation Tests**: Test create, update, close, resolve, delete operations
4. **Error Handling Tests**: Verify proper error responses for all HTTP status codes
5. **Pagination Tests**: Verify pagination works correctly

### Running Tests

```bash
cd freshservice_itsm
python3 -m pytest tests/test_freshservice_itsm.py -v
coverage run -m pytest tests/test_freshservice_itsm.py
coverage report -m
```

## Integration Configuration

### Connection Parameters

| Parameter | Type | Required | Encrypted | Description |
|-----------|------|----------|-----------|-------------|
| `api_host` | String | Yes | No | Freshservice domain URL (e.g., https://company.freshservice.com) |
| `api_key` | String | Yes | Yes | Freshservice API key for authentication |
| `verify_ssl` | Boolean | No | No | Verify SSL certificate |

### Sample Connection Parameters

```json
{
  "api_host": "https://company.freshservice.com",
  "api_key": "your_api_key_here",
  "verify_ssl": true
}
```

## Deployment Checklist

- [ ] API key obtained from Freshservice admin
- [ ] API host URL configured
- [ ] SSL verification settings determined
- [ ] Test connection parameters
- [ ] Verify ticket listing works
- [ ] Verify ticket creation works
- [ ] Verify remediation actions work
- [ ] Configure error notifications

## Known Limitations

1. **API Versioning**: Connector supports v2.0 API only. v1.0 APIs are deprecated.
2. **Rate Limiting**: API has rate limits (429 responses). Implement exponential backoff for production use.
3. **Pagination**: Large result sets may require multiple API calls.
4. **Embedding Costs**: Each embedded resource consumes additional API credits.

## Future Enhancements

- [ ] Add more ticket field operations (custom fields, attachments)
- [ ] Add conversation/message operations
- [ ] Add SLA policy management
- [ ] Add report generation
- [ ] Add bulk ticket operations
- [ ] Add webhook support for real-time updates

## Support

For API questions or issues, contact Freshservice support at support@freshservice.com
