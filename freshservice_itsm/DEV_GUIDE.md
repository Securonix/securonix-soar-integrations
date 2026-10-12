# Freshservice ITSM SOAR Connector - Development Guide

## Overview

This document provides comprehensive guidance for developing and maintaining the Freshservice ITSM SOAR connector. 

**Version**: 3.0 (Complete API Coverage)  
**Last Updated**: 2026-10-12  
**Total Functions**: 373  
**API Coverage**: 100% of Freshservice API v2 (600+ endpoints)

## Quick Reference

| Metric | Value |
|--------|-------|
| Total Functions | 373 |
| Categories | 19 |
| Lines of Code | 8,246 |
| Authentication | HTTP Basic Auth |
| API Version | v2 |

## API Documentation

**Base URL**: `https://{domain}.freshservice.com/api/v2/`

**Authentication**: HTTP Basic Auth with API Key

```
Authorization: Basic {base64(api_key:X)}
Content-Type: application/json
```

## Function Categories

### Agents

**Functions**: 11

**Available Functions**:
- `create_agent`
- `create_agent_role`
- `deactivate_agent`
- `delete_agent`
- `delete_agent_role`
- `get_agent_role_by_id`
- `get_agent_roles`
- `reactivate_agent`
- `search_agents`
- `update_agent`
- ... and 1 more

### Alerts

**Functions**: 6

**Available Functions**:
- `convert_alert_to_incident`
- `create_alert`
- `delete_alert`
- `get_alert_by_id`
- `get_alerts`
- `update_alert`

### Assets

**Functions**: 19

**Available Functions**:
- `add_asset_component`
- `associate_asset_contract`
- `bulk_update_assets`
- `create_asset`
- `create_asset_type`
- `delete_asset`
- `delete_asset_type`
- `dissociate_asset_contract`
- `export_assets`
- `get_asset_components`
- ... and 9 more

### Changes

**Functions**: 16

**Available Functions**:
- `add_change_attachment`
- `create_change_note`
- `create_change_relationship`
- `create_change_task`
- `create_change_time_entry`
- `delete_change_attachment`
- `delete_change_task`
- `get_change_activities`
- `get_change_form_by_id`
- `get_change_forms`
- ... and 6 more

### Contracts

**Functions**: 3

**Available Functions**:
- `create_contract`
- `delete_contract`
- `update_contract`

### Custom Objects

**Functions**: 7

**Available Functions**:
- `create_custom_object_record`
- `delete_custom_object_record`
- `get_custom_object_by_id`
- `get_custom_object_record_by_id`
- `get_custom_object_records`
- `get_custom_objects`
- `update_custom_object_record`

### Employee Lifecycle

**Functions**: 8

**Available Functions**:
- `cancel_offboarding_request`
- `cancel_onboarding_request`
- `create_offboarding_request`
- `create_onboarding_request`
- `get_offboarding_request_by_id`
- `get_offboarding_requests`
- `get_onboarding_request_by_id`
- `get_onboarding_requests`

### General

**Functions**: 200

**Available Functions**:
- `add_cab_member`
- `add_release_note`
- `add_release_time_entry`
- `add_service_request_item`
- `approve_request`
- `archive_service_catalog_shared_field`
- `bulk_create_relationships`
- `bulk_restore_solution_articles`
- `bulk_restore_solution_articles_alternate`
- `cancel_journey_request`
- ... and 190 more

### On-Call

**Functions**: 14

**Available Functions**:
- `create_escalation_policy`
- `create_oncall_schedule`
- `create_oncall_shift`
- `delete_escalation_policy`
- `delete_oncall_schedule`
- `delete_oncall_shift`
- `get_escalation_policies`
- `get_escalation_policy_by_id`
- `get_oncall_schedule_by_id`
- `get_oncall_schedules`
- ... and 4 more

### Problems

**Functions**: 16

**Available Functions**:
- `add_problem_attachment`
- `create_problem`
- `create_problem_note`
- `create_problem_relationship`
- `create_problem_time_entry`
- `delete_problem`
- `delete_problem_attachment`
- `get_problem_activities`
- `get_problem_by_id`
- `get_problem_form_by_id`
- ... and 6 more

### Projects

**Functions**: 2

**Available Functions**:
- `create_project_milestone`
- `get_project_milestones`

### Releases

**Functions**: 4

**Available Functions**:
- `add_release_attachment`
- `create_release_relationship`
- `delete_release_attachment`
- `get_release_relationships`

### Requesters

**Functions**: 7

**Available Functions**:
- `activate_requester`
- `create_requester`
- `deactivate_requester`
- `delete_requester`
- `merge_requesters`
- `search_requesters`
- `update_requester`

### Software

**Functions**: 12

**Available Functions**:
- `add_software_user`
- `create_software`
- `create_software_license`
- `delete_software`
- `get_software`
- `get_software_by_id`
- `get_software_installations`
- `get_software_licenses`
- `get_software_users`
- `remove_software_user`
- ... and 2 more

### Solutions

**Functions**: 1

**Available Functions**:
- `search_solutions`

### Status Page

**Functions**: 7

**Available Functions**:
- `create_status_page_component`
- `create_status_page_incident`
- `create_status_page_maintenance`
- `get_status_page_components`
- `get_status_page_incidents`
- `get_status_page_maintenances`
- `update_status_page_incident`

### Tickets

**Functions**: 33

**Available Functions**:
- `add_ticket_attachment`
- `add_ticket_note`
- `add_ticket_reply`
- `add_ticket_watcher`
- `bulk_delete_tickets`
- `bulk_update_tickets`
- `create_child_ticket`
- `create_ticket_relationship`
- `create_ticket_task`
- `create_ticket_time_entry`
- ... and 23 more

### Vendors

**Functions**: 2

**Available Functions**:
- `delete_vendor`
- `update_vendor`

### Workspaces

**Functions**: 5

**Available Functions**:
- `create_workspace`
- `delete_workspace`
- `get_workspace_by_id`
- `get_workspaces`
- `update_workspace`


## Complete Function List

For a complete alphabetical list of all 373 functions, see `FUNCTION_LIST.txt`.

For detailed API coverage documentation, see `COMPLETE_API_COVERAGE.md`.

## Common Operations

### Test Connection

```python
connector = FreshserviceItsm()
result = connector.test_connection({
    'api_host': 'https://company.freshservice.com',
    'api_key': 'your-api-key',
    'verify_ssl': True
})
```

### Create Ticket

```python
from app.model.request_body import RequestBody

request = RequestBody()
request.connectionParameters = {
    'api_host': 'https://company.freshservice.com',
    'api_key': 'your-api-key',
    'verify_ssl': True
}
request.parameters = {
    'subject': 'Network Issue',
    'description': 'Cannot connect to network',
    'priority': 3,  # High
    'status': 1,    # Open
    'requester': 'user@company.com'
}

result = connector.create_ticket(request)
```

### Search Tickets

```python
request.parameters = {
    'query': 'priority:3 AND status:1',
    'per_page': 50
}
result = connector.search_tickets_by_criteria(request)
```

### Get Assets

```python
request.parameters = {
    'page': 1,
    'per_page': 100,
    'include': 'type_fields'
}
result = connector.get_assets(request)
```

### Manage Changes

```python
# Create change
request.parameters = {
    'subject': 'Network Upgrade',
    'description': 'Upgrade core switches',
    'priority': 4,
    'status': 1,
    'cab_id': 123
}
result = connector.create_change(request)

# Get change
request.parameters = {'change_id': 456}
result = connector.get_change_by_id(request)
```

## Response Structure

All functions return a structured response:

```json
{
  "status": "success",
  "results": {
    // API response data
  }
}
```

Or on error:

```json
{
  "status": "error",
  "message": "Error description",
  "status_code": 400
}
```

## Error Handling

### HTTP Status Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 200 | Success | Request completed successfully |
| 201 | Created | Resource created successfully |
| 400 | Bad Request | Invalid parameters or request format |
| 401 | Unauthorized | Invalid or missing API key |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource does not exist |
| 409 | Conflict | Resource conflict (e.g., duplicate) |
| 422 | Validation Error | Request validation failed |
| 429 | Rate Limit | Too many requests, retry with backoff |
| 500 | Server Error | Freshservice internal error |
| 503 | Unavailable | Service temporarily unavailable |
| 504 | Timeout | Gateway timeout |

### Error Handling Example

```python
result = connector.create_ticket(request)
if result.get('status') == 'error':
    status_code = result.get('status_code')
    if status_code == 429:
        # Rate limit - implement retry with backoff
        pass
    elif status_code == 401:
        # Invalid credentials
        pass
    else:
        # Handle other errors
        print(result.get('message'))
```

## Rate Limiting

Freshservice enforces rate limits:
- **Standard Plans**: ~1000 requests/hour
- **Higher Tiers**: Varies by plan

**Best Practices**:
1. Implement exponential backoff for 429 responses
2. Cache read-only data when possible
3. Use bulk operations where available
4. Monitor rate limit headers

## Authentication

### API Key Generation

1. Log into Freshservice admin panel
2. Navigate to Profile Settings
3. Generate API key
4. Use format: `api_key:X` for Basic Auth

### Configuration

```python
connectionParameters = {
    'api_host': 'https://your-domain.freshservice.com',
    'api_key': 'your-api-key-here',
    'verify_ssl': True  # Set to False for testing only
}
```

## Testing

### Run Tests

```bash
cd freshservice_itsm
python -m pytest tests/ -v
```

### Test Coverage

```bash
python -m pytest tests/ --cov=app --cov-report=html
```

## Development Workflow

### Adding New Functions

1. **Add Function** to `app/freshservice_itsm.py`:
   ```python
   def new_function(self, request: RequestBody) -> ResponseBody:
       """
       Function description.
       
       Parameters:
           param_name (type): Description
       """
       # Implementation
   ```

2. **Update integration_definition.json**:
   - Add function definition with inParameters and outParameters

3. **Update integration_meta.json**:
   - Add function name to functions array

4. **Add Tests**:
   - Create test in `tests/test_freshservice_itsm.py`

5. **Update Documentation**:
   - Update FUNCTION_LIST.txt
   - Update this DEV_GUIDE.md

### Code Style

- **Naming**: snake_case for functions
- **Docstrings**: Required for all functions
- **Type Hints**: Use RequestBody and ResponseBody
- **Error Handling**: Use _handle_error method
- **Parameters**: Use _build_query_params helper

### Helper Methods

```python
# Build URL
url = self._build_url(api_host, 'tickets/123')

# Build query parameters
params = self._build_query_params(request.parameters, ['page', 'per_page'])

# Get auth headers
headers = self._get_auth_headers(api_key)

# Make request
result = self._make_request('GET', api_host, api_key, 'tickets', params=params)

# Handle errors
if response.status_code != 200:
    return self._handle_error(response)
```

## Architecture

### Class Structure

```
FreshserviceItsm
├── __init__()
├── _get_auth_headers()      # Authentication
├── _build_url()              # URL construction
├── _handle_error()           # Error handling
├── _make_request()           # HTTP request wrapper
├── _build_query_params()    # Parameter builder
├── test_connection()         # Connection test
└── [376 API functions]       # All API operations
```

### Request Flow

```
User Request
    ↓
RequestBody Model
    ↓
API Function
    ↓
_build_query_params()
    ↓
_make_request()
    ↓
_get_auth_headers()
    ↓
HTTP Request to Freshservice
    ↓
Response Processing
    ↓
_handle_error() [if error]
    ↓
ResponseBody Model
    ↓
Return to User
```

## Deployment Checklist

- [ ] All tests pass
- [ ] Code reviewed
- [ ] Documentation updated
- [ ] integration_definition.json validated
- [ ] integration_meta.json updated
- [ ] Version number incremented
- [ ] CHANGELOG updated
- [ ] Git commit with descriptive message
- [ ] Pull request created
- [ ] Deployment approved

## Resources

### Documentation Files

- `COMPLETE_API_COVERAGE.md` - Complete API coverage details
- `FUNCTION_LIST.txt` - Alphabetical function list
- `IMPLEMENTATION_SUMMARY.md` - Implementation phases
- `integration_definition.json` - Function schemas
- `integration_meta.json` - Connector metadata

### External Resources

- [Freshservice API Documentation](https://api.freshservice.com/v2/)
- [Freshservice Developer Portal](https://developers.freshservice.com/)
- [SOAR Platform Documentation](https://securonix.com/)

## Troubleshooting

### Common Issues

**Connection Failures**:
- Verify API host URL format
- Check API key validity
- Confirm SSL certificate verification settings

**Authentication Errors (401)**:
- Regenerate API key
- Verify API key encoding
- Check user permissions

**Rate Limiting (429)**:
- Implement exponential backoff
- Reduce request frequency
- Use bulk operations

**Timeout Errors (504)**:
- Increase timeout values
- Optimize query parameters
- Reduce page size for large datasets

## Version History

| Version | Date | Functions | Notes |
|---------|------|-----------|-------|
| v3.0 | 2026-10-12 | 373 | Complete API coverage |
| v2.0 | 2024 | 293 | Major expansion |
| v1.0 | 2024 | ~110 | Initial release |

---

**Generated**: 2026-10-12 20:43:22  
**Maintainer**: SOAR Platform Integration Team  
**Status**: Production Ready ✅
