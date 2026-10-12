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
| **Investigate (53)** | test_connection, get_tickets, get_ticket_by_id, search_tickets_by_criteria, get_agents, get_agent_by_id, get_requesters, get_requester_by_id, get_assets, get_asset_by_id, get_locations, get_location_by_id, get_service_catalog_items, get_service_catalog_item_by_id, get_service_catalog_categories, get_service_catalog_category_by_id, get_solution_articles, get_solution_article_by_id, get_solution_categories, get_solution_category_by_id, get_solution_folders, get_solution_folder_by_id, get_cabs, get_cab_by_id, get_changes, get_change_by_id, get_releases, get_release_by_id, get_announcements, get_announcement_by_id, get_applications, get_application_by_id, get_sla_policies, get_sla_policy_by_id, get_contracts, get_contract_by_id, get_canned_responses, get_canned_response_by_id, get_canned_response_folders, get_canned_response_folder_by_id, get_agent_fields, get_agent_field_by_id, get_requester_fields, get_requester_field_by_id, get_service_items, get_service_item_by_id, get_service_requests, get_service_request_by_id, get_approvals, get_approval_by_id, get_delegations, get_delegation_by_id, get_journey_requests, get_journey_request_by_id, get_pm_projects, get_pm_project_by_id, get_pm_tasks, get_pm_task_by_id, get_audit_logs | Retrieve tickets, agents, requesters, assets, locations, service catalog items, solution articles, CABs, changes, releases, announcements, applications, SLA policies, contracts, canned responses, user fields, service items, service requests, approvals, delegations, journey requests, projects, tasks, and audit logs |
| **Remediate (47)** | create_ticket, update_ticket, close_ticket, resolve_ticket, delete_ticket, create_cab, update_cab, delete_cab, create_change, update_change, delete_change, create_release, update_release, delete_release, create_announcement, update_announcement, delete_announcement, create_delegation, update_delegation, delete_delegation, create_journey_request, cancel_journey_request, create_pm_project, update_pm_project, delete_pm_project, create_pm_task, update_pm_task, delete_pm_task, create_solution_folder, update_solution_folder, delete_solution_folder, restore_solution_folder, create_solution_category, update_solution_category, delete_solution_category, restore_solution_category, create_solution_article, update_solution_article, delete_solution_article, restore_solution_article, bulk_restore_solution_articles, add_service_request_item, cancel_service_request, approve_request, reject_request | Create, update, close, resolve, delete tickets, CABs, changes, releases, announcements, delegations, journey requests, projects, tasks, solution folders/categories/articles; restore soft-deleted resources; approve/reject requests; add service request items |

## SOAR Functions

### Test Connection

#### 1. test_connection
**Description**: Test connection to Freshservice API and verify API key validity

**Parameters**: None

**Output**: 
- `status`: success or error
- `results`: Sample ticket data from the API

### Ticket Operations

#### 2. get_tickets
**Description**: Retrieve a paginated list of tickets with optional filtering

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page (max 100)
- `filter` (str): Filter name (new_and_my_open, watching, spam, deleted)
- `query` (str): Advanced query string for filtering
- `requester_id` (int): Filter by requester ID
- `email` (str): Filter by requester email
- `updated_since` (str): Filter by last updated timestamp (ISO8601)
- `type` (str): Filter by ticket type (Incident, Service Request, Problem, Change)
- `workspace_id` (int): Filter by workspace ID
- `include` (str): Comma-separated list of includes (requester, stats, tags, conversations, assets, etc.)
- `order_type` (str): Sort order (asc/desc)

**Output**: Paginated list of ticket objects

#### 3. get_ticket_by_id
**Description**: Retrieve a single ticket by ID with optional embedded resources

**Parameters**:
- `ticket_id` (int): Ticket ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed ticket object

#### 4. search_tickets_by_criteria
**Description**: Search tickets using Freshservice's advanced query syntax

**Parameters**:
- `query` (str): Query string using Freshservice field names (e.g., "priority: 1 AND status: 2 OR urgency: 3")
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page

**Output**: List of matching ticket objects

#### 5. create_ticket
**Description**: Create a new ticket in Freshservice

**Parameters**:
- `subject` (str): Ticket subject
- `description` (str): Ticket description
- `requester_id` (int): Requester ID (for existing requesters)
- `requester` (str): Requester email (creates new requester if not exists)
- `email` (str): Requester email
- `type` (str): Ticket type (Incident, Service Request, Problem, Change)
- `priority` (int): Priority (1=Low, 2=Medium, 3=High, 4=Urgent)
- `status` (int): Status (1=Open, 2=Pending, 3=Resolved, 4=Closed)
- `service_id` (int): Service ID
- `category` (str): Category
- `sub_category` (str): Sub category
- `item_category` (str): Item category
- `group_id` (int): Group ID to assign ticket to
- `agent_id` (int): Agent ID to assign ticket to
- `due_by` (str): Due date (ISO8601 format)
- `fr_due_by` (str): First response due date (ISO8601 format)
- `tags` (str): Comma-separated tags
- `custom_fields` (dict): JSON object for custom field values
- `workspace_id` (int): Workspace ID
- `attachments` (list): File paths for attachments

**Output**: Created ticket object with ID

#### 6. update_ticket
**Description**: Update an existing ticket

**Parameters**:
- `ticket_id` (int): Ticket ID (required)
- `subject` (str): Ticket subject
- `description` (str): Ticket description
- `requester_id` (int): Requester ID
- `type` (str): Ticket type
- `priority` (int): Priority
- `status` (int): Status
- `group_id` (int): Group ID
- `agent_id` (int): Agent ID to assign ticket to
- `due_by` (str): Due date (ISO8601 format)
- `fr_due_by` (str): First response due date (ISO8601 format)
- `tags` (str): Comma-separated tags
- `custom_fields` (dict): Custom field values
- `attachments` (list): File paths for attachments

**Output**: Updated ticket object

#### 7. close_ticket
**Description**: Close a ticket (sets status to Closed)

**Parameters**:
- `ticket_id` (int): Ticket ID (required)
- `status` (int): Status (4=Closed)
- `resolution` (str): Resolution description

**Output**: Closed ticket object

#### 8. resolve_ticket
**Description**: Resolve a ticket (sets status to Resolved)

**Parameters**:
- `ticket_id` (int): Ticket ID (required)
- `status` (int): Status (3=Resolved)
- `resolution` (str): Resolution description

**Output**: Resolved ticket object

#### 9. delete_ticket
**Description**: Soft delete a ticket

**Parameters**:
- `ticket_id` (int): Ticket ID (required)

**Output**: Delete confirmation message

### Agent Operations

#### 10. get_agents
**Description**: Retrieve a paginated list of agents

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `filter` (str): Filter by email, mobile_phone_number, work_phone_number, or active status
- `state` (str): Filter by state (fulltime, occasional)
- `query` (str): Advanced query string for filtering
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of agent objects

#### 11. get_agent_by_id
**Description**: Retrieve a single agent by ID

**Parameters**:
- `agent_id` (int): Agent ID (required)

**Output**: Detailed agent object

### Requester/Contact Operations

#### 12. get_requesters
**Description**: Retrieve a paginated list of requesters (contacts)

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `email` (str): Filter by email
- `mobile_phone_number` (str): Filter by mobile phone number
- `work_phone_number` (str): Filter by work phone number
- `query` (str): Advanced query string for filtering
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of requester objects

#### 13. get_requester_by_id
**Description**: Retrieve a single requester by ID

**Parameters**:
- `requester_id` (int): Requester ID (required)

**Output**: Detailed requester object

### Asset Operations

#### 14. get_assets
**Description**: Retrieve a paginated list of assets

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `order_by` (str): Order by field (created_at, updated_at)
- `order_type` (str): Order type (asc/desc)
- `include` (str): Include type_fields for asset-specific fields
- `trashed` (bool): Include trashed assets
- `workspace_id` (int): Filter by workspace ID
- `query` (str): Advanced query string for filtering

**Output**: Paginated list of asset objects

#### 15. get_asset_by_id
**Description**: Retrieve a single asset by display ID

**Parameters**:
- `display_id` (str): Asset display ID (required)
- `include` (str): Include type_fields for asset-specific fields

**Output**: Detailed asset object

### Location Operations

#### 16. get_locations
**Description**: Retrieve a paginated list of locations

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `query` (str): Advanced query string for filtering
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of location objects

#### 17. get_location_by_id
**Description**: Retrieve a single location by ID

**Parameters**:
- `location_id` (int): Location ID (required)

**Output**: Detailed location object

### Service Catalog Operations

#### 18. get_service_catalog_items
**Description**: Retrieve a paginated list of service catalog items

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `category_id` (int): Filter by category ID
- `workspace_id` (int): Filter by workspace ID
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of service catalog item objects

#### 19. get_service_catalog_item_by_id
**Description**: Retrieve a single service catalog item by ID

**Parameters**:
- `item_id` (int): Item ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed service catalog item object

#### 20. get_service_catalog_categories
**Description**: Retrieve a paginated list of service catalog categories

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `workspace_id` (int): Filter by workspace ID
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of service catalog category objects

#### 21. get_service_catalog_category_by_id
**Description**: Retrieve a single service catalog category by ID

**Parameters**:
- `category_id` (int): Category ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed service catalog category object

### Solution Management Operations

#### 22. get_solution_articles
**Description**: Retrieve a paginated list of solution articles

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `folder_id` (int): Filter by folder ID (required)
- `category_id` (int): Filter by category ID
- `workspace_id` (int): Filter by workspace ID
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of solution article objects

#### 23. get_solution_article_by_id
**Description**: Retrieve a single solution article by ID

**Parameters**:
- `article_id` (int): Article ID (required)
- `folder_id` (int): Folder ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed solution article object

#### 24. get_solution_categories
**Description**: Retrieve a paginated list of solution categories

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `workspace_id` (int): Filter by workspace ID
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of solution category objects

#### 25. get_solution_category_by_id
**Description**: Retrieve a single solution category by ID

**Parameters**:
- `category_id` (int): Category ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed solution category object

#### 26. get_solution_folders
**Description**: Retrieve a paginated list of solution folders

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `category_id` (int): Filter by category ID
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of solution folder objects

#### 27. get_solution_folder_by_id
**Description**: Retrieve a single solution folder by ID

**Parameters**:
- `folder_id` (int): Folder ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed solution folder object

#### 28. create_solution_folder
**Description**: Create a new solution folder

**Parameters**:
- `category_id` (int): Category ID (required)
- `name` (str): Folder name (required)
- `description` (str): Folder description
- `visibility` (str): Visibility (all, logged_in_users, agents)
- `workspace_id` (int): Workspace ID

**Output**: Created solution folder object with ID

#### 29. update_solution_folder
**Description**: Update an existing solution folder

**Parameters**:
- `folder_id` (int): Folder ID (required)
- `name` (str): Folder name
- `description` (str): Folder description
- `visibility` (str): Visibility (all, logged_in_users, agents)
- `workspace_id` (int): Workspace ID

**Output**: Updated solution folder object

#### 30. delete_solution_folder
**Description**: Delete a solution folder

**Parameters**:
- `folder_id` (int): Folder ID (required)

**Output**: Delete confirmation message

#### 31. restore_solution_folder
**Description**: Restore a deleted solution folder

**Parameters**:
- `folder_id` (int): Folder ID (required)

**Output**: Restore confirmation message with restored folder object

#### 32. create_solution_category
**Description**: Create a new solution category

**Parameters**:
- `name` (str): Category name (required)
- `description` (str): Category description
- `visibility` (str): Visibility (all, logged_in_users, agents)
- `workspace_id` (int): Workspace ID

**Output**: Created solution category object with ID

#### 33. update_solution_category
**Description**: Update an existing solution category

**Parameters**:
- `category_id` (int): Category ID (required)
- `name` (str): Category name
- `description` (str): Category description
- `visibility` (str): Visibility
- `workspace_id` (int): Workspace ID

**Output**: Updated solution category object

#### 34. delete_solution_category
**Description**: Delete a solution category

**Parameters**:
- `category_id` (int): Category ID (required)

**Output**: Delete confirmation message

#### 35. restore_solution_category
**Description**: Restore a deleted solution category

**Parameters**:
- `category_id` (int): Category ID (required)

**Output**: Restore confirmation message with restored category object

#### 36. create_solution_article
**Description**: Create a new solution article

**Parameters**:
- `folder_id` (int): Folder ID (required)
- `title` (str): Article title (required)
- `body` (str): Article body (required)
- `status` (int): Status (1=Draft, 2=Published)
- `is_enabled_for_self_service` (bool): Enable for self service
- `category_id` (int): Category ID
- `workspace_id` (int): Workspace ID

**Output**: Created solution article object with ID

#### 37. update_solution_article
**Description**: Update an existing solution article

**Parameters**:
- `article_id` (int): Article ID (required)
- `folder_id` (int): Folder ID
- `title` (str): Article title
- `body` (str): Article body
- `status` (int): Status
- `is_enabled_for_self_service` (bool): Enable for self service
- `category_id` (int): Category ID
- `workspace_id` (int): Workspace ID

**Output**: Updated solution article object

#### 38. delete_solution_article
**Description**: Delete a solution article

**Parameters**:
- `article_id` (int): Article ID (required)

**Output**: Delete confirmation message

#### 39. restore_solution_article
**Description**: Restore a deleted solution article

**Parameters**:
- `article_id` (int): Article ID (required)

**Output**: Restore confirmation message with restored article object

#### 40. bulk_restore_solution_articles
**Description**: Restore multiple solution articles from trash in a single operation

**Parameters**:
- `ids` (str): Comma-separated list of article IDs (required)

**Output**: List of restored article objects

### CAB (Change Advisory Board) Operations

#### 41. get_cabs
**Description**: Retrieve a paginated list of CABs (Change Advisory Boards)

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `include` (str): Comma-separated list of includes (member_details)

**Output**: Paginated list of CAB objects

#### 42. get_cab_by_id
**Description**: Retrieve a single CAB by ID

**Parameters**:
- `cab_id` (int): CAB ID (required)
- `include` (str): Comma-separated list of includes (member_details)

**Output**: Detailed CAB object with member details

#### 43. create_cab
**Description**: Create a new CAB (Change Advisory Board)

**Parameters**:
- `name` (str): CAB name (required)
- `description` (str): CAB description
- `members` (list): Array of member IDs (required)

**Output**: Created CAB object with ID

#### 44. update_cab
**Description**: Update an existing CAB

**Parameters**:
- `cab_id` (int): CAB ID (required)
- `name` (str): CAB name
- `description` (str): CAB description
- `members` (list): Array of member IDs

**Output**: Updated CAB object

#### 45. delete_cab
**Description**: Delete a CAB

**Parameters**:
- `cab_id` (int): CAB ID (required)

**Output**: Delete confirmation message

### Change Operations

#### 46. get_changes
**Description**: Retrieve a paginated list of changes

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `order_by` (str): Order by field (created_at, updated_at)
- `order_type` (str): Order type (asc/desc)
- `view` (str): View type (all, my_open, unassigned, completed, etc.)
- `updated_since` (str): Filter by last updated timestamp
- `workspace_id` (int): Filter by workspace ID
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of change objects

#### 47. get_change_by_id
**Description**: Retrieve a single change by ID

**Parameters**:
- `change_id` (int): Change ID (required)
- `include` (str): Comma-separated list of includes (stats)

**Output**: Detailed change object

#### 48. create_change
**Description**: Create a new change

**Parameters**:
- `subject` (str): Change subject (required)
- `description` (str): Change description (required)
- `priority` (int): Priority (1=Low, 2=Medium, 3=High, 4=Urgent)
- `status` (int): Status (1=Approved, 2=Cancelled, 3=Implemented, 4=Reviewing, 5=Testing, 6=Scheduled, 7=Approved, 8=Rejected)
- `cab_id` (int): CAB ID
- `start_time` (str): Start time (ISO8601)
- `end_time` (str): End time (ISO8601)
- `implementer_id` (int): Implementer ID
- `reviewer_id` (int): Reviewer ID
- `approval_status` (int): Approval status
- `workspace_id` (int): Workspace ID

**Output**: Created change object with ID

#### 49. update_change
**Description**: Update an existing change

**Parameters**:
- `change_id` (int): Change ID (required)
- `subject` (str): Change subject
- `description` (str): Change description
- `priority` (int): Priority
- `status` (int): Status
- `cab_id` (int): CAB ID
- `start_time` (str): Start time
- `end_time` (str): End time
- `implementer_id` (int): Implementer ID
- `reviewer_id` (int): Reviewer ID
- `approval_status` (int): Approval status

**Output**: Updated change object

#### 50. delete_change
**Description**: Delete a change

**Parameters**:
- `change_id` (int): Change ID (required)

**Output**: Delete confirmation message

### Release Operations

#### 51. get_releases
**Description**: Retrieve a paginated list of releases

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `filter_name` (str): Filter name (all, my_open, unassigned, completed, etc.)
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of release objects

#### 52. get_release_by_id
**Description**: Retrieve a single release by ID

**Parameters**:
- `release_id` (int): Release ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed release object

#### 53. create_release
**Description**: Create a new release

**Parameters**:
- `name` (str): Release name (required)
- `description` (str): Release description
- `start_date` (str): Start date (ISO8601)
- `end_date` (str): End date (ISO8601)
- `status` (str): Status (planned, in_progress, completed, cancelled)
- `workspace_id` (int): Workspace ID

**Output**: Created release object with ID

#### 54. update_release
**Description**: Update an existing release

**Parameters**:
- `release_id` (int): Release ID (required)
- `name` (str): Release name
- `description` (str): Release description
- `start_date` (str): Start date
- `end_date` (str): End date
- `status` (str): Status
- `workspace_id` (int): Workspace ID

**Output**: Updated release object

#### 55. delete_release
**Description**: Delete a release

**Parameters**:
- `release_id` (int): Release ID (required)

**Output**: Delete confirmation message

### Announcement Operations

#### 56. get_announcements
**Description**: Retrieve a paginated list of announcements

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `state` (str): Filter by state (archived, active, scheduled, unread)
- `workspace_id` (int): Filter by workspace ID
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of announcement objects

#### 57. get_announcement_by_id
**Description**: Retrieve a single announcement by ID

**Parameters**:
- `announcement_id` (int): Announcement ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed announcement object

#### 58. create_announcement
**Description**: Create a new announcement

**Parameters**:
- `subject` (str): Announcement subject (required)
- `description` (str): Announcement description (required)
- `state` (str): State (active, scheduled, archived)
- `start_time` (str): Start time (ISO8601)
- `end_time` (str): End time (ISO8601)
- `visibility` (str): Visibility (all, logged_in_users, agents)
- `workspace_id` (int): Workspace ID

**Output**: Created announcement object with ID

#### 59. update_announcement
**Description**: Update an existing announcement

**Parameters**:
- `announcement_id` (int): Announcement ID (required)
- `subject` (str): Announcement subject
- `description` (str): Announcement description
- `state` (str): State
- `start_time` (str): Start time
- `end_time` (str): End time
- `visibility` (str): Visibility
- `workspace_id` (int): Workspace ID

**Output**: Updated announcement object

#### 60. delete_announcement
**Description**: Delete an announcement

**Parameters**:
- `announcement_id` (int): Announcement ID (required)

**Output**: Delete confirmation message

### Application Management Operations

#### 61. get_applications
**Description**: Retrieve a paginated list of applications (software)

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `workspace_id` (int): Filter by workspace ID
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of application objects

#### 62. get_application_by_id
**Description**: Retrieve a single application by ID

**Parameters**:
- `application_id` (int): Application ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed application object

### SLA Policy Operations

#### 63. get_sla_policies
**Description**: Retrieve a paginated list of SLA policies

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `workspace_id` (int): Filter by workspace ID
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of SLA policy objects

#### 64. get_sla_policy_by_id
**Description**: Retrieve a single SLA policy by ID

**Parameters**:
- `sla_policy_id` (int): SLA policy ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed SLA policy object

### Contract Operations

#### 65. get_contracts
**Description**: Retrieve a paginated list of contracts

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `workspace_id` (int): Filter by workspace ID
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of contract objects

#### 66. get_contract_by_id
**Description**: Retrieve a single contract by ID

**Parameters**:
- `contract_id` (int): Contract ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed contract object

### Canned Response Operations

#### 67. get_canned_responses
**Description**: Retrieve a paginated list of canned responses

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `workspace_id` (int): Filter by workspace ID
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of canned response objects

#### 68. get_canned_response_by_id
**Description**: Retrieve a single canned response by ID

**Parameters**:
- `canned_response_id` (int): Canned response ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed canned response object

#### 69. get_canned_response_folders
**Description**: Retrieve a paginated list of canned response folders

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `workspace_id` (int): Filter by workspace ID
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of canned response folder objects

#### 70. get_canned_response_folder_by_id
**Description**: Retrieve a single canned response folder by ID

**Parameters**:
- `folder_id` (int): Folder ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed canned response folder object

### User Field Operations (Agent Fields / Requester Fields)

#### 71. get_agent_fields
**Description**: Retrieve a paginated list of agent fields (custom fields for agents)

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `include` (str): Comma-separated list of includes (user_field_groups)

**Output**: Paginated list of agent field objects

#### 72. get_agent_field_by_id
**Description**: Retrieve a single agent field by ID

**Parameters**:
- `field_id` (int): Field ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed agent field object

#### 73. get_requester_fields
**Description**: Retrieve a paginated list of requester fields (custom fields for requesters)

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `include` (str): Comma-separated list of includes (user_field_groups)

**Output**: Paginated list of requester field objects

#### 74. get_requester_field_by_id
**Description**: Retrieve a single requester field by ID

**Parameters**:
- `field_id` (int): Field ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed requester field object

### Service Item Operations

#### 75. get_service_items
**Description**: Retrieve a paginated list of service items

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `category_id` (int): Filter by category ID
- `workspace_id` (int): Filter by workspace ID
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of service item objects

#### 76. get_service_item_by_id
**Description**: Retrieve a single service item by ID

**Parameters**:
- `item_id` (int): Item ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed service item object

### Service Request Operations

#### 77. get_service_requests
**Description**: Retrieve a paginated list of service requests

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `service_item_id` (int): Filter by service item ID
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of service request objects

#### 78. get_service_request_by_id
**Description**: Retrieve a single service request by ID

**Parameters**:
- `service_request_id` (int): Service request ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed service request object

#### 79. add_service_request_item
**Description**: Add a catalog item to an existing service request

**Parameters**:
- `service_request_id` (int): Service request ID (required)
- `service_item_id` (int): Service item ID (required)
- `quantity` (int): Quantity

**Output**: Added service request item object

#### 80. cancel_service_request
**Description**: Cancel a service request

**Parameters**:
- `service_request_id` (int): Service request ID (required)

**Output**: Cancel confirmation message

### Approval Operations

#### 81. get_approvals
**Description**: Retrieve a paginated list of approvals

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `status` (str): Filter by status (pending, approved, rejected)
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of approval objects

#### 82. get_approval_by_id
**Description**: Retrieve a single approval by ID

**Parameters**:
- `approval_id` (int): Approval ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed approval object

#### 83. approve_request
**Description**: Approve a request (approval or service request)

**Parameters**:
- `approval_id` (int): Approval ID (required)
- `comments` (str): Approval comments

**Output**: Approved request object

#### 84. reject_request
**Description**: Reject a request (approval or service request)

**Parameters**:
- `approval_id` (int): Approval ID (required)
- `comments` (str): Rejection comments

**Output**: Rejected request object

### Delegation Operations

#### 85. get_delegations
**Description**: Retrieve a paginated list of delegations

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of delegation objects

#### 86. get_delegation_by_id
**Description**: Retrieve a single delegation by ID

**Parameters**:
- `delegation_id` (int): Delegation ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed delegation object

#### 87. create_delegation
**Description**: Create a new delegation

**Parameters**:
- `delegatee_id` (int): Delegatee ID (required)
- `start_date` (str): Start date (ISO8601)
- `end_date` (str): End date (ISO8601)
- `permissions` (list): Permissions to delegate (required)

**Output**: Created delegation object with ID

#### 88. update_delegation
**Description**: Update an existing delegation

**Parameters**:
- `delegation_id` (int): Delegation ID (required)
- `delegatee_id` (int): Delegatee ID
- `start_date` (str): Start date
- `end_date` (str): End date
- `permissions` (list): Permissions

**Output**: Updated delegation object

#### 89. delete_delegation
**Description**: Delete a delegation

**Parameters**:
- `delegation_id` (int): Delegation ID (required)

**Output**: Delete confirmation message

### Journeys Operations

#### 90. get_journey_requests
**Description**: Retrieve a paginated list of journey requests

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `filter_name` (str): Filter name (all, in_progress, completed, etc.)
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of journey request objects

#### 91. get_journey_request_by_id
**Description**: Retrieve a single journey request by ID

**Parameters**:
- `journey_request_id` (int): Journey request ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed journey request object

#### 92. create_journey_request
**Description**: Create a new journey request

**Parameters**:
- `journey_id` (int): Journey ID (required)
- `requester_id` (int): Requester ID (required)
- `journey_data` (dict): Journey data fields (required)

**Output**: Created journey request object with ID

#### 93. cancel_journey_request
**Description**: Cancel a journey request

**Parameters**:
- `journey_request_id` (int): Journey request ID (required)

**Output**: Cancel confirmation message

### Project Management Operations (Projects and Tasks)

#### 94. get_pm_projects
**Description**: Retrieve a paginated list of project management projects

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `workspace_id` (int): Filter by workspace ID
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of project objects

#### 95. get_pm_project_by_id
**Description**: Retrieve a single project management project by ID

**Parameters**:
- `project_id` (int): Project ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed project object

#### 96. create_pm_project
**Description**: Create a new project management project

**Parameters**:
- `name` (str): Project name (required)
- `description` (str): Project description
- `start_date` (str): Start date (ISO8601)
- `end_date` (str): End date (ISO8601)
- `workspace_id` (int): Workspace ID

**Output**: Created project object with ID

#### 97. update_pm_project
**Description**: Update an existing project management project

**Parameters**:
- `project_id` (int): Project ID (required)
- `name` (str): Project name
- `description` (str): Project description
- `start_date` (str): Start date
- `end_date` (str): End date
- `workspace_id` (int): Workspace ID

**Output**: Updated project object

#### 98. delete_pm_project
**Description**: Delete a project management project

**Parameters**:
- `project_id` (int): Project ID (required)

**Output**: Delete confirmation message

#### 99. get_pm_tasks
**Description**: Retrieve a paginated list of project management tasks

**Parameters**:
- `page` (int): Page number for pagination
- `per_page` (int): Number of results per page
- `project_id` (int): Filter by project ID
- `parent_id` (int): Filter by parent task ID
- `include` (str): Comma-separated list of includes

**Output**: Paginated list of task objects

#### 100. get_pm_task_by_id
**Description**: Retrieve a single project management task by ID

**Parameters**:
- `task_id` (int): Task ID (required)
- `include` (str): Comma-separated list of includes

**Output**: Detailed task object

#### 101. create_pm_task
**Description**: Create a new project management task

**Parameters**:
- `project_id` (int): Project ID (required)
- `parent_id` (int): Parent task ID
- `name` (str): Task name (required)
- `description` (str): Task description
- `start_date` (str): Start date (ISO8601)
- `end_date` (str): End date (ISO8601)
- `status` (int): Status

**Output**: Created task object with ID

#### 102. update_pm_task
**Description**: Update an existing project management task

**Parameters**:
- `task_id` (int): Task ID (required)
- `name` (str): Task name
- `description` (str): Task description
- `start_date` (str): Start date
- `end_date` (str): End date
- `status` (int): Status

**Output**: Updated task object

#### 103. delete_pm_task
**Description**: Delete a project management task

**Parameters**:
- `task_id` (int): Task ID (required)

**Output**: Delete confirmation message

### Audit Log Operations

#### 104. get_audit_logs
**Description**: Retrieve a paginated list of audit logs

**Parameters**:
- `cursor` (str): Cursor for pagination
- `per_page` (int): Results per page
- `start_time` (str): Start time (ISO8601)
- `end_time` (str): End time (ISO8601)
- `type` (str): Filter by type
- `user_id` (int): Filter by user ID

**Output**: Paginated list of audit log objects

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

Some endpoints (audit logs) use cursor-based pagination:
- `cursor` (string): Cursor for pagination
- `per_page` (number): Results per page

### Embedding Resources

Freshservice v2 API supports embedding additional resources using the `include` parameter:
- `requester`: Requester details
- `stats`: Ticket statistics (closed_at, resolved_at, first_responded_at)
- `tags`: Tags associated with the ticket
- `conversations`: Up to 10 conversations
- `assets`: Associated assets
- `related_tickets`: Related tickets metadata
- `department`: Department details
- `member_details`: CAB member details
- `user_field_groups`: User field group information
- Various other resource-specific includes

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
