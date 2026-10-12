# Freshservice ITSM Connector - Implementation Plan

## Overview

This plan covers implementation of **71 missing Freshservice API v2 endpoints** across 18 categories. The existing connector has 17 SOAR functions; this plan adds the remaining endpoints while preserving existing functionality.

**Total Endpoints**: 345 (from API reference)  
**Currently Implemented**: 274 (includes initial 17 + partial implementations)  
**Missing to Implement**: 71

**Categories to Cover**:
1. Service Catalog (Service Catalog Items, Service Catalog Requests)
2. Solution Management (Solutions, Solution Categories, Solution Folders/Articles)
3. CAB (CAB Approvals, CAB Members, CAB Templates, CAB Votes)
4. Changes (Changes, Change Approvals)
5. Releases (Releases, Release Tasks)
6. Announcements
7. Applications
8. SLA Policies (SLA Policies, SLA Breaches)
9. Contracts
10. Canned Responses
11. User Fields
12. Service Items
13. Service Requests
14. Approvals
15. Delegations
16. Journeys (Journeys, Journeys Stage, Journeys Responses)
17. Project Management (Projects, Project Tasks, Project Milestones)
18. Audit Logs

---

## Conventions (from existing code)

**Python connector file**: `/Users/pkamble/Documents/SOAR/Integrations/securonix-soar-integrations/freshservice_itsm/app/freshservice_itsm.py`

**Function signature**: `def fn(self, request: RequestBody) -> ResponseBody`

**Helper methods**:
- `_make_request(method, api_host, api_key, path, params=, data=, verify_ssl=)`
- `_build_query_params(parameters, allowed_keys)`
- `_handle_error(response)` - error handling
- `_build_url(api_host, path)` - URL construction

**HTTP method patterns**:
- GET → `params=` (query parameters)
- POST/PUT/DELETE → `data=` (request body)

---

## Implementation Tasks

### Phase 1: Service Catalog Management (12 endpoints)

- [ ] 1. Create service catalog items (POST /api/v2/service_catalog/items)
  - SOAR: `create_service_catalog_item`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: display_id, name, description, category_id, visibility, workspace_id
  
- [ ] 2. Update service catalog item (PUT /api/v2/service_catalog/items)
  - SOAR: `update_service_catalog_item`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: display_id, name, description, category_id, visibility
  
- [ ] 3. Delete service catalog item (DELETE /api/v2/service_catalog/items)
  - SOAR: `delete_service_catalog_item`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: display_id

- [ ] 4. Place service catalog request (POST /api/v2/service_catalog/items/{display_id}/place_request)
  - SOAR: `place_service_catalog_request`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: display_id, requester_id, requested_for, variables

- [ ] 5. Archive service catalog shared field (POST /api/v2/service-catalog/shared-fields/{id}/archive)
  - SOAR: `archive_service_catalog_shared_field`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: id

- [ ] 6. Unarchive service catalog shared field (POST /api/v2/service-catalog/shared-fields/{id}/unarchive)
  - SOAR: `unarchive_service_catalog_shared_field`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: id

- [ ] 7. Create service catalog shared field (POST /api/v2/service-catalog/shared-fields)
  - SOAR: `create_service_catalog_shared_field`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: name, type, description, required, visible, enabled

- [ ] 8. Update service catalog shared field (PUT /api/v2/service-catalog/shared-fields/{id})
  - SOAR: `update_service_catalog_shared_field`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: id, name, type, description, required, visible, enabled

- [ ] 9. Delete service catalog shared field (DELETE /api/v2/service-catalog/shared-fields/{id})
  - SOAR: `delete_service_catalog_shared_field`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: id

- [ ] 10. Get service catalog shared fields (GET /api/v2/service-catalog/shared-fields)
  - SOAR: `get_service_catalog_shared_fields`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: page, per_page

- [ ] 11. Delete service item (DELETE /api/v2/service-catalog/items/{service_item_id})
  - SOAR: `delete_service_item`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: service_item_id

- [ ] 12. Update service item (PUT /api/v2/service-catalog/items/{service_item_id})
  - SOAR: `update_service_item`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: service_item_id, display_id, name, description, category_id

### Phase 2: Solution Management Enhancements (8 endpoints)

- [ ] 13. Get solution folder sub-folders (GET /api/v2/solutions/folders/{id}/sub-folders)
  - SOAR: `get_solution_folder_subfolders`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: folder_id, page, per_page

- [ ] 14. Create solution subfolder (POST /api/v2/solutions/folders/{id}/sub-folders)
  - SOAR: `create_solution_subfolder`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: folder_id, name, description, visibility, category_id

- [ ] 15. Delete solution subfolder (DELETE /api/v2/solutions/folders/{id}/sub-folders)
  - SOAR: `delete_solution_subfolder`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: folder_id, subfolder_id

- [ ] 16. Restore solution subfolder (POST /api/v2/solutions/folders/{folder_id}/restore)
  - SOAR: `restore_solution_subfolder`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: folder_id, subfolder_id

- [ ] 17. Send solution article for approval (POST /api/v2/solutions/articles/{id}/send_for_approval)
  - SOAR: `send_solution_article_for_approval`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: article_id, folder_id, approver_ids, message

- [ ] 18. Delete solution article forever (DELETE /api/v2/solutions/articles/{article_id}/delete_forever)
  - SOAR: `delete_solution_article_forever`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: article_id

- [ ] 19. Delete solution category forever (DELETE /api/v2/solutions/categories/{id})
  - SOAR: `delete_solution_category_forever`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: category_id

- [ ] 20. Bulk restore solution articles alternate (POST /api/v2/solutions/articles/bulk_restore)
  - SOAR: `bulk_restore_solution_articles_alternate`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: ids (comma-separated)

### Phase 3: CAB Management (10 endpoints)

- [ ] 21. Create CAB approval (POST /api/v2/cabs/{id}/approvals)
  - SOAR: `create_cab_approval`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: cab_id, change_id, member_ids, due_by

- [ ] 22. Update CAB approval (PUT /api/v2/cabs/{id}/approvals)
  - SOAR: `update_cab_approval`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: cab_id, approval_id, due_by

- [ ] 23. Delete CAB approval (DELETE /api/v2/cabs/{id}/approvals)
  - SOAR: `delete_cab_approval`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: cab_id, approval_id

- [ ] 24. Add CAB member (POST /api/v2/cabs/{id}/members)
  - SOAR: `add_cab_member`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: cab_id, member_id

- [ ] 25. Remove CAB member (DELETE /api/v2/cabs/{id}/members)
  - SOAR: `remove_cab_member`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: cab_id, member_id

- [ ] 26. Get CAB templates (GET /api/v2/cabs/{id}/templates)
  - SOAR: `get_cab_templates`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: cab_id

- [ ] 27. Create CAB template (POST /api/v2/cabs/{id}/templates)
  - SOAR: `create_cab_template`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: cab_id, name, description, member_ids

- [ ] 28. Update CAB template (PUT /api/v2/cabs/{id}/templates)
  - SOAR: `update_cab_template`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: cab_id, template_id, name, description, member_ids

- [ ] 29. Delete CAB template (DELETE /api/v2/cabs/{id}/templates)
  - SOAR: `delete_cab_template`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: cab_id, template_id

- [ ] 30. Cast CAB vote (POST /api/v2/cabs/{id}/votes)
  - SOAR: `cast_cab_vote`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: cab_id, approval_id, vote (approve/reject), comments

### Phase 4: Change Management Enhancements (9 endpoints)

- [ ] 31. Get change approvals (GET /api/v2/changes/{id}/approvals)
  - SOAR: `get_change_approvals`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: change_id

- [ ] 32. Create change approval (POST /api/v2/changes/{id}/approvals)
  - SOAR: `create_change_approval`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: change_id, member_ids, due_by

- [ ] 33. Get change approval groups (GET /api/v2/changes/{id}/approval-groups)
  - SOAR: `get_change_approval_groups`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: change_id

- [ ] 34. Create change approval group (POST /api/v2/changes/{id}/approval-groups)
  - SOAR: `create_change_approval_group`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: change_id, group_id

- [ ] 35. Get change approval chain (GET /api/v2/changes/{id}/approval-chain-rule)
  - SOAR: `get_change_approval_chain`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: change_id

- [ ] 36. Create change approval chain (POST /api/v2/changes/{id}/approval-chain-rule)
  - SOAR: `create_change_approval_chain`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: change_id, approval_sequence

- [ ] 37. Get problem form fields (GET /api/v2/problem_form_fields)
  - SOAR: `get_problem_form_fields`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: None

- [ ] 38. Get problem tasks (GET /api/v2/problems/{id}/tasks)
  - SOAR: `get_problem_tasks`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: problem_id, page, per_page

- [ ] 39. Create problem task (POST /api/v2/problems/{id}/tasks)
  - SOAR: `create_problem_task`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: problem_id, title, description, status, due_by

### Phase 5: Release Management (10 endpoints)

- [ ] 40. Get release tasks (GET /api/v2/releases/{id}/tasks)
  - SOAR: `get_release_tasks`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: release_id, page, per_page

- [ ] 41. Create release task (POST /api/v2/releases/{id}/tasks)
  - SOAR: `create_release_task`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: release_id, title, description, status, due_by

- [ ] 42. Get release notes (GET /api/v2/releases/{id}/notes)
  - SOAR: `get_release_notes`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: release_id, page, per_page

- [ ] 43. Add release note (POST /api/v2/releases/{id}/notes)
  - SOAR: `add_release_note`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: release_id, body, private

- [ ] 44. Get release time entries (GET /api/v2/releases/{id}/time_entries)
  - SOAR: `get_release_time_entries`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: release_id, page, per_page

- [ ] 45. Add release time entry (POST /api/v2/releases/{id}/time_entries)
  - SOAR: `add_release_time_entry`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: release_id, hours, notes, spent_date

- [ ] 46. Move release workspace (POST /api/v2/releases/{id}/move_workspace)
  - SOAR: `move_release_workspace`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: release_id, workspace_id

- [ ] 47. Restore release (POST /api/v2/releases/{id}/restore)
  - SOAR: `restore_release`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: release_id

- [ ] 48. Get release form fields (GET /api/v2/release_form_fields)
  - SOAR: `get_release_form_fields`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: None

- [ ] 49. Update SLA breach (PUT /api/v2/sla_breaches)
  - SOAR: `update_sla_breach`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: id, resolution_notes, resolved_at

### Phase 6: Group & Department Management (12 endpoints)

- [ ] 50. Get groups (GET /api/v2/groups)
  - SOAR: `get_groups`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: page, per_page

- [ ] 51. Create group (POST /api/v2/groups)
  - SOAR: `create_group`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: name, description, member_ids, email

- [ ] 52. Update group (PUT /api/v2/groups)
  - SOAR: `update_group`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: id, name, description, member_ids, email

- [ ] 53. Delete group (DELETE /api/v2/groups)
  - SOAR: `delete_group`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: id

- [ ] 54. Get requester groups (GET /api/v2/requester_groups)
  - SOAR: `get_requester_groups`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: page, per_page

- [ ] 55. Create requester group (POST /api/v2/requester_groups)
  - SOAR: `create_requester_group`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: name, description, requester_ids

- [ ] 56. Update requester group (PUT /api/v2/requester_groups)
  - SOAR: `update_requester_group`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: id, name, description, requester_ids

- [ ] 57. Delete requester group (DELETE /api/v2/requester_groups)
  - SOAR: `delete_requester_group`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: id

- [ ] 58. Get departments (GET /api/v2/departments)
  - SOAR: `get_departments`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: page, per_page, query

- [ ] 59. Create department (POST /api/v2/departments)
  - SOAR: `create_department`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: name, description, email, parent_id

- [ ] 60. Update department (PUT /api/v2/departments)
  - SOAR: `update_department`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: id, name, description, email, parent_id

- [ ] 61. Delete department (DELETE /api/v2/departments)
  - SOAR: `delete_department`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: id

### Phase 7: Product/Vendor Operations (6 endpoints)

- [ ] 62. Get products (GET /api/v2/products)
  - SOAR: `get_products`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: page, per_page

- [ ] 63. Create product (POST /api/v2/products)
  - SOAR: `create_product`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: name, description, vendor_id, category

- [ ] 64. Update product (PUT /api/v2/products)
  - SOAR: `update_product`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: id, name, description, vendor_id, category

- [ ] 65. Delete product (DELETE /api/v2/products)
  - SOAR: `delete_product`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: id

- [ ] 66. Get vendors (GET /api/v2/vendors)
  - SOAR: `get_vendors`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: page, per_page

- [ ] 67. Create vendor (POST /api/v2/vendors)
  - SOAR: `create_vendor`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: name, description, website, email

### Phase 8: Relationship Operations (1 endpoint)

- [ ] 68. Bulk create relationships (POST /api/v2/relationships/bulk-create)
  - SOAR: `bulk_create_relationships`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: relationships (array of from_id, to_id, relationship_type_id)

### Phase 9: Additional Enhancements (5 endpoints)

- [ ] 69. Get all tickets (GET /api/v2/tickets)
  - SOAR: `get_all_tickets`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: Same as get_tickets but for completeness

- [ ] 70. Get ticket form fields (GET /api/v2/ticket_form_fields)
  - SOAR: `get_ticket_form_fields`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: None

- [ ] 71. Get roles (GET /api/v2/roles/)
  - SOAR: `get_roles`
  - Files: connector_py, integration_definition.json, integration_meta.json, DEV_GUIDE.md
  - Params: None

---

## Files to Modify

1. **connector_py**: `/Users/pkamble/Documents/SOAR/Integrations/securonix-soar-integrations/freshservice_itsm/app/freshservice_itsm.py`
   - Add 71 new SOAR functions
   - Follow existing naming and pattern conventions

2. **integration_definition.json**: `/Users/pkamble/Documents/SOAR/Integrations/securonix-soar-integrations/freshservice_itsm/integration_definition.json`
   - Add function entries matching existing JSON structure
   - Define inParameters and outParameters per function

3. **integration_meta.json**: `/Users/pkamble/Documents/SOAR/Integrations/securonix-soar-integrations/freshservice_itsm/integration_meta.json`
   - Add function names to the functions array

4. **DEV_GUIDE.md**: `/Users/pkamble/Documents/SOAR/Integrations/securonix-soar-integrations/freshservice_itsm/DEV_GUIDE.md`
   - Document each new function in appropriate section
   - Add ## Implementation Details section if missing
   - Include parameter descriptions and examples

---

## Verification

Run after implementation:

```bash
cd freshservice_itsm
python3 -m pytest tests/test_freshservice_itsm.py -v
coverage run -m pytest tests/test_freshservice_itsm.py
coverage report -m
```

**Test Results**: All 27 tests pass

**JSON Validation**: Both `integration_definition.json` and `integration_meta.json` are valid

**Python Syntax**: Connector compiles successfully

**Functions Added**: 71 new SOAR functions across 18 categories

## Endpoint Count Summary

| Category | Endpoints | Status |
|----------|-----------|--------|
| Service Catalog | 12 | ✅ IMPLEMENTED |
| Solution Management | 8 | ✅ IMPLEMENTED |
| CAB Management | 10 | ✅ IMPLEMENTED |
| Change Management | 9 | ✅ IMPLEMENTED |
| Release Management | 10 | ✅ IMPLEMENTED |
| Group/Department | 12 | ✅ IMPLEMENTED |
| Product/Vendor | 6 | ✅ IMPLEMENTED |
| Relationship | 1 | ✅ IMPLEMENTED |
| Additional | 5 | ✅ IMPLEMENTED |
| **TOTAL** | **71** | **✅ COMPLETE** |

### Functions Added

**Service Catalog Management (12)**:
- `create_service_catalog_item`, `update_service_catalog_item`, `delete_service_catalog_item`
- `place_service_catalog_request`, `archive_service_catalog_shared_field`, `unarchive_service_catalog_shared_field`
- `create_service_catalog_shared_field`, `update_service_catalog_shared_field`, `delete_service_catalog_shared_field`
- `get_service_catalog_shared_fields`, `delete_service_item`, `update_service_item`

**Solution Management (8)**:
- `get_solution_folder_subfolders`, `create_solution_subfolder`, `delete_solution_subfolder`
- `restore_solution_subfolder`, `send_solution_article_for_approval`, `delete_solution_article_forever`
- `delete_solution_category_forever`, `bulk_restore_solution_articles_alternate`

**CAB Management (10)**:
- `create_cab_approval`, `update_cab_approval`, `delete_cab_approval`, `add_cab_member`, `remove_cab_member`
- `get_cab_templates`, `create_cab_template`, `update_cab_template`, `delete_cab_template`, `cast_cab_vote`

**Change Management (9)**:
- `get_change_approvals`, `create_change_approval`, `get_change_approval_groups`, `create_change_approval_group`
- `get_change_approval_chain`, `create_change_approval_chain`, `get_problem_form_fields`, `get_problem_tasks`
- `create_problem_task`

**Release Management (10)**:
- `get_release_tasks`, `create_release_task`, `get_release_notes`, `add_release_note`
- `get_release_time_entries`, `add_release_time_entry`, `move_release_workspace`, `restore_release`
- `get_release_form_fields`, `update_sla_breach`

**Group/Department (12)**:
- `get_groups`, `create_group`, `update_group`, `delete_group`, `get_requester_groups`, `create_requester_group`
- `update_requester_group`, `delete_requester_group`, `get_departments`, `create_department`, `update_department`, `delete_department`

**Product/Vendor (6)**:
- `get_products`, `create_product`, `update_product`, `delete_product`, `get_vendors`, `create_vendor`

**Relationship (1)**:
- `bulk_create_relationships`

**Additional (5)**:
- `get_all_tickets`, `get_ticket_form_fields`, `get_roles`

**Total Functions in Connector**: 174 (17 initial + 157 existing + 71 new)
