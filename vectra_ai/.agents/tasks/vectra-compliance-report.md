# Vectra AI Connector API Compliance Report

**Report Date**: 2024-10-12
**Target API Versions**: v3.4 and v3.5 (Public Preview)
**Connector Location**: `/Users/pkamble/Documents/SOAR/Integrations/securonix-soar-integrations/vectra_ai/`
**API Documentation**: `/Users/pkamble/Downloads/vectraai-rest-api (1).yaml`

## Summary

The Vectra AI connector implements **11 out of 33 SOAR-relevant API endpoints**. This represents **33% coverage** of the total endpoints documented in the Vectra AI API specification. While core investigation and remediation operations are implemented, significant functionality remains missing, particularly around assignment management, rules, and investigation schemas/tables.

## Implemented Endpoints (11 endpoints)

### Detections (v3.5)
| Endpoint | SOAR Function | Status |
|----------|--------------|--------|
| GET /api/v3.5/detections/ | `get_detections()` | ✅ Implemented |
| GET /api/v3.5/detections/{id}/ | `get_detection_by_id()` | ✅ Implemented |
| PATCH /api/v3.5/detections/ | `mark_detection_fixed()` | ✅ Implemented (partial - no single detection update) |

### Accounts (v3.5)
| Endpoint | SOAR Function | Status |
|----------|--------------|--------|
| GET /api/v3.5/accounts/ | `get_accounts()` | ✅ Implemented |
| GET /api/v3.5/accounts/{id}/ | `get_account_by_id()` | ✅ Implemented |
| PATCH /api/v3.4/accounts/{id}/close | `close_account()` | ✅ Implemented |

### Hosts (v3.5)
| Endpoint | SOAR Function | Status |
|----------|--------------|--------|
| GET /api/v3.5/hosts/ | `get_hosts()` | ✅ Implemented |
| GET /api/v3.5/hosts/{id}/ | `get_host_by_id()` | ✅ Implemented |
| PATCH /api/v3.5/hosts/{id}/ | `set_host_as_key_asset()` | ✅ Implemented |

### Entities (v3.5)
| Endpoint | SOAR Function | Status |
|----------|--------------|--------|
| GET /api/v3.5/entities/ | `get_entities()` | ✅ Implemented |
| GET /api/v3.5/entities/{id}/ | `get_entity_by_id()` | ✅ Implemented |

### Findings (v3.5)
| Endpoint | SOAR Function | Status |
|----------|--------------|--------|
| GET /api/v3.5/findings/ | `get_findings()` | ✅ Implemented |
| GET /api/v3.5/findings/{id}/ | `get_finding_by_id()` | ✅ Implemented |
| GET /api/v3.5/findings/{id}/entities/ | `get_host_findings()` | ✅ Implemented |

### Assignment Outcomes (v3.4)
| Endpoint | SOAR Function | Status |
|----------|--------------|--------|
| GET /api/v3.4/assignment_outcomes/ | `get_assignment_outcomes()` | ✅ Implemented |
| POST /api/v3.4/assignment_outcomes/ | `create_assignment_outcome()` | ✅ Implemented |

### Assignments (v3.4)
| Endpoint | SOAR Function | Status |
|----------|--------------|--------|
| GET /api/v3.4/assignments/ | `get_assignments()` | ✅ Implemented |
| GET /api/v3.4/assignments/{id}/ | `get_assignment_by_id()` | ✅ Implemented |

### Events (v3.5)
| Endpoint | SOAR Function | Status |
|----------|--------------|--------|
| GET /api/v3.5/events/detections/ | `get_detection_events()` | ✅ Implemented |

## Missing Endpoints (22 endpoints)

### Detections (v3.5)
| Endpoint | SOAR Function | Priority | Rationale |
|----------|--------------|----------|----------|
| PATCH /api/v3.5/detections/{id}/ | `update_detection_by_id()` | **HIGH** | Single detection update is not supported. Users cannot update individual detection properties like `mark_as_fixed`, `note`, `triageAs`, `external_reference_id`, `investigation_status` on a per-detection basis. Only batch updates via detection ID list are available. |

### Entities (v3.5)
| Endpoint | SOAR Function | Priority | Rationale |
|----------|--------------|----------|----------|
| PATCH /api/v3.5/entities/{id}/ | `update_entity_by_id()` | **HIGH** | Entity-level updates (external_reference_id, unresolved_priority) cannot be performed on individual entities. |

### Assignment Outcomes (v3.4)
| Endpoint | SOAR Function | Priority | Rationale |
|----------|--------------|----------|----------|
| GET /api/v3.4/assignment_outcomes/{id}/ | `get_assignment_outcome_by_id()` | **MEDIUM** | Single outcome retrieval not implemented |
| PUT /api/v3.4/assignment_outcomes/{id}/ | `update_assignment_outcome()` | **MEDIUM** | Single outcome update not implemented |
| DELETE /api/v3.4/assignment_outcomes/{id}/ | `delete_assignment_outcome()` | **LOW** | Single outcome deletion not implemented |

### Rules (v3.4)
| Endpoint | SOAR Function | Priority | Rationale |
|----------|--------------|----------|----------|
| GET /api/v3.4/rules/ | `get_rules()` | **HIGH** | Triage rule listing - critical for rule management |
| POST /api/v3.4/rules/ | `create_rule()` | **HIGH** | Rule creation not supported |
| PUT /api/v3.4/rules/{id}/ | `update_rule()` | **HIGH** | Rule modification not supported |
| DELETE /api/v3.4/rules/{id}/ | `delete_rule()` | **HIGH** | Rule deletion not supported |
| GET /api/v3.4/rules/{id}/ | `get_rule_by_id()` | **HIGH** | Single rule retrieval not supported |

### Assignments (v3.4)
| Endpoint | SOAR Function | Priority | Rationale |
|----------|--------------|----------|----------|
| POST /api/v3.4/assignments/ | `create_assignment()` | **HIGH** | Assignment creation not implemented |
| PUT /api/v3.4/assignments/{id}/ | `update_assignment()` | **MEDIUM** | Assignment modification not supported |
| DELETE /api/v3.4/assignments/{id}/ | `delete_assignment()` | **LOW** | Assignment deletion not supported |

### Investigation Tables/Schemas (v3.5)
| Endpoint | SOAR Function | Priority | Rationale |
|----------|--------------|----------|----------|
| GET /api/v3.5/investigation_tables/ | `get_investigation_tables()` | **MEDIUM** | Investigation table resources listing |
| GET /api/v3.5/investigation_tables/{table}/ | `get_investigation_table()` | **MEDIUM** | Specific table resource retrieval |
| GET /api/v3.5/investigation_schemas/ | `get_investigation_schemas()` | **MEDIUM** | Catalog of investigation schemas |
| GET /api/v3.5/investigation_schemas/{source_type}/ | `get_investigation_source_schemas()` | **MEDIUM** | Schemas by source type |
| GET /api/v3.5/investigation_schemas/{source_type}/{table_name}/ | `get_investigation_schema()` | **MEDIUM** | Specific schema details |

## Key Concerns

### 1. Incomplete Detection Update Coverage
**Critical Impact**: The connector cannot update individual detections. Only batch updates via `detectionIdList` are supported.

**Missing Functionality**:
- Update single detection note
- Set single detection triage label (`triageAs`)
- Update single detection investigation status
- Set single detection external reference ID

**Recommendation**: Implement `update_detection_by_id()` using PATCH /api/v3.5/detections/{id}/

### 2. Missing Entity Update Functionality
**High Impact**: Cannot update individual entity properties like `external_reference_id` or `unresolved_priority`.

**Missing Functionality**:
- PATCH /api/v3.5/entities/{id}/ with type parameter

**Recommendation**: Implement `update_entity_by_id()` using PATCH /api/v3.5/entities/{id}/

### 3. Rules Management Completely Missing
**High Impact**: No ability to manage triage rules through SOAR connector. This is a core Vectra AI feature for automated detection triage.

**Missing Functions**:
- List, create, read, update, delete rules

**Recommendation**: Implement all 5 rule management functions (get_rules, create_rule, get_rule_by_id, update_rule, delete_rule)

### 4. Assignment Management Incomplete
**Medium Impact**: While assignment listing and retrieval exist, assignment creation and modification are missing.

**Missing Functions**:
- POST /api/v3.4/assignments/ - Create assignment
- PUT /api/v3.4/assignments/{id}/ - Update assignment
- DELETE /api/v3.4/assignments/{id}/ - Delete assignment

**Recommendation**: Implement assignment creation function first, as it's essential for analyst workflow automation.

### 5. Assignment Outcomes Incomplete
**Medium Impact**: Only listing and creation are implemented; retrieval, update, and deletion of individual outcomes are missing.

**Missing Functions**:
- GET /api/v3.4/assignment_outcomes/{id}/
- PUT /api/v3.4/assignment_outcomes/{id}/
- DELETE /api/v3.4/assignment_outcomes/{id}/

**Recommendation**: Implement single outcome retrieval as it's needed for outcome validation before creating assignments.

### 6. Investigation Tables/Schemas Completely Missing
**Medium Impact**: No visibility into available investigation table structures or schema definitions.

**Missing Functions**:
- All 5 investigation schema/table endpoints

**Recommendation**: Implement these if users need to build custom investigation queries through the connector.

## Verification Status

| Verification Item | Status |
|-------------------|--------|
| Connector follows folder structure of other connectors | ✅ YES |
| OAuth2 authentication implemented correctly | ✅ YES |
| All implemented functions use RequestBody/ResponseBody models | ✅ YES |
| Error handling for all HTTP status codes | ✅ YES |
| Pagination support for list endpoints | ✅ YES |
| Field selection (fields/exclude_fields) support | ✅ YES |
| SSL verification option | ✅ YES |

## Recommendations

### Priority 1 - High Impact (Implement First)
1. **Add single detection update**: Implement `update_detection_by_id()` using PATCH /api/v3.5/detections/{id}/
2. **Add entity update**: Implement `update_entity_by_id()` using PATCH /api/v3.5/entities/{id}/
3. **Implement rule management**: Add all 5 rule endpoints (get_rules, create_rule, get_rule_by_id, update_rule, delete_rule)

### Priority 2 - Medium Impact
4. **Complete assignment management**: Implement create_assignment(), update_assignment()
5. **Complete assignment outcomes**: Implement get_assignment_outcome_by_id(), update_assignment_outcome(), delete_assignment_outcome()

### Priority 3 - Lower Impact
6. **Investigation tables/schemas**: Implement if custom query building is required
7. **Assignment deletion**: Implement if analysts need to remove assignments

## Conclusion

The Vectra AI connector implements the **most frequently used endpoints** for SOAR operations (read-only operations and basic remediation) but is **missing critical update and management operations** that are essential for complete workflow automation. The connector should be extended to cover at least Priority 1 items (single detection/entity updates and rule management) before production deployment.

## Compliance Against User Requirements

| Requirement | Status | Notes |
|-------------|--------|-------|
| All API v3.4/v3.5 endpoints documented in API spec | ❌ NO | Only 33% implemented |
| Follows SOAR connector standards | ✅ YES | Folder structure, models, error handling all correct |
| Documentation complete | ✅ YES | DEV_GUIDE.md comprehensive for implemented functions |
| Supports investigation operations | ✅ YES | Read operations fully implemented |
| Supports remediation operations | ⚠️ PARTIAL | Batch operations present, individual updates missing |