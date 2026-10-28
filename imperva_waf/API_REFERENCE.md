# Imperva Cloud WAF API Reference — Connector Research

Research artifact for the **Support for Imperva WAF** SOAR connector.
Target product: **Imperva Cloud WAF** (formerly Incapsula) — the cloud-hosted/SaaS
WAF. All endpoints and parameters below are confirmed from Imperva's official
sources (the `imperva/incapsula-cli` source and the Imperva Incapsula API as
documented in the Cortex XSOAR Incapsula integration) — not assumed.

---

## 1. Overview

| Item | Value |
|---|---|
| Product | Imperva Cloud WAF (Incapsula), cloud-hosted SaaS |
| Base URL (provisioning v1) | `https://my.imperva.com/api/prov/v1` |
| Base URL (audit trail) | `https://api.imperva.com/audit-trail/v2` |
| Protocol | REST, RPC-style; prov/v1 POSTs use `application/x-www-form-urlencoded` |
| Auth | API key pair in headers: `x-API-Id` + `x-API-Key` |

Auth and base URL confirmed from the CLI's `Utils/executeRest.py`
(`x-API-Id`/`x-API-Key` headers, `my.imperva.com/api/prov/v1/`).

---

## 2. Scoped connector actions (8)

### Remediate / contain
| Action | Method & Endpoint | Params (confirmed) |
|---|---|---|
| Block IP | `POST /api/prov/v1/sites/configure/acl` | `site_id`, `rule_id=api.acl.blacklisted_ips`, `ips` |
| Unblock IP | `POST /api/prov/v1/sites/configure/acl` | `site_id`, `rule_id=api.acl.blacklisted_ips`, `ips` (resent without the IP) |
| Allowlist IP | `POST /api/prov/v1/sites/configure/acl` | `site_id`, `rule_id=api.acl.whitelisted_ips`, `ips` |
| Block Country | `POST /api/prov/v1/sites/configure/acl` | `site_id`, `rule_id=api.acl.blacklisted_countries`, `countries` |
| Add Security Rule (IncapRule) | `POST /api/prov/v1/sites/incapRules/add` | `site_id`, `name`, `action` (e.g. `RULE_ACTION_BLOCK_IP`), `filter` |

### Investigate / enrich
| Action | Method & Endpoint | Params (confirmed) |
|---|---|---|
| List Sites | `POST /api/prov/v1/sites/list` | `account_id?`, `page_size?`, `page_num?` |
| Get Site Status | `POST /api/prov/v1/sites/status` | `site_id`, `tests?` |
| Get Audit Events | `GET https://api.imperva.com/audit-trail/v2/events` | `account_id?`, `start?`, `end?`, `page_size?`, `page_num?` |

**Source of each endpoint path (verbatim from `imperva/incapsula-cli`):**
`sites/configure/acl` (`Sites/uACL.py`), `sites/configure/security`
(`Sites/uWaf.py`), `sites/incapRules/add` (`Sites/cIncapRule.py`), `sites/list`
(`Sites/rSites.py`), `sites/status` (`Sites/rSite.py`),
`audit-trail/v2/events` (`Accounts/account.py`).

### ACL rule_id values (confirmed from the XSOAR Incapsula reference)
`api.acl.blacklisted_ips`, `api.acl.whitelisted_ips`,
`api.acl.blacklisted_countries`, `api.acl.blacklisted_urls`.

### IncapRule action values (confirmed)
`RULE_ACTION_ALERT`, `RULE_ACTION_BLOCK`, `RULE_ACTION_BLOCK_IP`,
`RULE_ACTION_BLOCK_USER`, `RULE_ACTION_CAPTCHA`, `RULE_ACTION_REDIRECT`,
`RULE_ACTION_REWRITE_URL`, etc.

---

## 3. Connection parameters

- `api_id` (String) — Imperva API ID (sent as `x-API-Id`)
- `api_key` (String, secret + encrypted) — Imperva API key (sent as `x-API-Key`)
- `base_url` (String, optional, default `https://my.imperva.com/api/prov/v1`)
- `verify_ssl` (optional, default true)

---

## 4. Design notes

- Block/Unblock IP: the ACL `blacklisted_ips` list is set wholesale by the API
  (`ips` is the full comma-separated list). The connector sends the `ips` it is
  given; managing add/remove against the existing list is the caller's/playbook's
  responsibility unless a read-modify-write is added later. (Mirrors how the
  Akamai/AWS WAF connectors treat list updates.)
- prov/v1 is an RPC-style API: parameters are sent as form-encoded fields on a
  POST; success/failure is indicated by a `res` field in the JSON response
  (`res == 0` means success).

## 5. Notes / open items

- Endpoints, paths, params, ACL rule_id values, and IncapRule action values are
  confirmed from Imperva's official CLI source and the XSOAR Incapsula reference.
- Live verification requires an Imperva Cloud WAF account (Enterprise plan, which
  is required to use the API) with API keys — not available here, so verification
  is unit tests (HTTP mocked) + official-source confirmation.

## 6. Reference links

- Imperva CLI (official): https://github.com/imperva/incapsula-cli
- Cortex XSOAR Incapsula integration (command/param reference): https://xsoar.pan.dev/docs/reference/integrations/incapsula

_Content from Imperva sources was rephrased/summarized for compliance with licensing restrictions._
