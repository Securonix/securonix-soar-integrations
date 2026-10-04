# AlgoSec (ASMS) API Reference — Connector Research

Research artifact for the **Support for AlgoSec** SOAR connector.
Captures the full public AlgoSec REST API surface plus a recommended, scoped
action set for the connector. No customer-specified action list exists, so the
scope below is proposed by analogy with the existing firewall connectors in
this repo (Skybox Security, Cisco Meraki, Akamai/AWS WAF, Netskope).

> Source: AlgoSec public tech docs at https://techdocs.algosec.com (no login
> required). Version targeted: **latest / a33.20** unless told otherwise.

---

## 1. Product overview

AlgoSec's suite is **ASMS (AlgoSec Security Management Suite)**. It has three
products, each with its own API and its own authentication:

| Product | What it does | API styles | REST base URL |
|---|---|---|---|
| **AFA** (Firewall Analyzer) | Device inventory, policy/rule analysis, risk, reports, traffic simulation | REST + SOAP | `https://<server>/afa/api/v1` (and legacy `https://<server>/fa/server`) |
| **FireFlow** | Firewall change-request tickets (traffic/object/generic changes) | REST + SOAP | `https://<server>/FireFlow/api` |
| **AppViz** (formerly BusinessFlow) | Business-application connectivity, network objects/services | REST | `https://<server>/BusinessFlow/rest/v1` |

AlgoSec recommends **REST over SOAP**. Every existing connector in this repo is
REST/HTTP via the `requests` library, so the connector should stay REST-only.

Live Swagger (on a running instance, needs a login):
`https://<ASMS-IP>/algosec/swagger/swagger-ui.html`

---

## 2. Authentication (differs per product)

Each product authenticates separately. All three are **cookie/session based** —
not a bearer token like the Skybox connector. This is an important
implementation detail for the connector's `_get_session()` helper.

### AFA REST
- **Login:** `POST /afa/api/v1` login endpoint returns a `sessionId`.
- Two flavors of auth depending on the endpoint group:
  - Most endpoints (`/afa/api/v1/...`): send cookie `PHPSESSID=<sessionId>`.
  - Legacy endpoints (`/fa/server/...`): send `?session=<sessionId>` as a URL parameter.
- Example: `curl --cookie "PHPSESSID=<sessionId>" https://<server>/afa/api/v1/...`

### FireFlow REST
- **Login:** `POST /FireFlow/api/authentication/authenticate`
  - Body: `{"username": "...", "password": "..."}`
  - Success response contains `data.sessionId` (plus `faSessionId`, `phpSessionId`).
- Subsequent calls send cookie `FireFlow_Session=<sessionId>`.
- Base URL: `https://<server>/FireFlow/api`

### AppViz REST
- **Login:** `POST /BusinessFlow/rest/v1/login` using HTTP Basic auth (username/password).
  - Response body contains `jsessionid`.
- Subsequent calls send cookie `JSESSIONID=<jsessionid>`.
- Every request must set `Content-Type: application/json`.
- Base URL: `https://<server>/BusinessFlow/rest/v1`

---

## 3. Full REST API surface (inventory)

This is the complete set of documented endpoint groups. Kept here so the whole
API is on record; **not** all of these will be built (see section 4).

### 3.1 AFA REST (`/afa/api/v1`) — ~100+ endpoints

| Group | Endpoints (summary) |
|---|---|
| Login / logout | Log in to ASMS, Log out of ASMS |
| Analysis & reports | Start an analysis, Retrieve analysis status, Baseline compliance report, Query Troubleshooting Tool, Get all reports, Last completed report of devices, Export report to PDF, Get changes from report, Get report statistics |
| Device Management | Retrieve interfaces, Identify/Merge missing routers, Get device details, Add/Edit device, View device parameter templates, Delete device, **Get list of devices**, **Get devices + policy details**, Get managed device info, Get zones data, Get parents for child devices, Export device changes to XLS, Bulk update AWS cloud account keys, **Get NAT rules**, Get device routing info, Device Groups CRUD (EA), Get groups by device display name |
| Devices Relocation | Relocate devices between nodes, Check/Cancel relocation progress, Enable processes after relocation |
| Notification Center | Manage AFA notifications |
| Object Management | **Get list of network objects**, Retrieve network objects & IPs, Network objects in device, Get network objects by device, **Retrieve service objects**, FQDN↔network-object mapping, Network objects containing all FQDNs, Match objects by name, Find objects by device name, Get service objects by entity |
| Policy Optimization | Consolidated rules, Covered rules (+CSV export), Disabled rules, Redundant special-case rules, Unused rules, Rules without logging, Unattached objects, Rules with empty comments, **Permissive rules** |
| Risks | **Retrieve risk profile list**, **Run a Risk Check**, Import risk profile from spreadsheet, Update risk definitions |
| Risk Profiles | User-defined risk profiles, Download risk profile file, Custom risk profile data, Risk profiles for report |
| Rule data | **Get all rules in device/group policy**, **Get risky rules**, Rules hit count, Add/edit rule documentation, Get rule documentation, Redundant special-case rules, Rules Advanced Search, Get NAT rules, Get implicit rules |
| Security zones | Retrieve security zones, Assign zone types to interfaces |
| Traffic Simulation | **Perform Traffic Simulation Query**, **Find Route Between Source and Destination** |
| Trusted Traffic | Get/Add/Edit/Delete trusted traffic, Trust existing rule, Import/Export trusted traffic |
| Trusted rules | List/Add/Delete trusted rules |
| Users & Roles | User CRUD, Change password, Role CRUD, Retrieve role/user data *(admin — out of scope)* |
| URL Categories | List/Create/Delete URL categories, Add/remove URLs & IPs, Rename category |
| Additional | Sync ACE resources, Get changes over period, Advanced config get/set, Configure proxy, Get license details, Resolve IP→hostname *(mostly admin — out of scope)* |

### 3.2 FireFlow — change request lifecycle

REST (`/FireFlow/api`):
- `POST /change-requests/traffic` — **Create a traffic change request** (block/allow traffic; core remediation action).
- `POST /change-requests/object` — Create object change request.
- `POST /change-requests/generic` — Create generic change request.
- Get change request details / status (by ID), Get SLA info for a change request.

> Note: several classic FireFlow methods (`createTicket`, `getTicket`,
> `getFields`) are documented on the **SOAP** API. The REST equivalents are the
> `/change-requests/*` endpoints above. Stay on REST to match the rest of the repo.

### 3.3 AppViz REST (`/BusinessFlow/rest/v1`)

- `/applications` — **Get business applications** (and their connectivity flows).
- `/network_objects` — Network objects.
- `/network_services` — Network services.
- `/settings/permissions` — Permissions *(admin — out of scope)*.
- Import vulnerability data.
- Run a Risk Check.

---

## 4. Proposed connector scope (recommendation)

"Everything" the API exposes is 120+ endpoints, most of which are admin/config
operations (user management, server config, device relocation, proxy setup)
that don't belong in a SOAR playbook. For comparison, the largest existing
connector in this repo (Skybox) has 10 functions.

Recommendation: build the **SOAR-relevant** subset — investigate + analyze +
remediate — mirroring how Skybox and the WAF connectors are scoped. This is
comprehensive across all three products while staying usable and testable.

These are the exact paths/methods confirmed against the individual AlgoSec
tech-docs endpoint pages (not guessed). AFA login:
`POST /fa/server/connection/login` with body `{"username","password"}` →
returns `SessionID`, used as the `PHPSESSID` cookie for `/afa/api/v1` calls.

### Investigate / read
| Action | Product | Method & Path (confirmed) | Key params |
|---|---|---|---|
| Get Devices | AFA | `GET /afa/api/v1/devices` | — |
| Get Devices with Policy | AFA | `GET /afa/api/v1/allowedDevices` | optional `device`/`deviceTreeName` |
| Get Device Rules | AFA | `GET /afa/api/v1/rules` | `entity` (req), `entityType` |
| Get Risky Rules | AFA | `GET /afa/api/v1/risks/riskyRules` | `entity` (req), `entityType` |
| Get NAT Rules | AFA | `GET /afa/api/v1/rule/natRulesInfo` | `entityTreeName` (req) |
| Get Network Objects | AFA | `GET /afa/api/v1/networkObject/search/findByOriginalNameContaining` | `deviceName`, `query` |
| Get Service Objects | AFA | `GET /afa/api/v1/network_services` | `entity` (req), `entityType` |
| Get Reports | AFA | `GET /afa/api/v1/report/findAllReports` | `deviceName` (req), `fromDate` |
| Get Applications | AppViz | `GET /BusinessFlow/rest/v1/applications/` | `page_number` |

### Analyze
| Action | Product | Method & Path (confirmed) | Key params |
|---|---|---|---|
| Run Traffic Simulation Query | AFA | `POST /afa/api/v1/query/` | body: `QueryInput[]`, `QueryTarget` |
| Find Route (Source → Destination) | AFA | `POST /afa/api/v1/query/routing` | body: `source`, `destination` |
| Retrieve Risk Profile List | AFA | `GET /afa/api/v1/risks/profiles` | — |
| Run a Risk Check | AFA | `POST /afa/api/v1/risks/calculate` | body: `traffic[]`, `riskProfile` *(body fields need live-Swagger confirmation)* |

### Remediate / act (FireFlow)
FireFlow login: `POST /FireFlow/api/authentication/authenticate` →
`data.sessionId`, used as cookie `FireFlow_Session`.
| Action | Product | Method & Path (confirmed) | Key params |
|---|---|---|---|
| Create Traffic Change Request | FireFlow | `POST /FireFlow/api/change-requests/traffic` | body: `template`, `traffic[]` |
| Create Object Change Request | FireFlow | `POST /FireFlow/api/change-requests/object` | body: `template`, `objects[]` |
| Get Change Request Status | FireFlow | `GET /FireFlow/api/change-requests/traffic/{id}` | path: change request id |

**Total: 16 focused functions** — covers AFA + FireFlow + AppViz, spans
read/analyze/remediate like every peer connector, REST-only, no admin noise.

> All paths above except the `run_risk_check` request **body** were confirmed
> from the per-endpoint tech-docs pages. `run_risk_check`'s path is confirmed;
> its exact body field names should be verified against a live instance's
> Swagger. This is the one remaining item for the live-instance check.

### Explicitly out of scope (unless requested)
- User & role management, password changes (AFA Users & Roles)
- Server/advanced config, proxy setup, license (AFA Additional APIs)
- Device relocation between nodes
- SOAP-only methods

---

## 5. Open questions for Sanket

1. **ASMS version** — targeting latest / a33.20 unless the customer runs an older release.
2. **REST-only OK?** — FireFlow's classic ticket methods are SOAP; the plan uses the REST `/change-requests/*` endpoints instead. Confirm no SOAP-only capability is required.
3. **Test instance / credentials** — need a sandbox ASMS URL + creds (or sample request/response payloads) to build and verify against a live API.
4. **Scope sign-off** — confirm the ~16-action set above, or point to a specific action the customer needs that isn't listed.

---

## 6. Reference links (all public)

- ASMS API reference (index): https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/api_introduction.htm
- AFA REST web services: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/afa-rest-web-services.htm
- FireFlow REST web services: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/fireflow-rest-web-services.htm
- FireFlow authentication: https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/authenticating.htm
- Create a traffic change request: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/createatrafficchangerequest_request.htm
- Work with change requests: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/working-with-change-requests.htm
- AppViz REST web services: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/businessflow-rest-web-services.htm

_Content from AlgoSec tech docs was rephrased/summarized for compliance with licensing restrictions._
