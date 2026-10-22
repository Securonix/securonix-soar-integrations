# Kaspersky EDR API Reference — Connector Research

Research artifact for the **Support for Kaspersky EDR** SOAR connector.
All details below are confirmed from Kaspersky's official docs — not assumed.

> Sources: Kaspersky Security Center (KSC) Open API protocol docs and the
> Kaspersky Endpoint Security for Windows 12.9+ "API for EDR Threat Response"
> appendix (support.kaspersky.com).

---

## 1. How Kaspersky EDR responses work

Kaspersky EDR response actions are **not** separate REST endpoints. They are all
delivered through a single KSC Open API method — `HostGroup.AddIncident` — whose
incident body (`KLINCDT_BODY`) carries a JSON "task" describing the response.
After KSC processes the incident, Kaspersky Endpoint Security creates the
corresponding EDR response task on the target host.

### Transport decision (why raw HTTP, not KlAkOAPI)
Kaspersky documents the KSC Open API as an HTTP/JSON interface. Kaspersky's
`KlAkOAPI` Python wrapper is **not on PyPI** — it ships only inside the KSC
install. Previous connectors in this repo use plain `requests` or pip-installable
SDKs. To stay consistent and avoid a non-distributable dependency, this connector
calls the KSC Open API **directly over HTTPS/JSON** (no `KlAkOAPI`).

---

## 2. Connection & authentication (confirmed from KSC Open API docs)

| Item | Value |
|---|---|
| Base URL | `https://<kscHost>:<kscPort>/api/v1.0` |
| Default port | `13299` |
| Content type | `application/json` |

**Connection-based auth (verified against the KlAkOAPI SDK source):**
1. `POST /api/v1.0/login` on a persistent connection (requests.Session)
   - Header: `Authorization: KSCBasic user="<base64(user)>", pass="<base64(pass)>", domain="", internal="0"`
   - Body: `{}`
   - Success → HTTP 200 (connection is now authenticated).
2. All subsequent method calls reuse the **same authenticated session/connection**.
   There is **no** per-request session-id header and **no** `Session.StartSession`
   call — the KlAkOAPI SDK authenticates the connection and reuses it. (Confirmed
   by reading the actual `KlAkOAPI/AdmServer.py` source.)

**Connection parameters:** `ksc_host`, `ksc_port` (default 13299), `ksc_user`,
`ksc_password` (secret), `verify_ssl`.

**Responses:** success returns `{"PxgRetVal": <value>}`; errors are returned
**inside an HTTP 200** as `{"PxgError": {"code", "message", ...}}` — must be
parsed and surfaced as an error.

**Kaspersky typed values:** some fields use typed objects, e.g. a datetime is
`{"type":"datetime","value":"2016-09-19T15:22:35Z"}`. `KLINCDT_ADDED` uses this.

---

## 3. The AddIncident call (confirmed)

`POST /api/v1.0/HostGroup.AddIncident`
```json
{
  "pData": {
    "KLINCDT_SEVERITY": 2,
    "KLINCDT_ADDED": {"type": "datetime", "value": "<ISO8601 UTC>"},
    "KLINCDT_BODY": "<JSON string: the EDR task, see section 4>",
    "KLHST_WKS_HOSTNAME": "<target host id>"
  }
}
```
Returns `{"PxgRetVal": <incidentId>}`.

`KLINCDT_BODY` is a JSON **string** of (confirmed verbatim from Kaspersky's
official "Connecting to KSC" / "Incident parameters" example):
```json
{
  "task": "<task type>",
  "targetHost": "<host id>",
  "params": { ... per-task params ... },
  "responseEventIncident": true,
  "responseEventIncidentArea": "<caller app name>"
}
```

Per Kaspersky's documented flow, `AddIncident` is **followed by** `UpdateIncident`
on the same session:
```
POST /api/v1.0/HostGroup.UpdateIncident
{ "nId": <incidentId>, "pData": { "KLINCDT_IS_HANDLED": false, "KLHST_WKS_HOSTNAME": "<host id>" } }
```
`KLINCDT_SEVERITY` is `2` and `responseEventIncident` is `true` in Kaspersky's
example — these are the documented values, not connector choices.

---

## 4. EDR response actions (9) — exact task types & params

| # | Action | task | params (exact) |
|---|---|---|---|
| 1 | Isolate host | `isolateHost` | `action` (int: 0=off, 1=on) |
| 2 | Prevent execution | `preventExecution` | `hash` (MD5), `path`, `caseSensitive` (bool) |
| 3 | Quarantine file | `quarantineFile` | `md5hash`, `sha256hash`, `path` |
| 4 | Delete file | `deleteFile` | `md5hash`, `sha256hash`, `path`, `searchInSubfolders?` (bool) |
| 5 | Get file | `getFile` | `md5hash`, `sha256hash`, `path` |
| 6 | Terminate process | `terminateProcess` | `md5hash`, `sha256hash`, `path`, `caseSensitive` (bool) |
| 7 | Start process | `startProcess` | `executablePath`, `arguments?`, `workingFolder?` |
| 8 | IOC scan | `iocScan` | `ioc` (base64 zip), `isolateHost` (bool), `scanCriticalAreas` (bool), `quarantineObject` (bool) |
| 9 | Malware scan | `onDemandScan` | array of `{enabled (bool), path, recursive (bool), type (int)}` |

ScanObjectType enum for `onDemandScan.type`: SystemMemory=14,
StartupObjectsAndRunningProcesses=15, DiskBootSectors=16, SystemBackupStorage=17,
Email=18, Folder=22, AllRemovableDrives=23, AllNetworkDrives=24, AllFixedDrives=25.

All actions also require `targetHost` and `responseEventIncidentArea`.

---

## 5. Notes / open items

- `AddIncident` creates the incident that delivers the EDR task; the actual
  endpoint response is executed by Kaspersky Endpoint Security once KSC processes
  the incident (requires a background connection between the Administration Server
  and KSC Web Console; KES 12.9+ for Windows).
- Dedicate a separate KSC internal user for these actions (Kaspersky guidance).
- **Not safe to auto-retry** `AddIncident` on an ambiguous timeout — it can create
  duplicate incidents.
- The transport (connection-based `login` + reused session, KSCBasic header with
  base64 user/pass and `domain`/`internal` fields) was verified against the real
  `KlAkOAPI` SDK source (KSC 15.1).
- The `KLINCDT_BODY` body, the `KLINCDT_SEVERITY=2`/`responseEventIncident=true`
  values, and the AddIncident -> UpdateIncident flow were verified verbatim
  against Kaspersky's official "Connecting to KSC" and "Incident parameters"
  example pages — not assumed.
- Live verification requires a KSC + KES deployment with EDR enabled — not
  available here, so end-to-end behavior against a live server is unproven
  (same live-API caveat as every connector). The code-level contract (endpoints,
  auth, params, body, flow) is doc/SDK-verified.

## 6. Reference links (public)

- KSC Open API protocol: https://support.kaspersky.com/help/KSC/15.1/KSCAPI/index.html
- API for EDR Threat Response: https://support.kaspersky.com/help/KESWIN/12.12/en-US/300214.htm

_Content from Kaspersky docs was rephrased/summarized for compliance with licensing restrictions._
