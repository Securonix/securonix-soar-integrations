# Cisco Umbrella Enforcement API Reference — Connector Research

Research artifact for the **SOAR connector integration with Cisco Umbrella
Enforcement** ticket. Scope is fixed by the ticket: 3 response actions against
the Umbrella Enforcement API. All details below are confirmed from Cisco's
official docs — not assumed.

> Source: Cisco DevNet Legacy Umbrella API docs
> (https://developer.cisco.com/docs/legacy-umbrella-api/).

---

## 1. Overview

| Item | Value |
|---|---|
| Base URI | `https://s-platform.api.opendns.com/1.0` |
| Protocol | REST / HTTPS, JSON |
| Auth | `customerKey` query parameter on **every** request (`?customerKey={key}`) |
| Rate limits | 5 req/sec; 200 domains/min; 1 MB/min; HTTP 429 on exceed |
| Domain max length | 255 chars |

---

## 2. Scoped connector actions 

### 1. Block Domain / Submit Threat Event — `add_domain_event`
- **`POST /events?customerKey={key}`**, `Content-Type: application/json`
- Body is an **array of event objects**. Required fields per event:
  `alertTime` (ISO 8601), `deviceId`, `deviceVersion`, `dstDomain`, `dstURL`,
  `eventTime` (ISO 8601), `protocolVersion` (= "1.0a"), `providerName`.
- Optional: `disableDstSafeguards`, `dstIP`, `eventSeverity`, `eventType`,
  `eventDescription`, `eventHash`, `fileName`, `fileHash`, `externalURL`, `src`.
- **Response:** `202` → `{"id": "..."}`

Connector design: expose the meaningful inputs (`dst_domain`, `dst_url`, and
optional `event_severity`/`event_type`/`event_description`/`disable_dst_safeguards`)
and auto-fill the required fields. Two of these are **fixed values mandated by
the Cisco docs** and are hardcoded (not inputs):
`protocolVersion="1.0a"` and `providerName="Security Platform"` (the docs state
"Set the field to" these exact values). The remaining required fields are
defaulted and overridable: `alertTime`/`eventTime` default to now (UTC ISO 8601),
`deviceId` generated, `deviceVersion` defaulted.

### 2. List Blocked Domains — `list_blocked_domains`
- **`GET /domains?customerKey={key}`**
- Optional query params: `limit` (default/max 200), `page`.
- **Response:** `200` → `{"data": [{"id": 30916, "name": "internetbadguys.com", "lastSeenAt": 1625759735}]}`

### 3. Remove Blocked Domain — `delete_blocked_domain`
- **`DELETE /domains/{id}?customerKey={key}`**
- `{id}` accepts a numeric domain ID **or** a URL-encoded domain name.
- **Response:** `204 No Content`

---

## 3. Connection parameters

Confirmed from the API (customerKey auth) + aligned with the existing Cisco
connectors' conventions (timeout / verify_ssl / proxy):

- `customer_key` (String, secret + encrypted) — Enforcement API customer key
- `base_url` (String, default `https://s-platform.api.opendns.com/1.0`)
- `timeout` (optional, default 30s)
- `verify_ssl` (optional, default true)
- `proxy` (optional)

---

## 4. Notes / open items

- `add_domain_event` auto-fills required fields; the SOAR-relevant inputs are
  the domain/URL and optional threat metadata. `protocolVersion` and
  `providerName` are fixed values prescribed by the docs ("1.0a" and
  "Security Platform") and are hardcoded, not inputs.
- `disableDstSafeguards`: when false (default), Umbrella validates the domain via
  Investigate before blocking; true bypasses that (riskier). Exposed as optional.
- Live verification requires an Umbrella org with an Enforcement API customer key
  — not available in this environment, so verification is unit tests + official
  Cisco doc confirmation.

## 5. Reference links (public)

- Enforcement intro: https://developer.cisco.com/docs/legacy-umbrella-api/enforcement-introduction/
- Getting started (base URI, auth, params): https://developer.cisco.com/docs/legacy-umbrella-api/enforcement-getting-started/
- Request samples (bodies + responses): https://developer.cisco.com/docs/legacy-umbrella-api/enforcement-request-samples/

_Content from Cisco docs was rephrased/summarized for compliance with licensing restrictions._
