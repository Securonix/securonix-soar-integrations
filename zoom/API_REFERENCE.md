# Zoom API Reference — Connector Research

Research artifact for the **Support for Zoom** SOAR connector.
Captures the Zoom REST API surface, authentication, and the scoped 15-action set
for the connector. No customer-specified action list exists, so the scope below
is the SOAR-relevant subset (identity + session visibility + audit + light
remediation), chosen by analogy with existing connectors (Cisco Duo, PingOne,
Cisco Umbrella).

> Source: Zoom public developer docs at https://developers.zoom.us (no login
> required to read). Endpoint inventory mirrors the official Zoom API Hub OpenAPI.

---

## 1. Overview

| Item | Value |
|---|---|
| Base URL | `https://api.zoom.us/v2` |
| Protocol | REST / HTTPS, JSON |
| Auth | OAuth 2.0 Bearer token (Server-to-Server OAuth for backend) |
| Token endpoint | `POST https://zoom.us/oauth/token` |
| Token lifetime | 1 hour (3600s); no refresh token for S2S — request a new one |
| Pagination | `next_page_token` + `page_size` |
| Rate limits | HTTP 429 on exceed (per-second QPS and daily limits) |

Zoom's full API is 600+ endpoints across ~20 product areas (Meetings, Users,
Phone, Chat, Mail, Calendar, Rooms, Webinars, Contact Center, Reports, etc.).
Most are collaboration/admin features irrelevant to security automation, so the
connector targets the SOAR-relevant subset only.

---

## 2. Authentication — Server-to-Server OAuth

Backend (two-legged) flow — no user interaction. This matches how the repo's
OAuth connectors (Cisco Umbrella, PingOne) are built.

**Connection parameters:**
- `account_id` (String)
- `client_id` (String)
- `client_secret` (String, secret + encrypted)

**Token request:**
```
POST https://zoom.us/oauth/token
Header: Authorization: Basic base64(client_id:client_secret)
Header: Content-Type: application/x-www-form-urlencoded
Body:   grant_type=account_credentials&account_id=<account_id>
```

**Token response:**
```json
{ "access_token": "<JWT>", "token_type": "bearer", "expires_in": 3599, "scope": "..." }
```

**Subsequent API calls:** `Authorization: Bearer <access_token>`

---

## 3. Scoped connector actions (15)

### Investigate / read (9)
| Action | Method & Path |
|---|---|
| List Users | `GET /users` |
| Get User | `GET /users/{userId}` |
| Get User Settings | `GET /users/{userId}/settings` |
| Get User Permissions | `GET /users/{userId}/permissions` |
| Get User Presence Status | `GET /users/{userId}/presence_status` |
| List Meetings | `GET /users/{userId}/meetings` |
| Get Meeting | `GET /meetings/{meetingId}` |
| Get Past Meeting Details | `GET /past_meetings/{meetingId}` |
| Get Past Meeting Participants | `GET /past_meetings/{meetingId}/participants` |

### Reports / audit (3)
| Action | Method & Path |
|---|---|
| Get Sign In / Sign Out Activity Report | `GET /report/activities` |
| Get Operation Logs Report | `GET /report/operationlogs` |
| Get Active/Inactive Host Report | `GET /report/users` |

### Remediate / act (3)
| Action | Method & Path |
|---|---|
| Update User Status (activate/deactivate) | `PUT /users/{userId}/status` |
| Revoke User's SSO Token (force sign-out) | `DELETE /users/{userId}/token` |
| Delete a Meeting | `DELETE /meetings/{meetingId}` |

**Total: 15 functions** — identity visibility, session/meeting visibility,
security audit logs, and light remediation. REST-only, Server-to-Server OAuth.

> Paths, methods, query params, and request bodies for all 15 endpoints were
> confirmed against Zoom's official API Hub OpenAPI specs (Users + Meetings
> `endpoints.json`), not assumed. Notes from that verification:
> - `delete_meeting`: "notify hosts" maps to the `cancel_meeting_reminder` query
>   param (also supports `occurrence_id`).
> - `get_signin_signout_activity` (`/report/activities`): `from`/`to` are
>   optional per spec, and the report requires a Zoom Business/Enterprise+ plan.
> - `get_operation_logs` and `get_active_inactive_hosts`: `from`/`to` are
>   required per spec.

### Explicitly out of scope (unless requested)
- Phone, Chat, Mail, Calendar, Rooms, Webinars, Contact Center product areas
- Collaboration/admin features (virtual backgrounds, polls, schedulers, templates)
- Cloud recording management, billing reports
- User-delegated OAuth flow (connector uses Server-to-Server OAuth)

---

## 4. Open questions for the ticket owner

1. **Scope sign-off** — the 15 actions above (identity + audit + light
   remediation), or does the customer want a specific area (Phone/Chat/recordings)?
2. **Auth** — confirm a Server-to-Server OAuth app will be created and Account ID
   / Client ID / Client Secret provided (not the user-delegated OAuth flow).
3. **Scopes** — the S2S app must be granted the matching granular scopes
   (e.g. `user:read:admin`, `report:read:admin`, `meeting:read:admin`,
   `meeting:write:admin`). Confirm these can be enabled on the app.
4. **Test account** — need a Zoom account with an S2S OAuth app + credentials to
   verify against the live API.

---

## 5. Reference links (public)

- API reference & auth overview: https://developers.zoom.us/docs/api/
- Server-to-Server OAuth: https://developers.zoom.us/docs/internal-apps/s2s-oauth/
- Users endpoint inventory: https://github.com/zoom/skills/blob/main/skills/rest-api/references/users.md
- Meetings endpoint inventory: https://github.com/zoom/skills/blob/main/skills/rest-api/references/meetings.md

_Content from Zoom docs was rephrased/summarized for compliance with licensing restrictions._
