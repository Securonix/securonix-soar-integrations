# Alibaba Cloud API Reference — Connector Research

Research artifact for the **Support for Alibaba** SOAR connector.
"Alibaba" here means **Alibaba Cloud (Aliyun)** — the connector targets its
security products. Scope is the SOAR-relevant subset (Cloud Firewall
remediation + Security Center alert investigation), chosen by analogy with the
existing cloud connectors (aws_waf, aws_security_hub).

> Source: Alibaba Cloud public OpenAPI docs at https://help.aliyun.com
> (Cloud Firewall `Cloudfw` 2017-12-07, Security Center `Sas` 2018-12-03).

---

## 1. Overview

| Item | Value |
|---|---|
| Products | Cloud Firewall (`Cloudfw`), Security Center (`Sas`) |
| Protocol | Alibaba Cloud OpenAPI (RPC-style actions), JSON |
| Auth | AccessKey pair (AccessKey ID + AccessKey Secret) with request signing |
| Region | `region_id` selects the regional endpoint |
| SDK | Official `alibabacloud_*` SDK (Tea OpenAPI) handles signing/retry |

Alibaba Cloud's full API is huge (hundreds of operations across dozens of
products). This connector targets only the SOAR-relevant security operations.

---

## 2. Authentication & SDK decision

Alibaba Cloud OpenAPI uses an **AccessKey pair** with HMAC request signing —
the same signed-request model AWS uses. The existing `aws_waf` and
`aws_security_hub` connectors handle this by using the **vendor SDK (boto3)**
rather than hand-rolling signatures.

Following that established repo pattern, this connector uses the **official
Alibaba Cloud SDK** (`alibabacloud_*`, Tea OpenAPI) instead of custom signing.
This is consistent, maintainable, and avoids fragile crypto.

**Connection parameters** (mirroring the AWS connectors):
- `access_key_id` (String)
- `access_key_secret` (String, secret + encrypted)
- `region_id` (String, e.g. `cn-hangzhou`)

**SDK packages (versions verified against PyPI):**
- `alibabacloud_tea_openapi==0.4.6` — shared client/credentials/config
- `alibabacloud_cloudfw20171207==9.4.4` — Cloud Firewall
- `alibabacloud_sas20181203==10.2.1` — Security Center

All method names (snake_case) and request-model class names used by the
connector were verified against the actual SDK package source, not assumed.

Client build pattern:
`Config(access_key_id, access_key_secret, endpoint)` → `Client(config)` →
`client.<Action>(<Action>Request(**params))`.

---

## 3. Scoped connector actions (8)

### Cloud Firewall — Remediate (4)
| Action | SDK operation |
|---|---|
| Add Control Policy (block/allow/monitor traffic) | `AddControlPolicy` |
| Modify Control Policy | `ModifyControlPolicy` |
| Delete Control Policy | `DeleteControlPolicy` |
| Add Address Book (group of IPs/domains) | `AddAddressBook` |

### Cloud Firewall — Investigate (2)
| Action | SDK operation |
|---|---|
| Describe Control Policies | `DescribeControlPolicy` |
| Describe Address Books | `DescribeAddressBook` |

### Security Center — Investigate (2)
| Action | SDK operation |
|---|---|
| Describe Alarm Events | `DescribeSuspEvents` |
| Describe Alarm Event Detail | `DescribeAlarmEventDetail` |

**Total: 8 functions** — block/unblock + audit (Cloud Firewall) and alert
investigation (Security Center). Mirrors the read + act shape of the peer
cloud connectors.

### Explicitly out of scope (unless requested)
- WAF, Anti-DDoS, and other product APIs
- VPC/NAT firewall policy variants
- Account/RAM administration

---

## 4. Key parameters per action (from docs)

- **AddControlPolicy** (required): `AclAction` (accept/drop/log), `Direction`
  (in/out), `Source`, `SourceType`, `Destination`, `DestinationType`, `Proto`,
  `Description`, `NewOrder`. Returns `AclUuid`.
- **ModifyControlPolicy** (required): `AclUuid`, `Direction`, plus the fields to
  change.
- **DeleteControlPolicy** (required): `AclUuid`, `Direction`.
- **DescribeControlPolicy** (required): `Direction`; optional paging
  (`CurrentPage`, `PageSize`) and filters (`Source`, `Destination`).
- **AddAddressBook** (required): `GroupType` (ip/domain/port/...),
  `GroupName`, `AddressList`, `Description`.
- **DescribeAddressBook**: optional `GroupType`, paging.
- **DescribeSuspEvents** (Sas): optional filters (`name`, `dealed`, `levels`),
  paging (`current_page`, `page_size`), `lang`. (This is the current list-alerts
  operation; the older `DescribeAlarmEventList` does not exist in SDK 10.2.1.)
- **DescribeAlarmEventDetail** (Sas, required): `alarm_unique_info`.

> Note: SDK request-model attributes are snake_case (e.g. `acl_action`,
> `current_page`). The field names used by the connector were verified against
> the actual SDK model source. The full set of optional params per operation is
> larger — the connector exposes the SOAR-relevant ones and passes them through.

---

## 5. Notes / open items

- SDK-based (no custom signing), consistent with aws_waf / aws_security_hub.
- Live verification requires an Alibaba Cloud account with an AccessKey and
  Cloud Firewall / Security Center enabled — not available here, so verification
  is unit tests (SDK client mocked) + official-doc confirmation.

## 6. Reference links (public)

- Cloud Firewall API overview: https://help.aliyun.com/en/cloud-firewall/cloudfirewall/developer-reference/api-reference/
- AddControlPolicy: https://help.aliyun.com/en/cloud-firewall/cloudfirewall/developer-reference/api-cloudfw-2017-12-07-addcontrolpolicy
- AddAddressBook: https://help.aliyun.com/en/cloud-firewall/cloudfirewall/developer-reference/api-cloudfw-2017-12-07-addaddressbook
- Security Center API overview: https://help.aliyun.com/en/security-center/developer-reference/api-sas-2018-12-03-overview
- Alibaba Cloud SDK (Python): https://help.aliyun.com/en/sdk/developer-reference/v2-python-sdk/

_Content from Alibaba Cloud docs was rephrased/summarized for compliance with licensing restrictions._
