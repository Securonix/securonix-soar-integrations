# Cisco Umbrella Investigate Connector for Securonix SOAR

## Overview

This connector integrates Securonix SOAR with Cisco Umbrella Investigate API v2, providing threat intelligence and DNS security insights. It enables security analysts to investigate domains, IPs, and URLs using Cisco's global DNS intelligence network.

## Prerequisites

### Cisco Umbrella Account

Before using this connector, you need:

1. A Cisco Umbrella Investigate account
2. API credentials (API Key and API Secret) with Investigate permissions
3. Required OAuth scope: `investigate.investigate:read`

### API Credentials

1. Log in to Cisco Umbrella Admin Console
2. Navigate to **Settings > API**
3. Create a new API key with the `investigate.investigate:read` scope
4. Note the API Key and API Secret

## Connection Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `api_key` | String | Yes | Cisco Umbrella API key/client ID |
| `api_secret` | String | Yes | Cisco Umbrella API secret/client secret |
| `base_url` | String | No | Cisco Umbrella API base URL (default: `https://api.umbrella.com`) |
| `request_timeout` | Number | No | Timeout in seconds for API requests (default: 30) |
| `verify_ssl` | String | No | Enable TLS certificate verification: "true" or "false" (default: "true") |

## Authentication

This connector uses **OAuth 2.0 Client Credentials** flow:

1. Makes a POST request to `https://api.umbrella.com/auth/v2/token`
2. Uses HTTP Basic authentication with `api_key:api_secret`
3. Requests scope `investigate.investigate:read`
4. Caches the access token for 3600 seconds with 60-second refresh buffer
5. Automatically refreshes token on 401 errors

## Supported Actions

### 1. Domain Categorization
**Action Name:** `umbrella_domain_categorization`

Retrieve Cisco Umbrella security and content categories for a domain.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `domain` | String | Yes | Domain name to categorize |

**Output:**
- `status`: Operation status
- `domain`: The queried domain
- `securityCategories`: Array of security categories (Malware, Phishing, etc.)
- `contentCategories`: Array of content categories (Business, Education, etc.)
- `rawResponse`: Raw Cisco API response

**Example:** Find if a domain is categorized as malicious

---

### 2. Domain Search
**Action Name:** `umbrella_domain_search`

Search newly observed domains matching a Cisco-supported search expression.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `expression` | String | Yes | Search expression (regex pattern) |
| `limit` | Number | No | Maximum number of results (default: 100) |

**Output:**
- `status`: Operation status
- `results`: Array of matching domains
- `count`: Number of results
- `rawResponse`: Raw Cisco API response

**Example:** Detect DGA-generated domains

---

### 3. Domain Co-occurrences
**Action Name:** `umbrella_domain_co_occurrences`

Find domains commonly observed together with a target domain.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `domain` | String | Yes | Target domain |

**Output:**
- `status`: Operation status
- `domain`: The queried domain
- `coOccurrences`: Array of related domains with counts
- `count`: Number of co-occurrences
- `rawResponse`: Raw Cisco API response

**Example:** Infrastructure pivoting

---

### 4. Related Domains
**Action Name:** `umbrella_domain_related`

Retrieve Cisco Umbrella related-domain information for campaign expansion.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `domain` | String | Yes | Target domain |

**Output:**
- `status`: Operation status
- `domain`: The queried domain
- `relatedDomains`: Array of related domains
- `count`: Number of related domains
- `rawResponse`: Raw Cisco API response

**Example:** Threat campaign expansion

---

### 5. Domain Security
**Action Name:** `umbrella_domain_security`

Retrieve domain security characteristics/reputation information.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `domain` | String | Yes | Domain name to check |

**Output:**
- `status`: Operation status
- `domain`: The queried domain
- `security`: Security characteristics object
- `rawResponse`: Raw Cisco API response

**Example:** IOC enrichment

---

### 6. Domain Risk Score
**Action Name:** `umbrella_get_domain_risk_score`

Retrieve domain risk score (0-100).

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `domain` | String | Yes | Domain name to check |

**Output:**
- `status`: Operation status
- `domain`: The queried domain
- `riskScore`: Risk score (0-100, higher = more risky)
- `rawResponse`: Raw Cisco API response

**Example:** Prioritize suspicious domains

---

### 7. Passive DNS
**Action Name:** `umbrella_list_resource_record`

Retrieve passive DNS/resource-record information.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | String | Yes | Domain, IP, or value to search |
| `query_type` | String | Yes | Query type: `name`, `domain`, `ip`, `raw` |

**Output:**
- `status`: Operation status
- `query`: The query string
- `records`: Array of passive DNS records
- `count`: Number of records
- `rawResponse`: Raw Cisco API response

**Record Fields:**
- `recordType`: DNS record type (A, AAAA, MX, etc.)
- `recordName`: Domain name
- `recordData`: Record value (IP address, etc.)
- `firstSeen`: First seen timestamp (epoch)
- `lastSeen`: Last seen timestamp (epoch)
- `minTtl`: Minimum TTL
- `maxTtl`: Maximum TTL

**Example:** DNS investigation

---

### 8. Subdomain Enumeration
**Action Name:** `umbrella_list_domain_subdomain`

Enumerate subdomains for a target domain.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `domain` | String | Yes | Parent domain |
| `limit` | Number | No | Maximum number of results |

**Output:**
- `status`: Operation status
- `domain`: The queried domain
- `subdomains`: Array of subdomains
- `count`: Number of subdomains
- `rawResponse`: Raw Cisco API response

**Example:** Attack-surface discovery

---

### 9. Domain WHOIS
**Action Name:** `umbrella_get_whois_for_domain`

Retrieve WHOIS information for a domain.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `domain` | String | Yes | Domain name |

**Output:**
- `status`: Operation status
- `domain`: The queried domain
- `whois`: WHOIS information object
- `rawResponse`: Raw Cisco API response

**Example:** Domain ownership investigation

---

### 10. Domain WHOIS History
**Action Name:** `umbrella_get_domain_whois_history`

Retrieve WHOIS history for a domain.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `domain` | String | Yes | Domain name |

**Output:**
- `status`: Operation status
- `domain`: The queried domain
- `history`: Array of WHOIS history records
- `count`: Number of history records
- `rawResponse`: Raw Cisco API response

**Example:** Domain change tracking

---

### 11. Email WHOIS
**Action Name:** `umbrella_get_email_whois`

Retrieve domains registered with an email address.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `email` | String | Yes | Email address |

**Output:**
- `status`: Operation status
- `email`: The queried email
- `domains`: Array of registered domains
- `count`: Number of domains
- `rawResponse`: Raw Cisco API response

**Example:** Registration/infrastructure pivoting

---

### 12. Domain Timeline
**Action Name:** `umbrella_get_domain_timeline`

Retrieve timeline events for a domain.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `domain` | String | Yes | Domain name |

**Output:**
- `status`: Operation status
- `indicator`: The queried domain
- `indicatorType`: "domain"
- `timeline`: Array of timeline events
- `count`: Number of timeline events
- `rawResponse`: Raw Cisco API response

**Example:** Domain lifecycle investigation

---

### 13. URL Timeline
**Action Name:** `umbrella_get_url_timeline`

Retrieve timeline events for a URL.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | String | Yes | URL to query (must include scheme) |

**Output:**
- `status`: Operation status
- `indicator`: The queried URL
- `indicatorType`: "url"
- `timeline`: Array of timeline events
- `count`: Number of timeline events
- `rawResponse`: Raw Cisco API response

**Example:** URL investigation

---

### 14. IP Timeline
**Action Name:** `umbrella_get_ip_timeline`

Retrieve timeline events for an IP address.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ip` | String | Yes | IP address (IPv4 only) |

**Output:**
- `status`: Operation status
- `indicator`: The queried IP
- `indicatorType`: "ip"
- `timeline`: Array of timeline events
- `count`: Number of timeline events
- `rawResponse`: Raw Cisco API response

**Example:** IP address investigation

---

### 15. IP BGP Lookup
**Action Name:** `umbrella_get_ip_bgp`

Determine ASN/network ownership information for an IP.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ip` | String | Yes | IP address (IPv4 or IPv6) |

**Output:**
- `status`: Operation status
- `ip`: The queried IP
- `asn`: Autonomous System Number
- `cidr`: CIDR block
- `rir`: Regional Internet Registry
- `description`: Network description
- `rawResponse`: Raw Cisco API response

**Example:** ASN/network ownership investigation

---

### 16. ASN BGP Prefixes
**Action Name:** `umbrella_get_asn_bgp`

Retrieve network prefixes associated with an ASN.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `asn` | String | Yes | ASN (e.g., `15169` or `AS15169`) |

**Output:**
- `status`: Operation status
- `asn`: The queried ASN
- `prefixes`: Array of network prefixes
- `count`: Number of prefixes
- `rawResponse`: Raw Cisco API response

**Example:** Network prefix investigation

---

## Troubleshooting

### Common Errors

1. **Invalid Credentials**
   - Error: "Invalid API key or API secret"
   - Solution: Verify your API key and secret are correct

2. **Insufficient Permissions**
   - Error: "API key does not have Investigate permissions"
   - Solution: Ensure your API key has the `investigate.investigate:read` scope

3. **Rate Limiting**
   - Error: "Rate limited"
   - Solution: Implement exponential backoff. Cisco Investigate has daily rate limits.

4. **SSL Certificate Verification Failed**
   - Error: "TLS/SSL certificate verification failed"
   - Solution: Verify your system has valid CA certificates. Set `verify_ssl` to "false" only in test environments.

### Debugging

1. Check the Securonix SOAR integration logs
2. Verify network connectivity to `api.umbrella.com`
3. Test credentials using the `test_connection` action
4. Review Cisco Umbrella API status at https://status.cisco.com

---

## Testing

### Unit Tests

```bash
# Install dependencies
pip install pytest coverage requests

# Run tests
pytest tests/

# Run with coverage
coverage run -m pytest tests/
coverage report -m
coverage html
```

### Live Testing

Create a `.env` file (not committed to git):

```bash
UMBRELLA_API_KEY=your_api_key
UMBRELLA_API_SECRET=your_api_secret
UMBRELLA_BASE_URL=https://api.umbrella.com
```

Run live tests:

```bash
pytest tests/ -m live
```

---

## Security Considerations

1. **Never commit credentials** - Use environment variables or secure vaults
2. **TLS is enabled by default** - Do not disable certificate verification in production
3. **OAuth tokens are cached** - Token caching prevents unnecessary authentication requests
4. **Rate limits apply** - Cisco Investigate has daily rate limits (~2000 requests/day)
5. **API secrets are never logged** - The connector sanitizes logs

---

## Rate Limits

Cisco Umbrella Investigate rate limits vary by tier. Typical limits:
- **Standard tier:** ~2,000 requests per day
- **Premium tier:** Higher limits based on contract

Design your integrations for efficient request usage:
- Batch operations where possible
- Cache results appropriately
- Implement exponential backoff on rate limit errors

---

## Cisco Documentation

- [Cisco Umbrella Investigate API v2](https://developer.cisco.com/docs/umbrella/)
- [OAuth Authentication](https://developer.cisco.com/docs/umbrella/oauth/)
- [Domain Categorization](https://developer.cisco.com/docs/umbrella/dns-categorization/)
- [Passive DNS](https://developer.cisco.com/docs/umbrella/passive-dns/)
- [WHOIS](https://developer.cisco.com/docs/umbrella/whois/)

---

## Version History

- **v1.0.0** (Current) - Initial release with 16 actions

---

## Support

For issues with:
- **Cisco Umbrella Investigate API:** Visit [Cisco DevNet](https://developer.cisco.com/)
- **Securonix SOAR Integration:** Contact Securonix Support
