# Forcepoint SMC Connector for Securonix SOAR

## Overview

This connector integrates Securonix SOAR with Forcepoint Security Management Center (SMC) API, enabling security analysts to manage hosts, networks, services, policies, and perform security operations through the Forcepoint SMC API.

## Prerequisites

### Forcepoint SMC Account

Before using this connector, you need:

1. A Forcepoint SMC server instance (version 7.0 or later)
2. API access enabled on the SMC server
3. An API key with appropriate permissions

### API Key Setup

1. Log in to Forcepoint SMC Management Console
2. Navigate to **Platform Services > Admin > API Keys**
3. Create a new API key with the required permissions:
   - Read access for investigative actions
   - Write access for create/update/delete actions
   - Deploy access for policy management
4. Note the API Key

## Connection Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `api_host` | String | Yes | Forcepoint SMC server hostname or IP address |
| `api_port` | Number | No | Forcepoint SMC API port (default: 8082) |
| `api_key` | String | Yes | Forcepoint SMC API authentication key |
| `verify_ssl` | String | No | Enable TLS certificate verification: "true" or "false" (default: "true") |

## Authentication

This connector uses **API Key authentication**:

1. Sends API key in the `X-API-KEY` header
2. No OAuth flow required
3. Key must have appropriate permissions for the actions being performed

## Supported Actions

### 1. Test Connection
**Action Name:** `test_connection`

Test Forcepoint SMC API connection.

**Input Parameters:** None

**Output:**
- `status`: Operation status
- `message`: Status message

**Example:** Verify connectivity before configuration

---

### 2. Get Hosts
**Action Name:** `get_hosts`

Retrieve a list of all hosts from Forcepoint SMC.

**Input Parameters:** None

**Output:**
- `status`: Operation status
- `hosts`: Array of host objects (name, uid, ipaddr, type)
- `count`: Number of hosts

**Example:** List all managed hosts

---

### 3. Create Host
**Action Name:** `create_host`

Create a new host in Forcepoint SMC.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | String | Yes | Host name |
| `ipaddr` | String | Yes | Host IP address |
| `type` | String | No | Host type (default: host) |

**Output:**
- `status`: Operation status
- `message`: Status message
- `uid`: Host UID
- `name`: Host name

**Example:** Add new server to SMC inventory

---

### 4. Update Host
**Action Name:** `update_host`

Update an existing host in Forcepoint SMC.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `uid` | String | Yes | Host UID to update |
| `name` | String | No | New host name |
| `ipaddr` | String | No | New IP address |

**Output:**
- `status`: Operation status
- `message`: Status message
- `uid`: Updated host UID

**Example:** Update host IP address

---

### 5. Delete Host
**Action Name:** `delete_host`

Delete a host from Forcepoint SMC.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `uid` | String | Yes | Host UID to delete |

**Output:**
- `status`: Operation status
- `message`: Status message
- `uid`: Deleted host UID

**Example:** Remove decommissioned host

---

### 6. Get Networks
**Action Name:** `get_networks`

Retrieve a list of all networks from Forcepoint SMC.

**Input Parameters:** None

**Output:**
- `status`: Operation status
- `networks`: Array of network objects (name, uid, subnet, cidr, type)
- `count`: Number of networks

**Example:** List all configured networks

---

### 7. Create Network
**Action Name:** `create_network`

Create a new network in Forcepoint SMC.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | String | Yes | Network name |
| `subnet` | String | Yes | Network subnet address |
| `cidr` | Number | No | Network CIDR notation |

**Output:**
- `status`: Operation status
- `message`: Status message
- `uid`: Network UID
- `name`: Network name

**Example:** Add new network segment

---

### 8. Get Services
**Action Name:** `get_services`

Retrieve a list of all services from Forcepoint SMC.

**Input Parameters:** None

**Output:**
- `status`: Operation status
- `services`: Array of service objects (name, uid, protocol, port, type)
- `count`: Number of services

**Example:** List all configured services

---

### 9. Create Service
**Action Name:** `create_service`

Create a new service in Forcepoint SMC.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | String | Yes | Service name |
| `protocol` | String | No | Service protocol (default: tcp) |
| `port` | Number | Yes | Service port |

**Output:**
- `status`: Operation status
- `message`: Status message
- `uid`: Service UID
- `name`: Service name

**Example:** Add custom application service

---

### 10. Get Policies
**Action Name:** `get_policies`

Retrieve a list of all policies from Forcepoint SMC.

**Input Parameters:** None

**Output:**
- `status`: Operation status
- `policies`: Array of policy objects (name, uid, type, engine_count)
- `count`: Number of policies

**Example:** List all security policies

---

### 11. Get Policy Rules
**Action Name:** `get_policy_rules`

Retrieve rules for a specific policy.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `uid` | String | Yes | Policy UID |

**Output:**
- `status`: Operation status
- `rules`: Array of rule objects (name, uid, source, destination, service, action, enabled)
- `count`: Number of rules

**Example:** Review policy rules for audit

---

### 12. Search Unused Elements
**Action Name:** `search_unused_elements`

Search for unused elements in Forcepoint SMC.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `type` | String | No | Element type to search (default: all) |

**Output:**
- `status`: Operation status
- `unused_elements`: Array of unused element objects
- `count`: Number of unused elements

**Example:** Identify elements for cleanup

---

### 13. Search Duplicate IPs
**Action Name:** `search_duplicate_ips`

Search for duplicate IP addresses in Forcepoint SMC.

**Input Parameters:** None

**Output:**
- `status`: Operation status
- `duplicates`: Array of duplicate IP objects (ip, count, elements)
- `count`: Number of duplicate IPs

**Example:** Detect IP conflicts

---

### 14. Get System Status
**Action Name:** `get_system_status`

Retrieve system status from Forcepoint SMC.

**Input Parameters:** None

**Output:**
- `status`: Operation status
- `status`: System status object (uptime, version, engines_connected)

**Example:** Monitor SMC health

---

### 15. Deploy Policy
**Action Name:** `deploy_policy`

Deploy a policy to engines.

**Input Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `uid` | String | Yes | Policy UID to deploy |
| `engine_uids` | Array | No | List of engine UIDs to deploy to |

**Output:**
- `status`: Operation status
- `message`: Status message
- `deployment_id`: Deployment job ID
- `status`: Deployment status (in_progress, completed, failed)

**Example:** Deploy updated policy to engines

---

## Troubleshooting

### Common Errors

1. **Authentication Failed**
   - Error: "Authentication failed: invalid API key"
   - Solution: Verify your API key is correct and has required permissions

2. **Access Forbidden**
   - Error: "Access forbidden: API key may not have required permissions"
   - Solution: Ensure your API key has the appropriate permissions for the action

3. **Connection Failed**
   - Error: "Request failed" or "Connection refused"
   - Solution: Verify SMC server is reachable and API port is open

4. **Invalid JSON Response**
   - Error: "Invalid JSON response from Forcepoint SMC API"
   - Solution: Check SMC server version compatibility

### Debugging

1. Check the Securonix SOAR integration logs
2. Verify network connectivity to Forcepoint SMC server
3. Test API key using curl:
   ```bash
   curl -k -H "X-API-KEY: your_api_key" https://smc-server:8082/api/hosts
   ```
4. Verify SMC server API status

---

## Testing

### Unit Tests

```bash
# Install dependencies
pip install pytest coverage

# Run tests
pytest tests/

# Run with coverage
coverage run -m pytest tests/
coverage report -m
coverage html
```

---

## Security Considerations

1. **Never commit API keys** - Use secure credential management
2. **TLS is enabled by default** - Do not disable certificate verification in production
3. **API keys should have least privilege** - Grant only required permissions
4. **Rate limits may apply** - Implement exponential backoff on failures

---

## Forcepoint Documentation

- [Forcepoint SMC API User Guide](https://help.forcepoint.com/ngfw/en-us/7.0.0/smc_api_ug/)
- [Forcepoint SMC Documentation](https://help.forcepoint.com/)

---

## Version History

- **v1.0.0** (Current) - Initial release with 15 actions

---

## Support

For issues with:
- **Forcepoint SMC API:** Visit [Forcepoint Support](https://www.forcepoint.com/support)
- **Securonix SOAR Integration:** Contact Securonix Support
