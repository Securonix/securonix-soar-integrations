# Forcepoint SMC - Validation Guide

## Quick Validation Steps

### Step 1: Get Your Forcepoint SMC API Key

1. Log in to [Forcepoint SMC Management Console](https://smc.yourcompany.com)
2. Go to **Platform Services > Admin > API Keys**
3. Click **Create API Key**
4. Select appropriate permissions for:
   - Read: hosts, networks, services, policies
   - Write: create/update hosts/networks/services
   - Deploy: policy deployment
5. Copy the **API Key**

### Step 2: Test Connection

Run this Python script (replace credentials):

```python
from app.forcepoint_smc import ForcepointSmc
from app.model.request_body import RequestBody
import json

integration = ForcepointSmc()

# Replace with YOUR credentials
params = {
    "api_host": "smc.yourcompany.com",
    "api_port": 8082,
    "api_key": "YOUR_API_KEY_HERE",
    "verify_ssl": "true"
}

# Test connection
response = integration.test_connection(params)
print(f"Connection Status: {response.status}")
print(f"Message: {response.message}")
```

### Step 3: Verify Expected Results

**Connection Test:**
- Expected: `Status: SUCCESS`
- Expected: `Message: Connection successful - Forcepoint SMC API is accessible`

**Get Hosts:**
- Expected: `Status: SUCCESS`
- Should return array of hosts from your SMC

**Get Networks:**
- Expected: `Status: SUCCESS`
- Should return array of networks from your SMC

**Get Policies:**
- Expected: `Status: SUCCESS`
- Should return array of policies from your SMC

### Step 4: Common Issues

| Issue | Solution |
|-------|----------|
| `Authentication failed: invalid API key` | Verify API key in SMC console |
| `Access forbidden` | Ensure API key has required permissions |
| `Connection refused` | Check SMC server is running and port is open |
| `TLS/SSL certificate verification failed` | Check system CA certificates or set verify_ssl to false (test only) |
| `Invalid JSON response` | Verify SMC server version compatibility |

### Step 5: Check SMC Server Status

1. Verify SMC server is running
2. Check API port (default 8082) is accessible
3. Verify API service is enabled in SMC settings

### Step 6: Verify API Key Permissions

1. In SMC console, check API key has:
   - Read access for investigative actions
   - Write access for create/update/delete
   - Deploy access for policy management

---

## API Endpoint Reference

| Action | HTTP Method | Endpoint | Description |
|--------|-------------|----------|-------------|
| test_connection | GET | /api/hosts | Test connectivity |
| get_hosts | GET | /api/hosts | List all hosts |
| create_host | POST | /api/hosts | Create new host |
| update_host | PUT | /api/hosts/{uid} | Update host |
| delete_host | DELETE | /api/hosts/{uid} | Delete host |
| get_networks | GET | /api/networks | List all networks |
| create_network | POST | /api/networks | Create network |
| get_services | GET | /api/services | List all services |
| create_service | POST | /api/services | Create service |
| get_policies | GET | /api/policies | List all policies |
| get_policy_rules | GET | /api/policies/{uid}/rules | Get policy rules |
| search_unused_elements | GET | /api/unused_elements | Find unused elements |
| search_duplicate_ips | GET | /api/duplicates/ip | Find duplicate IPs |
| get_system_status | GET | /api/status | Get system status |
| deploy_policy | POST | /api/deploy | Deploy policy |

---

## Sample API Requests (curl)

```bash
# Test connection
curl -k -H "X-API-KEY: your_api_key" https://smc-server:8082/api/hosts

# Get networks
curl -k -H "X-API-KEY: your_api_key" https://smc-server:8082/api/networks

# Get policies
curl -k -H "X-API-KEY: your_api_key" https://smc-server:8082/api/policies

# Create host
curl -k -X POST \
  -H "X-API-KEY: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{"name":"test-host","ipaddr":"192.168.1.100","type":"host"}' \
  https://smc-server:8082/api/hosts

# Deploy policy
curl -k -X POST \
  -H "X-API-KEY: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{"policies":["policy_uid"],"engines":["engine_uid"]}' \
  https://smc-server:8082/api/deploy
```
