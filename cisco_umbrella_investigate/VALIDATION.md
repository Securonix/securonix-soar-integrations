# Cisco Umbrella Investigate - Validation Guide

## Quick Validation Steps

### Step 1: Get Your Cisco API Credentials

1. Log in to [Cisco Umbrella Admin Console](https://app.umbrella.com)
2. Go to **Settings > API**
3. Click **Create new API key**
4. Select scope: `investigate.investigate:read`
5. Copy the **API Key** and **API Secret**

### Step 2: Test Connection

Run this Python script (replace credentials):

```python
from app.cisco_umbrella_investigate import Cisco_Umbrella_Investigate
from app.model.request_body import RequestBody
import json

integration = Cisco_Umbrella_Investigate()

# Replace with YOUR credentials
params = {
    "api_key": "YOUR_API_KEY_HERE",
    "api_secret": "YOUR_API_SECRET_HERE",
    "base_url": "https://api.umbrella.com"
}

# Test connection
response = integration.test_connection(params)
print(f"Connection Status: {response.status}")
print(f"Message: {response.message}")

# Test domain categorization
request = RequestBody()
request.parameters = {"domain": "cisco.com"}
request.connectionParameters = params
response = integration.umbrella_domain_categorization(request)
print(f"Domain Categorization Status: {response.status}")
```

### Step 3: Verify Expected Results

**Connection Test:**
- Expected: `Status: SUCCESS`, `Message: Connection successful - Cisco Umbrella Investigate API is accessible`

**Domain Categorization (cisco.com):**
- Expected: `Status: SUCCESS`
- Should show security and content categories for cisco.com

**Domain Risk Score (cisco.com):**
- Expected: `Status: SUCCESS`
- Risk score should be low (Cisco is a reputable company)

**IP BGP (8.8.8.8):**
- Expected: `Status: SUCCESS`
- ASN should be `15169` (Google LLC)

### Step 4: Common Issues

| Issue | Solution |
|-------|----------|
| `Invalid API key or API secret` | Verify credentials in Cisco Umbrella console |
| `API key does not have Investigate permissions` | Add `investigate.investigate:read` scope |
| `Rate limited` | Wait before retrying (Cisco has daily limits) |
| `TLS/SSL certificate verification failed` | Check system CA certificates |

### Step 5: Check Cisco API Status

Visit: https://status.cisco.com

Check if Umbrella Investigate API is operational.
