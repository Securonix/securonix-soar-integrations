from app.cisco_meraki import CiscoMeraki
from app.model.request_body import RequestBody
from pykson import Pykson
from unittest.mock import patch, Mock
import json

pykson = Pykson()
integration_class = CiscoMeraki()


@patch('requests.get')
def test_cisco_meraki_test_connection(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = [{"id": "123", "name": "Test Org"}]
    mock_get.return_value = mock_response

    conn_params = {
        "api_key": "sample_api_key"
    }

    resp = integration_class.test_connection(conn_params)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["message"] == "Connected to Cisco Meraki successfully."


@patch('requests.get')
def test_meraki_get_networks(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {
            "id": "N_123",
            "organizationId": "123456",
            "name": "Main Office",
            "productTypes": ["appliance", "switch"],
            "timeZone": "America/Los_Angeles",
            "tags": ["production"],
            "isBoundToConfigTemplate": False
        },
        {
            "id": "N_456",
            "organizationId": "123456",
            "name": "Branch Office",
            "productTypes": ["wireless"],
            "timeZone": "America/New_York",
            "tags": ["branch"],
            "isBoundToConfigTemplate": True
        }
    ]
    mock_response.headers = {}
    mock_get.return_value = mock_response

    req = """
    {
        "connectionParameters": {
            "api_key": "sample_api_key"
        },
        "parameters": {
            "organizationId": "123456",
            "perPage": 50
        }
    }
    """

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.meraki_get_networks(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["count"] == 2
    assert len(resp["networks"]) == 2
    assert resp["networks"][0]["id"] == "N_123"
    assert resp["networks"][1]["name"] == "Branch Office"


@patch('requests.get')
def test_meraki_get_devices(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {
            "name": "MX-Device-1",
            "serial": "Q2XX-XXXX-XXXX",
            "mac": "00:11:22:33:44:55",
            "networkId": "N_123",
            "productType": "appliance",
            "model": "MX64"
        },
        {
            "name": "MS-Switch-1",
            "serial": "Q3XX-XXXX-XXXX",
            "mac": "00:11:22:33:44:66",
            "networkId": "N_123",
            "productType": "switch",
            "model": "MS120-8"
        },
        {
            "name": "MR-AP-1",
            "serial": "Q4XX-XXXX-XXXX",
            "mac": "00:11:22:33:44:77",
            "networkId": "N_456",
            "productType": "wireless",
            "model": "MR36"
        }
    ]
    mock_response.headers = {}
    mock_get.return_value = mock_response

    req = """
    {
        "connectionParameters": {
            "api_key": "sample_api_key"
        },
        "parameters": {
            "organizationId": "123456"
        }
    }
    """

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.meraki_get_devices(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["message"] == "Devices fetched successfully."
    assert resp["count"] == 3
    assert len(resp["devices"]) == 3


@patch('requests.get')
def test_meraki_get_devices_with_filters(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {
            "name": "MX-Device-1",
            "serial": "Q2XX-XXXX-XXXX",
            "networkId": "N_123",
            "productType": "appliance"
        },
        {
            "name": "MS-Switch-1",
            "serial": "Q3XX-XXXX-XXXX",
            "networkId": "N_123",
            "productType": "switch"
        },
        {
            "name": "MR-AP-1",
            "serial": "Q4XX-XXXX-XXXX",
            "networkId": "N_456",
            "productType": "wireless"
        }
    ]
    mock_response.headers = {}
    mock_get.return_value = mock_response

    req = """
    {
        "connectionParameters": {
            "api_key": "sample_api_key"
        },
        "parameters": {
            "organizationId": "123456",
            "networkId": "N_123",
            "productType": "appliance"
        }
    }
    """

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.meraki_get_devices(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["count"] == 1
    assert len(resp["devices"]) == 1
    assert resp["devices"][0]["productType"] == "appliance"
    assert resp["devices"][0]["networkId"] == "N_123"


@patch('requests.get')
def test_meraki_get_device_uplink(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {
            "networkId": "N_123",
            "serial": "Q2XX-ABCD-5678",
            "model": "MX64",
            "uplinks": [
                {
                    "interface": "wan1",
                    "status": "active",
                    "ip": "192.168.1.1",
                    "gateway": "192.168.1.254",
                    "publicIp": "1.2.3.4",
                    "dns": "8.8.8.8"
                },
                {
                    "interface": "wan2",
                    "status": "ready",
                    "ip": "10.0.0.1"
                }
            ]
        }
    ]
    mock_response.headers = {}
    mock_get.return_value = mock_response

    req = """
    {
        "connectionParameters": {
            "api_key": "sample_api_key"
        },
        "parameters": {
            "organizationId": "123456",
            "serial": "Q2XX-ABCD-5678"
        }
    }
    """

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.meraki_get_device_uplink(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["message"] == "Device uplink fetched successfully."
    assert resp["serial"] == "Q2XX-ABCD-5678"
    assert resp["uplink"] is not None
    assert resp["uplink"]["serial"] == "Q2XX-ABCD-5678"
    assert resp["uplink"]["model"] == "MX64"
    assert len(resp["uplink"]["uplinks"]) == 2
    assert resp["httpCode"] == 200


@patch('requests.get')
def test_meraki_get_device_uplink_not_found(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = []  # No uplink found
    mock_response.headers = {}
    mock_get.return_value = mock_response

    req = """
    {
        "connectionParameters": {
            "api_key": "sample_api_key"
        },
        "parameters": {
            "organizationId": "123456",
            "serial": "Q2XX-XXXX-XXXX"
        }
    }
    """

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.meraki_get_device_uplink(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["serial"] == "Q2XX-XXXX-XXXX"
    assert resp["uplink"] is None


@patch('requests.get')
def test_meraki_get_clients(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {
            "id": "client1",
            "mac": "00:11:22:33:44:55",
            "ip": "192.168.1.100",
            "description": "Laptop",
            "firstSeen": 1234567890,
            "lastSeen": 1234567900,
            "status": "Online",
            "usage": {"sent": 1000, "recv": 2000}
        },
        {
            "id": "client2",
            "mac": "00:11:22:33:44:66",
            "ip": "192.168.1.101",
            "description": "Phone",
            "firstSeen": 1234567800,
            "lastSeen": 1234567850,
            "status": "Offline"
        }
    ]
    mock_response.headers = {}
    mock_get.return_value = mock_response

    req = """
    {
        "connectionParameters": {
            "api_key": "sample_api_key"
        },
        "parameters": {
            "networkId": "N_123",
            "timespan": 86400
        }
    }
    """

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.meraki_get_clients(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["message"] == "Clients fetched successfully."
    assert resp["count"] == 2
    assert len(resp["clients"]) == 2
    assert resp["clients"][0]["mac"] == "00:11:22:33:44:55"
    assert resp["clients"][1]["status"] == "Offline"


@patch('requests.get')
def test_meraki_get_clients_with_t0_t1(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {
            "id": "client1",
            "mac": "00:11:22:33:44:55",
            "ip": "192.168.1.100",
            "status": "Online"
        }
    ]
    mock_response.headers = {}
    mock_get.return_value = mock_response

    req = """
    {
        "connectionParameters": {
            "api_key": "sample_api_key"
        },
        "parameters": {
            "networkId": "N_123",
            "t0": "2024-01-01T00:00:00Z",
            "t1": "2024-01-02T00:00:00Z"
        }
    }
    """

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.meraki_get_clients(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["count"] == 1
    assert resp["clients"][0]["mac"] == "00:11:22:33:44:55"


@patch('requests.post')
def test_meraki_remove_device(mock_post):
    mock_response = Mock()
    mock_response.status_code = 204  # No Content
    mock_post.return_value = mock_response

    req = """
    {
        "connectionParameters": {
            "api_key": "sample_api_key"
        },
        "parameters": {
            "networkId": "N_123",
            "serial": "Q2XX-ABCD-5678"
        }
    }
    """

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.meraki_remove_device(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["message"] == "Device removed from network successfully."
    assert resp["networkId"] == "N_123"
    assert resp["serial"] == "Q2XX-ABCD-5678"
    assert resp["httpCode"] == 204

    # Verify the POST call was made correctly
    mock_post.assert_called_once()
    call_args = mock_post.call_args
    assert "networks/N_123/devices/remove" in call_args[0][0]
    assert call_args[1]["json"] == {"serial": "Q2XX-ABCD-5678"}


@patch('requests.put')
def test_meraki_update_device(mock_put):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "serial": "Q2XX-ABCD-5678",
        "name": "Updated Device",
        "tags": ["production", "updated"],
        "lat": 37.4180951,
        "lng": -122.098531,
        "address": "1600 Pennsylvania Ave",
        "notes": "Updated notes",
        "model": "MX64"
    }
    mock_put.return_value = mock_response

    req = """
    {
        "connectionParameters": {
            "api_key": "sample_api_key"
        },
        "parameters": {
            "serial": "Q2XX-ABCD-5678",
            "name": "Updated Device",
            "tags": ["production", "updated"],
            "lat": 37.4180951,
            "lng": -122.098531,
            "address": "1600 Pennsylvania Ave",
            "notes": "Updated notes"
        }
    }
    """

    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.meraki_update_device(req)

    assert resp is not None
    assert resp["status"] == "success"
    assert resp["message"] == "Device updated successfully."
    assert resp["serial"] == "Q2XX-ABCD-5678"
    assert resp["device"]["name"] == "Updated Device"
    assert len(resp["device"]["tags"]) == 2

    # Verify the PUT call was made correctly
    mock_put.assert_called_once()
    call_args = mock_put.call_args
    assert "devices/Q2XX-ABCD-5678" in call_args[0][0]
    assert call_args[1]["json"]["name"] == "Updated Device"
