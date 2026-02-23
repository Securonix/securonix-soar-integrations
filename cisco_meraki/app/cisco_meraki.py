from app.model.request_body import RequestBody
import logging
import requests
import time

class CiscoMeraki():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    # ---------------------------------------------------------------------
    # Test Connection
    # ---------------------------------------------------------------------
    def test_connection(self, connectionParameters: dict):
        try:
            self._init_client(connectionParameters)
            resp = requests.get(f"{self.base_url}/organizations", headers=self.headers, timeout=30)
            if resp.status_code >= 300:
                raise Exception(resp.text)
            return {'status': 'success', 'message': 'Connected to Cisco Meraki successfully.'}
        except Exception as e:
            self.logger.error("Exception while testing connection", exc_info=e)
            raise Exception(str(e))

    # ---------------------------------------------------------------------
    # Get Networks
    # ---------------------------------------------------------------------
    def meraki_get_networks(self, request: RequestBody) -> dict:
        try:
            if not request or not request.connectionParameters:
                raise Exception("request and connectionParameters are required")
            if not request.parameters:
                raise Exception("parameters are required")
            
            self._init_client(request.connectionParameters)
            
            org_id = request.parameters.get('organizationId')
            if not org_id:
                raise Exception("organizationId is required")

            params = {}
            if request.parameters.get('configTemplateId'):
                params['configTemplateId'] = request.parameters['configTemplateId']
            if request.parameters.get('isBoundToConfigTemplate') is not None:
                params['isBoundToConfigTemplate'] = request.parameters['isBoundToConfigTemplate']
            if request.parameters.get('tags'):
                params['tags[]'] = request.parameters['tags']
            if request.parameters.get('tagsFilterType'):
                params['tagsFilterType'] = request.parameters['tagsFilterType']
            if request.parameters.get('productTypes'):
                params['productTypes[]'] = request.parameters['productTypes']
            if request.parameters.get('perPage'):
                params['perPage'] = request.parameters['perPage']
            if request.parameters.get('startingAfter'):
                params['startingAfter'] = request.parameters['startingAfter']
            if request.parameters.get('endingBefore'):
                params['endingBefore'] = request.parameters['endingBefore']

            resp = self._get_with_retry(f"{self.base_url}/organizations/{org_id}/networks", params)
            networks = resp.json()
            
            result = {
                "status": "success",
                "networks": networks,
                "count": len(networks)
            }
            
            link_header = resp.headers.get('Link', '')
            if 'rel="next"' in link_header:
                for link in link_header.split(','):
                    if 'rel="next"' in link:
                        result['pagination'] = {'next': link.split(';')[0].strip('<> ')}
                        break

            return result

        except Exception as e:
            self.logger.error("error while running action 'meraki_get_networks'", exc_info=e)
            raise Exception(str(e))

    # ---------------------------------------------------------------------
    # Get Devices
    # ---------------------------------------------------------------------
    def meraki_get_devices(self, request: RequestBody) -> dict:
        try:
            if not request or not request.connectionParameters:
                raise Exception("request and connectionParameters are required")
            if not request.parameters:
                raise Exception("parameters are required")
            
            self._init_client(request.connectionParameters)
            
            org_id = request.parameters.get('organizationId')
            if not org_id:
                raise Exception("organizationId is required")

            params = {}
            if request.parameters.get('perPage'):
                params['perPage'] = request.parameters['perPage']
            if request.parameters.get('startingAfter'):
                params['startingAfter'] = request.parameters['startingAfter']
            if request.parameters.get('endingBefore'):
                params['endingBefore'] = request.parameters['endingBefore']

            resp = self._get_with_retry(f"{self.base_url}/organizations/{org_id}/devices", params)
            devices = resp.json()
            
            network_id = request.parameters.get('networkId')
            if network_id:
                devices = [d for d in devices if d.get('networkId') == network_id]
            
            product_type = request.parameters.get('productType')
            if product_type:
                devices = [d for d in devices if d.get('productType') == product_type]

            return {
                "status": "success",
                "message": "Devices fetched successfully.",
                "count": len(devices),
                "devices": devices
            }

        except Exception as e:
            self.logger.error("error while running action 'meraki_get_devices'", exc_info=e)
            raise Exception(str(e))

    # ---------------------------------------------------------------------
    # Get Device Uplink
    # ---------------------------------------------------------------------
    def meraki_get_device_uplink(self, request: RequestBody) -> dict:
        try:
            if not request or not request.connectionParameters:
                raise Exception("request and connectionParameters are required")
            if not request.parameters:
                raise Exception("parameters are required")
            
            self._init_client(request.connectionParameters)
            
            org_id = request.parameters.get('organizationId')
            serial = request.parameters.get('serial')
            
            if not org_id:
                raise Exception("organizationId is required")
            if not serial:
                raise Exception("serial is required")

            params = {'serials[]': serial}
            
            if request.parameters.get('networkIds'):
                params['networkIds[]'] = request.parameters['networkIds']
            if request.parameters.get('perPage'):
                params['perPage'] = request.parameters['perPage']
            if request.parameters.get('startingAfter'):
                params['startingAfter'] = request.parameters['startingAfter']
            if request.parameters.get('endingBefore'):
                params['endingBefore'] = request.parameters['endingBefore']

            resp = self._get_with_retry(f"{self.base_url}/organizations/{org_id}/appliance/uplink/statuses", params)
            uplinks = resp.json()
            
            uplink = uplinks[0] if uplinks else None

            return {
                "status": "success",
                "message": "Device uplink fetched successfully.",
                "serial": serial,
                "uplink": uplink,
                "httpCode": 200
            }

        except Exception as e:
            self.logger.error("error while running action 'meraki_get_device_uplink'", exc_info=e)
            raise Exception(str(e))

    # ---------------------------------------------------------------------
    # Get Clients
    # ---------------------------------------------------------------------
    def meraki_get_clients(self, request: RequestBody) -> dict:
        try:
            if not request or not request.connectionParameters:
                raise Exception("request and connectionParameters are required")
            if not request.parameters:
                raise Exception("parameters are required")
            
            self._init_client(request.connectionParameters)
            
            network_id = request.parameters.get('networkId')
            if not network_id:
                raise Exception("networkId is required")

            params = {}
            
            if request.parameters.get('timespan'):
                params['timespan'] = request.parameters['timespan']
            if request.parameters.get('t0'):
                params['t0'] = request.parameters['t0']
            if request.parameters.get('t1'):
                params['t1'] = request.parameters['t1']
            if request.parameters.get('perPage'):
                params['perPage'] = request.parameters['perPage']
            if request.parameters.get('startingAfter'):
                params['startingAfter'] = request.parameters['startingAfter']
            if request.parameters.get('endingBefore'):
                params['endingBefore'] = request.parameters['endingBefore']

            resp = self._get_with_retry(f"{self.base_url}/networks/{network_id}/clients", params)
            clients = resp.json()

            return {
                "status": "success",
                "message": "Clients fetched successfully.",
                "count": len(clients),
                "clients": clients
            }

        except Exception as e:
            self.logger.error("error while running action 'meraki_get_clients'", exc_info=e)
            raise Exception(str(e))

    # ---------------------------------------------------------------------
    # Remove Device
    # ---------------------------------------------------------------------
    def meraki_remove_device(self, request: RequestBody) -> dict:
        try:
            if not request or not request.connectionParameters:
                raise Exception("request and connectionParameters are required")
            if not request.parameters:
                raise Exception("parameters are required")
            
            self._init_client(request.connectionParameters)
            
            network_id = request.parameters.get('networkId')
            serial = request.parameters.get('serial')
            
            if not network_id:
                raise Exception("networkId is required")
            if not serial:
                raise Exception("serial is required")

            payload = {"serial": serial}

            resp = self._post_with_retry(
                f"{self.base_url}/networks/{network_id}/devices/remove",
                self.headers,
                payload
            )

            return {
                "status": "success",
                "message": "Device removed from network successfully.",
                "networkId": network_id,
                "serial": serial,
                "httpCode": resp.status_code
            }

        except Exception as e:
            self.logger.error("error while running action 'meraki_remove_device'", exc_info=e)
            raise Exception(str(e))

    # ---------------------------------------------------------------------
    # Update Device
    # ---------------------------------------------------------------------
    def meraki_update_device(self, request: RequestBody) -> dict:
        try:
            if not request or not request.connectionParameters:
                raise Exception("request and connectionParameters are required")
            if not request.parameters:
                raise Exception("parameters are required")
            
            self._init_client(request.connectionParameters)
            
            serial = request.parameters.get('serial')
            if not serial:
                raise Exception("serial is required")

            payload = {}
            allowed_fields = ['name', 'tags', 'lat', 'lng', 'address', 'notes', 'moveMapMarker', 'switchProfileId', 'floorPlanId']
            
            for field in allowed_fields:
                if field in request.parameters and request.parameters[field] is not None:
                    payload[field] = request.parameters[field]
            
            if not payload:
                raise Exception("No update fields provided")

            resp = self._put_with_retry(
                f"{self.base_url}/devices/{serial}",
                self.headers,
                payload
            )

            device = resp.json()

            return {
                "status": "success",
                "message": "Device updated successfully.",
                "serial": serial,
                "device": device
            }

        except Exception as e:
            self.logger.error("error while running action 'meraki_update_device'", exc_info=e)
            raise Exception(str(e))

    # =========================
    # Internal helper methods
    # =========================

    def _init_client(self, connectionParameters):
        if not connectionParameters:
            raise Exception("connectionParameters is required")
        
        base_url = connectionParameters.get('base_url')
        api_key = connectionParameters.get('api_key')
        
        if not base_url:
            raise Exception("base_url is required in connectionParameters")
        if not api_key:
            raise Exception("api_key is required in connectionParameters")
        
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

    def _get_with_retry(self, url, params, max_retries=3):
        for attempt in range(max_retries):
            resp = requests.get(url, headers=self.headers, params=params, timeout=30)
            if resp.status_code == 429:
                retry_after = int(resp.headers.get('Retry-After', 2))
                if attempt < max_retries - 1:
                    time.sleep(retry_after)
                    continue
            if resp.status_code >= 300:
                raise Exception(resp.text)
            return resp
        if resp.status_code >= 300:
            raise Exception(resp.text)
        return resp

    def _post_with_retry(self, url, headers, payload, max_retries=3):
        for attempt in range(max_retries):
            resp = requests.post(url, headers=headers, json=payload, timeout=30)
            if resp.status_code == 429:
                retry_after = int(resp.headers.get('Retry-After', 2))
                if attempt < max_retries - 1:
                    time.sleep(retry_after)
                    continue
            if resp.status_code == 204:
                return resp
            if resp.status_code >= 300:
                raise Exception(resp.text)
            return resp
        if resp.status_code >= 300:
            raise Exception(resp.text)
        return resp

    def _put_with_retry(self, url, headers, payload, max_retries=3):
        for attempt in range(max_retries):
            resp = requests.put(url, headers=headers, json=payload, timeout=30)
            if resp.status_code == 429:
                retry_after = int(resp.headers.get('Retry-After', 2))
                if attempt < max_retries - 1:
                    time.sleep(retry_after)
                    continue
            if resp.status_code >= 300:
                raise Exception(resp.text)
            return resp
        if resp.status_code >= 300:
            raise Exception(resp.text)
        return resp