
from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import requests
import json
from akamai.edgegrid import EdgeGridAuth

class AkamaiWaf():

    def __init__(self) -> None:
        self.logger = logging.getLogger()

    # ---------------------------
    # P1 ACTION: Block IP
    # ---------------------------
    def block_ip(self, request: RequestBody) -> ResponseBody:
        host = request.connectionParameters['host']
        client_token = request.connectionParameters['client_token']
        client_secret = request.connectionParameters['client_secret']
        access_token = request.connectionParameters['access_token']
        network_list_id = request.parameters['network_list_id']
        ip_addresses = request.parameters['ip_addresses']
        self.logger.info("executing block_ip action")
        session = self.get_session(client_token, client_secret, access_token)
        data, error = self._get_network_list(network_list_id, host, session)
        if error:
            return error

        existing_ips = set(data.get("list", []))
        new_ips = set(ip_addresses)
        updated_ips = list(existing_ips.union(new_ips))
        # If no change needed
        if existing_ips == set(updated_ips):
            return {
                "status": "success",
                "message": "IP(s) already present in network list",
                "network_list_id": network_list_id,
                "total_ips": len(existing_ips)
            }

        payload = {
            "name": data.get("name"),
            "type": data.get("type"),
            "list": updated_ips,
            "description": data.get("description", "")
        }
        update_response, error = self._update_network_list(host, network_list_id, payload, session)
        if error:
            return error

        return {
            "status": "success",
            "message": "IP(s) successfully added",
            "network_list_id": network_list_id,
            "total_ips": len(updated_ips)
        }

    def unblock_ip(self, request: RequestBody) -> ResponseBody:
        host = request.connectionParameters['host']
        client_token = request.connectionParameters['client_token']
        client_secret = request.connectionParameters['client_secret']
        access_token = request.connectionParameters['access_token']
        network_list_id = request.parameters['network_list_id']
        ip_addresses = request.parameters['ip_addresses']
        self.logger.info("executing unblock_ip action")
        session = self.get_session(client_token, client_secret, access_token)
        data, error = self._get_network_list(network_list_id, host, session)
        if error:
            return error

        existing_ips = set(data.get("list", []))
        remove_ips = set(ip_addresses)
        updated_ips = list(existing_ips - remove_ips)
        # If nothing to remove
        if existing_ips == set(updated_ips):
            return {
                "status": "success",
                "message": "No matching IP(s) found in network list",
                "network_list_id": network_list_id,
                "total_ips": len(existing_ips)
            }
        payload = {
            "name": data.get("name"),
            "type": data.get("type"),
            "list": updated_ips,
            "description": data.get("description", "")
        }
        update_response, error = self._update_network_list(host, network_list_id, payload, session)
        if error:
            return error

        return {
            "status": "success",
            "message": "IP(s) successfully removed",
            "network_list_id": network_list_id,
            "total_ips": len(updated_ips)
        }
    
    def get_security_events( self, request: RequestBody ):
        """
        Retrieve security events from Akamai WAF.

        :param start_time: ISO8601 string (e.g., 2024-01-01T00:00:00Z)
        :param end_time: ISO8601 string
        :param policy_id: Optional policy filter
        :param attack_type: Optional attack group filter
        :param ip_address: Optional IP filter
        :param limit: Max records to return
        """
        self.logger.info("executing get_security_events action")
        host = request.connectionParameters['host']
        client_token = request.connectionParameters['client_token']
        client_secret = request.connectionParameters['client_secret']
        access_token = request.connectionParameters['access_token']
        start_time = request.parameters['start_time']
        end_time = request.parameters['end_time']
        policy_id = request.parameters['policy_id']
        attack_type = request.parameters['attack_type']
        ip_address = request.parameters['ip_address']
        limit = request.parameters['limit']
        
        url = f"{host}/appsec/v1/events"

        params = {
            "start": start_time,
            "end": end_time,
            "limit": limit
        }

        if policy_id:
            params["policyId"] = policy_id

        if attack_type:
            params["attackGroup"] = attack_type

        if ip_address:
            params["clientIP"] = ip_address

        response = self.get_session(client_token, client_secret, access_token).get(url, params=params)

        if response.status_code != 200:
            return self._handle_error(response)

        data = response.json()

        return {
            "status": "success",
            "event_count": len(data.get("events", [])),
            "events": data.get("events", [])
        }

    def test_connection(self, connection_parameters: dict):
        host = connection_parameters['host']
        client_token = connection_parameters['client_token']
        client_secret = connection_parameters['client_secret']
        access_token = connection_parameters['access_token']
        if not all([host, client_token, client_secret, access_token]):
            raise ValueError("Missing required connection parameters.")
    
        try:
            session = self.get_session(client_token=client_token, client_secret=client_secret, access_token=access_token)
            data, error = self._get_network_list(network_list_id="", host=host, session=session)
            if error:
                raise Exception("Connection failed: " + str(error))
            
            return "Connection Successful"
        except Exception as e:
            self.logger.error("Exception while testing connection parameters", exc_info=e)
            raise Exception(str(e))

    def get_session(self, client_token, client_secret, access_token):
        session = requests.Session()
        session.auth = EdgeGridAuth(
                client_token=client_token,
                client_secret=client_secret,
                access_token=access_token
            )
        session.headers.update({
                "Content-Type": "application/json"
            })
        
        return session
        
    def _get_network_list(self, network_list_id, host, session):
        url = f"{host}/network-list/v2/network-lists/{network_list_id}"
        response = session.get(url)
        if response.status_code != 200:
            return None, self._handle_error(response)
        return response.json(), None
    
    def _update_network_list(self, host, network_list_id, payload, session):
        url = f"{host}/network-list/v2/network-lists/{network_list_id}"
        response = session.put(url, data=json.dumps(payload))

        if response.status_code not in [200, 201]:
            return None, self._handle_error(response)

        return response.json(), None
    
    def _handle_error(self, response):
        return {
            "status": "error",
            "message": f"API request failed with status {response.status_code}",
            "status_code": response.status_code
        }
