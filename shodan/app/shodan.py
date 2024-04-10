
from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import requests

class Shodan():

    def __init__(self) -> None:
        self.logger = logging.getLogger()
        pass

    def ip_address(self, request: RequestBody) -> ResponseBody:
        server_url = request.connectionParameters['server_url']
        api_token = request.connectionParameters['api_token']
        ip_addr = request.parameters['ip_addr']
        url = f"{server_url}/host/{ip_addr}"
        headers = {
        'Key': api_token
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
           hosts_info = response.json()
           hosts = hosts_info.get('data', [])
           return {'hosts': hosts}
        else:
        
            return {'hosts': []}

    def test_connection(self, connectionParameters: dict):
        server_url = connectionParameters['server_url']
        api_token = connectionParameters['api_token']
        ip_addr = '1.1.1.1'  # Hardcoded IP address for testing
        url = f"{server_url}/host/{ip_addr}"
        headers = {
        'Key': api_token
        }

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return 'Connection Successful'
            else:
               response.raise_for_status()
        except Exception as e:
            raise Exception(str(e))
