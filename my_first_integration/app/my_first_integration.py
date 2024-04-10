
from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
import logging
import requests

class MyFirstIntegration():

    def __init__(self) -> None:
        self.logger = logging.getLogger()
        pass

    def addtowatchlist(self, request: RequestBody) -> ResponseBody:
        username = request.connectionParameters['username']
        password = request.connectionParameters['password']
        serverurl = request.connectionParameters['serverurl']
        domain = request.connectionParameters['domain']
        addwatchlistname = request.parameters['addwatchlistname']
        containerdata = request.parameters['container']
        if containerdata:
            tenant_name = containerdata.get('tenantname')
            entity_type = containerdata.get('violator')
            resource_group_id = containerdata.get('resourcegroupid')
            entity_id = containerdata.get('entityId')
            if all([tenant_name, entity_type, resource_group_id, entity_id]):
                token_url = f'{serverurl}/ws/token/generate'
                auth = (username, password)
                try:
                    token_response = requests.post(token_url, auth=auth)
                    token_response.raise_for_status()
                    token = token_response.json().get('token')
                    add_to_watchlist_url = f'{serverurl}/ws/incident/addToWatchlist'
                    watchlist_params = {'tenantname': tenant_name, 'entityType': entity_type, 'watchlistname': addwatchlistname, 'expirydays': 10, 'resourcegroupid': resource_group_id, 'entityId': entity_id}
                    watchlist_response = requests.post(add_to_watchlist_url, headers={'token': token}, params=watchlist_params)
                    watchlist_response.raise_for_status()
                    return watchlist_response.json()
                except requests.exceptions.RequestException as e:
                    return {'Status': 'Error', 'Message': f'Failed to complete the operation: {str(e)}'}
            else:
                return {'Status': 'Error', 'Message': 'Required parameters are missing in containerdata'}
        else:
            return {'Status': 'Error', 'Message': 'Containerdata is missing'}

    def createwatchlist(self, request: RequestBody) -> ResponseBody:
        username = request.connectionParameters['username']
        password = request.connectionParameters['password']
        serverurl = request.connectionParameters['serverurl']
        domain = request.connectionParameters['domain']
        createwatchlistname = request.parameters['createwatchlistname']
        token_url = f'{serverurl}/ws/token/generate'
        headers = {
         'username': username,
         'password': password,
        }
        print(token_url)
        try:
            token_response = requests.get(token_url,headers=headers)
            token = token_response.text.strip()
            print("Token Response Content:", token)
            if createwatchlistname:
                create_watchlist_url = f'{serverurl}/ws/incident/createWatchlist'
                watchlist_params = {'watchlistname': createwatchlistname, 'tenantname': '64april_r2_mssp', 'token': token}
                watchlist_response = requests.post(create_watchlist_url, params=watchlist_params)
                watchlist_response.raise_for_status()
                watchlist_status = watchlist_response.text
                return {'Status': 'Success', 'Message': watchlist_status}
            else:
                return {'Status': 'Error', 'Message': 'Watchlist name is missing'}
        except requests.exceptions.RequestException as e:
            return {'Status': 'Error', 'Message': f'Failed to complete the operation: {str(e)}'}

    def RemoveWatchlist(self, request: RequestBody) -> ResponseBody:
        username = request.connectionParameters['username']
        password = request.connectionParameters['password']
        serverurl = request.connectionParameters['serverurl']
        domain = request.connectionParameters['domain']
        ORG = request.connectionParameters['ORG']
        createwatchlistname = request.parameters['createwatchlistname']
        'implement your custom logic for action handling here'
        return {'Status': ''}

    def test_connection(self, connectionParameters: dict):
        username = connectionParameters['username']
        password = connectionParameters['password']
        serverurl = connectionParameters['serverurl']
        domain = connectionParameters['domain']
        ORG = connectionParameters['ORG']
        try:
            return 'Connection Successful'
        except Exception as e:
            raise Exception(str(e))
