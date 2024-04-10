
from app.model.request_body import RequestBody
from app.model.response_body import ResponseBody
from botocore.exceptions import ClientError, EndpointConnectionError
import boto3
import logging
import json


class AwsWaf():

    def __init__(self) -> None:
        self.logger = logging.getLogger()
        pass

    def test_connection(self, connectionParameters: dict):
        access_key = connectionParameters['access_key']
        secret_key = connectionParameters['secret_key']
        region = connectionParameters['region']
        try:
            client = boto3.client('wafv2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
            resp = client.list_ip_sets(Scope='REGIONAL', Limit=1 )
            self.logger.debug("aws waf response to list_api_keys is %s", json.dumps(resp))
            return {'status':'success', 'message':f'Connected to AWS WAF successfully.'}
        except Exception as e:
            self.logger.error("Exception while testing connection parameters", exc_info=e)
            raise Exception(str(e))
        

    def update_ip_set(self, request: RequestBody) -> ResponseBody:
        try:
            access_key = request.connectionParameters['access_key']
            secret_key = request.connectionParameters['secret_key']
            region = request.connectionParameters['region']
            id = request.parameters['id']
            name = request.parameters['name']
            scope = request.parameters['scope']
            addresses = request.parameters['addresses']
            if isinstance(addresses[0], str):
                addresses = addresses[0].replace(' ', '').split(',')
            else :
                addresses = addresses[0]
            addresses = list(map(lambda ip: ip + '/32', addresses))
            resp = {}
            self.client = boto3.client('wafv2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
            ipSetResp = self.client.get_ip_set(Name=name, Scope=scope, Id=id)
            print(ipSetResp)
            existingAddresses = ipSetResp['IPSet']['Addresses']
            existingAddresses.extend(addresses)
            updateResp = self.client.update_ip_set(Name=name, Scope=scope, Id=id, Addresses=existingAddresses, LockToken=ipSetResp['LockToken'])
            resp['status'] = updateResp['ResponseMetadata']['HTTPStatusCode']
            resp['message'] = 'IPSet updated successfully.'
        except ClientError as ce:
            self.logger.error("error whlile running action 'update_ip_set'", exc_info=ce)
            raise Exception(ce.response['Error']['Message'])
        except EndpointConnectionError as ece:
            self.logger.error("error whlile running action 'update_ip_set'", exc_info=ce)
            raise Exception(ece.args[0])
        return resp
