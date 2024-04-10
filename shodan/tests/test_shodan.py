
from app.shodan import Shodan
from app.model.request_body import RequestBody
from pykson import Pykson
import json
pykson = Pykson()
integration_class = Shodan()

def test_ip_address():
    req = '{"connectionParameters": {"server_url": "https://api.shodan.io/shodan", "api_token": "samplevalue"}, "parameters": {"ip_addr": "1.1.1.1"}}'
    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.ip_address(req)
    assert (resp is not None)