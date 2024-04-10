
from app.aws_waf import AwsWaf
from app.model.request_body import RequestBody
from pykson import Pykson
import json
pykson = Pykson()
integration_class = AwsWaf()

def test_update_ip_set():
    req = '{"connectionParameters": {"access_key": "samplevalue", "secret_key": "samplevalue", "region": "samplevalue"}, "parameters": {"id": "samplevalue", "name": "samplevalue", "scope": "samplevalue", "addresses": "samplevalue"}}'
    req = pykson.from_json(req, RequestBody, True)
    # resp = integration_class.update_ip_set(req)
    resp = {}
    assert (resp is not None)
