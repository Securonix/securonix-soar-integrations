
from app.my_first_integration import MyFirstIntegration
from app.model.request_body import RequestBody
from pykson import Pykson
import json
pykson = Pykson()
integration_class = MyFirstIntegration()

def test_addtowatchlist():
    
    req = '{"connectionParameters": {"username": "admin", "password": "GqKnH7SjINVd3ADV", "serverurl": "https://a1t3ygft-uat01.securonix.net/Snypr", "domain": "google.com"}, "parameters": {"addwatchlistname": "test_watchlist", "container": {"tenantname": "64april_r2_mssp", "violator": "Users","resourcegroupid": "1","entityId": "Sai"}}'
    req = pykson.from_json(req, RequestBody, True)
    resp = integration_class.addtowatchlist(req)
    assert (resp is not None)


def test_createwatchlist():
    req = '{"connectionParameters": {"username": "admin", "password": "GqKnH7SjINVd3ADV", "serverurl": "https://a1t3ygft-uat01.securonix.net/Snypr", "domain": "google.com"}, "parameters": {"createwatchlistname": "test_watchlist2"}}'
    req = pykson.from_json(req, RequestBody, True)
    print("Request:", req)
    resp = integration_class.createwatchlist(req)
    print("Response:", resp)
    assert (resp is not None)

#def test_RemoveWatchlist():
  #  req = '{"connectionParameters": {"username": "samplevalue", "password": "samplevalue", "serverurl": "samplevalue", "domain": "samplevalue", "ORG": "samplevalue"}, "parameters": {"createwatchlistname": "samplevalue"}}'
  #  req = pykson.from_json(req, RequestBody, True)
  #  resp = integration_class.RemoveWatchlist(req)
  #  assert (resp is not None)
