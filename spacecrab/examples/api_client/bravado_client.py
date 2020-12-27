#!/usr/bin/env python

import os
from bravado.requests_client import RequestsClient
from bravado.client import SwaggerClient
from bravado.swagger_model import load_file
from pprint import pprint
import bravado_core

http_client = RequestsClient()
http_client.set_api_key(
    os.environ.get('SPACECRAB_API_HOSTNAME'), os.environ.get('SPACECRAB_API_KEY'),
    param_name='x-api-key', param_in='header'
)

client = SwaggerClient.from_spec(
    load_file('SpaceCrab API-v0-swagger-apigateway.yaml'),
    http_client=http_client,
    config={'also_return_response': True}
)

AddTokenRequest = client.get_model('AddTokenRequest')
requestBody = AddTokenRequest(Owner="John Smithington",Location="DMZ",ExpiresAt="2016-01-01 00:00:00", Notes="Generated by bravado")
AddToken, http_response = client.token.AddToken(AddTokenRequest=requestBody).result()
print(AddToken)

UpdateTokenRequest = client.get_model('UpdateTokenRequest')
requestBody = UpdateTokenRequest(AccessKeyId=AddToken.AccessKey['AccessKeyId'], Owner="Bob",Location="Inner sanctum",ExpiresAt="2017-01-01 00:00:00", Notes="Updated by bravado")
UpdateToken, http_response = client.token.UpdateToken(UpdateTokenRequest=requestBody).result()
print(UpdateToken)

DeleteTokenRequest = client.get_model('DeleteTokenRequest')
requestBody = DeleteTokenRequest(AccessKeyId=AddToken.AccessKey['AccessKeyId'])
DeleteToken, http_response = client.token.DeleteToken(DeleteTokenRequest=requestBody).result()
print(DeleteToken)