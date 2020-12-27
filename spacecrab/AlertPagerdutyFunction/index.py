import os
import base64
import json
import boto3
from botocore.exceptions import ClientError
import requests


def lambda_handler(event, context):
    return_value = {}
    return_value['Status'] = 'FAILED'
    encrypted_pg_token = os.environ.get('ENCRYPTED_PAGERDUTY_TOKEN', None)
    if None in [encrypted_pg_token]:
        return_value['Reason'] = 'Missing pagerduty token'
        print(json.dumps(return_value))
        return return_value
    encrypted_pg_token = base64.b64decode(encrypted_pg_token)

    try:
        kmsclient = boto3.client('kms')
        response = kmsclient.decrypt(CiphertextBlob=encrypted_pg_token)
        pg_token = response['Plaintext']
    except ClientError as e:
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value

    if pg_token == "DONTUSE":
        return_value['Reason'] = 'No valid pagerduty token provided'
        print(json.dumps(return_value))
        return return_value
    # ok, we've got a, hopefully valid, pagerduty token.
    # let's break some stuff!
    # construct message
    sns_message = json.loads(event['Records'][0]['Sns']['Message'])

    highlights = {}
    for k in ['userIdentity', 'eventName', 'sourceIPAddress', 'userAgent', 'eventTime']:
        highlights[k] = sns_message[k]
    for k in ['notes', 'location', 'owner']:
        highlights[k] = sns_message['alertMetadata'][k]

    summary = "AWS token %s has been used from source IP %s" % (
            highlights['userIdentity']['accessKeyId'], highlights['sourceIPAddress']
            )

    data = {
        'routing_key': pg_token,
        'event_action': 'trigger',
        'payload':  {
            'summary': summary,
            'source': 'aws monitoring',
            'severity': 'error',
            'custom_details': highlights

        }
    }

    endpoint = 'https://events.pagerduty.com/v2/enqueue'

    r = requests.post(endpoint, json=data)
    if r.status_code == 200:
        return_value['Status'] = 'SUCCESS'
    return_value['Reason'] = r.text
    print(json.dumps(return_value))
    return return_value
