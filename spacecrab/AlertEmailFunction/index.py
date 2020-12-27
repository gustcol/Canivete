import os
import base64
import json
import boto3
import pprint
from botocore.exceptions import ClientError

mail_html = """
<div>
<hr />
    <table class="table table-condensed table-bordered table-hover">
        <tr><th>eventTime</th><td>%(eventTime)s</td></tr>
        <tr><th>notes</th><td>%(notes)s</td></tr>
        <tr><th>eventSource</th><td>%(eventSource)s</td></tr>
        <tr><th>eventName</th><td>%(eventName)s</td></tr>
        <tr><th>userIdentity</th><td>
            <table class="table table-condensed table-bordered table-hover">
                <tr><th>userName</th><td>%(userName)s</td></tr>
                <tr><th>principalId</th><td>%(principalId)s</td></tr>
                <tr><th>accessKeyId</th><td>%(accessKeyId)s</td></tr>
                <tr><th>type</th><td>%(type)s</td></tr>
                <tr><th>arn</th><td>%(arn)s</td></tr>
                <tr><th>accountId</th><td>%(accountId)s</td></tr>
            </table>
        </td></tr>
        <tr><th>location</th><td>%(location)s</td></tr>
        <tr><th>owner</th><td>%(owner)s</td></tr>
        <tr><th>userAgent</th><td>%(userAgent)s</td></tr>
        <tr><th>sourceIPAddress</th><td>%(sourceIPAddress)s</td></tr>
    </table></td></tr>
    <hr />
    </div>
    """


def lambda_handler(event, context):
    return_value = {}
    return_value['Status'] = 'FAILED'
    encrypted_email = os.environ.get('ENCRYPTED_EMAIL', None)
    ses_region = os.environ.get('SES_REGION', 'us-west-2')
    if None in [encrypted_email]:
        return_value['Reason'] = 'Missing email address'
        print(json.dumps(return_value))
        return return_value
    encrypted_email = base64.b64decode(encrypted_email)
    encrypted_from_email = os.environ.get('ENCRYPTED_FROM_EMAIL', None)
    if None in [encrypted_from_email]:
        encrypted_from_email = encrypted_email
    else:
        encrypted_from_email = base64.b64decode(encrypted_from_email)

    try:
        kmsclient = boto3.client('kms')
        response = kmsclient.decrypt(CiphertextBlob=encrypted_email)
        email = response['Plaintext']
    except ClientError as e:
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value

    try:
        kmsclient = boto3.client('kms')
        response = kmsclient.decrypt(CiphertextBlob=encrypted_from_email)
        from_email = response['Plaintext']
    except ClientError as e:
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value
    return_value['Status'] = 'SUCCESS'
    return_value['Reason'] = 'Found an email address'

    sns_message = json.loads(event['Records'][0]['Sns']['Message'])

    highlights = {}
    for k in ['eventName', 'eventSource', 'sourceIPAddress', 'userAgent', 'eventTime']:
        highlights[k] = sns_message[k]
    for k in ['userName', 'principalId', 'accessKeyId', 'type', 'arn', 'accountId']:
        highlights[k] = sns_message['userIdentity'][k]
    for k in ['notes', 'location', 'owner']:
        highlights[k] = sns_message['alertMetadata'][k]

    ses = boto3.client('ses', region_name=ses_region)
    email_from = from_email
    email_to = email
    email_subject = "AWS honey token usage alert"
    message = pprint.pformat(json.dumps(highlights), indent=4)
    message += '\n'
    message += pprint.pformat(json.dumps(sns_message), indent=4)

    response = ses.send_email(
        Source=email_from,
        Destination={
            'ToAddresses': [
                email_to
            ]
        },
        Message={
            'Subject': {
                'Data': email_subject,
                'Charset': 'utf8'
            },
            'Body': {
                'Text': {
                    'Data': message,
                    'Charset': 'utf8'
                },
                'Html': {
                    'Data': mail_html % highlights,
                    'Charset': 'utf8'
                }
            }
        },
        ReplyToAddresses=[
            email_from
        ]

    )
    print(response)
    print(json.dumps(return_value))
    return return_value
