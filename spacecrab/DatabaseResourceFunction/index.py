import json
import os
import boto3
import base64
import psycopg2
import httplib
import urlparse
import re


def lambda_handler(event, context):
    print(json.dumps(event))  # for debugging only

    # Setup the defaults for our response
    response = {
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Status': 'SUCCESS'
    }

    # Every resource needs a unqiue physical id
    if 'PhysicalResourceId' in event:
        response['PhysicalResourceId'] = event['PhysicalResourceId']
    else:
        response['PhysicalResourceId'] = os.urandom(8).encode('hex')

    # Make sure a request type was provided, and this is a legit
    # cloudformation event
    if 'RequestType' not in event or not event['RequestType']:
        response['Status'] = 'FAILED'
        response['Reason'] = 'Missing request type.'
        return send_response(event, response)

    # Create our database tables, indicies and users
    if event['RequestType'] == 'Create':
        regex = re.compile('[^a-zA-Z0-9_]')
        function_user = regex.sub('', event['ResourceProperties'][
                                  'FunctionDatabaseUser'])
        function_password = base64.b64decode(event['ResourceProperties'][
            'EncryptedFunctionDatabasePassword'])
        try:
            kmsclient = boto3.client('kms')
            kmsresponse = kmsclient.decrypt(CiphertextBlob=function_password)
            function_password = kmsresponse['Plaintext']
        except Exception as e:
            print(e.message)
            return

        con = None
        try:
            con = psycopg2.connect(dbname='TokenDatabase',
                                   host=os.environ['TOKEN_DATABASE_ADDRESS'],
                                   port=os.environ['TOKEN_DATABASE_PORT'],
                                   user=os.environ['TOKEN_DATABASE_USER'],
                                   password=os.environ['TOKEN_DATABASE_PASSWORD'])
            cur = con.cursor()

            cur.execute('''
                CREATE TABLE token (
                  AccessKeyId VARCHAR (128) PRIMARY KEY,
                  SecretAccessKey VARCHAR (128) NOT NULL,
                  CreatedAt TIMESTAMP DEFAULT NOW(),
                  UserName VARCHAR (256),
                  UserArn VARCHAR (256),
                  Owner VARCHAR (256),
                  Location VARCHAR (256),
                  ExpiresAt TIMESTAMP,
                  DeactivatedAt TIMESTAMP,
                  Active BOOLEAN DEFAULT TRUE,
                  Notes TEXT
                );
            ''')

            cur.execute(
                'CREATE INDEX SecretAccessKey_index ON token (SecretAccessKey);')
            cur.execute('CREATE INDEX Owner_index ON token (Owner);')
            cur.execute('CREATE INDEX username_index ON token (UserName);')
            cur.execute('CREATE INDEX location_index ON token (Location);')
            cur.execute('CREATE INDEX expires_index ON token (ExpiresAt);')

            cur.execute("CREATE ROLE " + function_user +
                        " WITH PASSWORD %s LOGIN;", (function_password,))
            cur.execute(
                "GRANT SELECT, INSERT, UPDATE ON token TO " + function_user + ";")

            con.commit()
            cur.close()
        except Exception as e:
            response['Status'] = 'FAILED'
            response['Reason'] = e.message
    elif event['RequestType'] == 'Delete':
        # Do nothing as the table will be deleted along with the database.
        response['Status'] = 'SUCCESS'
    elif event['RequestType'] == 'Update':
        # Do nothing as we just want to do a one off bootstrap
        response['Status'] = 'SUCCESS'
        # setting to success so other things in stack don't get rolled back.
        # means nothing, though.
        response['Reason'] = 'Updates not allowed.'
    else:
        # This should never happen
        response['Status'] = 'FAILED'
        response['Reason'] = 'Unexpected request type.'

    return send_response(event, response)


def send_response(request, response):
    print(json.dumps(response))  # for debugging only

    if 'ResponseURL' in request and request['ResponseURL']:
        url = urlparse.urlparse(request['ResponseURL'])
        body = json.dumps(response)
        https = httplib.HTTPSConnection(url.hostname)
        https.request('PUT', url.path + '?' + url.query, body)

    return response
