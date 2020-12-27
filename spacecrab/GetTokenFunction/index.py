import os
import boto3
from botocore.exceptions import ClientError
import psycopg2
import json
import base64


def lambda_handler(event, context):
    lambda_client = boto3.client('lambda')
    Owner = event['params']['querystring']['Owner']
    Location = event['params']['path']['Location']
    return_value = {}
    return_value['Status'] = 'FAILED'
    return_value['Function'] = 'GetTokenFunction'
    encrypted_db_password = os.environ.get('ENCRYPTED_DATABASE_PASSWORD', None)
    encrypted_db_password = base64.b64decode(encrypted_db_password)

    try:
        # get encrypted secrets
        kmsclient = boto3.client('kms')
        response = kmsclient.decrypt(CiphertextBlob=encrypted_db_password)
        db_password = response['Plaintext']
    except Exception as e:
        print(e.message)

    try:
        # connect to db
        con = psycopg2.connect(dbname='TokenDatabase',
                               host=os.environ['TOKEN_DATABASE_ADDRESS'],
                               port=os.environ['TOKEN_DATABASE_PORT'],
                               user=os.environ['FUNCTION_DATABASE_USER'],
                               password=db_password)
        cur = con.cursor()
    except Exception as e:
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value

    try:
        # check for existing token
        cur.execute('''
                    SELECT AccessKeyId,
                        SecretAccessKey,
                        UserName,
                        UserArn,
                        Owner,
                        Location,
                        ExpiresAt,
                        Notes
                    FROM
                        token
                    WHERE
                        Location = %s AND
                        Owner = %s;
                    ''',
                    (Location, Owner)
                    )
        if cur.rowcount > 0:
            # we've got a token
            record = cur.fetchone()
            AccessKey = {}
            AccessKey['AccessKeyId'] = record[0]
            AccessKey['SecretAccessKey'] = record[1]
            AccessKey['UserName'] = record[2]
            return_value['AccessKey'] = AccessKey
            Notes = {}
            Notes['Owner'] = record[4]
            Notes['Location'] = record[5]
            Notes['ExpiresAt'] = record[6]
            Notes['Notes'] = record[7]
            return_value['Notes'] = Notes
            User = {}
            User['Arn'] = record[3]
            User['UserName'] = record[2]
            try:
                User['Path'] = '/' + User['Arn'].split(':')[-1].split('/')[1] + '/'
            except:
                pass
            return_value['User'] = User
            return_value['Status'] = 'SUCCESS'
            # dirty hack to not log secret keys
            SecretAccessKey = return_value["AccessKey"].pop("SecretAccessKey", None)
            print(json.dumps(return_value))
            return_value["AccessKey"]["SecretAccessKey"] = SecretAccessKey
            return return_value
        else:
            # no token, let's make one:
            payload = {}
            payload['Owner'] = Owner
            payload['Location'] = Location
            response = lambda_client.invoke(
                FunctionName='AddTokenFunction',
                Payload=json.dumps(payload)
                )
            return json.load(response['Payload'])

    except ClientError as e:
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value
