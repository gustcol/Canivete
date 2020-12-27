import os
import psycopg2
import base64
import boto3
import json
from dateutil.parser import parse


def lambda_handler(event, context):
    '''
    event = {
        "AccessKeyId": "AKIAEXAMPLEKEY1",
        "Owner": "dgrzelak",
        "location": "Danger Zone",
        "ExpiresAt": null,
        "Notes": "Hello world!"
    }
    '''
    return_value = {}
    return_value['Status'] = 'Failure'
    return_value['Reason'] = ''
    return_value['Function'] = 'UpdateTokenFunction'
    AccessKeyId = event.get('AccessKeyId', None)
    if AccessKeyId is None:
        return_value['Reason'] = 'No AccessKeyId found in event.'
        print(json.dumps(return_value))
        return return_value
    encrypted_db_password = os.environ.get('ENCRYPTED_DATABASE_PASSWORD', None)
    encrypted_db_password = base64.b64decode(encrypted_db_password)
    try:
        kmsclient = boto3.client('kms')
        response = kmsclient.decrypt(CiphertextBlob=encrypted_db_password)
        db_password = response['Plaintext']

    except Exception as e:
        print(e.message)

    try:
        con = psycopg2.connect(dbname='TokenDatabase',
                               host=os.environ['TOKEN_DATABASE_ADDRESS'],
                               port=os.environ['TOKEN_DATABASE_PORT'],
                               user=os.environ['FUNCTION_DATABASE_USER'],
                               password=db_password)
        cur = con.cursor()
    except Exception as e:
        return_value['Status'] = 'Failure'
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value
    try:
        cur.execute('''
                    SELECT
                        AccessKeyId,
                        Owner,
                        Location,
                        ExpiresAt,
                        Notes
                    FROM token
                    WHERE AccessKeyId = %s
                    ''', (AccessKeyId,)
                    )
        if cur.rowcount > 0:
            first_result = cur.fetchone()
            Owner = first_result[1]
            Location = first_result[2]
            ExpiresAt = first_result[3]
            Notes = first_result[4]
        else:
            return_value['Reason'] = 'Unable to locate access key %s in database' % AccessKeyId
            print(json.dumps(return_value))
            return return_value
    except Exception as e:
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value

    Owner = event.get('Owner', Owner)
    Location = event.get('Location', Location)
    ExpiresAt = event.get('ExpiresAt', ExpiresAt)
    Notes = event.get('Notes', Notes)
    if isinstance(ExpiresAt, basestring):
        old_expiresat = ExpiresAt[:]
        try:
            ExpiresAt = parse(ExpiresAt)
        except ValueError as e:
            return_value['Reason'] = 'Unable to parse %s into valid datetime' % old_expiresat
            print(json.dumps(return_value))
            return return_value
    # time to update the database boyee
    try:
        cur.execute('''
                    update
                        token
                    set
                        Owner=%s,
                        Location=%s,
                        ExpiresAt=%s,
                        Notes=%s
                    where
                        AccessKeyId=%s

                    ''',
                    (Owner, Location, ExpiresAt, Notes, AccessKeyId)
                    )
        con.commit()
        cur.close()
        updated_token = {
            "AccessKeyId": AccessKeyId, "Owner": Owner, "Location": Location,
             "Notes": Notes
            }
        if ExpiresAt:
            updated_token['ExpiresAt'] = ExpiresAt.isoformat()
        else:
            updated_token['ExpiresAt'] = None
    except Exception as e:
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value
    return_value['Status'] = 'Success'
    return_value['Reason'] = 'Updated token %s with new values' % AccessKeyId
    return_value['Notes'] = updated_token
    print(json.dumps(return_value))
    return return_value
