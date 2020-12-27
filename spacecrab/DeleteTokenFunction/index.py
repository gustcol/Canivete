import os
import base64
import boto3
from botocore.exceptions import ClientError
import psycopg2
from datetime import datetime


def lambda_handler(event, context):

    return_value = {}
    client = boto3.client('iam')
    AccessKeyId = event.get('AccessKeyId', None)
    if not AccessKeyId:
        return_value['Status'] = 'FAILED'
        return_value['Reason'] = 'No AccessKeyId provided'
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
        print(e.message)
        return_value['Status'] = 'FAILED'
        return_value['Reason'] = e.message
        return return_value
    # need to retrieve username from database to delete key, for some reason
    try:
        cur.execute('''
                    SELECT
                        AccessKeyId,
                        UserName,
                        Active,
                        DeactivatedAt
                    FROM token
                    WHERE AccessKeyId = %s
                    ''', (AccessKeyId,)
                    )
        if cur.rowcount > 0:
            firstResult = cur.fetchone()
            UserName = firstResult[1]
            Active = firstResult[2]
            DeactivatedAt = firstResult[3]
        else:
            return_value['Status'] = 'FAILED'
            return_value['Reason'] = 'Unable to locate AccessKeyId %s in database' % AccessKeyId
            return return_value
    except Exception as e:
        print(e)
        return_value['Status'] = 'FAILED'
        return_value['Reason'] = e.message
        return return_value
    # assuming delete_access_key always works, and we only get errors if the key doesn't exist
    # anymore. risky business! Not a sponsored comment.
    try:
        response = client.delete_access_key(
            UserName=UserName,
            AccessKeyId=AccessKeyId
        )
        if Active:
            DeactivatedAt = datetime.utcnow()
            Active = False
    except ClientError as e:
        print(e.message)

    try:
        response = client.remove_user_from_group(
            GroupName=os.environ['TOKEN_GROUP'],
            UserName=UserName
        )
        response = client.delete_user(
            UserName=UserName
        )
    except ClientError as e:
        print(e.message)

    cur.execute('''
                UPDATE token
                SET Active=%s,
                    DeactivatedAt=%s
                WHERE AccessKeyId=%s
                ''',
                (Active, DeactivatedAt, AccessKeyId)
                )
    con.commit()
    cur.close()
    return_value['Status'] = 'SUCCESS'
    return_value['Reason'] = 'Successfully deleted %s and marked as deactivated in db' % AccessKeyId  # noqa
    print(return_value)
    return return_value
