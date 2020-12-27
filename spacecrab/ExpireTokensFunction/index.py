import os
import boto3
import base64
import json
from botocore.exceptions import ClientError
import psycopg2


def lambda_handler(event, context):
    return_value = {}
    client = boto3.client('iam')
    expired_count = 0
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
        return_value['Status'] = 'FAILED'
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value

    try:
        cur.execute('''
                    SELECT
                        AccessKeyId,
                        UserName
                    FROM
                        token
                    WHERE
                        Active = TRUE
                    AND
                        ExpiresAt < NOW()
                    '''
                    )
    except Exception as e:
        return_value['Status'] = 'FAILED'
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value

    if cur:
        for row in cur:
            expired_count += expire_token(row[0], row[1], client, con)

    cur.close()
    con.close()

    return_value['Status'] = 'SUCCESS'
    return_value['Reason'] = 'Successfully expired %d token(s)' % expired_count
    print(json.dumps(return_value))
    return return_value


def expire_token(AccessKeyId, UserName, client, con):
    try:
        response = client.delete_access_key(
            UserName=UserName,
            AccessKeyId=AccessKeyId
        )
    except ClientError as e:
        print(e.message)
        return 0

    try:
        # Users have to be removed from groups before they can be deleted
        response = client.remove_user_from_group(
            GroupName=os.environ['TOKEN_GROUP'],
            UserName=UserName
        )
        response = client.delete_user(
            UserName=UserName
        )
    except ClientError as e:
        print(e.message)

    try:
        cur = con.cursor()
        cur.execute('''
                    UPDATE token
                    SET Active=FALSE,
                        DeactivatedAt=NOW()
                    WHERE AccessKeyId=%s
                    ''',
                    (AccessKeyId,)
                    )
        con.commit()
        cur.close()
    except Exception as e:
        print(e.message)
        return 0

    return 1
