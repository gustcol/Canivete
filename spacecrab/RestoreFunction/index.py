import os
import boto3
import base64
from botocore.exceptions import ClientError
from botocore.client import Config
import psycopg2
import time
import gzip
import json


def lambda_handler(event, context):
    return_value = {}
    backup_bucket = os.environ['BACKUP_BUCKET']
    encrypted_db_password = os.environ.get('ENCRYPTED_MASTER_DATABASE_PASSWORD', None)
    encrypted_db_password = base64.b64decode(encrypted_db_password)
    backup_kms_key_id = os.environ.get('BACKUP_KMS_KEY_ID', None)

    # Decrypt the database password
    kms_client = boto3.client('kms')
    try:
        response = kms_client.decrypt(CiphertextBlob=encrypted_db_password)
        db_password = response['Plaintext']
    except Exception as e:
        pass

    # Connect to the database
    try:
        con = psycopg2.connect(dbname='TokenDatabase',
                               host=os.environ['TOKEN_DATABASE_ADDRESS'],
                               port=os.environ['TOKEN_DATABASE_PORT'],
                               user=os.environ['MASTER_DATABASE_USER'],
                               password=db_password)
        cur = con.cursor()
    except Exception as e:
        return_value['Status'] = 'FAILED'
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value

 

    # Clean up the connection
    try:
        cur.close()
        con.close()
    except Exception as e:
        pass

    return_value['Status'] = 'SUCCESS'
    return_value['Reason'] = 'Token database restored successfully'
    print(json.dumps(return_value))
    return return_value
