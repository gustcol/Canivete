import os
import boto3
import base64
from botocore.exceptions import ClientError
from botocore.client import Config
import psycopg2
import time
import gzip


def lambda_handler(event, context):
    return_value = {}
    backup_bucket = os.environ['BACKUP_BUCKET']
    file_key = time.strftime("%Y-%m-%d_") + os.urandom(8).encode('hex') + '.csv.gz'
    local_file = '/tmp/' + file_key
    encrypted_db_password = os.environ.get('ENCRYPTED_DATABASE_PASSWORD', None)
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
                               user=os.environ['FUNCTION_DATABASE_USER'],
                               password=db_password)
        cur = con.cursor()
    except Exception as e:
        return_value['Status'] = 'FAILED'
        return_value['Reason'] = e.message
        return return_value

    # Setup the SQL query to export to CSV
    query = '''
            COPY (
                SELECT * FROM token
            ) TO STDOUT WITH CSV HEADER
            '''
    # Export and zip the honey token data
    try:
        with gzip.open(local_file, 'wb') as f:
            cur.copy_expert(query, f)
    except Exception as e:
        return_value['Status'] = 'FAILED'
        return_value['Reason'] = e.message
        return return_value

    # Upload the zip file to S3
    try:
        with open(local_file, mode='rb') as f:
            s3_client = boto3.client('s3', config=Config(signature_version='s3v4'))
            response = s3_client.put_object(
                Bucket=backup_bucket,
                Key=file_key,
                Body=f,
                SSEKMSKeyId=backup_kms_key_id,
                ServerSideEncryption='aws:kms'
            )
    except ClientError as e:
        return_value['Status'] = 'FAILED'
        return_value['Reason'] = e.message
        return return_value

    # Delete local files
    try:
        os.unlink(local_file)
    except Exception as e:
        pass

    # Clean up the connection
    try:
        cur.close()
        con.close()
    except Exception as e:
        pass

    return_value['Status'] = 'SUCCESS'
    return_value['Reason'] = 'Token database backed up successfully'
    return return_value
