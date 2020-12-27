import json
import os
import base64
import boto3
import psycopg2
import psycopg2.extras
import gzip


def lambda_handler(event, context):
    # Each event should only have one record but...
    return_value = {}
    return_value['Status'] = 'FAILED'
    user_records = {}
    sns_topic = os.environ['ALERTING_SNS_TOPIC']
    encrypted_db_password = os.environ.get('ENCRYPTED_DATABASE_PASSWORD', None)
    encrypted_db_password = base64.b64decode(encrypted_db_password)
    try:
        kmsclient = boto3.client('kms')
        response = kmsclient.decrypt(CiphertextBlob=encrypted_db_password)
        db_password = response['Plaintext']

    except Exception as e:
        print(e)
    try:
        con = psycopg2.connect(dbname='TokenDatabase',
                               host=os.environ['TOKEN_DATABASE_ADDRESS'],
                               port=os.environ['TOKEN_DATABASE_PORT'],
                               user=os.environ['FUNCTION_DATABASE_USER'],
                               password=db_password)
        cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    except Exception as e:
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value

    try:
        cur.execute('''
                    SELECT AccessKeyId,
                        UserName,
                        UserArn,
                        Owner,
                        Location,
                        Notes
                    FROM token
                    WHERE Active = true
                    '''
                    )
        if cur.rowcount > 0:
            for row in cur.fetchall():
                user_records[row['accesskeyid']] = row
                user_records[row['username']] = row

    except Exception as e:
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value
    records = []

    for s3_record in event['Records']:
        records.extend(process_s3_record(s3_record, user_records))
    sns = boto3.client('sns')

    for item in records:
        sns.publish(
            TopicArn=sns_topic,
            Message=json.dumps(item)
            )
        print(json.dumps(item))
        # emit to sns


def process_s3_record(s3_record, user_records):
    bucket_name = s3_record['s3']['bucket']['name']
    # bucket_arn = s3_record['s3']['bucket']['arn']
    file_key = s3_record['s3']['object']['key']
    local_file = '/tmp/cloudtrail.json.gz'
    trail = {}
    # Download the CloudTrail file from S3
    try:
        s3 = boto3.resource('s3')
        s3.meta.client.download_file(bucket_name, file_key, local_file)
    except Exception as e:
        print(e)
        return []

    # Decompress the CloudTrail file and load the object
    try:
        with gzip.open(local_file, 'rb') as f:
            trail = json.load(f)
    except Exception as e:
        print(e)
        return []

    try:
        os.unlink(local_file)
    except Exception as e:
        pass
        # oh well. it'll get burned down in a while anyway

    UserNames = set(user_records.keys())
    records = []
    try:
        for trail_record in trail['Records']:
            record = process_trail_record(trail_record, UserNames)
            if record:
                record['alertMetadata'] = user_records.get(record['userToken'], None)
                record.pop('userToken')
                records.append(record)
        return records
    except KeyError:
        return []


def process_trail_record(trail_record, UserNames):
    userid = trail_record['userIdentity']
    usertoken = None
    if userid['type'] == 'IAMUser':
        # iam user, not assumed role
        usertoken = userid.get('accessKeyId', '')
    elif userid['type'] == 'AssumedRole':
        arn = userid.get('arn', None)
        if arn:
            usertoken = arn.split('/')[-1]  # returns username, ideally
    if usertoken in UserNames:
        trail_record['userToken'] = usertoken
        return trail_record
    return


# http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html
# http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
# http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html
