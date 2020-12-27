import os
import boto3
from botocore.exceptions import ClientError
import psycopg2
import json
import base64
from dateutil.parser import parse


def get_available_user(path=None):
    iam = boto3.client('iam')
    for user in list_users(path):
        # check for token counts, if too many, bail:
        try:
            response = iam.list_access_keys(UserName=user['UserName'])
            if len(response['AccessKeyMetadata']) >= 2:
                continue
            else:
                return user
        except ClientError as e:
            pass


def list_users(path=None):
    iam = boto3.client('iam')
    if path is None:
        path = os.environ.get('HONEY_TOKEN_USER_PATH', '/')
    # there has to be a better way to initialise paginated API calls but idk what it is.
    response = iam.list_users(PathPrefix=path)
    is_truncated = response['IsTruncated']
    marker = response.get('Marker', None)
    users = response['Users']
    for user in users:
        yield user
    while is_truncated:
        response = iam.list_users(PathPrefix=path, Marker=marker)
        is_truncated = response['IsTruncated']
        marker = response.get('Marker', None)
        users = response['Users']
        for user in users:
            yield user


def lambda_handler(event, context):
    honey_path = os.environ['HONEY_TOKEN_USER_PATH']
    token_group = os.environ['TOKEN_GROUP']
    generate_username_function_arn = os.environ['GENERATE_USERNAME_FUNCTION_ARN']
    lambda_client = boto3.client('lambda')
    client = boto3.client('iam')
    AccessKeyId = None
    SecretAccessKey = None
    Owner = event.get('Owner', None)
    Location = event.get('Location', None)
    ExpiresAt = event.get('ExpiresAt', None)
    Notes = event.get('Notes', None)
    return_value = {}
    return_value['Status'] = 'FAILED'
    return_value['Function'] = 'AddTokenFunction'
    if ExpiresAt and isinstance(ExpiresAt, basestring):
        try:
            ExpiresAt = parse(ExpiresAt)
        except ValueError as e:
            ExpiresAt = None

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
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value

    # Try and generate a custom username
    try:
        response = lambda_client.invoke(FunctionName=generate_username_function_arn)
        if(response.get('StatusCode') == 200):
            returned_data = json.loads(response['Payload'].read())
            user = returned_data['UserName']
    except Exception as e:
        print(e.message)
        user = os.urandom(16).encode('hex')

    try:
        response = client.create_user(
            Path=honey_path,
            UserName=user
        )
        response['User']['CreateDate'] = response['User']['CreateDate'].isoformat()
        return_value['User'] = response['User']
        UserArn = response['User']['Arn']
        user = response['User']['UserName']
    except ClientError as e:
        print(e.message)
        # It's reasonably plausible we've run out of IAM users, by now.
        # So let's go through them and find one we can add a new key to.
        user_blob = get_available_user(honey_path)
        if user_blob is None:
            print('Unable to locate user with space to add tokens')
            return_value['Reason'] = 'Unable to locate user with space to add tokens - please @ AWS'
            return_value['Reason'] += ' to increase your IAM user limit or delete some.'
            return return_value
        # else assume everything is fine it's fiiine
        UserArn = user_blob['Arn']
        user = user_blob['UserName']
        user_blob['CreateDate'] = user_blob['CreateDate'].isoformat()
        return_value['User'] = user_blob

    try:
        response = client.add_user_to_group(
            GroupName=token_group,
            UserName=user
        )
    except ClientError as e:
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value

    try:
        response = client.create_access_key(
            UserName=user
        )
        AccessKeyId = response['AccessKey']['AccessKeyId']
        SecretAccessKey = response['AccessKey']['SecretAccessKey']
        response['AccessKey']['CreateDate'] = response['AccessKey']['CreateDate'].isoformat()
        return_value['AccessKey'] = response['AccessKey']
    except ClientError as e:
        return_value['Reason'] = e.message
        print(json.dumps(return_value))
        return return_value

    # Insert new token entry into the TokenDatabase
    try:
        cur.execute('''
                INSERT INTO token (
                  AccessKeyId,
                  SecretAccessKey,
                  UserName,
                  UserArn,
                  Owner,
                  Location,
                  ExpiresAt,
                  Notes
                ) VALUES (
                  %s, %s, %s, %s, %s, %s , %s, %s
                );
        ''', (
            AccessKeyId,
            SecretAccessKey,
            user,
            UserArn,
            Owner,
            Location,
            ExpiresAt,
            Notes
        ))
        con.commit()
        con.close()
    except Exception as e:
        message = '\n'
        try:
            client.delete_access_key(AccessKeyId=AccessKeyId)
        except ClientError as e:
            message += 'Unable to delete access key %s\n' % AccessKeyId
        try:
            client.delete_user(UserName=user)
        except ClientError as e:
            message += 'Unable to delete user %s\n' % user

        message = e.message + message
        return_value['Reason'] = message
        return return_value
    created_token = {
        "AccessKeyId": AccessKeyId, "user": user, "Owner": Owner,
        "Location": Location, "Notes": Notes
    }
    if ExpiresAt:
        created_token['ExpiresAt'] = ExpiresAt.isoformat()
    else:
        created_token['ExpiresAt'] = None
    return_value['Notes'] = created_token
    return_value['Status'] = 'SUCCESS'
    # dirty hack to not log secret keys
    SecretAccessKey = return_value["AccessKey"].pop("SecretAccessKey", None)
    print(json.dumps(return_value))
    return_value["AccessKey"]["SecretAccessKey"] = SecretAccessKey
    return return_value
