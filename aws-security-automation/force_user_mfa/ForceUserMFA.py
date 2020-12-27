"""
Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at
    http://aws.amazon.com/apache2.0/
or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

Summary

Attributes:
    createPassword (bool): Description
    IAM_CLIENT (TYPE): Description
"""
from __future__ import print_function
from base64 import b64encode
import json
import hmac
import struct
import base64
import hashlib
import time
import sys
import boto3


# Do you want to create a randomized password for the user?
createPassword = False

# Do you want to delete the user if MFA assignment failed?
deleteOnFail = False

# Log data to DynamoDB?
logActions = True
DynamoDBtable = "userMFA"

# Central clients
IAM_CLIENT = boto3.client('iam')


def lambda_handler(event, context):
    """Summary

    Args:
        event (TYPE): Description
        context (TYPE): Description

    Returns:
        TYPE: Description
    """
    logdata = create_log_data(event)
    mfaFail = False

    # Verify if user is approved to create new IAM users
    approved = check_approved(logdata['userName'], logdata['userArn'])
    if approved is False:
        if deleteOnFail is True:
            deleteUser(logdata['newUserName'], logdata['serialNumber'])
            print("IAM user " + logdata['userName'] + " not allowed to create users.\nUser " + logdata['newUserName'] + " deleted.")
            sys.exit()
        print("IAM user " + logdata['userName'] + " not allowed to create users.\nUser " + logdata['newUserName'] + " not deleted.")

    # Create virtual MFA
    mfa = create_virtual_mfa(logdata['newUserName'], logdata['newUserArn'])

    # Verify MFA is created and get seed
    if "SerialNumber" in str(mfa):
        logdata['serialNumber'] = mfa['VirtualMFADevice']['SerialNumber']
        seed = mfa['VirtualMFADevice']['Base32StringSeed']
        enableResult = ""
        i = 1
        while enableResult != "Success":
            enableResult = enable_mfa(logdata['newUserName'], logdata['serialNumber'], seed)
            time.sleep(i)
            i += 1
            if i == 10:
                print("MFA Creation failed, aborting")
                mfaFail = True
                if deleteOnFail is True:
                    deleteUser(logdata['newUserName'], logdata['serialNumber'])
                    print("Token creation failed, aborting.\nUser " + logdata['newUserName'] + " deleted.")
                    sys.exit()
                else:
                    print("Token creation failed, aborting.\nUser " + logdata['newUserName'] + " not deleted.")
                    sys.exit()
        print("Seed created")
    else:
        if deleteOnFail is True:
            deleteUser(logdata['newUserName'], logdata['serialNumber'])
            print("Token creation failed, aborting.\nUser " + logdata['newUserName'] + " deleted.")
            sys.exit()
        else:
            print("Token creation failed, aborting.\nUser " + logdata['newUserName'] + " not deleted.")
            sys.exit()

    # Encrypt the seed using aKMS CMK alias MFAUser.
    encryptedSeed = encrypt_string(mfa['VirtualMFADevice']['Base32StringSeed'])

    # Send seed number to user to allow adding it to tokens, can use QR but easier tracking with text.
    send_seed(encryptedSeed)

    # Add encrypted seed to logdata
    logdata['encryptedSeed'] = str(encryptedSeed)

    # Set randomized password if module is enabled
    if createPassword:
        logdata['encryptedPass'] = generate_password(logData[userName])

    # Store seed in parameter store for user to fetch
    store_mfa(logdata['newUserName'], mfa['VirtualMFADevice']['Base32StringSeed'], logdata['region'], logdata['account'])

    # Logging
    if logActions is True:
        result = log_event(logdata)

    print("MFA Created for user " + logdata['newUserName'] + ". Users can retrieve the seed themselves from Parameter Store using:")
    print("aws ssm get-parameters --names mfa-" + logdata['newUserName'] + " --with-decryption  --region " + logdata['region'])
    return 0


def create_log_data(event):
    """Summary

    Args:
        event (TYPE): Description

    Returns:
        TYPE: Description
    """
    # Extract used info
    try:
        userName = event['detail']['userIdentity']['userName']
    except KeyError:
        # User is federated/assumeRole
        userName = event['detail']['userIdentity']['sessionContext']['sessionIssuer']['userName']
    userArn = event['detail']['userIdentity']['arn']
    accessKeyId = event['detail']['userIdentity']['accessKeyId']
    region = event['region']
    account = event['account']
    eventTime = event['detail']['eventTime']
    userAgent = event['detail']['userAgent']
    sourceIP = event['detail']['sourceIPAddress']
    newUserName = event['detail']['responseElements']['user']['userName']
    newUserArn = event['detail']['responseElements']['user']['arn']
    logData = {}
    logData = {'userName': userName, 'userArn': userArn, 'accessKeyId': accessKeyId, 'region': region, 'account': account, 'eventTime': eventTime, 'userAgent': userAgent, 'sourceIP': sourceIP, 'newUserName': newUserName, 'newUserArn': newUserArn}
    return logData


def mfa_store_policy(user, region, account):
    # Let's try and attach the policy if it's created by the CFN template
    try:
        IAM_CLIENT.attach_user_policy(
            UserName=user,
            PolicyArn='arn:aws:iam::' + account + ':policy/user_mfa_access'
        )
    # If failed we need to create the policy and attach the new one
    except:
        KMS_CLIENT = boto3.client('kms')
        response = KMS_CLIENT.describe_key(
            KeyId='alias/MFAUser',
        )
        keyArn = response['KeyMetadata']['Arn']
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ssm:GetParameters"
                    ],
                    "Resource": "arn:aws:ssm:" + region + ":" + account + ":parameter/mfa-${aws:username}"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "kms:Decrypt"
                    ],
                    "Resource": keyArn
                }
            ]
        }
        response = IAM_CLIENT.create_policy(
            PolicyName='user_mfa_access',
            PolicyDocument=json.dumps(policy),
            Description='User policy for MFA token access'
        )
        IAM_CLIENT.attach_user_policy(
            UserName=user,
            PolicyArn='arn:aws:iam::' + account + ':policy/user_mfa_access'
        )
    return 0


def store_mfa(user, seed, region, account):
    SSM_CLIENT = boto3.client('ssm')
    KMS_CLIENT = boto3.client('kms')
    response = KMS_CLIENT.describe_key(
        KeyId='alias/MFAUser',
    )
    keyArn = response['KeyMetadata']['Arn']
    try:
        response = SSM_CLIENT.put_parameter(
            Name='mfa-' + user,
            Description='MFA token seed',
            Value=seed,
            Type='SecureString',
            KeyId=keyArn,
            Overwrite=True
        )
        mfa_store_policy(user, region, account)
        print("Token stored in Parameter Store")
    except Exception as e:
        print("Failed to store seed. You will need to retrieve it from the used log DDB or create a new token manually.")
        response = "Fail"
    return response


def create_virtual_mfa(newUserName, newUserArn):
    """Summary

    Args:
        newUserName (TYPE): Description
        newUserArn (TYPE): Description

    Returns:
        TYPE: Description
    """
    print("Creating virtual MFA token")
    deviceName = newUserName + '-MFA'
    # Try to delete token first to avoid conflict/stale tokens
    try:
        deviceArn = newUserArn + '-MFA'
        response = IAM_CLIENT.delete_virtual_mfa_device(
            SerialNumber=deviceArn
        )
    except:
        pass
    # Try to create new token, we will try 5 times before giving up
    tries = 0
    while tries < 5:
        try:
            response = IAM_CLIENT.create_virtual_mfa_device(
                VirtualMFADeviceName=deviceName
            )
            break
    # Try one more time if fails, could be race issue with delete
        except:
            time.sleep(tries + 1)
            response = str(sys.exc_info()[0])
    if "SerialNumber" in str(response):
        return response
    else:
        return "FailedToCreateToken"


def deleteUser(userName, SN):
    try:
        response = client.deactivate_mfa_device(
            UserName=userName,
            SerialNumber=SN
        )
        print("MFA device deactivated, trying to delete device.")
    except:
        print("Unable to deactivate MFA token. Could be that it's not created.")
    try:
        response = client.delete_virtual_mfa_device(
            SerialNumber=SN
        )
        print("MFA device deleted, trying to delete new user.")
    except:
        print("Unable to delete MFA token. Could be that it's not created.")
    try:
        response = client.delete_user(
            UserName=userName
        )
        print("User deleted")
    except:
        print("Unable to delete user: " + userName)
    return True


def enable_mfa(userName, mfaArn, seed):
    """Summary

    Args:
        userName (TYPE): Description
        mfaArn (TYPE): Description
        seed (TYPE): Description

    Returns:
        TYPE: Description
    """
    # Get token 1
    token1 = generate_token(seed)
    x = 0
    fail = False
    while (len(str(token1)) != 6):
        token1 = generate_token(seed)
        time.sleep(5)
        x = x + 1
        if x > 20:
            fail = True
            break
    if fail:
        print("Token1 creation failed. Token1 = " + str(token1))
        return "token1 fail"

    # Get token 2
    time.sleep(5)
    token2 = generate_token(seed)
    x = 0
    fail = False
    while (token1 == token2) or (len(str(token2)) != 6):
        time.sleep(5)
        token2 = generate_token(seed)
        x = x + 1
        if x > 20:
            fail = True
            break
    if fail:
        print("Token2 creation failed. Token1 = " + str(token2))
        return "token2 fail"
    print("Token enabled")

    # Attach to user
    try:
        response = IAM_CLIENT.enable_mfa_device(
            UserName=userName,
            SerialNumber=mfaArn,
            AuthenticationCode1=str(token1),
            AuthenticationCode2=str(token2)
        )
    except:
        response = str(sys.exc_info()[0])
        print("Attach to user failed for user: " + userName)
        print("Will try 10 times")
        print(response)
    else:
        response = "Success"
        print("Token assigned to user: " + userName)
    return response


def generate_password(newUserName):
    """Summary

    Args:
        newUserName (TYPE): Description

    Returns:
        TYPE: Description
    """
    N = 17
    pwd = ''.join(random.SystemRandom().choice(string.ascii_letters + '!@#$%^&*()_+-=[]\{\}|\'' + string.digits) for _ in range(N))
    iam_resource = boto3.resource('iam')
    user = iam_resource.User(newUserName)
    login_profile = user.create_login_profile(
        Password=pwd,
        PasswordResetRequired=True
    )
    pwd = ""
    return 0


def generate_token(seed):
    """Summary

    Args:
        seed (TYPE): Description

    Returns:
        TYPE: Description
    """
    seed = base64.b32decode(seed, True)
    hmacHash = hmac.new(
        seed, struct.pack(
            ">Q", int(
                time.time() // 30)),
        hashlib.sha1).digest()
    hashOffset = ord(hmacHash[19]) & 0xf
    token = (struct.unpack(
        ">I",
        hmacHash[hashOffset:hashOffset + 4])[0] & 0x7fffffff) % 10 ** 6
    return token


def check_approved(userName, userArn):
    """Summary

    Args:
        userName (TYPE): Description
        userArn (TYPE): Description

    Returns:
        TYPE: Description
    """
    # Default
    approved = False

    # Connect change record DDB

    # Check if approved for adding users

    # Check how many users added

    # Determine if account should be locked

    approved = True
    return approved


def encrypt_string(value):
    """Summary

    Args:
        value (TYPE): Description

    Returns:
        TYPE: Description
    """
    # Encrypt using AWS Key Management Service
    KMS_CLIENT = boto3.client('kms')
    try:
        encryptedString = b64encode(
            KMS_CLIENT.encrypt(
                KeyId='alias/MFAUser', Plaintext=value
            )['CiphertextBlob'])
    except:
        print("Failed to encrypt seed, no key with alias MFAUser.\nSeed will not be stored in logs.")
        encryptedString = "Failed to encrypt using KMS CMK alias MFAUser, seed will not be stored."
    return encryptedString


def send_seed(encryptedSeed):
    """Summary

    Args:
        encryptedSeed (TYPE): Description

    Returns:
        TYPE: Description
    """
    # Send to DDB or alternative recipient using for example SNS.
    # Note that sending over unecnrypted protocols/methods is not recomended.
    # This script also uses Parameter Store for per user access
    result = "Using DDB and Parameter Store"
    return result


def log_event(logData):
    """Summary

    Args:
        logData (TYPE): Description

    Returns:
        TYPE: Description
    """
    client = boto3.client('dynamodb')
    resource = boto3.resource('dynamodb')

    # Verify that the table exists
    tableExists = False
    try:
        result = client.describe_table(TableName=DynamoDBtable)
        tableExists = True
    except:
        # Table does not exist, create it
        table = resource.create_table(
            TableName=DynamoDBtable,
            KeySchema=[
                {'AttributeName': 'userName', 'KeyType': 'HASH'},
                {'AttributeName': 'eventTime', 'KeyType': 'RANGE'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'userName', 'AttributeType': 'S'},
                {'AttributeName': 'eventTime', 'AttributeType': 'S'}
            ],
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
        )

        # Wait for table creation
        table.meta.client.get_waiter('table_exists').wait(TableName=DynamoDBtable)
        tableExists = True

    response = client.put_item(
        TableName=DynamoDBtable,
        Item={
            'userName': {'S': logData['newUserName']},
            'userArn': {'S': logData['newUserArn']},
            'encryptedSeed': {'S': logData['encryptedSeed']},
            'callerUserName': {'S': logData['userName']},
            'callerUserArn': {'S': logData['userArn']},
            'callerAccessKeyId': {'S': logData['accessKeyId']},
            'region': {'S': logData['region']},
            'account': {'S': logData['account']},
            'eventTime': {'S': logData['eventTime']},
            'userAgent': {'S': logData['userAgent']},
            'sourceIP': {'S': logData['sourceIP']}
        }
    )
    return 0
