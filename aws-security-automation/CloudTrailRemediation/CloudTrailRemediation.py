'''
Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at
    http://aws.amazon.com/apache2.0/
or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

Attributes:
    LOGTABLE (str): Description
'''
from __future__ import print_function
import boto3

LOGTABLE = "cweCloudTrailLog"


def lambda_handler(event, context):
    """Summary

    Args:
        event (TYPE): Description
        context (TYPE): Description

    Returns:
        TYPE: Description
    """
    # Extract user info from the event
    trailArn = event['detail']['requestParameters']['name']
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
    logData = {'trailArn': trailArn, 'userName': userName, 'userArn': userArn, 'accessKeyId': accessKeyId, 'region': region, 'account': account, 'eventTime': eventTime, 'userAgent': userAgent, 'sourceIP': sourceIP}

    # Priority action
    startTrail(trailArn)

    # Alerting
    result = sendAlert(logData)

    # Forensics
    realTable = verifyLogTable()
    result = forensic(logData, realTable)

    # Logging
    result = logEvent(logData, realTable)
    return result


def verifyLogTable():
    """Verifies if the table name provided is deployed using CloudFormation
       template and thereby have a prefix and suffix in the name.

    Returns:
        The real table name
        TYPE: String
    """
    client = boto3.client('dynamodb')
    resource = boto3.resource('dynamodb')
    table = LOGTABLE

    response = client.list_tables()
    tableFound = False
    for n, _ in enumerate(response['TableNames']):
        if table in response['TableNames'][n]:
            table = response['TableNames'][n]
            tableFound = True

    if not tableFound:
        # Table not created in CFn, let's check exact name or create it
        try:
            result = client.describe_table(TableName=table)
        except:
            # Table does not exist, create it
            newtable = resource.create_table(
                TableName=table,
                KeySchema=[
                    {'AttributeName': 'userName', 'KeyType': 'HASH'},
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'userName', 'AttributeType': 'S'},
                ],
                ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            )
            # Wait for table creation
            newtable.meta.client.get_waiter('table_exists').wait(TableName=table)
    return table


def startTrail(trailArn):
    """Priority action.
       Verifies if the provided trail is running and if not starts it.

    Args:
        trailArn (String): ARN for the triggered trail.

    Returns:
        TYPE: String
    """
    client = boto3.client('cloudtrail')
    response = client.get_trail_status(
        Name=trailArn
    )
    # Check if someone already started the trail
    if response['IsLogging']:
        print "Logging already started"
        return "NoActionNeeded"
    else:
        print "Starting trail: ", trailArn
        response = client.start_logging(
            Name=trailArn
        )
        return "Trail started"


def sendAlert(data):
    """Placeholder for alert functionality.
       This could be Amazon SNS, SMS, Email or adding to a ticket tracking
       system like Jira or Remedy.
       You can also use a separate target using CloudWatch Event for alerts.

    Args:
        data (dict): All extracted event info.

    Returns:
        TYPE: String
    """
    print "No alert"
    return 0


def forensic(data, table):
    """Perform forensic on the resources and details in the event information.
       Example: Look for MFA, previous violations, corporate CIDR blocks etc.
    Args:
        data (dict): All extracted event info.
        table (string): Table name for event history.

    Returns:
        TYPE: String
    """
    # Set remediationStatus to True to trigger remediation function.
    remediationStatus = True

    if remediationStatus:
        # See if user have tried this before.
        client = boto3.client('dynamodb')
        response = client.get_item(
            TableName=table,
            Key={
                'userName': {'S': data['userName']}
            }
        )
        try:
            if response['Item']:
                # If not first time, trigger countermeasures.
                result = disableAccount(data['userName'])
                return result
        except:
            # First time incident, let it pass.
            return "NoRemediationNeeded"


def disableAccount(userName):
    """Countermeasure function that disables the user by applying an
       inline IAM deny policy on the user.
       policy.

    Args:
        userName (string): Username that caused event.

    Returns:
        TYPE: Success
    """
    client = boto3.client('iam')
    response = client.put_user_policy(
        UserName=userName,
        PolicyName='BlockPolicy',
        PolicyDocument='{"Version":"2012-10-17", "Statement":{"Effect":"Deny", "Action":"*", "Resource":"*"}}'
    )
    return 0


def logEvent(logData, table):
    """Log all information to the provided DynamoDB table.

    Args:
        logData (dict): All extracted information
        table (string): Table name for event history.

    Returns:
        TYPE: Success
    """
    client = boto3.client('dynamodb')

    # Store data
    response = client.put_item(
        TableName=table,
        Item={
            'userName': {'S': logData['userName']},
            'eventTime': {'S': logData['eventTime']},
            'userArn': {'S': logData['userArn']},
            'region': {'S': logData['region']},
            'account': {'S': logData['account']},
            'userAgent': {'S': logData['userAgent']},
            'sourceIP': {'S': logData['sourceIP']}
        }
    )
    return 0
