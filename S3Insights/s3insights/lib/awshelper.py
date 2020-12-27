#   Copyright 2020 Ashish Kurmi
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License

import boto3
from boto3.session import Session

from lib import config

class ServiceName(object):
    """ Names for various AWS services used in the platform
    """
    s3 = 's3'
    cloudformation = 'cloudformation'
    ses = 'ses'
    dynamodb = 'dynamodb'
    athena = 'athena'
    sqs = 'sqs'
    sts = 'sts'


class SessionManager(object):
    """ AWS IAM session manager
    """
    def __init__(self, account_id, role_name, run_id):
        """ Constructor for creating an instance of SessionManager

        Arguments:
            object {SessionManager} -- instance of the class
            account_id {string} -- AWS account id
            role_name {string} -- IAM role to assume in case of cross account access
            run_id {string} -- run_id for the current Step Function execution
        """
        self.account_id = account_id
        self.role_name = role_name
        self.run_id = run_id

    @staticmethod
    def get_host_account_id():
        """ Discover AWS account id for the host account

        Returns:
            string -- AWS account id
        """
        sts_client = boto3.client(ServiceName.sts)
        response = sts_client.get_caller_identity()
        account_id = response['Account']
        return account_id

    @staticmethod
    def get_host_aws_session():
        """ Create an AWS session for the host account

        Returns:
            Session -- AWS Session
        """
        return Session()

    def get_session(self):
        """ Create an AWS session

        Returns:
            Session -- AWS Session
        """
        session = None
        if self.account_id != SessionManager.get_host_account_id():
            role_info = {
                'RoleArn': 'arn:aws:iam::{0}:role/{1}'.format(self.account_id, self.role_name),
                'RoleSessionName': 's3-insights-{0}-session'.format(self.run_id)
            }
            client = boto3.client('sts')
            credentials = client.assume_role(**role_info)
            session = Session(
                aws_access_key_id=credentials['Credentials']['AccessKeyId'],
                aws_secret_access_key=credentials['Credentials']['SecretAccessKey'],
                aws_session_token=credentials['Credentials']['SessionToken']
            )
        else:
            session = Session()

        return session


def get_session(account_id=None, run_id=None):
    """ Create and return an AWS session

    Keyword Arguments:
        account_id {string} -- AWS account id (default: host account)
        run_id {string} -- run_id for the current Step Function execution (required only for non-host accounts)

    Returns:
        Session -- AWS Session
    """
    if account_id is None:
        session = SessionManager.get_host_aws_session()
    else:
        session_manager = SessionManager(
            account_id,
            config.DeploymentDetails.cross_account_role_name,
            run_id)

        session = session_manager.get_session()
    return session


def get_client(service_name, region_name=None, account_id=None, run_id=None):
    """ Return a Boto3 client

    Arguments:
        service_name {string} -- AWS service name

    Keyword Arguments:
        region_name {string} -- AWS region name (default: {None})
        account_id {string} -- AWS account id (default: {None})
        run_id {string} -- run_id for the current Step Function execution (default: {None})

    Returns:
        boto3.client -- An instance of Boto3 client
    """
    session = get_session(account_id, run_id)
    if region_name is None:
        client = session.client(service_name)
    else:
        client = session.client(service_name, region_name)
    return client


def get_resource(service_name, account_id=None, run_id=None):
    """ Create an instance of Boto3 resource

    Arguments:
        service_name {string} -- AWS service name

    Keyword Arguments:
        account_id {string} -- AWS account id (default: {None})
        run_id {string} -- run_id for the current Step Function execution (default: {None})

    Returns:
        [type] -- [description]
    """
    session = get_session(account_id, run_id)
    resource = session.resource(service_name)
    return resource
