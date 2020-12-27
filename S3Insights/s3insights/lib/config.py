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

import os
from typing import List


class AccountDetails(object):
    def __init__(self, id, exclude):
        """ Constructor for creating an instance of Account details

        Arguments:
            object {AccountDetails} -- Object instance
            id {string} -- AWS Account list
            exclude {list(string)} -- List of S3 buckets to exclude
        """
        self.id = id
        self.exclude = exclude

    @classmethod
    def from_json(cls, json_data: dict):
        """ Deserializer for AccountDetails

        Arguments:
            json_data {json} -- AccountDetails object in json serialized format

        Returns:
            AccountDetails -- Deserialized instance of AccountDetails
        """
        return cls(**json_data)


class AthenaQuery(object):
    def __init__(self, name, query):
        """ Constructor for creating an instance of AthenaQuery

        Arguments:
            object {AthenaQuery} -- Instance of AthenaQuery
            name {string} -- Athena query name
            query {string} -- Athena query
        """
        self.name = name
        self.query = query

    @classmethod
    def from_json(cls, json_data: dict):
        """ Deserializer for AthenaQuery

        Arguments:
            json_data {dict} -- AthenaQuery object in json serialized format

        Returns:
            AthenaQuery -- Deserialized instance of AthenaQuery
        """
        return cls(**json_data)


class DefaultValue(object):
    config_table_name = 's3insights_configuration_table'
    sqs_arn = 'arn:aws:sqs:us-east-1:123456789012:s3insights-sqs-consolidate-inventory-files'
    deployment_name = 's3insights'
    consolidated_inventory_bucket_name = 's3insights-123456789012-consolidated'


class DeploymentDetails(object):
    consolidated_inventory_bucket_name = os.environ.get('CONSOLIDATEDINVENTORYBUCKETNAME', DefaultValue.consolidated_inventory_bucket_name)
    sqs_arn = os.environ.get('SQSARN', DefaultValue.sqs_arn)
    config_table_name = os.environ.get('CONFIGURATIONTABLENAME', DefaultValue.config_table_name)
    deployment_name = os.environ.get('DEPLOYMENTNAME', DefaultValue.deployment_name)
    region = os.environ.get('AWS_REGION', 'us-east-1')
    cross_account_role_name = deployment_name + '-cross-account-iam-role'


class ServiceParameters(object):
    iterator_count = 100
    iterator_step = 1
    wait_time_in_seconds = 1800
    wait_time_in_seconds_smoke_test = 60
    inventory_monitor_iterator_name = 'inventory_monitor'
    iterator_key_name = 'iterator'
    iterator_index_key_name = 'index'
    iterator_step_key_name = 'step'
    iterator_continue_key_name = 'continue'
    iterator_wait_time_in_seconds_key_name = 'wait_time_in_seconds'
    iterator_regions_key_name = 'regions'
    iterator_account_ids_key_name = 'account_ids'
    iterator_current_attempt_count_key_ame = 'current_attempt_count'
    max_attempt_count = 20
    consolidated_inventory_s3_folder = 'inventory'
    lambda_timeout_in_minutes = 15
    smoke_test_sleep_time_in_seconds = 45
    buffer_time_after_nventory_completion_in_hours = 6


class S3InsightsInput(object):
    def __init__(self, run_id, accounts: List[AccountDetails], athena_queries: List[AthenaQuery], sender_email_address, recipient_email_addresses, is_smoke_test, athena_database_name, athena_table_name, supported_regions):
        """ Constructor for S3InsightsInput

        Arguments:
            object {S3InsightsInput} -- Instance of S3InsightsInput
            run_id {string} -- run_id for the current Step Function execution
            accounts {List[AccountDetails]} -- List of accounts to include in the analysis
            athena_queries {List[AthenaQuery]} -- List of Athena queries to run once all inventories have been generated
            sender_email_address {[type]} -- Sender email address to use in the welcome email
            recipient_email_addresses {[type]} -- Recipient list for the welcome email
            is_smoke_test {bool} -- Is this a smoke test run?
            athena_database_name {[type]} -- Athena database name
            athena_table_name {[type]} -- Athena table name which would allow us to query the inventory data
            supported_regions {[type]} -- List of supported regions for this analysis
        """
        self.run_id = run_id
        self.accounts = accounts
        self.athena_queries = athena_queries
        self.sender_email_address = sender_email_address
        self.recipient_email_addresses = recipient_email_addresses
        self.is_smoke_test = is_smoke_test
        self.athena_database_name = athena_database_name
        self.athena_table_name = athena_table_name
        self.supported_regions = supported_regions

    @classmethod
    def from_json(cls, json_data: dict):
        """ Deserializer for S3InsightsInput

        Arguments:
            json_data {dict} -- S3InsightsInput object in json serialized format

        Returns:
            S3InsightsInput -- Deserialized instance of S3InsightsInput
        """
        run_id = json_data["run_id"]
        accounts = list(map(AccountDetails.from_json, json_data["accounts"]))
        athena_queries = list(map(AthenaQuery.from_json, json_data["athena_queries"]))
        sender_email_address = json_data["sender_email_address"]
        recipient_email_addresses = json_data["recipient_email_addresses"]
        is_smoke_test = json_data["is_smoke_test"] if "is_smoke_test" in json_data else False
        athena_database_name = json_data["athena_database_name"] if "athena_database_name" in json_data else "s3insights"
        athena_table_name = json_data["athena_table_name"] if "athena_table_name" in json_data else run_id + "inventorytable"
        supported_regions = json_data["supported_regions"] if "supported_regions" in json_data else [
            "ap-south-1",
            "eu-west-3",
            "eu-west-2",
            "eu-west-1",
            "ap-northeast-2",
            "ap-northeast-1",
            "sa-east-1",
            "ca-central-1",
            "ap-southeast-1",
            "ap-southeast-2",
            "eu-central-1",
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2"]
        return cls(
            run_id,
            accounts,
            athena_queries,
            sender_email_address,
            recipient_email_addresses,
            is_smoke_test,
            athena_database_name,
            athena_table_name,
            supported_regions)


def parse_input_parameters(event):
    """ Parse json object into an instance of S3InsightsInput

    Arguments:
        event {json} -- S3InsightsInput object in json serialized format

    Returns:
        S3InsightsInput -- Deserialized instance of S3InsightsInput
    """
    return S3InsightsInput.from_json(event)
