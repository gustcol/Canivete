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

import pytest

import conftest

from s3insights.lib import account_iterator
from s3insights.lib import awshelper
from s3insights.lib import athena
from s3insights.lib import ddb
from s3insights.lib import s3
from s3insights.lib import ses
from s3insights.lib import utility


def test_process_input_parameters_smoke_test(process_input_parameters_smoke_test):
    table = process_input_parameters_smoke_test.table
    config_added = conftest.db_contains_entry(table, ddb.TableValueCategory.config)
    print(config_added)
    assert config_added is True


def test_discover_source_buckets_smoke_test(discover_source_buckets_smoke_test):
    table = discover_source_buckets_smoke_test.table
    buckets_added = conftest.db_contains_entry(table, ddb.TableValueCategory.source_bucket)
    assert buckets_added is True


def test_create_destination_buckets(discover_source_buckets_smoke_test):
    input_parameters = discover_source_buckets_smoke_test.input_parameters
    s3.create_inventory_destination_buckets(input_parameters)

    stack_name = s3.get_stack_name(input_parameters.run_id)
    cloudformation_client = awshelper.get_client(
        awshelper.ServiceName.cloudformation,
        'us-west-2')
    details = cloudformation_client.describe_stacks(
        StackName=stack_name,
    )
    current_status = details['Stacks'][0]['StackStatus'].lower()
    assert utility.compare_strings(current_status, 'create_complete') is True

def ses_email_verification_request_helper(input_parameters, verify_sender_email_address, expected_count):
    input_parameters.verify_sender_email_address = verify_sender_email_address
    ses.send_email_verification_requests(input_parameters)
    ses_client = awshelper.get_client(awshelper.ServiceName.ses)
    response = ses_client.list_identities(
        IdentityType='EmailAddress'
    )
    for recipient in input_parameters.recipient_email_addresses:
        assert recipient in response['Identities']
    if verify_sender_email_address:
        assert input_parameters.sender_email_address in response['Identities']



@pytest.mark.parametrize("verify_sender_email_address,expected_count", [
    (False, 1),
    (True, 2)
])
def test_send_ses_email_verification_request(discover_source_buckets_smoke_test, verify_sender_email_address, expected_count):

    input_parameters = discover_source_buckets_smoke_test.input_parameters
    ses_email_verification_request_helper(input_parameters, verify_sender_email_address, expected_count)


def validate_db_resources(table):
    assert conftest.db_contains_entry(table, ddb.TableValueCategory.config) is True


def test_initialize_environment_smoke_test(initialize_environment_smoke_test):
    table = initialize_environment_smoke_test.table
    validate_db_resources(table)
    assert conftest.db_contains_entry(table, ddb.TableValueCategory.source_bucket) is True


def test_if_athena_table_exists(initialize_environment_smoke_test):
    input_parameters = initialize_environment_smoke_test.input_parameters
    exists = athena.does_athena_table_exist(
        input_parameters.run_id,
        input_parameters.athena_database_name,
        input_parameters.athena_table_name)
    assert exists is False


def test_create_inventory_configuration(initialize_environment_smoke_test):
    ddb.update_source_bucket_inventory_status(conftest.TestValues.test_bucket_1_name, ddb.BucketInventoryStatus.inventory_configuration_not_created)
    ddb.update_source_bucket_inventory_status(conftest.TestValues.test_bucket_2_name, ddb.BucketInventoryStatus.inventory_configuration_not_created)
    test_event = {'account_ids': [conftest.TestValues.test_account_id], 'index': 0, 'continue': True}
    account_iterator.iterate(test_event, s3.create_inventory_configuration_helper)
    assert conftest.find_ddb_bucket(conftest.TestValues.test_bucket_1_name, ddb.BucketInventoryStatus.in_progress)
    assert conftest.find_ddb_bucket(conftest.TestValues.test_bucket_2_name, ddb.BucketInventoryStatus.bucket_is_empty)
