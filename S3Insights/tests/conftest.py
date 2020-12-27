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
from boto3.dynamodb.conditions import Key
import botocore
import collections
import json

from moto import mock_cloudformation
from moto import mock_dynamodb2
from moto import mock_s3
from moto import mock_ses
from moto import mock_sqs
from moto import mock_sts
import pytest
import os

from s3insights import initialize
from s3insights.lib import awshelper
from s3insights.lib import athena
from s3insights.lib import ddb
from s3insights.lib import config
from s3insights.lib import s3
from s3insights.lib import ses
from s3insights.lib import utility

TestResources = collections.namedtuple('TestResources', ['table', 'input_parameters', 'source_buckets'])


class TestValues(object):
    test_account_id = '123456789012'
    test_bucket_1_name = 'testbucket1'
    test_bucket_2_name = 'testbucket2'
    regional_inventory_destination_bucket_name = 's3insights-1-dest-123456789012-us-west-2'
    sample_inventory_object_key = '123456789012/us-west-2/testbucket1/s3insights-1-s3-inventory-orc/data/sample.orc'
    sample_inventory_manifest_key = '123456789012/us-west-2/testbucket1/s3insights-1-s3-inventory-orc/manifest/manifest.checksum'


def get_lambda_event(file_name):
    config_file_path = utility.get_file_path(__file__, f'data/{file_name}')
    with open(config_file_path, "r") as config_file:
        config_str = config_file.read()
        return json.loads(config_str)


def get_object_count(bucket_name):
    s3_client = awshelper.get_client(awshelper.ServiceName.s3)
    object_list = s3_client.list_objects_v2(Bucket=bucket_name)
    object_count = object_list['KeyCount']
    return object_count


def find_ddb_bucket(bucket_name, inventory_status):
    ddb_buckets = ddb.get_source_buckets_details(TestValues.test_account_id)
    for ddb_bucket in ddb_buckets:
        ddb_inventory_status = ddb_bucket[ddb.TableFieldName.inventory_status]
        ddb_bucket_name = ddb_bucket[ddb.TableFieldName.sortkey]
        if utility.compare_strings(bucket_name, ddb_bucket_name) and utility.compare_strings(inventory_status, ddb_inventory_status):
            return True
    return False


def db_contains_entry(table, partition_key):
    response = table.query(
        ProjectionExpression="partitionkey",
        KeyConditionExpression=Key('partitionkey').eq(partition_key)
    )
    return response['Count'] > 0


def mock_get_host_aws_session():
    return boto3


def mock_get_session(account_id=None, run_id=None):
    return boto3


def mock_get_client(service_name, region_name=None, account_id=None, run_id=None):
    session = mock_get_session(account_id, run_id)
    if region_name is None:
        region_name = 'us-west-2'
    client = session.client(service_name, region_name)
    return client


def mock_get_resource(service_name, account_id=None, run_id=None):
    session = mock_get_session(account_id, run_id)
    resource = session.resource(service_name, region_name='us-west-2')
    return resource


orig = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == 'StartQueryExecution':
        return {'QueryExecutionId': 'string'}
    elif operation_name == 'GetQueryExecution':
        return {'QueryExecution': {'QueryExecutionId': 'string', 'Status': {'State': 'SUCCEEDED'}, 'Query': 'string', 'ResultConfiguration': {'OutputLocation': 'string'}}, 'ResultSet': {'Rows': [{'Data': [{'VarCharValue': 'string'}, ]}, ]}}
    elif utility.compare_strings(operation_name, 'GetQueryResults'):
        return {'QueryExecution': {'QueryExecutionId': 'string', 'Status': {'State': 'SUCCEEDED'}}, 'ResultSet': {'Rows': [{'Data': [{'VarCharValue': 'string'}, ]}, ]}}
    return orig(self, operation_name, kwarg)


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch):
    monkeypatch.setattr(awshelper.SessionManager, 'get_host_aws_session', mock_get_host_aws_session)
    monkeypatch.setattr(awshelper, 'get_session', mock_get_session)
    monkeypatch.setattr(awshelper, 'get_client', mock_get_client)
    monkeypatch.setattr(awshelper, 'get_resource', mock_get_resource)
    monkeypatch.setattr(ddb.awshelper.SessionManager, 'get_host_aws_session', mock_get_host_aws_session)
    monkeypatch.setattr(ddb.awshelper, 'get_client', mock_get_client)
    monkeypatch.setattr(ddb.awshelper, 'get_resource', mock_get_resource)
    monkeypatch.setattr(ses.ddb.awshelper.SessionManager, 'get_host_aws_session', mock_get_host_aws_session)
    monkeypatch.setattr(ses.ddb.awshelper, 'get_client', mock_get_client)
    monkeypatch.setattr(ses.ddb.awshelper, 'get_resource', mock_get_resource)
    monkeypatch.setattr(botocore.client.BaseClient, '_make_api_call', mock_make_api_call)
    monkeypatch.setattr(config.DeploymentDetails, 'consolidated_inventory_bucket_name', 's3insights-123456789012-consolidated')


@pytest.fixture
def setup_s3_and_ddb(aws_credentials):
    mock_cloudformation().start()
    mock_dynamodb2().start()
    mock_s3().start()
    mock_ses().start()
    mock_sts().start()
    dynamodb_client = awshelper.get_resource(awshelper.ServiceName.dynamodb)
    table = dynamodb_client.create_table(
        TableName=config.DefaultValue.config_table_name,
        KeySchema=[
            {
                'AttributeName': 'partitionkey',
                'KeyType': 'HASH'
            },
            {
                'AttributeName': 'sortkey',
                'KeyType': 'RANGE'
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'partitionkey',
                'AttributeType': 'S'
            },
            {
                'AttributeName': 'sortkey',
                'AttributeType': 'S'
            }

        ]
    )

    s3_client = awshelper.get_client(awshelper.ServiceName.s3)
    s3_client.create_bucket(
        Bucket=TestValues.test_bucket_1_name,
        CreateBucketConfiguration={
            'LocationConstraint': 'us-west-2'})

    s3_client.create_bucket(
        Bucket=TestValues.test_bucket_2_name,
        CreateBucketConfiguration={
            'LocationConstraint': 'us-west-2'})

    body = bytes('hello world', 'utf-8')

    s3_client.put_object(
        Bucket=TestValues.test_bucket_1_name,
        Key='sampleobject',
        Body=body)

    s3_client.create_bucket(
        Bucket=config.DeploymentDetails.consolidated_inventory_bucket_name,
        CreateBucketConfiguration={
            'LocationConstraint': 'us-west-2'})

    index = config.ServiceParameters.iterator_count

    ddb.store_iterator_index(
        config.ServiceParameters.inventory_monitor_iterator_name,
        index)

    yield TestResources(table, None, None)
    mock_sts().stop()
    mock_ses().stop()
    mock_s3().stop()
    mock_dynamodb2().stop()
    mock_cloudformation().stop()


@pytest.fixture
def process_input_parameters_smoke_test(setup_s3_and_ddb):
    event = get_lambda_event("config_smoke_test.json")
    input_parameters = config.parse_input_parameters(event)
    ddb.store_input_parameters(input_parameters)
    yield TestResources(setup_s3_and_ddb.table, input_parameters, None)


@pytest.fixture
def discover_source_buckets_smoke_test(process_input_parameters_smoke_test):
    input_parameters = process_input_parameters_smoke_test.input_parameters
    account_id = input_parameters.accounts[0].id
    source_buckets = s3.get_source_buckets(input_parameters, account_id)
    ddb.store_source_buckets(source_buckets)
    yield TestResources(process_input_parameters_smoke_test.table, process_input_parameters_smoke_test.input_parameters, source_buckets)


@pytest.fixture
def initialize_environment_smoke_test(discover_source_buckets_smoke_test):
    mock_sqs().start()
    queue_arn_parts = config.DeploymentDetails.sqs_arn.split(sep=':')
    queue_name = queue_arn_parts[len(queue_arn_parts) - 1]
    sqs_client = awshelper.get_client(awshelper.ServiceName.sqs)
    sqs_client.create_queue(QueueName=queue_name)
    s3_client = awshelper.get_client(awshelper.ServiceName.s3)
    s3_client.create_bucket(
        Bucket=TestValues.regional_inventory_destination_bucket_name,
        CreateBucketConfiguration={
            'LocationConstraint': 'us-west-2'})

    body = bytes('hello world', 'utf-8')

    s3_client.put_object(
        Bucket=TestValues.regional_inventory_destination_bucket_name,
        Key=TestValues.sample_inventory_object_key,
        Body=body)

    s3_client.put_object(
        Bucket=TestValues.regional_inventory_destination_bucket_name,
        Key=TestValues.sample_inventory_manifest_key,
        Body=body)
    yield discover_source_buckets_smoke_test
    mock_sqs().stop()


@pytest.fixture
def run_analysis(initialize_environment_smoke_test):
    athena.create_resources()
    yield initialize_environment_smoke_test
