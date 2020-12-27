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

from boto3.dynamodb.conditions import Key, Attr
import collections
from decimal import Decimal
from datetime import datetime
import logging
import json

from lib import awshelper
from lib import config
from lib import utility

class BucketInventoryStatus(object):
    inventory_configuration_not_created = 'inventory_configuration_not_created'
    in_progress = 'in_progress'
    done = 'done'
    bucket_not_available = 'bucket_not_available'
    bucket_is_empty = 'bucket_is_empty'
    bucket_access_lost = 'bucket_access_lost'


class TableFieldName(object):
    partitionkey = 'partitionkey'
    sortkey = 'sortkey'
    account_id = 'account_id'
    region = 'region'
    inventory_status = 'inventory_status'
    field_value = 'field_value'
    name = 'name'
    change_timestamp = 'change_timestamp'


class TableValueCategory(object):
    source_bucket = 'source_bucket'
    config = 'config'
    input_parameters = 'input_parameters'
    athena_query = 'athena_query'
    iterator = 'iterator'
    manual_cleanup = 'manual_cleanup'


def get_table():
    """ Get the configuration DynamoDB table

    Returns:
        boto3.DynamoDB.Table -- DynamoDB table client
    """
    table_name = config.DeploymentDetails.config_table_name
    dynamodb_resource = awshelper.get_resource(awshelper.ServiceName.dynamodb)
    return dynamodb_resource.Table(table_name)


def store_input_parameters(input_parameters):
    """ Store execution input parameters in the configuration table

    Arguments:
        input_parameters {config.S3InsightsInput} -- Execution input parameters
    """
    table = get_table()
    table.put_item(
        Item={
                TableFieldName.partitionkey: TableValueCategory.config,
                TableFieldName.sortkey: TableValueCategory.input_parameters,
                TableFieldName.field_value: json.dumps(input_parameters, default=lambda input_parameters: input_parameters.__dict__)
            }
        )


def get_input_parameters():
    """ Get execution input parameters from the configuration table

    Returns:
        config.S3InsightsInput -- Execution input parameters
    """
    table = get_table()
    response = table.get_item(
        Key={
                TableFieldName.partitionkey: TableValueCategory.config,
                TableFieldName.sortkey: TableValueCategory.input_parameters,
            }
        )
    return config.parse_input_parameters(json.loads(response['Item'][TableFieldName.field_value]))

def store_source_buckets(source_buckets):
    """ Store source buckets in the configuration table

    Arguments:
        source_buckets {dict<string, dict<string, list(string)>>} -- Source buckets
    """
    table = get_table()

    with table.batch_writer() as batch:
        for account_id in source_buckets:
            for region in source_buckets[account_id]:
                for bucket in source_buckets[account_id][region]:
                    batch.put_item(
                        Item={
                            TableFieldName.partitionkey: TableValueCategory.source_bucket,
                            TableFieldName.sortkey: bucket,
                            TableFieldName.account_id: account_id,
                            TableFieldName.region: region,
                            TableFieldName.inventory_status: BucketInventoryStatus.inventory_configuration_not_created,
                            TableFieldName.change_timestamp : Decimal(0)
                        }
                    )


SourceBucketDDBAttributes = collections.namedtuple(
    'SourceBucketDDBAttributes', 'name inventory_status')


def get_source_buckets(account_id_param = None):
    """ Get source buckets from the configuration table

    Keyword Arguments:
        account_id_param {string} -- AWS account id (default: {None})

    Returns:
        dict<string, dict<string, list(string)>> -- Source buckets
    """
    table = get_table()
    if account_id_param is None:
        response = table.query(
            KeyConditionExpression=Key(TableFieldName.partitionkey).eq(TableValueCategory.source_bucket)
        )
    else:
        response = table.query(
            KeyConditionExpression=Key(TableFieldName.partitionkey).eq(TableValueCategory.source_bucket),
            FilterExpression=Attr(TableFieldName.account_id).eq(account_id_param)
        )
    source_buckets = {}

    for item in response['Items']:
        account_id = item[TableFieldName.account_id]
        region = item[TableFieldName.region]
        name = item[TableFieldName.sortkey]

        if account_id not in source_buckets:
            source_buckets[account_id] = {}

        if region not in source_buckets[account_id]:
            source_buckets[account_id][region] = []

        source_buckets[account_id][region].append(SourceBucketDDBAttributes(name, item[TableFieldName.inventory_status]))

    return source_buckets


def store_athena_queries(query_execution_details):
    """ Store athena queries in the configuration table

    Arguments:
        query_execution_details {dict<string, string>} -- Query details
    """
    table = get_table()

    with table.batch_writer() as batch:
        for execution_id in query_execution_details:
            query_details = query_execution_details[execution_id]
            batch.put_item(
                Item={
                    TableFieldName.partitionkey: TableValueCategory.athena_query,
                    TableFieldName.sortkey: execution_id,
                    TableFieldName.name: query_details.name,
                    TableFieldName.field_value: query_details.query
                }
            )

AthenaDetails = collections.namedtuple(
    'AthenaDetails',
    'query_execution_id query_name query outputlocation state actual_query')

def get_athena_queries():
    """ Get Athena queries from the configuration table

    Returns:
        list(AthenaDetails) -- Athena query details
    """
    table = get_table()
    response = table.query(
        KeyConditionExpression=Key(TableFieldName.partitionkey).eq(TableValueCategory.athena_query)
    )
    details = []
    athena_client = awshelper.get_client(awshelper.ServiceName.athena)
    for item in response['Items']:
        query_execution_id = item[TableFieldName.sortkey]
        get_query_execution_response = athena_client.get_query_execution(QueryExecutionId=query_execution_id)
        query_execution_result = get_query_execution_response['QueryExecution']
        s3_output_location = query_execution_result['ResultConfiguration']['OutputLocation']
        execution_state = query_execution_result['Status']['State']
        actual_query = query_execution_result['Query']
        details.append(AthenaDetails(query_execution_id,
                                     item[TableFieldName.name],
                                     item[TableFieldName.field_value],
                                     s3_output_location,
                                     execution_state,
                                     actual_query))
    return details


def store_iterator_index(name, index):
    """ Store iterator index

    Arguments:
        name {string} -- Iterator name
        index {integer} -- Iterator index
    """
    table = get_table()

    table.update_item(
        Key={
            TableFieldName.partitionkey: TableValueCategory.iterator,
            TableFieldName.sortkey: name,
        },
        UpdateExpression='set {0} = :i'.format(TableFieldName.field_value),
        ExpressionAttributeValues={
            ':i': index
        }
    )


def get_iterator_index(name):
    """ Get iterator index

    Arguments:
        name {string} -- Iterator name

    Returns:
        integer -- Current iterator index
    """
    table = get_table()
    response = table.get_item(
        Key={
            TableFieldName.partitionkey: TableValueCategory.iterator,
            TableFieldName.sortkey: name
        }
    )
    index = response['Item'][TableFieldName.field_value]
    return int(index)


def set_manual_cleanup_flag():
    """ Set manual cleanup flag in db
    """
    table = get_table()

    table.update_item(
        Key={
            TableFieldName.partitionkey: TableValueCategory.config,
            TableFieldName.sortkey: TableValueCategory.manual_cleanup,
        },
        UpdateExpression='set {0} = :i'.format(TableFieldName.field_value),
        ExpressionAttributeValues={
            ':i': True
        }
    )


def is_manual_cleanup():
    """ Check if this is a manual cleanup request
    """
    table = get_table()
    response = table.query(
        KeyConditionExpression=Key(TableFieldName.partitionkey).eq(TableValueCategory.config) & Key(TableFieldName.sortkey).eq(TableValueCategory.manual_cleanup)
    )
    found = False
    if 'Items' in response and len(response['Items']) > 0:
        found = True
    return found

def update_source_bucket_inventory_status(bucket_name, new_status):
    """ Update inventory status for a source bucket

    Arguments:
        bucket_name {string} -- Source bucket name
        new_status {string} -- New inventory status
    """
    table = get_table()
    utc_epoch = datetime.utcnow().timestamp()
    utc_epoch_decimal = Decimal(utc_epoch)
    table.update_item(
        Key={
            TableFieldName.partitionkey: TableValueCategory.source_bucket,
            TableFieldName.sortkey: bucket_name,
        },
        UpdateExpression='set {0} = :s, {1} =:t'.format(TableFieldName.inventory_status, TableFieldName.change_timestamp),
        ExpressionAttributeValues={
            ':s': new_status,
            ':t': utc_epoch_decimal
        }
    )


def remove_all_items():
    """ Remove all values from the configuration table.
    """
    table = get_table()
    scan = table.scan()
    with table.batch_writer() as batch:
        for item in scan['Items']:
            batch.delete_item(
                Key={
                    TableFieldName.partitionkey: item[TableFieldName.partitionkey],
                    TableFieldName.sortkey: item[TableFieldName.sortkey]
                }
            )


def get_source_buckets_details(account_id):
    """ Get source bucket details

    Arguments:
        account_id {string} -- AWS account id

    Returns:
        [json] -- Response json object
    """
    table = get_table()
    response = table.query(
        KeyConditionExpression=Key(TableFieldName.partitionkey).eq(TableValueCategory.source_bucket),
        FilterExpression=Attr(TableFieldName.account_id).eq(account_id))
    logging.info(f'table query response for account {account_id}:{response}')
    return response['Items']


def have_inventory_jobs_finished():
    """ Check if all inventory jobs have finished

    Returns:
        boolean -- Flag indicating if all jobs have finished
    """
    table = get_table()
    response = table.query(
        KeyConditionExpression=Key(TableFieldName.partitionkey).eq(TableValueCategory.source_bucket),
        FilterExpression=Attr(TableFieldName.inventory_status).eq(BucketInventoryStatus.in_progress)
    )
    buckets = [item[TableFieldName.sortkey] for item in response['Items']]
    logging.info(f'buckets with incomplete inventory jobs:{buckets}')
    return len(buckets) == 0


def is_inprogress_inventory_job(account_id, bucket_name):
    """ Check if the inventory job is in progress for a given source bucket

    Arguments:
        account_id {string} -- AWS account id
        bucket_name {string} -- Source bucket name

    Returns:
        boolean -- Flag indicating if the job is in progress
    """
    result = False
    table = get_table()
    response = table.query(
        KeyConditionExpression=Key(TableFieldName.partitionkey).eq(TableValueCategory.source_bucket) & Key(TableFieldName.sortkey).eq(bucket_name)
    )
    if 'Items' in response and len(response['Items']) == 1:
        item = response['Items'][0]
        inventory_status = item[TableFieldName.inventory_status]
        if utility.compare_strings(inventory_status, BucketInventoryStatus.in_progress):
            result = True
        elif utility.compare_strings(inventory_status, BucketInventoryStatus.done):
            if TableFieldName.change_timestamp in item:
                utc_epoch_time_decimal = item[TableFieldName.change_timestamp]
                utc_epoch_time = float(utc_epoch_time_decimal)
                inventory_completion_timestamp = datetime.fromtimestamp(utc_epoch_time)
                current_timestamp = datetime.utcnow()
                delta = current_timestamp - inventory_completion_timestamp
                delta_seconds = delta.total_seconds()
                if delta_seconds < (config.ServiceParameters.buffer_time_after_nventory_completion_in_hours * 3600):
                    # This must be an out of order notification. Let's copy this inventory file
                    result = True
    return result
