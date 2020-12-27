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

import logging
import time

from lib import awshelper
from lib import config
from lib import ddb
from lib import s3
from lib import utility


def get_s3_output_location_prefix(run_id):
    """ S3 prefix for storing Athena results

    Arguments:
        run_id {string} -- run_id for the current Step Function execution

    Returns:
        string -- S3 prefix to use
    """
    return f'athena/{run_id}/'


def run_query(run_id, athena_client, query, athena_database_name, wait_to_finish):
    """ Run the given Athena query

    Arguments:
        run_id {string} -- run_id for the current Step Function execution
        athena_client {boto3.client} -- Boto3 Athena client
        query {string} -- Athena query to execute
        athena_database_name {string} -- Athena database to use for query execution
        wait_to_finish {boolean} -- Should method wait for the Athena query to finish?

    Raises:
        utility.S3InsightsException: when Athena query fails

    Returns:
        string -- Athena execution id
    """
    output_location = {
        'OutputLocation': 's3://{0}/{1}'.format(
            config.DeploymentDetails.consolidated_inventory_bucket_name,
            get_s3_output_location_prefix(run_id)),
    }

    if athena_database_name is not None:
        query_response = athena_client.start_query_execution(
            QueryString=query,
            QueryExecutionContext={
                'Database': athena_database_name
            },
            ResultConfiguration=output_location)
    else:
        query_response = athena_client.start_query_execution(
            QueryString=query,
            ResultConfiguration=output_location)

    execution_id = query_response['QueryExecutionId']
    if wait_to_finish:
        for attempt_count in range(1, 10):
            query_status = athena_client.get_query_execution(
                QueryExecutionId=execution_id)
            query_execution_status = query_status['QueryExecution']['Status']['State']
            if utility.compare_strings(query_execution_status, 'succeeded'):
                break
            elif utility.compare_strings(query_execution_status, 'failed'):
                    raise utility.S3InsightsException('Athena query failed for unknown reasons')
            time.sleep(30)
    return execution_id


def does_athena_table_exist(run_id, athena_database_name, athena_table_name):
    """ Checks if an Athena table already exists

    Arguments:
        run_id {string} -- run_id for the current Step Function execution
        athena_database_name {string} -- Athena database to use for query execution
        athena_table_name {string} -- Athena table name

    Returns:
        boolean -- Flag representing if the table already exists
    """
    exists = False
    athena_client = awshelper.get_client(awshelper.ServiceName.athena)
    execution_id = None
    try:
        execution_id = run_query(
            run_id,
            athena_client,
            f'SHOW TABLES IN {athena_database_name}',
            None,
            True)
    except utility.S3InsightsException as e:
        logging.info('received exception while listing tables: {e}')

    if execution_id is not None:
        result = athena_client.get_query_results(QueryExecutionId=execution_id)
        for row in result['ResultSet']['Rows']:
            table_name = row['Data'][0]['VarCharValue']
            if utility.compare_strings(athena_table_name, table_name):
                exists = True
                break
    return exists


def create_resources():
    """ Create Athena resources once all inventory objects have been partitioned
        and stored in the consolidation bucket.
    """

    input_parameters = ddb.get_input_parameters()
    database_name = input_parameters.athena_database_name
    table_name = input_parameters.athena_table_name
    athena_client = awshelper.get_client(awshelper.ServiceName.athena)
    create_database_query = 'CREATE DATABASE IF NOT EXISTS {0}'.format(database_name)
    logging.info(f'create database query={create_database_query}')
    run_id = input_parameters.run_id
    run_query(
        run_id,
        athena_client,
        create_database_query,
        None,
        True)

    athena_table_format = """
        CREATE EXTERNAL TABLE {0}(
        bucket string,
        key string,
        version_id string,
        is_latest boolean,
        is_delete_marker boolean,
        size bigint,
        last_modified_date timestamp,
        e_tag string,
        storage_class string,
        is_multipart_uploaded boolean,
        replication_status string,
        encryption_status string,
        object_lock_retain_until_date timestamp,
        object_lock_mode string,
        object_lock_legal_hold_status string)
        PARTITIONED BY (
        account string,
        region string,
        bucketname string)
        ROW FORMAT SERDE
        'org.apache.hadoop.hive.ql.io.orc.OrcSerde'
        STORED AS INPUTFORMAT
        'org.apache.hadoop.hive.ql.io.orc.OrcInputFormat'
        OUTPUTFORMAT
        'org.apache.hadoop.hive.ql.io.orc.OrcOutputFormat'
        LOCATION
        's3://{1}/{2}'
    """

    create_table_query = athena_table_format.format(
        table_name,
        config.DeploymentDetails.consolidated_inventory_bucket_name,
        s3.get_inventory_prefix_at_consolidated_bucket(run_id))
    logging.info(f'create table query={create_table_query}')

    run_query(
        run_id,
        athena_client,
        create_table_query,
        database_name,
        True)

    run_query(
        run_id,
        athena_client,
        'MSCK REPAIR TABLE {0}'.format(table_name),
        database_name,
        True)

    query_execution_details = {}
    for athena_query in input_parameters.athena_queries:
        execution_id = run_query(
            run_id,
            athena_client,
            athena_query.query.replace("{ATHENA_TABLE}", table_name),
            database_name,
            False)

        query_execution_details[execution_id] = athena_query
        logging.info('Execution Id: {0} Name: {1} Query:{2}'.format(
            execution_id,
            athena_query.name,
            athena_query.query))
    ddb.store_athena_queries(query_execution_details)


def return_wait_time():
    """ Return wait time for Athena query execution

    Returns:
        integer -- time in seconds to wait
    """
    input_parameters = ddb.get_input_parameters()
    wait_time_in_seconds = config.ServiceParameters.wait_time_in_seconds_smoke_test if input_parameters.is_smoke_test else config.ServiceParameters.wait_time_in_seconds
    return {
        config.ServiceParameters.iterator_wait_time_in_seconds_key_name: wait_time_in_seconds
    }
