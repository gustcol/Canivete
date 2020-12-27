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

from boto3.dynamodb.conditions import Key
import logging
import time

from lib import athena
from lib import awshelper
from lib import config
from lib import ddb
from lib import s3
from lib import utility


def simulate(input_parameters):
    """ Simulate smoke test

    Arguments:
        input_parameters {config.S3InsightsInput} -- Input parameters for the current execution

    Raises:
        utility.S3InsightsException: If none of the source buckets can generator inventory reports
    """
    logging.info('simulating smoke test in the current environment')
    account_id = None
    region = None
    bucket_name = None
    account_ids = [account_config.id for account_config in input_parameters.accounts]

    for account_id in account_ids:
        source_buckets_details = ddb.get_source_buckets_details(account_id)
        for ddb_bucket in source_buckets_details:
            inventory_status = ddb_bucket[ddb.TableFieldName.inventory_status]
            if utility.compare_strings(inventory_status, ddb.BucketInventoryStatus.in_progress):
                account_id = ddb_bucket[ddb.TableFieldName.account_id]
                region = ddb_bucket[ddb.TableFieldName.region]
                bucket_name = ddb_bucket[ddb.TableFieldName.sortkey]
                break
        if account_id is not None:
            break

    if bucket_name is None:
        raise utility.S3InsightsException('could not find a bucket for smoke test')

    s3_client = awshelper.get_client(awshelper.ServiceName.s3)
    file_path = utility.get_file_path(
        __file__,
        "smoketestdata/sample_inventory_object.orc")

    s3_key = "{0}/{1}/{2}/inventorysmoketest/data/smoke_test_inventory_object.orc".format(account_id, region, bucket_name)
    destination_bucket_name = s3.get_destination_bucket_name(
        input_parameters.run_id,
        region)

    logging.info(f'smoke test destination_bucket_name:{destination_bucket_name} s3_key:{s3_key}')
    response = s3_client.upload_file(file_path, destination_bucket_name, s3_key)
    logging.info(f'uploading a sample inventory object. response:{response}')
    s3_key = "{0}/{1}/{2}/inventorysmoketest/somedate/manifest.checksum".format(account_id, region, bucket_name)
    logging.info(response)
    sleep_time_in_seconds = config.ServiceParameters.smoke_test_sleep_time_in_seconds
    time.sleep(sleep_time_in_seconds)
    response = s3_client.upload_file(file_path, destination_bucket_name, s3_key)
    logging.info(f'uploading a sample manifest checksum. response:{response}')
    time.sleep(sleep_time_in_seconds)


def cleanup_and_verify():
    """ Cleanup smoke test resources and verify that smoke test worked as expected

    Raises:
        utility.S3InsightsException: If the test fails
    """
    input_parameters = ddb.get_input_parameters()
    database_name = input_parameters.athena_database_name
    run_id = input_parameters.run_id
    is_manual_cleanup = ddb.is_manual_cleanup()
    athena_client = awshelper.get_client(awshelper.ServiceName.athena)
    try:
        athena.run_query(
            run_id,
            athena_client,
            'DROP TABLE  {0}'.format(input_parameters.athena_table_name),
            input_parameters.athena_database_name,
            True)
    except utility.S3InsightsException as e:
        logging.info('received exception while deleting athena table: {e}')
        if is_manual_cleanup:
            logging.info('ignoring the exception as this is a manual cleanup operation')
        else:
            raise
    try:
        athena.run_query(
            run_id,
            athena_client,
            'DROP DATABASE  {0}'.format(input_parameters.athena_database_name),
            None,
            True)
    except utility.S3InsightsException as e:
        logging.info('received exception while deleting athena table: {e}')
        if is_manual_cleanup:
            logging.info('ignoring the exception as this is a manual cleanup operation')
        else:
            raise

    s3_resource = awshelper.get_resource(awshelper.ServiceName.s3)
    s3_athena_output_prefix = athena.get_s3_output_location_prefix(run_id)
    consolidated_bucket = s3_resource.Bucket(config.DeploymentDetails.consolidated_inventory_bucket_name)
    athena_outout_objects = consolidated_bucket.objects.filter(
        Prefix=s3_athena_output_prefix)
    athena_outout_objects.delete()

    did_smoke_test_fail = False
    if len(run_id) > 0:
        s3_inventory_prefix = s3.get_inventory_prefix_at_consolidated_bucket(run_id)

        objects = consolidated_bucket.objects.filter(Prefix=s3_inventory_prefix)
        objects_count = 0
        for obj in objects:
            objects_count += 1
        logging.info(f'Number of objects that were created in the consolidation bucket:{objects_count}')
        objects = consolidated_bucket.objects.filter(Prefix=s3_inventory_prefix)
        objects.delete()
        if objects_count == 0:
            did_smoke_test_fail = True
    else:
        did_smoke_test_fail = True
    if is_manual_cleanup is not True and did_smoke_test_fail:
        raise utility.S3InsightsException('smoke test failed. Clean up operation itself might have succeeded.')
