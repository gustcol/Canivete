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

from botocore.exceptions import ClientError
from botocore.config import Config as botocore_config
import json
import logging
import random
import time

from lib import awshelper
from lib import config
from lib import ddb
from lib import utility


def get_source_buckets(input_parameters, account_id):
    """ Get all eligible source buckets

    Arguments:
        input_parameters {config.S3InsightsInput} -- Input parameters for the current execution
        account_id {string} -- AWS account id

    Returns:
        dict<string, dict<string, list(string)>> -- Source buckets
    """
    source_buckets = {}
    account_id = account_id.lower()
    account_config = next(account_config for account_config in input_parameters.accounts if utility.compare_strings(account_config.id, account_id))
    source_buckets[account_id] = {}
    s3_client = awshelper.get_client(
        awshelper.ServiceName.s3,
        None,
        account_id,
        input_parameters.run_id)

    # Exclude the consolidation and inventory destination buckets
    pipeline_buckets = []
    if utility.compare_strings(account_id, awshelper.SessionManager.get_host_account_id()):
        pipeline_buckets.append(config.DeploymentDetails.consolidated_inventory_bucket_name)
        for region in input_parameters.supported_regions:
            bucket_name = get_destination_bucket_name(input_parameters.run_id, region)
            pipeline_buckets.append(bucket_name)
    response = s3_client.list_buckets()
    for bucket in response["Buckets"]:
        name = bucket["Name"].lower()
        if name not in account_config.exclude and name not in pipeline_buckets:
            try:
                location = s3_client.get_bucket_location(
                    Bucket=name)
                region = location['LocationConstraint']
                if region is None:
                    region = 'us-east-1'
                region = region.lower()
                if region in input_parameters.supported_regions:
                    if region not in source_buckets[account_id]:
                        source_buckets[account_id][region] = []
                    source_buckets[account_id][region].append(name)
            except ClientError as e:
                logging.error(f'error while retrieving bucket information for {account_id}:{name}. error details: {e}')

    return source_buckets


def get_destination_bucket_name(run_id, region):
    """ Get destination bucket name for a region

    Arguments:
        run_id {string} -- run_id for the current execution
        region {string} -- AWS region name

    Returns:
        string -- Destination bucket name
    """
    host_account_id = awshelper.SessionManager.get_host_account_id()
    return utility.get_resource_name(
        run_id,
        f'dest-{host_account_id}',
        region)


def is_bucket_empty(s3_resource, bucket_name):
    """ Check if a given S3 bucket is empty

    Arguments:
        s3_resource {Boto3.S3.ServiceResource} -- Boto3 S3 resource
        bucket_name {string} -- bucket name

    Returns:
        boolean -- Flag indicating if the bucket is empty
    """
    empty = True
    client_error = None
    bucket = s3_resource.Bucket(bucket_name)
    try:
        s3_objects = bucket.objects.all()
        for s3_object in s3_objects:
            empty = False
            break
    except ClientError as e:
        logging.error(f'error while listing objects from {bucket_name}. error details:{e}')
        client_error = e
    return empty, client_error


def is_destination_bucket_name(input_parameters, bucket_name):
    """ Check if the given S3 bucket is a destination bucket

    Arguments:
        input_parameters {config.S3InsightsInput} -- Input parameters for the current execution
        bucket_name {string} -- Bucket name

    Returns:
        boolean -- Flag indicating if the bucket is a destination bucket
    """
    for region in input_parameters.supported_regions:
        destination_bucket_name = get_destination_bucket_name(input_parameters.run_id, region)
        if utility.compare_strings(destination_bucket_name, bucket_name):
            return True
    return False


class StackDetails(object):
    def __init__(self, client, name):
        """ Constructor for creating an instance of

        Arguments:
            object {StackDetails} -- Instance of StackDetails
            client {Boto3.CloudFormation.Client} -- Boto3 CloudFormation client
            name {string} -- CloudFormation stack name
        """
        self.client = client
        self.name = name

    def is_complete(self, in_progress_state_name, complete_state_name):
        """ Check if the CloudFormation stack operation has finished

        Arguments:
            in_progress_state_name {string} -- In-progress state name
            complete_state_name {[string} -- Complete state name

        Raises:
            utility.S3InsightsException: When the stack status is neither in-progress nor complete

        Returns:
            boolean -- Flag indicating if the operation has finished successfully
        """
        details = self.client.describe_stacks(StackName=self.name)
        logging.info(f'current stack details: {self.name} {details}')
        current_status = details['Stacks'][0]['StackStatus'].lower()
        if utility.compare_strings(current_status, in_progress_state_name):
            return False
        elif utility.compare_strings(current_status, complete_state_name):
            return True
        else:
            error_message = f'unknown stack status. Stack name:{self.name} current status:{current_status} expected status:{in_progress_state_name}/{complete_state_name} details:{details}'
            raise utility.S3InsightsException(error_message)


def wait_for_stack_operations_to_finish(stacks, in_progress_state_name, complete_state_name, max_iteration_count):
    """ Wait for stack operations to finish

    Arguments:
        stacks {list(StackDetails)} -- List of stacks
        in_progress_state_name {string} -- In-progress state name
        complete_state_name {[string} -- Complete state name
        max_iteration_count {integer} -- Max iteration count

    Raises:
        utility.S3InsightsException: When stacks do not move to the complete state in the alloted time
    """
    are_stacks_ready = False
    attempts = 0
    while are_stacks_ready is False and attempts < max_iteration_count:
        are_stacks_ready = True
        attempts = attempts + 1
        for stack in stacks:
            if stack.is_complete(in_progress_state_name, complete_state_name) == False:
                are_stacks_ready = False
                time.sleep(30)
                break
    if are_stacks_ready is False:
        raise utility.S3InsightsException('stacks did not finish in the alloted time')


def get_stack_name(run_id):
    """ Get CloudFormation stack name

    Arguments:
        run_id {string} -- run_id for the current Step Function execution

    Returns:
        string -- CloudFormation Stack name
    """
    return utility.get_resource_name(
        run_id,
        'stack',
        'dest-resources')


def create_inventory_destination_buckets(input_parameters):
    """ Create inventory destination buckets

    Arguments:
        input_parameters {config.S3InsightsInput} -- Input parameters for the current execution
    """
    template_file_path = utility.get_file_path(__file__, "template/inventory-destination.json")
    with open(template_file_path, "r") as template_file:
        template_text = template_file.read()
    stacks = []
    regions = input_parameters.supported_regions
    for region in regions:
        bucket_name = get_destination_bucket_name(
            input_parameters.run_id,
            region)
        topic_name = utility.get_resource_name(
            input_parameters.run_id,
            'sns',
            'notification-topic')

        acceleration_status = 'Enabled'

        parameters = [
            {
                'ParameterKey': 'BucketName',
                'ParameterValue': bucket_name
            },
            {
                'ParameterKey': 'SQSArn',
                'ParameterValue': config.DeploymentDetails.sqs_arn
            },
            {
                'ParameterKey': 'TopicName',
                'ParameterValue': topic_name
            },
            {
                'ParameterKey': 'AccelerationStatus',
                'ParameterValue': acceleration_status
            }
        ]

        stack_name = get_stack_name(input_parameters.run_id)
        cloudformation_client = awshelper.get_client(
            awshelper.ServiceName.cloudformation,
            region)
        response = cloudformation_client.create_stack(
            StackName=stack_name,
            TemplateBody=template_text,
            Parameters=parameters)
        logging.info(f'create stack response: {response}')
        stacks.append(StackDetails(cloudformation_client, stack_name))
    wait_for_stack_operations_to_finish(
        stacks,
        'create_in_progress',
        'create_complete',
        20)


def create_inventory_configuration_helper(account_id):
    """ Helper function to create inventory configurations

    Arguments:
        account_id {string} -- AWS account id
    """
    input_parameters = ddb.get_input_parameters()
    source_buckets = get_source_buckets(input_parameters, account_id)
    ddb.store_source_buckets(source_buckets)
    create_bucket_inventory_configurations(
        input_parameters.run_id,
        source_buckets)


def create_bucket_inventory_configurations(run_id, source_buckets):
    """ Enable S3 inventory for the given list of source buckets

    Arguments:
        run_id {string} -- run_id for the current Step Function execution
        source_buckets {dict<string, dict<string, list(string)>>} -- Source buckets
    """
    host_account_id = awshelper.SessionManager.get_host_account_id()
    for account_id in source_buckets:
        for region in source_buckets[account_id]:
            s3_resource = awshelper.get_resource(awshelper.ServiceName.s3, account_id, run_id)
            s3_client = awshelper.get_client(
                awshelper.ServiceName.s3,
                region,
                account_id,
                run_id)
            for bucket_name in source_buckets[account_id][region]:
                logging.info(f'Processing {bucket_name} in {region} from {account_id}')
                is_empty, client_error = is_bucket_empty(s3_resource, bucket_name)
                if client_error is None:
                    if is_empty:
                        # Update DB status
                        logging.info(f'{bucket_name} in {region} from {account_id} is empty')
                        ddb.update_source_bucket_inventory_status(bucket_name, ddb.BucketInventoryStatus.bucket_is_empty)
                    else:
                        destination_prefix = account_id + "/" + region
                        destination_bucket = "arn:aws:s3:::" + get_destination_bucket_name(run_id, region)
                        inventory_id = utility.get_resource_name(run_id, 's3-inventory', 'orc')
                        inventory_configuration_orc = {
                            "Schedule": {
                                "Frequency": "Daily"
                            },
                            "IsEnabled": True,
                            "Destination": {
                                "S3BucketDestination": {
                                    "Prefix": destination_prefix,
                                    "Format": "ORC",
                                    "Bucket": destination_bucket,
                                    "AccountId": host_account_id
                                }
                            },
                            "OptionalFields": [
                                "Size",
                                "LastModifiedDate",
                                "StorageClass",
                                "ETag",
                                "ReplicationStatus",
                                "IsMultipartUploaded",
                                "EncryptionStatus",
                                "ObjectLockMode",
                                "ObjectLockRetainUntilDate",
                                "ObjectLockLegalHoldStatus"
                            ],
                            "IncludedObjectVersions": "All",
                            "Id": inventory_id
                        }
                        try:
                            response = s3_client.put_bucket_inventory_configuration(
                                Bucket=bucket_name,
                                Id=inventory_id,
                                InventoryConfiguration=inventory_configuration_orc)
                            logging.info(f'put bucket inventory configuration response:{response}')
                            ddb.update_source_bucket_inventory_status(bucket_name, ddb.BucketInventoryStatus.in_progress)
                        except ClientError as e:
                            logging.error(f'error while creating inventory configuration on {account_id}:{region}:{bucket_name}. error details:{e}')


def remove_bucket_inventory_configurations(input_parameters, source_buckets_ddb):
    """ Remove inventory configurations from the given list of source buckets

    Arguments:
        input_parameters {config.S3InsightsInput} -- Input parameters for the current execution
        source_buckets_ddb {dict<string, dict<string, list(string)>>} -- Source buckets
    """
    for account_id in source_buckets_ddb:
        for region in source_buckets_ddb[account_id]:
            s3_client = awshelper.get_client(
                awshelper.ServiceName.s3,
                region,
                account_id,
                input_parameters.run_id)

            for bucket in source_buckets_ddb[account_id][region]:
                bucket_name = bucket.name
                remove_bucket_inventory_configuration_internal(
                    s3_client,
                    input_parameters.run_id,
                    account_id,
                    region,
                    bucket_name)


def remove_bucket_inventory_configuration(run_id, account_id, region, bucket_name):
    """ Remove inventory configuration from the given S3 bucket

    Arguments:
        run_id {string} -- run_id for the current Step Function execution
        account_id {string} -- AWS account id
        region {string} -- AWS region name
        bucket_name {string} -- Bucket name
    """
    s3_client = awshelper.get_client(
        awshelper.ServiceName.s3,
        region,
        account_id,
        run_id)
    remove_bucket_inventory_configuration_internal(s3_client, run_id, account_id, region, bucket_name)


def remove_bucket_inventory_configuration_internal(s3_client, run_id, account_id, region, bucket_name):
    """ Helper function for removing nventory configuration from the given S3 bucket

    Arguments:
        s3_client {boto3.S3.Client} -- Boto3 S3 client
        run_id {string} -- run_id for the current Step Function execution
        account_id {string} -- AWS account id
        region {string} -- AWS region name
        bucket_name {string} -- Bucket name
    """
    try:
        id = utility.get_resource_name(run_id, 's3-inventory', 'orc')
        response = s3_client.delete_bucket_inventory_configuration(
            Bucket=bucket_name,
            Id=id)
        logging.info(f'delete bucket inventory response for {account_id}:{region}:{bucket_name} = {response}')
    except ClientError as e:
        logging.error(f'error while deleting inventory configuration from {account_id}:{region}:{bucket_name}. error details:{e}')


def get_inventory_prefix_at_consolidated_bucket(run_id):
    """ Get the prefix to use for partitioning inventory objects

    Arguments:
        run_id {string} -- run_id for the current Step Function execution

    Returns:
        string -- S3 prefix
    """
    return f'{config.ServiceParameters.consolidated_inventory_s3_folder}/{run_id}/'


def copy_inventory_object_into_consolidation_bucket(run_id, source_bucket_name, source_object_key, destination_bucket_name):
    """ Copy inventory object into the consolidation bucket

    Arguments:
        run_id {string} -- run_id for the current Step Function execution
        source_bucket_name {string} -- Source bucket name
        source_object_key {string} -- Source object key
        destination_bucket_name {string} -- Destination bucket name
    """
    session = awshelper.SessionManager.get_host_aws_session()
    s3_resource = session.resource('s3', config=botocore_config(s3={'use_accelerate_endpoint': True}))
    object_key_parts = source_object_key.split('/')
    object_key_parts_len = len(object_key_parts)
    new_object_key = "{0}account={1}/region={2}/bucketname={3}/{4}".format(
        get_inventory_prefix_at_consolidated_bucket(run_id),
        object_key_parts[0],
        object_key_parts[1],
        object_key_parts[2],
        object_key_parts[object_key_parts_len - 1])

    copy_source = {
        'Bucket': source_bucket_name,
        'Key': source_object_key
    }

    try:
        s3_resource.meta.client.copy(
            copy_source,
            destination_bucket_name,
            new_object_key)
    except ClientError as e:
        if 'Error' in e.response and 'Code' in e.response['Error']['Code'] and utility.compare_strings(e.response['Error']['Code'], "slowdown"):
            wait_in_seconds = random.randint(1, 120)

            # S3 is throttling upload operations. Let's back off for a few seconds
            logging.warning(f's3 is throttling copy request for {source_bucket_name}:{source_object_key}. wait time in seconds:{wait_in_seconds}')
            time.sleep(wait_in_seconds)
        raise


def delete_regional_s3_inventory_bucket(input_parameters, region):
    """ Delete the staging destination bucket for the given region

    Arguments:
        input_parameters {config.S3InsightsInput} -- Input parameters for the current execution
        region {string} -- AWS region name
    """
    s3_resource = awshelper.get_resource(awshelper.ServiceName.s3)
    bucket_name = get_destination_bucket_name(input_parameters.run_id, region)
    logging.info(f'deleting all objects from {region} {bucket_name}')
    try:
        bucket = s3_resource.Bucket(bucket_name)
        bucket.objects.all().delete()
    except ClientError as e:
        logging.error(f'error while deleting all s3 objects from inventory destination bucket {bucket_name}. error details: {e}')

    cloudformation_client = awshelper.get_client(
        awshelper.ServiceName.cloudformation,
        region)
    stack_name = get_stack_name(input_parameters.run_id)
    logging.info(f'deleting cloudformation stack {stack_name} from {region}')
    try:
        response = cloudformation_client.delete_stack(
            StackName=stack_name)
        logging.info(response)
    except ClientError as e:
        logging.error(f'error while deleting inventory destnation bucket stack {stack_name} for {region} region. error details: {e}')


def update_source_bucket_inventory_status(input_parameters, account_id):
    """ Update inventory status for all applicable source buckets under the given AWS account

    Arguments:
        input_parameters {config.S3InsightsInput} -- Input parameters for the current execution
        account_id {string} -- AWS account id
    """
    source_buckets = get_source_buckets(input_parameters, account_id)
    source_buckets_details = ddb.get_source_buckets_details(account_id)
    s3_resources = {}
    for ddb_bucket in source_buckets_details:
        inventory_status = ddb_bucket[ddb.TableFieldName.inventory_status]
        if utility.compare_strings(inventory_status, ddb.BucketInventoryStatus.in_progress):
            ddb_account_id = ddb_bucket[ddb.TableFieldName.account_id]
            ddb_region = ddb_bucket[ddb.TableFieldName.region]
            ddb_bucket_name = ddb_bucket[ddb.TableFieldName.sortkey]

            if not (ddb_account_id in source_buckets
                    and ddb_region in source_buckets[ddb_account_id]
                    and ddb_bucket_name in source_buckets[ddb_account_id][ddb_region]):
                logging.info(f'{ddb_bucket_name} not available anymore. updating the ddb entry')
                ddb.update_source_bucket_inventory_status(
                    ddb_bucket_name,
                    ddb.BucketInventoryStatus.bucket_not_available)
            else:
                if ddb_account_id not in s3_resources:
                    s3_resources[ddb_account_id] = awshelper.get_resource(awshelper.ServiceName.s3, ddb_account_id, input_parameters.run_id)
                s3_resource = s3_resources[ddb_account_id]
                is_empty, client_error = is_bucket_empty(s3_resource, ddb_bucket_name)
                remove_inventory_configuration = False
                if client_error is not None:
                    logging.info(f'{ddb_bucket_name} bucket access lost for some reason. updating the ddb entry')
                    ddb.update_source_bucket_inventory_status(
                        ddb_bucket[ddb.TableFieldName.sortkey],
                        ddb.BucketInventoryStatus.bucket_access_lost)
                    remove_inventory_configuration = True
                elif is_empty:
                    logging.info(f'{ddb_bucket_name} is empty. Updating the DDB entry')
                    ddb.update_source_bucket_inventory_status(
                        ddb_bucket[ddb.TableFieldName.sortkey],
                        ddb.BucketInventoryStatus.bucket_is_empty)
                    remove_inventory_configuration = True

                if remove_inventory_configuration:
                    remove_bucket_inventory_configuration(
                        input_parameters.run_id,
                        ddb_account_id,
                        ddb_region,
                        ddb_bucket_name)


def process_inventory_object(event):
    """ Process an inventory object once it has been stored in a staging destination bucket

    Arguments:
        event {json} -- S3 notification event
    """
    if 'Records' in event:
        input_parameters = ddb.get_input_parameters()
        for record in event['Records']:
            if 'body' in record:
                body_json = json.loads(record['body'])
                if 'Records' in body_json:
                    for record in body_json['Records']:
                        if 'eventName' in record and record['eventName'] == 'ObjectCreated:Put':
                            source_bucket_name = record['s3']['bucket']['name']
                            if is_destination_bucket_name(input_parameters, source_bucket_name):
                                source_object_key = record['s3']['object']['key']
                                object_key_parts = source_object_key.split('/')
                                object_key_parts_len = len(object_key_parts)

                                bucket_account_id = object_key_parts[0].lower()
                                bucket_region = object_key_parts[1].lower()
                                bucket_name = object_key_parts[2].lower()
                                logging.info(f'source_object_key:{source_object_key} bucket_account_id:{bucket_account_id} bucket_name:{bucket_name}')
                                if ddb.is_inprogress_inventory_job(bucket_account_id, bucket_name):
                                    if object_key_parts_len > 4:
                                        if utility.compare_strings(object_key_parts[object_key_parts_len - 1], 'manifest.checksum'):
                                            ddb.update_source_bucket_inventory_status(object_key_parts[2], ddb.BucketInventoryStatus.done)
                                            remove_bucket_inventory_configuration(
                                                input_parameters.run_id,
                                                bucket_account_id,
                                                bucket_region, bucket_name
                                            )
                                        elif utility.compare_strings(object_key_parts[object_key_parts_len - 2], 'data'):
                                            copy_inventory_object_into_consolidation_bucket(
                                                input_parameters.run_id,
                                                source_bucket_name,
                                                source_object_key,
                                                config.DeploymentDetails.consolidated_inventory_bucket_name
                                            )
                                else:
                                    logging.warning('Received an unexpected SQS notification')
