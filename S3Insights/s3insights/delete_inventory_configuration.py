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

from lib import account_iterator
from lib import awshelper
from lib import config
from lib import ddb
from lib import s3
from lib import smoketest
from lib import sqs
from lib import utility

def delete_helper(account_id):
    """ Helper function for deleting inventory configurations from source buckets

    Arguments:
        account_id {string} -- AWS account id
    """
    source_buckets_ddb = ddb.get_source_buckets(account_id)
    input_parameters = ddb.get_input_parameters()
    s3.remove_bucket_inventory_configurations(
        input_parameters,
        source_buckets_ddb)

def delete(event):
    """ Delete inventory configurations from source buckets

    Arguments:
        event {json} -- Lambda execution event

    Returns:
        json -- Lambda input for the next Step Function task
    """
    return account_iterator.iterate(event, delete_helper)

@utility.setup_logger
def lambda_handler(event, context):
    """ Lambda handler

    Arguments:
        event -- AWS Lambda event object
        context -- AWS Lambda context object

    Returns:
        json -- Lambda input for the next Step Function task
    """
    return delete(event)
