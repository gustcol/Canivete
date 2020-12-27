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
from multiprocessing import Process
import multiprocessing
import time

from lib import config
from lib import s3
from lib import ddb
from lib import ses
from lib import smoketest
from lib import utility

def cleanup(event):
    """ Delete staging destination CloudFormation stacks

    Arguments:
        event {json} -- Lambda execution event

    Returns:
        json -- Lambda input for the next Step Function task
    """
    iterator_info = event
    if config.ServiceParameters.iterator_key_name in event:
        iterator_info = event[config.ServiceParameters.iterator_key_name]
    should_continue = True
    current_attempt_count = iterator_info[config.ServiceParameters.iterator_current_attempt_count_key_ame]
    regions = iterator_info[config.ServiceParameters.iterator_regions_key_name]
    index = iterator_info[config.ServiceParameters.iterator_index_key_name]
    if (current_attempt_count >= config.ServiceParameters.max_attempt_count) or (len(regions) <= index):
        should_continue = False
    else:
        region = regions[index]
        input_parameters = ddb.get_input_parameters()
        worker_process = Process(
            target=s3.delete_regional_s3_inventory_bucket,
            args=(input_parameters, region,))

        worker_process.start()
        timeout_in_seconds = (config.ServiceParameters.lambda_timeout_in_minutes - 2) * 60
        worker_process.join(timeout_in_seconds)
        if not worker_process.is_alive(): # Cleanup finished
            index = index + 1
            current_attempt_count = 0
        else: # Need more time to cleanup regional inventory objects
            worker_process.terminate()
            current_attempt_count = current_attempt_count + 1

    return {
        config.ServiceParameters.iterator_regions_key_name: regions,
        config.ServiceParameters.iterator_index_key_name: index,
        config.ServiceParameters.iterator_current_attempt_count_key_ame: current_attempt_count,
        config.ServiceParameters.iterator_continue_key_name: should_continue
    }


@utility.setup_logger
def lambda_handler(event, context):
    """ Lambda handler

    Arguments:
        event -- AWS Lambda event object
        context -- AWS Lambda context object

    Returns:
        json -- Lambda input for the next Step Function task
    """
    return cleanup(event)

