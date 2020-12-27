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

from lib import config
from lib import ddb
from lib import sqs


def iterate(event, task_function):
    """ Repeats a task for all account ids included in event

    Arguments:
        event {json} -- Lambda execution event
        task_function {function} -- Function to execute

    Returns:
        json -- Lambda execution event for the next iteration
    """
    iterator_info = event
    if config.ServiceParameters.iterator_key_name in event:
        iterator_info = event[config.ServiceParameters.iterator_key_name]
    should_continue = True
    account_ids = iterator_info[config.ServiceParameters.iterator_account_ids_key_name]
    index = iterator_info[config.ServiceParameters.iterator_index_key_name]
    if len(account_ids) <= index:
        should_continue = False
    else:
        account_id = account_ids[index]
        task_function(account_id)
        index = index + 1

    logging.info(f'new_index:{index} should_continue_loop:{should_continue} event:{event}')

    return {
        config.ServiceParameters.iterator_account_ids_key_name: account_ids,
        config.ServiceParameters.iterator_index_key_name: index,
        config.ServiceParameters.iterator_continue_key_name: should_continue
    }


def initialize():
    """ Initialize the iterator for repeating a task for multiple AWS accounts

    Returns:
        json -- Lambda execution event
    """
    input_parameters = ddb.get_input_parameters()
    account_ids = [account_config.id for account_config in input_parameters.accounts]
    return {
        config.ServiceParameters.iterator_account_ids_key_name: account_ids,
        config.ServiceParameters.iterator_index_key_name: 0,
        config.ServiceParameters.iterator_continue_key_name: True
    }


def are_inventories_ready(input_parameters):
    """ Check if all inventory jobs have finished

    Arguments:
        input_parameters {config.S3InsightsInput} -- Input parameters for the current step function execution

    Returns:
        boolean -- Flag indicating if all inventory jobs have finished
    """
    if ddb.have_inventory_jobs_finished() and sqs.is_notification_queue_empty():
        logging.info('all inventory jobs have finished')
        return True
    return False


def iterate_to_track_progress_of_inventory_jobs():
    """ Iterator for monitoring progress all of inventory jobs

    Returns:
        json -- Lambda event input for the next iteration
    """
    index = ddb.get_iterator_index(
        config.ServiceParameters.inventory_monitor_iterator_name)
    new_index = index - 1
    should_continue_loop = True
    input_parameters = ddb.get_input_parameters()
    wait_time_in_seconds = config.ServiceParameters.wait_time_in_seconds
    if input_parameters.is_smoke_test:
        should_continue_loop = False
    elif are_inventories_ready(input_parameters):
        should_continue_loop = False
    elif new_index < 1:
        logging.warning('inventory jobs did not finish in time. moving forward with all existing inventories files.')
        should_continue_loop = False
    logging.info(
        f'new_index:{new_index} should_continue_loop:{should_continue_loop} wait_time_in_seconds:{wait_time_in_seconds}')
    ddb.store_iterator_index(
        config.ServiceParameters.inventory_monitor_iterator_name,
        new_index)
    return {
        config.ServiceParameters.iterator_index_key_name: new_index,
        config.ServiceParameters.iterator_continue_key_name: should_continue_loop,
        config.ServiceParameters.iterator_wait_time_in_seconds_key_name: wait_time_in_seconds,
        config.ServiceParameters.iterator_step_key_name: config.ServiceParameters.iterator_step
    }
