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
import json

from lib import athena
from lib import config
from lib import ddb
from lib import s3
from lib import ses
from lib import utility

def initialize(event):
    """ Initialize the environment

    Arguments:
        event -- AWS Lambda event object

    Raises:
        utility.S3InsightsException: If input validation fails
    """
    ddb.remove_all_items()
    input_parameters = config.parse_input_parameters(event)
    run_id_len = len(input_parameters.run_id)
    if run_id_len < 1 or run_id_len > 8:
        raise utility.S3InsightsException(f'length of run_id parameter should be between 1 and 7. current length:{run_id_len}')
    if not input_parameters.run_id.isalnum():
        raise utility.S3InsightsException('run_id should only contain alphanumeric characters')

    logging.info(f'input_parameters:{event}')
    if input_parameters.is_smoke_test:
        # Override certain properties to make sure that we can clean them up
        input_parameters.athena_database_name = utility.random_string()
        input_parameters.athena_table_name = utility.random_string()
    else:
        exists = athena.does_athena_table_exist(
            input_parameters.run_id,
            input_parameters.athena_database_name,
            input_parameters.athena_table_name
        )
        if exists:
           raise utility.S3InsightsException(f'athena table {input_parameters.athena_table_name} already exists under athena database {input_parameters.athena_database_name}. Please use a non-existent Athena table name.')
    ddb.store_input_parameters(input_parameters)
    ses.send_email_verification_requests(input_parameters)
    s3.create_inventory_destination_buckets(input_parameters)

@utility.setup_logger
def lambda_handler(event, context):
    """ Lambda handler

    Arguments:
        event -- AWS Lambda event object
        context -- AWS Lambda context object
    """
    initialize(event)

