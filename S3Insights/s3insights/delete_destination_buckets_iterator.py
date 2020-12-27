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
from lib import s3
from lib import ddb
from lib import utility

def configure_iterator():
    """ Configure iterator for deleting destination buckets

    Returns:
        json -- Lambda input for the next Step Function task
    """
    input_parameters = ddb.get_input_parameters()
    regions = input_parameters.supported_regions

    return {
        config.ServiceParameters.iterator_regions_key_name: regions,
        config.ServiceParameters.iterator_index_key_name: 0,
        config.ServiceParameters.iterator_current_attempt_count_key_ame: 0,
        config.ServiceParameters.iterator_continue_key_name: True
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
    return configure_iterator()

