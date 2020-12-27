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

from lib import awshelper
from lib import config

def is_notification_queue_empty():
    """ Checks if the notification queue is empty

    Returns:
        boolean -- Flag representing if the notification queue is empty
    """
    queue_arn_parts = config.DeploymentDetails.sqs_arn.split(sep=':')
    queue_name = queue_arn_parts[len(queue_arn_parts) - 1]
    sqs_client = awshelper.get_client(awshelper.ServiceName.sqs)
    response = sqs_client.get_queue_url(
        QueueName=queue_name
    )
    sqs_url = response['QueueUrl']
    approx_msg_count_attribute_name = 'ApproximateNumberOfMessages'
    approx_not_visible_msg_count_attribute_name = 'ApproximateNumberOfMessagesNotVisible'
    approx_delayed_msg_count_attribute_name = 'ApproximateNumberOfMessagesDelayed'

    response = sqs_client.get_queue_attributes(
        QueueUrl=sqs_url,
        AttributeNames=[approx_msg_count_attribute_name, approx_not_visible_msg_count_attribute_name, approx_delayed_msg_count_attribute_name]
    )
    logging.info(f'SQS attributes:{response}')
    attributes = response['Attributes']
    if attributes[approx_msg_count_attribute_name] == '0' and attributes[approx_not_visible_msg_count_attribute_name] == '0' and attributes[approx_delayed_msg_count_attribute_name] == '0':
        return True
    return False
