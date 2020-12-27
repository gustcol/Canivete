# MIT No Attribution

# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import boto3
import json
import logging
import os
from urllib2 import Request, urlopen, URLError, HTTPError
import requests
import pprint

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def publish_to_slack_handler(event, context):
    # The Slack hook to use
    SLACK_HOOK_URL = os.environ['SlackHookUrl']
    # The Slack channel to send a message to stored in the slackChannel environment variable
    SLACK_CHANNEL = os.environ['SlackChannel']
    for record in event['Records']:
      slack_message = {
          'channel': SLACK_CHANNEL,
          'text': json.loads(record['Sns']['Message'])['TextMessage']
      }
      req = Request(SLACK_HOOK_URL, json.dumps(slack_message))
      try:
          response = urlopen(req)
          response.read()
          logger.info('Message posted to % s ', slack_message['channel'])
      except HTTPError as e:
          logger.error('Unable to publish message:' + record['Sns']['Message'])['TextMessage']
          logger.error('Request failed: % d % s ', e.code, e.reason)
      except URLError as e:
          logger.error('Unable to publish message:' + record['Sns']['Message'])['TextMessage']
          logger.error('Server connection failed: % s ', e.reason)

def publish_to_chime_handler(event, context):
    # The Chime hook to use. This is specific to a room
    CHIME_HOOK_URL = os.environ['ChimeHookUrl']
    for record in event['Records']:
          requests.post(url=CHIME_HOOK_URL, json={ 'Content': json.loads(record['Sns']['Message'])['TextMessage'] })

