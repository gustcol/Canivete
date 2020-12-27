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
import logging
import json
import os
import urllib

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def access_denied_handler(event, context):
  if 'Records' in event:
    record = event['Records'][0]
    snsMessage = json.loads(record['Sns']['Message'])['detail']
    useridentity = snsMessage['userIdentity']
  else:
    useridentity = event['detail']['userIdentity']
    snsMessage = event['detail']

  # format initial message
  message = 'Access denied on event {0} occured in account {1} by {2}\n'.format(
      snsMessage['eventName'],
      useridentity['accountId'] if 'accountId' in useridentity else '<N/A>',
      useridentity['userName'] if 'userName' in useridentity else '<N/A>'
  )
  message += 'Event source: {0}\n'.format(snsMessage['eventSource'])
  message += 'Source agent: {0}\n'.format(snsMessage['sourceIPAddress'])
  message += 'Useragent: {0}\n'.format(snsMessage['userAgent'])
  if 'APIKey' in os.environ and os.environ['APIKey']:
    sourceIPAddress = snsMessage['sourceIPAddress']
    ip_geo_data = getIPGeoDetails(sourceIPAddress)
    country = ip_geo_data['location']['country'] if 'location' in ip_geo_data else 'N/A'
    region = ip_geo_data['location']['region'] if 'location' in ip_geo_data else 'N/A'
    city = ip_geo_data['location']['city'] if 'location' in ip_geo_data else 'N/A'
    ip_whois_data = getIPWhoisDetails(sourceIPAddress)
    owner = ip_whois_data['WhoisRecord']['registrant']['organization'] if 'WhoisRecord' in ip_whois_data else 'N/A'
    message += 'Location: {0}, {1}, {2}\n'.format(city, region, country)
    message += 'Source IP owner: {0}\n'.format(owner)

  # send message
  client = boto3.client('sns')
  client.publish(
      TopicArn=os.environ['TopicTarget'],
      Message=json.dumps({'TextMessage': message}),
  )

def publish_user_history(event, context):
  if 'Records' in event:
    record = event['Records'][0]
    snsMessage = json.loads(record['Sns']['Message'])['detail']
    useridentity = snsMessage['userIdentity']
  else:
    useridentity = event['detail']['userIdentity']
    snsMessage = event['detail']
  if useridentity['type'] != "AssumedRole":
    username = useridentity['userName'] # username
    client = boto3.client('cloudtrail')
    response = client.lookup_events(
        LookupAttributes=[
            {
                'AttributeKey': 'Username',
                'AttributeValue': username
            },
        ]
    )

    history = 'History for user:\n' if len(response['Events'])>0 else '\n No previous history reported for the user'
    len_events = 0
    for e in response['Events']:
        cloudtrailEvent = json.loads(e['CloudTrailEvent'])
        sourceIPAddress = cloudtrailEvent['sourceIPAddress']
        history += '{0}, Event: {1} IP: {2} Agent: {3}.\n'.format(
          str(e['EventTime']), # date/time
          e['EventName'], # action
          cloudtrailEvent['sourceIPAddress'], # ip
          cloudtrailEvent['userAgent'] # useragent
        )

        if 'APIKey' in os.environ and os.environ['APIKey']:
            ip_geo_data = getIPGeoDetails(sourceIPAddress)
            country = ip_geo_data['location']['country'] if 'location' in ip_geo_data else 'N/A'
            region = ip_geo_data['location']['region'] if 'location' in ip_geo_data else 'N/A'
            city = ip_geo_data['location']['city'] if 'location' in ip_geo_data else 'N/A'
            ip_whois_data = getIPWhoisDetails(sourceIPAddress)
            owner = ip_whois_data['WhoisRecord']['registrant']['organization'] if 'WhoisRecord' in ip_whois_data else 'N/A'
            history +='This IP is located in {0}, {1}, {2} and is owned by {3}\n'.format(city, region, country, owner)
        len_events += 1
        if len_events >= 5:
          break
    client = boto3.client('sns')
    client.publish(
        TopicArn=os.environ['TopicTarget'],
        Message=json.dumps({'TextMessage': history}),
    )

def publish_iam_user_history(event, context):
  if 'Records' in event:
    record = event['Records'][0]
    snsMessage = json.loads(record['Sns']['Message'])['detail']
    useridentity = snsMessage['userIdentity']
  else:
    useridentity = event['detail']['userIdentity']
    snsMessage = event['detail']
  if useridentity['type'] != "AssumedRole":
    username = useridentity['userName'] # username
    client = boto3.client('cloudtrail')
    response = client.lookup_events(
        LookupAttributes=[
            {
                'AttributeKey': 'ResourceName',
                'AttributeValue': username
            },
        ]
    )

    history = '\nHistory of IAM user:\n' if len(response['Events'])>0 else '\n No previous history reported for the user'
    len_events = 0
    for e in response['Events']:
        cloudtrailEvent = json.loads(e['CloudTrailEvent'])
        sourceIPAddress = cloudtrailEvent['sourceIPAddress']
        

        history += '{0}, Action:m {1}, performed by  {2}, from {3}\n'.format(
                              str(e['EventTime']), # date/time
                              e['EventName'], # action
                              e['Username'], # user/role name
                              cloudtrailEvent['sourceIPAddress'], # ip
                              cloudtrailEvent['userAgent'] # useragent
                            )
        if 'APIKey' in os.environ and os.environ['APIKey']:
            ip_geo_data = getIPGeoDetails(sourceIPAddress)
            country = ip_geo_data['location']['country'] if 'location' in ip_geo_data else 'N/A'
            region = ip_geo_data['location']['region'] if 'location' in ip_geo_data else 'N/A'
            city = ip_geo_data['location']['city'] if 'location' in ip_geo_data else 'N/A'
            ip_whois_data = getIPWhoisDetails(sourceIPAddress)
            owner = ip_whois_data['WhoisRecord']['registrant']['organization'] if 'WhoisRecord' in ip_whois_data else 'N/A'
            history +='This IP is located in {0}, {1}, {2} and is owned by {3}\n'.format(city, region, country, owner)

        len_events += 1
        if len_events >= 5:
          break
    client = boto3.client('sns')
    client.publish(
        TopicArn=os.environ['TopicTarget'],
        Message=json.dumps({'TextMessage': history}),
    )

def getIPGeoDetails(sourceIPAddress):
  try:
    api_key = os.environ['APIKey']
    url = 'https://geoipify.whoisxmlapi.com/api/v1?apiKey=' + api_key + '&ipAddress=' + sourceIPAddress
    ip_geo_data = (urllib.urlopen(url).read().decode('utf8'))
    ip_geo_data = json.loads(ip_geo_data)
    return ip_geo_data
  except:
    ip_geo_data = {}
    ip_geo_data = json.dumps(ip_geo_data)
    return ip_geo_data

def getIPWhoisDetails(sourceIPAddress):
  try:
    api_key = os.environ['APIKey']
    url = 'https://www.whoisxmlapi.com/whoisserver/WhoisService?outputFormat=JSON&apiKey=' + api_key + '&domainName=' + sourceIPAddress
    logger.info(url)
    ip_whois_data = (urllib.urlopen(url).read().decode('utf8'))
    ip_whois_data = json.loads(ip_whois_data)
    return ip_whois_data
  except:
    logger.error()
    ip_whois_data = {}
    ip_whois_data = json.dumps(ip_whois_data)
    return ip_whois_data
