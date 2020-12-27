
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

ssmclient = boto3.client('ssm')

# Creates a Support Ticket in ITSM system about the incident

def lambda_handler(event, context):

    # TODO Implement ITSM Connectivity to log an incident in ITSM system
    # Python Sample to connect to ServiceNow
    #Need to install requests package for python

    # #easy_install requests
    # import requests
    #
    # # Set the request parameters
    # url = 'https://instance.service-now.com/api/now/table/incident'
    #
    # # Eg. User name="admin", Password="admin" for this code sample.
    # user = 'admin'
    # pwd = 'admin'
    #
    # # Set proper headers
    # headers = {"Content-Type":"application/xml","Accept":"application/xml"}
    #
    # # Do the HTTP request
    # response = requests.post(url, auth=(user, pwd), headers=headers ,data="<request><entry><short_description>Unable to connect to office wifi</short_description><assignment_group>287ebd7da9fe198100f92cc8d1d2154e</assignment_group><urgency>2</urgency><impact>2</impact></entry></request>")
    #
    # # Check for HTTP codes other than 200
    # if response.status_code != 200:
    #     print('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:',response.json())
    #     exit()
    #
    # # Decode the JSON response into a dictionary and use the data
    # data = response.json()
    # print(data)

    return event
