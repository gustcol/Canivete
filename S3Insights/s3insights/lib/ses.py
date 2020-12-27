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

import json
import logging

from lib import awshelper
from lib import config
from lib import ddb
from lib import utility


def send_email_verification_requests(input_parameters):
    """ Send email verification request

    Arguments:
        input_parameters {config.S3InsightsInput} -- Input parameters for the current execution
    """
    for recipient in input_parameters.recipient_email_addresses:
        send_email_verification_request(recipient)
    send_email_verification_request(input_parameters.sender_email_address)


def send_email_verification_request(email_address):
    """ Send email verification request for a specific email address

    Arguments:
        email_address {string} -- Email address
    """
    if is_email_address_verified(email_address) == False:
        ses_client = awshelper.get_client(awshelper.ServiceName.ses)
        response = ses_client.verify_email_identity(
            EmailAddress=email_address
        )
        logging.info('ses verify email api response:{0}'.format(response))

def get_verified_identities(identity_type):
    """ Return verified identities

    Arguments:
        identity_type {string} -- EmailAddress/Domain
    """
    ses_client = awshelper.get_client(awshelper.ServiceName.ses)
    verified_identities = []
    paginator = ses_client.get_paginator('list_identities')
    response_iterator = paginator.paginate(
        IdentityType=identity_type,
        PaginationConfig={
            'MaxItems': 1000,
            'PageSize': 100
        }
    )
    for response in response_iterator:
        verified_identities.extend(response['Identities'])
    return verified_identities


def is_email_address_verified(email_address):
    """ Check if an email address is already verified

    Arguments:
        email_address {string} -- Email address
    """
    if email_address is not None and len(email_address) > 0:
        for verified_email in get_verified_identities('EmailAddress'):
            if verified_email.casefold() == email_address.casefold():
                return True

        for verified_domain in get_verified_identities('Domain'):
            if email_address.lower().endswith("@" + verified_domain.lower()):
                return True

    return False

def send_welcome_email():
    """ Send welcome email
    """
    queries = ddb.get_athena_queries()
    query_details_html = '''
    <html>
        <head>
            <style>
                table, th, td {
                    border: 1px solid black;
                    border-collapse: collapse;
                }
                .success {
                    background-color: rgba(0, 255, 0, 0.2);
                }
                .failed {
                    background-color: rgba(255, 0, 0, 0.2);
                }
                .neutral {
                    background-color:white;
                }
            </style>
        </head>
    <body>
        <body>
        <p>
            Your latest <a href="https://github.com/kurmiashish/S3Insights/blob/master/docs/user_guide.md#how-to-initiate-a-state-machine-execution">S3Insights Harvester execution</a> generated this welcome email. You can learn more about the platform <a href="https://github.com/kurmiashish/S3Insights">here</a>.
        </p>
    '''
    intro_html = 'In this run, the following Athena queries were executed. You can run additional Athena queries manually by following <a href="https://github.com/kurmiashish/S3Insights/blob/master/docs/user_guide.md#running-athena-analysis-queries-manually">these instructions</a>. Please refer to the <a href="https://github.com/kurmiashish/S3Insights/blob/master/docs/troubleshooting.md#athena-failures">Athena troubleshooting document</a> if any of the following Athena queries have failed.'
    input_parameters = ddb.get_input_parameters()
    if input_parameters.is_smoke_test:
        intro_html = intro_html + ' <b>As this is a smoke test run, the following links may not work as the platform may have deleted the Athena resources.</b>'
    query_details_html = query_details_html + "<h4>Analysis Queries</h4><p>" + intro_html + "</p>"

    query_details_html = query_details_html + '''
    <table>
            <tr>
                <th>Name</th>
                <th>Query</th>
                <th>Status</th>
                <th>Execution Details</th>
            </tr>
    '''
    succeeded_status_value = 'succeeded'
    done_status_value = 'done'
    bucket_is_empty_status_value = 'bucket_is_empty'
    everything_else_status_value = 'everything_else'

    success_css_class_name = 'success'
    failed_css_class_name = 'failed'
    neutral_css_class_name = 'neutral'

    css_mappings = {
        succeeded_status_value: success_css_class_name,
        done_status_value: success_css_class_name,
        everything_else_status_value: failed_css_class_name,
        bucket_is_empty_status_value: neutral_css_class_name}

    for state in [succeeded_status_value, everything_else_status_value]:
        for query in queries:
            should_include = False
            if not utility.compare_strings(state, everything_else_status_value):
                should_include = utility.compare_strings(state, query.state)
            else:
                should_include = not utility.compare_strings(succeeded_status_value, query.state)

            if should_include:
                css_class_name = css_mappings[state]
                query_web_console_link = 'https://console.aws.amazon.com/athena/home?region={0}#query/history/{1}'.format(config.DeploymentDetails.region, query.query_execution_id)
                query_web_console_link_html = '<a href={0}> Web Console Link </a>'.format(query_web_console_link)
                query_details_html = query_details_html + f'<tr class="{css_class_name}"><td>' + ' </td><td>'.join([query.query_name, query.actual_query, query.state, query_web_console_link_html]) + '</td></tr>'

    query_details_html = query_details_html + '</table><br>'
    bucket_html_table = '''
            <h4>Source buckets</h4>
            <p>
                The following buckets are included in the analysis. If the platform failed to generate inventory for any of the buckets (i.e., if any entry in the following table is highlighted in Red), please consult the <a href="https://github.com/kurmiashish/S3Insights/blob/master/docs/troubleshooting.md#inventory-generation-failures">inventory generation troubleshooting document</a>.
            </p>
            <table>
            <tr>
                <th>Account</th>
                <th>Region</th>
                <th>Bucket</th>
                <th>Inventory Status</th>
            </tr>
    '''

    source_buckets = ddb.get_source_buckets()
    for account_id in source_buckets:
        # Let's calculate the value for rowspan
        account_row_span = sum([len(source_buckets[account_id][region]) for region in source_buckets[account_id]])
        inserted_account_row = False
        for region in source_buckets[account_id]:
            region_row_span = len(source_buckets[account_id][region])
            inserted_region_row = False
            for inventory_status in [done_status_value, bucket_is_empty_status_value, everything_else_status_value]:
                for bucket in source_buckets[account_id][region]:
                    should_include = False
                    if not utility.compare_strings(inventory_status, everything_else_status_value):
                        should_include = utility.compare_strings(inventory_status, bucket.inventory_status)
                    else:
                        already_included = utility.compare_strings(done_status_value, bucket.inventory_status) or utility.compare_strings(bucket_is_empty_status_value, bucket.inventory_status)
                        should_include = not already_included

                    if should_include:
                        css_class_name = css_mappings[inventory_status]
                        row = "<tr>"
                        if not inserted_account_row:
                            inserted_account_row = True
                            row =  row + "<td rowspan={0}>{1}</td>".format(account_row_span, account_id)
                        if not inserted_region_row:
                            inserted_region_row = True
                            row = row + "<td rowspan={0}>{1}</td>".format(region_row_span, region)
                        row = row + f'<td class="{css_class_name}">{bucket.name}</td>'
                        row = row + f'<td class="{css_class_name}">{bucket.inventory_status}</td></tr>'
                        bucket_html_table = bucket_html_table + row
    bucket_html_table = bucket_html_table + "</table>"
    query_details_html = query_details_html + bucket_html_table

    input_parameters_str = json.dumps(
                            input_parameters,
                            default=lambda input_parameters: input_parameters.__dict__,
                            sort_keys=True,
                            indent=4,
                            separators=(',', ': '))

    input_parameters_section = '''
<br>
<h4>Input Parameters</h4>
<p>
<div style="white-space: pre-wrap;">
The execution parameters used for this run are given below.
{0}
</div>
</p>
    '''.format(input_parameters_str)
    query_details_html = query_details_html + input_parameters_section + '</body></html>'
    logging.info(f'welcome email content:{query_details_html}')

    input_parameters = ddb.get_input_parameters()
    ses_client = awshelper.get_client(awshelper.ServiceName.ses)
    response = ses_client.send_email(
                    Destination={
                        'ToAddresses': input_parameters.recipient_email_addresses,
                    },
                    Message={
                        'Body': {
                            'Html': {
                                'Charset': 'UTF-8',
                                'Data': query_details_html,
                            },
                            'Text': {
                                'Charset': 'UTF-8',
                                'Data': query_details_html,
                            },
                        },
                        'Subject': {
                            'Charset': 'UTF-8',
                            'Data': 'Your S3Insights snapshot is ready',
                        },
                    },
                    Source=input_parameters.sender_email_address,
                )
    logging.info(f'send email api response:{response}')
