#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import glob
import zipfile
import random
import string
import time
import json
import boto3
import botocore.exceptions
from fqdn import FQDN

SPACECRAB = r"""
  __                __
 / /_   ___   ___  _\ \
 \  /  (_*_) (_*_) \  /                          PROJECT
  { }    |     |   { }    _____ ____  ___   ______________________  ___    ____
   \\/''''''''''''\//    / ___// __ \/   | / ____/ ____/ ____/ __ \/   |  / __ )
   (  . + *   ˚  .  )    \__ \/ /_/ / /| |/ /   / __/ / /   / /_/ / /| | / __ \
    \  +   +  * ˚  /    ___/ / ____/ ___ / /___/ /___/ /___/ _, _/ ___ |/ /_/ /
     \  ˚   *  ˚  /    /____/_/   /_/  |_\____/_____/\____/_/ |_/_/  |_/_____/
     //'//''''\\'\\
     V  V      V  V
"""


def wait_on_stack(stackId):
    '''
    Boto waiter doesn't provide user feedback while waiting on a CFN stack so we implement our own in wait_on_stack() passing in a CFN stackId
    '''
    cfn = boto3.client('cloudformation')

    created = False
    while not created:
        time.sleep(3)

        response = cfn.describe_stacks(StackName=stackId)
        if response['Stacks'][0]['StackStatus'] == 'CREATE_COMPLETE':
            return True
        elif response['Stacks'][0]['StackStatus'] == 'CREATE_IN_PROGRESS':
            print("  ...")
        elif response['Stacks'][0]['StackStatus'] == 'CREATE_FAILED':
            print('Building stack %s failed. The mysterious AWS related reason is found in the AWS Console ...' % response['Stacks'][0]['StackName'])
            sys.exit(1)
        else:
            print('Stack %s entered an unexpected state %s!' % (response['Stacks'][0]['StackName'], response['Stacks'][0]['StackStatus']) )
            sys.exit(1)

def get_buckets(OwnerArn=None):
    template_bucket = None
    function_bucket = None
    api_bucket = None
    s3 = boto3.client('s3')
    region = s3._client_config.region_name
    bucket_response = s3.list_buckets()
    for bucket in bucket_response['Buckets']:
        if "spacecrabcodebucketstack-templatecodebucket" in bucket['Name']:
            bucket_region = s3.get_bucket_location(Bucket=bucket['Name'])
            bucket_region = bucket_region['LocationConstraint']
            if bucket_region == region or (bucket_region is None and region == "us-east-1"):
                template_bucket = bucket['Name']
        elif "spacecrabcodebucketstack-functioncodebucket" in bucket['Name']:
            bucket_region = s3.get_bucket_location(Bucket=bucket['Name'])
            bucket_region = bucket_region['LocationConstraint']
            if bucket_region == region or (bucket_region is None and region == "us-east-1"):
                function_bucket = bucket['Name']
        elif "spacecrabcodebucketstack-apicodebucket" in bucket['Name']:
            bucket_region = s3.get_bucket_location(Bucket=bucket['Name'])
            bucket_region = bucket_region['LocationConstraint']
            if bucket_region == region or (bucket_region is None and region == "us-east-1"):
                api_bucket = bucket['Name']
    if None in [template_bucket, function_bucket, api_bucket]:
        # deploy the bucket stack
        print("We can't find the S3 bucket stack, redeploying...")
        with open('CloudFormationTemplates/bootstrap-code-buckets.template', 'r') as f:
            bucket_template = "\n".join(f.readlines())
        cfn = boto3.client('cloudformation')
        if OwnerArn:
            parameters = {
                'OwnerArn': OwnerArn
            }
            parameters = convert_parameters(parameters)
            response = cfn.create_stack(StackName='SpaceCrabCodeBucketStack',
                                        TemplateBody=bucket_template,
                                        Parameters=parameters)
        else:
            response = cfn.create_stack(StackName='SpaceCrabCodeBucketStack',
                                        TemplateBody=bucket_template)
        # Hurry up an wait for CFN
        wait_on_stack(response['StackId'])
        return get_buckets()
    return (template_bucket, function_bucket, api_bucket)


def zip_directory(directory):
    # make a zip file called 'directory' and fill it with the things in directory
    if '/' in directory:
        zipname = directory.split('/')[-1]
    else:
        zipname = directory
    zipf = zipfile.ZipFile(zipname+'.zip', 'w', zipfile.ZIP_DEFLATED)
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file == '.DS_Store':
                continue
            file_root = os.path.join(root, file)
            # next line removes the first directory from the 'archive name' so it doesn't break aws
            file_path = os.path.join(*(file_root.split(os.path.sep)[1:]))
            zipf.write(file_root, file_path)
    zipf.close()
    return zipname + '.zip'


def convert_parameters(params):
    retval = []
    for k, v in params.iteritems():
        if v is None:
            retval.append({'ParameterKey': k, 'UsePreviousValue': True})
        else:
            retval.append({'ParameterKey': k, 'ParameterValue': v})
    return retval


def yesno(prompt, default=None):
    retval = {
        'y': True,
        'n': False
        }
    options = "y/n"
    if default == 'y':
        options = 'Y/n'
    if default == 'n':
        options = 'y/N'

    a = raw_input(prompt + ' ' + options + ': ').lower()

    try:
        if a[0].lower() in ['y', 'n']:
            return retval[a[0].lower()]
        else:
            print("Sorry, I didn't understand that.")
            return yesno(prompt, default)
    except IndexError:
        if default:
            return retval[default]
        else:
            print('Please answer. Pls.')
            return yesno(prompt, default)


def input_to_email():
    addr = raw_input('Please enter an email address to send alert messages to: ').strip()
    a = yesno("Is %s the correct 'to' email?" % addr, 'y')
    if a:
        return addr
    else:
        print("OK! Trying again.\n")
        return input_to_email()


def input_from_email():
    addr = raw_input('Please enter an email address to send alert messages from: ').strip()
    a = yesno("Is %s the correct 'from' email?" % addr, 'y')
    if a:
        return addr
    else:
        print("OK! Trying again.\n")
        return input_from_email()


def get_region():
    regions = {
        1: 'us-east-1',
        2: 'us-west-2',
        3: 'eu-west-1'
    }
    print("\nPlease choose the SES endpoint you'd like to use.\n" +
          "Keep in mind that you must have verified your email or domain\n" +
          " - on this endpoint specifically -\n" +
          "for this to work.\n"
          )
    for k, v in regions.iteritems():
        print('%s:\t%s' % (k, v))
    region = raw_input('Enter a number or region name: ')
    if region.lower() not in regions.values():
        try:
            if int(region) in regions:
                region = regions[int(region)]
        except ValueError:
            a = yesno("I'm not sure what you mean so I'm going to choose us-west-2, ok?", 'y')
            if not a:
                print("OK, trying again.")
                return get_region()
            region = 'us-west-2'
    print(region)
    return region


def update_get_email():
    retval = {
        'email': None,
        'from_email': None,
        'region': None
    }
    a = yesno("\nWould you like to update your email settings", 'n')
    if a:
        return get_email()
    return retval


def get_email():
    a = yesno("\nWould you like to send alerts via email?", 'y')
    retval = {
        'email': 'DONTUSE',
        'from_email': 'DONTUSE',
        'region': 'DONTUSE'
    }
    if not a:
        return retval
    print("\nYou will need to set up SES in AWS for the email/domain you are using.\n" +
          "You can read AWS's documentation about that here:\n" +
          "http://docs.aws.amazon.com/ses/latest/DeveloperGuide/verify-addresses-and-domains.html" +
          "\nGood luck.\n"
          )
    email = input_to_email()
    a = yesno("\nWould you like to use the same email as the from address?", 'y')
    if not a:
        from_email = input_from_email()
    else:
        from_email = email
    a = yesno("\nOK, we'll send emails:\nFrom: %s\nTo: %s\nIs this ok?" % (from_email, email), 'y')
    if not a:
        return get_email()
    retval['email'] = email
    retval['from_email'] = from_email

    # set up SES region business.
    region = get_region()
    retval['region'] = region

    print("OK, testing SES a bit.")

    ses = boto3.client('ses', region_name=region)

    try:
        domain = from_email.split('@')[-1]
        print("  Checking domain...")
        r = ses.get_identity_verification_attributes(
            Identities=[domain]
        )
        if domain in r['VerificationAttributes']:
            if r['VerificationAttributes'][domain]['VerificationStatus'] == 'Success':
                # verified by domain, ok
                print("    The domain %s is verified in region %s.\n" % (domain, region))
        else:
            print("    The domain %s is not?? verified in region %s" % (domain, region))
            print("    Proceed at your own risk!\n")

        print("  Checking email...")
        r = ses.get_identity_verification_attributes(
            Identities=[from_email]
        )
        if from_email in r['VerificationAttributes']:
            if r['VerificationAttributes'][from_email]['VerificationStatus'] == 'Success':
                # verified specific address, ok
                print("    The email %s is verified in region %s.\n" % (from_email, region))
        else:
            print("    The email %s is not?? verified in region %s." % (from_email, region))
            print("    Proceed at your own risk!\n")
    except botocore.exceptions.ClientError as e:
        print(e)
        print("Something horrible has happened with AWS. We'll try and carry on regardless.")

    return retval


def input_pagerduty_token():
    pagerdutytoken = raw_input(
        "Please enter a Pagerduty Events API v2 integration key: "
        ).strip()
    a = yesno("Using %s for Pagerduty Integration, is this correct?" % pagerdutytoken,
              'y')
    if a:
        return pagerdutytoken
    else:
        print("OK! Trying again.\n")
        return input_pagerduty_token()


def input_admin_arn():
    arn = raw_input(
        "Please enter an ARN to use as admin/owner: "
        ).strip()
    a = yesno("Using %s as admin/owner, is this correct?" % arn,
              'y')
    if a:
        return arn
    else:
        print("OK! Trying again.\n")
        return input_admin_arn()


def update_get_pagerduty_token(pagerdutytoken=None):
    a = yesno("\nWould you like to update your pagerduty settings?", 'n')
    if a:
        return get_pagerduty_token(pagerdutytoken)
    else:
        return None


def get_pagerduty_token(pagerdutytoken=None):
    a = yesno("\nWould you like to send alerts to PagerDuty?", 'y')
    if a:
        print("\nWe will need a Pagerduty Events API v2 integration key for this alert to work.")
        if pagerdutytoken:
            b = yesno("We found this token in your environment variables: " + pagerdutytoken +
                      "\nWould you like to use it?", 'y')
            if b:
                return pagerdutytoken

        return input_pagerduty_token()
    else:
        return "DONTUSE"


def get_current_userid():
    retval = {}
    retval['account'] = None
    retval['type'] = None
    retval['id'] = None
    retval['name'] = None
    sts = boto3.client('sts')
    callid = sts.get_caller_identity()
    arn = callid['Arn']
    # arn:aws:sts::accountID:federated-user/username
    # arn:aws:iam::accountID:user/username
    # arn:aws:sts::accountID:assumed-role/role-name/someusername
    bits = arn.split(':')[-2:]
    retval['account'] = bits[0]
    name_bits = bits[1].split('/')
    retval['type'] = name_bits[0]
    retval['name'] = name_bits[1]
    if ':' in callid['UserId']:
        retval['id'] = callid['UserId'].split(':')[0]
    else:
        retval['id'] = callid['UserId']
    return retval


def get_permission_stuff():
    r = get_current_userid()
    account = r['account']
    name = r['name']
    user_type = r['type']
    if user_type == 'assumed-role':
        user_type = 'role'
    # "arn:aws:iam::222222222222:role/ROLENAME",
    # "arn:aws:iam::222222222222:user/USERNAME"
    arn = 'arn:aws:iam::%s:%s/%s' % (account, user_type, name)
    print('\nIn order to secure your SPACECRAB infrastructure, we will need to limit access to a' +
          ' certain user or role')
    print('You are currently authenticated as:\n')
    print(arn)
    a = yesno('Would you like to use %s as your admin %s?' % (arn, user_type), 'y')
    if a:
        return arn
    else:
        return input_admin_arn()


def get_spacecrab_path():
    print("\nWe'll need a path, which will be part of the generated token's ARNs.")
    print("The path must start and end with /")
    print("Consider *not* using /SpaceCrab/ or anything like it.")
    print("i.e. make this something plausible if attackers see the path.")
    path = raw_input(
        'Please enter a "Path" for your users: '
        ).strip()
    if len(path) == 0:
        path = get_spacecrab_path()
    if path[0] != '/':
        path = '/' + path
    if path[-1] != '/':
        path = path + '/'
    a = yesno("\nWe'll use the path \"%s\", is this ok?" % path, 'y')
    if a:
        return path
    else:
        return get_spacecrab_path()

def get_spacecrab_custom_fqdn():
    custom_fqdn = {}
    use_custom_domain = yesno('Would you like to use a custom FQDN for the SpaceCrab API ?', 'n')
    if use_custom_domain:
        print("NOTE: You need to configure your DNS CNAME record yourself after SpaceCrab deployment\n")
        print("See https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-custom-domains.html for more details\n\n")
        domain = raw_input(
            'Please enter a Fully Qualified Domain Name for your API gateway: '
            )
        fqdn = FQDN(domain)
        if fqdn.is_valid:
            a = yesno("\nWe'll use the domain \"%s\", is this ok?" % fqdn, 'y')
            if a:
                custom_fqdn['CustomFqdn'] = domain
            else:
                print("Domain name failed to validate, trying again \n")
                return get_spacecrab_custom_fqdn()
        print("NOTE: Your ACM ARN must already exist before SpaceCrab deployment otherwise CloudFormation WILL fail\n")
        print("See https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-custom-domains-prerequisites.html for more details\n\n")
        acm_arn = raw_input(
            'Please enter the ARN for your ACM certificate: '
            )
        try:
            client = boto3.client('acm')
            response = client.describe_certificate(
                CertificateArn=acm_arn
            )

            if response['Certificate']['Status'] == "ISSUED":
                print("Validated certificate issued and available for domain %s" % response['Certificate']['DomainName'])
            else:
                print("Validated certificate %s exists, but has issues. Status is %s Investigate in the ACM console." % response['Certificate']['CertificateArn'], response['Certificate']['Status'])
                sys.exit(1)
            custom_fqdn['CustomFqdnAcmArn'] = response['Certificate']['CertificateArn']
        except Exception as e:
            print(e)
            print("Something broke, try again .. \n")
            return get_spacecrab_custom_fqdn()
        return custom_fqdn
    else:
        # Return an emptry string because CloudFormation type validation ...
        custom_fqdn['CustomFqdn'] =  ""
        custom_fqdn['CustomFqdnAcmArn'] =  ""
        return custom_fqdn


def upload_s3_contents(s3, cfn, template_bucket, function_bucket, api_bucket):
    # upload cfn templates to template_bucket
    print("\nUploading CloudFormation templates.")
    for template in glob.glob('CloudFormationTemplates/*.template'):
        name = template.split('/')[-1]
        print("  Uploading %s" % name)
        s3.upload_file(template, template_bucket, name)
        response = cfn.validate_template(
            TemplateURL='https://s3.amazonaws.com/%s/%s' % (template_bucket, name)
            )
        # this will throw an error if the template is malformed. Educational so not suppressed.

    # upload function lambdas to function bucket
    print("\nUploading Lambda function zips.")
    for function in glob.glob('*Function/'):
        function = function[:-1]  # look it ensures we're getting directories. I'm lazy.
        # I mean I could use os.walk or whatever but I'm not a computer guy.
        zipf = zip_directory(function)  # ... uses os.walk
        print("  Uploading %s" % zipf)
        s3.upload_file(zipf, function_bucket, zipf)

    # upload swagger.json to API bucket
    oas_filename = "api/swagger.json"
    try:
        with open(oas_filename, 'r') as f:
            tags = json.load(f)
    except json.JSONDecodeError as e:
        print("JSON validation failed for %s at %s" % e.doc, e.pos)
        sys.exit(1)
    print("\nUploading %s " % oas_filename)
    name = oas_filename.split('/')[-1]
    s3.upload_file(oas_filename, api_bucket, name)


def burndown(cfn):
    a = yesno("\nDo you really want to destroy the whole stack?", 'n')
    if not a:
        return
    print("OK. We will keep the backups, etc, but we'll destroy what we can.\n")
    print("Deleting stack 'SpaceCrabStack'")
    cfn.delete_stack(StackName='SpaceCrabStack')
    print("\nThis process takes significant time, and sometimes fails.")
    print("You can check in the AWS console to make sure it's deleting.\n")
    print("Clearing out s3 buckets.")
    template_bucket = None
    function_bucket = None
    api_bucket = None
    s3 = boto3.client('s3')
    region = s3._client_config.region_name
    bucket_response = s3.list_buckets()
    for bucket in bucket_response['Buckets']:
        if "spacecrabcodebucketstack-templatecodebucket" in bucket['Name']:
            bucket_region = s3.get_bucket_location(Bucket=bucket['Name'])
            bucket_region = bucket_region['LocationConstraint']
            if bucket_region == region or (bucket_region is None and region == "us-east-1"):
                template_bucket = bucket['Name']
        elif "spacecrabcodebucketstack-functioncodebucket" in bucket['Name']:
            bucket_region = s3.get_bucket_location(Bucket=bucket['Name'])
            bucket_region = bucket_region['LocationConstraint']
            if bucket_region == region or (bucket_region is None and region == "us-east-1"):
                function_bucket = bucket['Name']
        elif "spacecrabcodebucketstack-apicodebucket" in bucket['Name']:
            bucket_region = s3.get_bucket_location(Bucket=bucket['Name'])
            bucket_region = bucket_region['LocationConstraint']
            if bucket_region == region or (bucket_region is None and region == "us-east-1"):
                api_bucket = bucket['Name']
    if function_bucket:
        delete_bucket(s3, function_bucket)
    if template_bucket:
        delete_bucket(s3, template_bucket)
    if api_bucket:
        delete_bucket(s3, api_bucket)
    r = cfn.delete_stack(StackName='SpaceCrabCodeBucketStack')
    print("\n\nOK, hopefully it's all gone now. Please check the console to confirm.")
    sys.exit(0)


def delete_bucket(s3, bucket):
    objects = []
    r = s3.list_objects(Bucket=bucket)
    while r['IsTruncated']:
        for b in r['Contents']:
            objects.append({'Key': b['Key']})
        r = s3.list_objects(Bucket=bucket, Marker=r['Marker'])
    for b in r['Contents']:
        objects.append({'Key': b['Key']})
    # I'm going to pretend for now that we'll never have more than 1000 objects in a bucket.
    # I know it's wrong but I'm doing it anyway. Pull requests gratefully accepted.
    Delete = {'Objects': objects}
    s3.delete_objects(Bucket=bucket, Delete=Delete)
    i = 0
    while i < 5:
        try:
            s3.delete_bucket(Bucket=bucket)
            i = 50
        except botocore.exceptions.ClientError:
            i += 1
            time.sleep(5)  # wait for deletes? idk.
    if i != 50:
        print("Unable to delete bucket %s for some reason. Sorry." % bucket)
        return
    print("Deleted bucket %s" % bucket)


def new_stack(cfn):
    print("\n\nWelcome to Project SPACECRAB setup.\n" +
          "We'll begin constructing SPACECRAB infrastructure shortly,\n" +
          "but first we'll need to collect some data.\n"
          )
    arn = get_permission_stuff()
    token_user_path = get_spacecrab_path()
    custom_fqdn = get_spacecrab_custom_fqdn()
    PagerdutyApiToken = os.environ.get('PAGERDUTY_API_KEY', None)
    pagerdutytoken = get_pagerduty_token(PagerdutyApiToken)
    alertemail = get_email()
    from_email = alertemail['from_email']
    region = alertemail['region']
    alertemail = alertemail['email']

    s3 = boto3.client('s3')
    template_bucket, function_bucket, api_bucket = get_buckets(arn)
    try:
        upload_s3_contents(s3, cfn, template_bucket, function_bucket, api_bucket)
    except Exception as e:
        print(e)
        print("We had an error updating the stack." +
              " If you can't resolve it, burn the stack down and redeploy.")
    chars = string.printable.translate(None, '"@/ \t\n\r\x0b\x0c')  # thanks amzn
    db_master_pass = ''.join(random.SystemRandom().choice(chars) for _ in range(128))
    db_user_pass = ''.join(random.SystemRandom().choice(chars) for _ in range(128))

    # smash out everything else
    parameters = {}
    parameters['FunctionCodeBucket'] = function_bucket
    parameters['TemplateCodeBucket'] = template_bucket
    parameters['PagerdutyApiToken'] = pagerdutytoken
    parameters['AlertEmailAddress'] = alertemail
    parameters['AlertFromAddress'] = from_email
    parameters['MasterDatabasePassword'] = db_master_pass
    parameters['FunctionDatabasePassword'] = db_user_pass
    parameters['IamTokenUserPath'] = token_user_path
    parameters['SESRegion'] = region
    parameters['OwnerArn'] = arn
    parameters['CustomFqdn'] = custom_fqdn['CustomFqdn']
    parameters['CustomFqdnAcmArn'] = custom_fqdn['CustomFqdnAcmArn']
    parameters = convert_parameters(parameters)
    # getting tags
    with open('tags.json', 'r') as f:
        tags = json.load(f)
    print("\nDeploying space outside the crab ...")
    try:
        response = cfn.create_stack(StackName='SpaceCrabVpcStack',
                         TemplateURL='https://s3.amazonaws.com/%s/bootstrap-networking.template'
                                     % template_bucket,
                         Capabilities=['CAPABILITY_IAM'],
                         Tags=tags['tags'])
        # VPC is required for deployment, ETA is usually 3-4 minutes.
        # Hurry up an wait for CFN
        wait_on_stack(response['StackId'])
    except botocore.exceptions.ClientError as error_msg:
        if 'AlreadyExistsException' in error_msg or 'already exists' in error_msg:
            print("Using existing SpaceCrabVpcStack ...")
            pass

    print("\nDeploying space inside the crab, prepare to wait a long time ... ")
    cfn.create_stack(StackName='SpaceCrabStack',
                     TemplateURL='https://s3.amazonaws.com/%s/bootstrap.template'
                                 % template_bucket,
                     Parameters=parameters,
                     TimeoutInMinutes=60,
                     Capabilities=['CAPABILITY_IAM'],
                     Tags=tags['tags'])


def update_stack(cfn):

    print("\nWelcome back! We can see a deployed SPACECRAB stack.\n")
    a = yesno('Would you like to destroy the stack?', 'n')
    if a:
        burndown(cfn)
    a = yesno('Would you like to update the stack?', 'y')
    template_bucket, function_bucket, api_bucket = get_buckets()
    if not a:
        print('\nOK, see you later!')
        sys.exit()
    print("\nOK, we'll ask a few questions.")
    # do "asking questions about parameters bits"
    custom_fqdn = get_spacecrab_custom_fqdn()
    alertemail = update_get_email()
    from_email = alertemail['from_email']
    region = alertemail['region']
    alertemail = alertemail['email']
    PagerdutyApiToken = os.environ.get('PAGERDUTY_API_KEY', None)
    pagerdutytoken = update_get_pagerduty_token(PagerdutyApiToken)

    parameters = {}
    parameters['FunctionCodeBucket'] = function_bucket
    parameters['TemplateCodeBucket'] = template_bucket
    if pagerdutytoken is not None:
        parameters['PagerdutyApiToken'] = pagerdutytoken
    if alertemail is not None:
        parameters['AlertEmailAddress'] = alertemail
        parameters['AlertFromAddress'] = from_email
        parameters['SESRegion'] = region
    parameters['CustomFqdn'] = custom_fqdn['CustomFqdn']
    parameters['CustomFqdnAcmArn'] = custom_fqdn['CustomFqdnAcmArn']
    parameters = convert_parameters(parameters)

    with open('tags.json', 'r') as f:
        tags = json.load(f)

    s3 = boto3.client('s3')
    try:
        upload_s3_contents(s3, cfn, template_bucket, function_bucket, api_bucket)
    except Exception as e:
        print(e)
        print("We had an error updating the stack." +
              " If you can't resolve it, burn the stack down and redeploy.")

    print("Updating stack")
    try:
        cfn.update_stack(StackName='SpaceCrabStack',
                         TemplateURL='https://s3.amazonaws.com/%s/bootstrap.template'
                                     % template_bucket,
                         Parameters=parameters,
                         Capabilities=['CAPABILITY_IAM'],
                         Tags=tags['tags'])
    except botocore.exceptions.ClientError as e:
        print(e)
        print("We had an error updating the stack." +
              " If you can't resolve it, burn the stack down and redeploy.")
    # better update the lambdas also in case they're being dumb

    lam = boto3.client('lambda')
    print("Updating lambdas")
    for function in glob.glob('*Function/'):
        function = function[:-1]
        try:
            lam.update_function_code(
                FunctionName=function,
                S3Bucket=function_bucket,
                S3Key=function + '.zip'
                )
        except Exception as e:
            print(e)
            print("This is probably ok, dwaboutit\n")
    print("Finished pushing updates, check CloudFormation for progress.")
    sys.exit(0)


def main(argv):

    print(SPACECRAB)
    cfn = boto3.client('cloudformation')
    try:
        r = cfn.describe_stacks(StackName='SpaceCrabStack')
        # exception if the stack doesn't exist. Handy.
        update_stack(cfn)
    except botocore.exceptions.ClientError:
        new_stack(cfn)


if __name__ == "__main__":
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        print("\nHooroo!")
