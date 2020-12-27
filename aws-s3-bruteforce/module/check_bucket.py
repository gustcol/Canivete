#!/usr/bin/env python
import random, requests, time, re
from lib.constants import base_url
from lib.logger import *

no_bucket_responses = [
                        "NoSuchBucket",
                        "InvalidBucketName",
                       ]
denied_responses = [
                    "AccessDenied",
                    "AllAccessDisabled",
                   ]


#S3 Connector
from boto.s3.connection import S3Connection

explained = {
    'READ': 'readable',
    'WRITE': 'writable',
    'READ_ACP': 'permissions readable',
    'WRITE_ACP': 'permissions writeable',
    'FULL_CONTROL': 'Full Control'
}
groups_to_check = {
    'http://acs.amazonaws.com/groups/global/AllUsers': 'Everyone',
    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers': 'Authenticated AWS users'
}


def check_s3_bucket(bucket_name, access_key, secret_key, output_file, redirect=False):
    #Initialize initial bucket variables
    bucket_result = {
                        "name":bucket_name,
                        "url":"{base_url}{bucket_name}".format(base_url=base_url, bucket_name=bucket_name),
                        "exists":False,
                        "public":None,
                        "authenticated_access":False,
                        "empty":False,
                        "error":False,
                        "redirected":False,
                    }


    #Check if you are in a redirect or are supposed to be redirected.
    if redirect:
        bucket_result["redirected"] = True
        bucket_result["url"] = "https://{bucket_name}.s3.amazonaws.com".format(bucket_name=bucket_name)
        request = get_bucket(url=bucket_result["url"])
    else:
        request = get_bucket(url=bucket_result["url"])
        #If a redirect is seen, go to it
        if "<Endpoint>" in request.text or "PermanentRedirect" in request.text:
            return check_s3_bucket(
                                    bucket_name=re.search("<Endpoint>(.+?)</Endpoint>", request.text).group(1).replace(".s3.amazonaws.com",""), 
                                    access_key=access_key, 
                                    secret_key=secret_key,
                                    output_file=output_file,
                                    redirect=True
                                  )
   
    #Check to see if the bucket does not exist
    for no_bucket_response in no_bucket_responses:
        if "<Code>{message}</Code>".format(message=no_bucket_response) in request.text:
            bucket_result["error"] = no_bucket_response
            # log_bucket_found(bucket_result=bucket_result, output_file=output_file)   #Not going to log non-existant buckets
            return

    for denied_response in denied_responses:
        if "<Code>{message}</Code>".format(message=denied_response) in request.text:
            bucket_result["exists"] = True
            bucket_result["public"] = False
            bucket_result["error"] = denied_response
            if denied_response == "AccessDenied":
                if access_key and secret_key:
                    try:
                        conn = S3Connection(access_key, secret_key)
                        bucket = conn.get_bucket(bucket_name)
                        issues = check_acl(bucket)
                        if issues:
                            bucket_result["authenticated_access"] = True
                            print '''
    ************************************************************************************
    AUTHENTICATED ACCESS - %s
    ************************************************************************************
    ''' % (bucket_result["url"])
                            # This is how you can get the keys if you want it.  Using it to test to see if there are any files
                            #This might take a while and seem like it's paused
                            for key in bucket.list():
                                bucket_result["empty"] = False
                    except Exception as e:
                        pass
            #Denied response seen so break from the check
            break

    #At this point the bucket exists, just seeing if it is empty
    else:
        bucket_result["exists"] = True
        bucket_result["public"] = True
        if "<Key>" in request.text:
            bucket_result["empty"] = False
        else:
            bucket_result["empty"] = True

    #Log the final result for the bucket
    log_bucket_found(bucket_result=bucket_result, output_file=output_file)


def get_bucket(url):
    #Get the response to the bucket's access, returning if there was an error
    try:
        return requests.get(url, verify=False)
    except:
        return None


def check_acl(bucket):
    issues = []
    acp = bucket.get_acl()
    for grant in acp.acl.grants:
        if grant.type == 'Group' and grant.uri in groups_to_check:
            issues.append(
                            {
                                "permission" : grant.permission,
                                "explained" : explained[grant.permission],
                                "grantee" :  groups_to_check[grant.uri]
                            }
                         )
    return issues
