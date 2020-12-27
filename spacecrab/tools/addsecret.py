#!/usr/bin/env python
# -*- coding: utf-8 -*-
import boto3
import base64
import os
import json
from collections import OrderedDict

# there's two kinds of secrets we can do:
# * throw it at the kms now and just store the encrypted value locally
# * put it in the stack params and pass it down to the encrypt stack and back up.
# the second one's a nightmare so let's just get kms to do it now.

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

def get_value(prompt, confirm_prompt, default=None):
    print('\n')
    # this sucks if your string has whitespace at the start or end. But uh. Don't do that. I don't know.
    x = raw_input(prompt).strip()
    if r'%s' in confirm_prompt:  # really m8
        confirm_prompt = confirm_prompt % x
    a = yesno(confirm_prompt, default)
    if a:
        return x
    else:
        return get_value(prompt, confirm_prompt, default)


kms = boto3.client('kms')
cfn = boto3.client('cloudformation')

exports = cfn.list_exports().get('Exports',None)

kms_arn = None
crabstack = None

if exports:
    for export in exports:
        # there is probably a better way to do this. Do you know what it is?
        if export['Name']=='KMSKeyArn' and 'SpaceCrabStack' in export['ExportingStackId']:
            kms_arn = export['Value']
            crabstack = export['ExportingStackId']
            break
if kms_arn:
    sekrit = get_value('Please enter the string you would like to encrypt: ','Is "%s" your string (now in quotes)? ', 'y')
    codes = kms.encrypt(KeyId=kms_arn, Plaintext=sekrit)
    safe_sekrit = base64.b64encode(codes['CiphertextBlob'])
    name = get_value('Please enter a name for your value: ', 'Is "%s" correct? ', 'y')
    description = get_value('Please enter a description for the value: ', 'is "%s" correct? ', 'y')

    secret = {"Type": "String",
            "Description": description,
            "Default": safe_sekrit,
            "NoEcho": "true"
            }


    print('ok, updating template file')
    script_path = os.path.realpath(__file__)
    template_path = os.path.relpath('CloudFormationTemplates', script_path)
    bootstrap_path = os.path.join(template_path, 'bootstrap.template')
    with open(bootstrap_path, 'r+') as f:
        template = json.load(f, object_pairs_hook=OrderedDict)
        template['Parameters'][name] = secret
        f.seek(0)
        json.dump(template, f, indent=2)
        f.truncate()

    print('template file updated, glhf')
