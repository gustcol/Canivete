# FixUserMFA
Demo script to automatically create a virtual MFA token and assign it to any IAM users created in the account.
Once created, the user will be able to fetch their own seed values using the AWS CLI.
The script has a function for sending the seed value using for example SNS but please use caution and don't send it over any unencrypted channels.
When using the self service functionality the seed number is stored encrypted using Parameter Store and deliver over TLS.

Once the user have the seed value they can simply paste it into any password manager that support TOTP tokens and start using MFA. There is no need for syncing since this is done server side by the Lambda function.
Example software for phones without any preferences are Google Authenticator or 1password. Please search for suitable software for your team.


## Execution
### Requirement
Verified with AWS Lambda [Python 2.7].

### Installation
1. Download the CloudFormation template called ForceUserMFA.template and the archive called ForceUserMFA.zip from this repo
2. Logon to the AWS Management console
3. Click Services and go to S3
4. Choose or create a bucket where you want to store the code for the Lambda function and upload the zip file.
5. Click Services and go to CloudFormation
6. Click "Create Stack"
7. Select "Upload a template to Amazon S3" followed by clicking "Choose File" and select the template file you downloaded and click Next
8. Choose a stackname. This can be anything you want to use to identify the various resources
9. Fill in the s3 bucket and path that the .zip file is stored in (step 4) and click Next
10. Click Next unless you want to run this as a separate user
11. Click the checkbox and then "Create"
Done


### Usage instructions
You have a few amount of option listed in the beginning of the Lambda function.
Using these you can choose if you want to enable delete on fail, logging and setting a random password on the user.
Since the script is using CloudWatch Events there is nothing you need to do once implemented.
When a IAM user is added it will automatically trigger and the Lambda function will create and attach a virtual MFA to the user.
Once attached the user can fetch their own virtual MFA "seed" info using the AWS CLI if they have access keys.
To fetch seed info they should use the following command if the username is user1
~~~~
aws ssm get-parameters --names mfa-user1 --with-decryption  --region us-east-1
~~~~

Note that admins with full access also have access to the seed stored in parameter store. Please restrict IAM access based on regular IAM best practices.

If enabled, the information like username, event time, seed will be stored in the selected DynamoDB table.
Please note that the seed will only be stored if the script could encrypt it first.

If delete on fail is enabled the script will automatically delete any created IAM user where it couldn't assign a virtual MFA.

Please note that this is a example project. Please exercise caution when using and follow AWS best practices around IAM.
***

Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/apache2.0/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
