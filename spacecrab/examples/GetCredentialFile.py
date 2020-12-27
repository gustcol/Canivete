import sys
import json
import boto3
import pprint

bashformat = "\nexport AWS_ACCESS_KEY_ID=%s\nexport AWS_SECRET_ACCESS_KEY=%s\n\n"
awsformat = "[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n"


def main():
    if len(sys.argv) > 1 and sys.argv[1].lower() in ['-h', 'help']:
        print("Usage: %s [filename]" % sys.argv[0])
        print("Without [filename] will print bash environment variable export commands.")
        print("With [filename] will write an AWS configuration file with credentials to [filename]")
        sys.exit()
    client = boto3.client('lambda')
    response = client.invoke(FunctionName='AddTokenFunction')
    if response['StatusCode'] == 200:
        payload = json.loads(response['Payload'].read())
        AccessKey = payload['AccessKey']
        AccessKeyId = AccessKey['AccessKeyId']
        SecretKey = AccessKey['SecretAccessKey']
    else:
        print("Something went wrong. I don't know.")
        pprint.pprint(payload)
    if len(sys.argv) == 1:
        print bashformat % (AccessKeyId, SecretKey)
    else:
        with open(sys.argv[1], 'w') as f:
            # are you serious you're just taking user input and writing to it?
            # fine. This is fine. Don't even worry about it.
            f.write(awsformat % (AccessKeyId, SecretKey))


main()
