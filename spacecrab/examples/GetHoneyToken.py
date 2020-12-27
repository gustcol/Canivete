import json
import boto3


def get_input(prompt, validation=None):
    try:
        s = raw_input(prompt + ': ')
    except EOFError:
        if validation == 'NONBLANK':
            print("Sorry, I can't accept this treatment.")
            s = get_input(prompt, validation)
        else:
            s = ''
    return s.lower()


def main():
    client = boto3.client('lambda')
    response = client.invoke(FunctionName='AddTokenFunction')
    if response['StatusCode'] == 200:
        payload = json.loads(response['Payload'].read())
        AccessKey = payload['AccessKey']
        AccessKeyId = AccessKey['AccessKeyId']
        SecretKey = AccessKey['SecretAccessKey']
        UserName = AccessKey['UserName']
        s = get_input("Would you like to add owner/location details? y/n", 'NONBLANK')
        if s.startswith('y'):
            location = get_input("Please enter the location you'll store these credentials (optional)")
            owner = get_input("Please enter the owner of these credentials (optional)")
            notes = get_input("Please enter any notes about these credentials (optional)")
            expiry = get_input("Please enter an expiry for these credentials  (optional, yyyy-mm-dd)")
            payload = {"Location": location, "Owner": owner, "Notes": notes, "AccessKeyId": AccessKeyId}
            if expiry != "":
                payload['ExpiresAt'] = expiry
            payload = json.dumps(payload)
            r = client.invoke(
                FunctionName='UpdateTokenFunction',
                Payload=payload
                )
            import pprint
            pprint.pprint(r)
        s = get_input("Store credentials to file? Y/n")
        if s == "" or s.startswith('y'):
            with open('%s-credentials' % UserName, 'w') as f:
                f.write("[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n" %
                        (AccessKeyId, SecretKey))
            print("Wrote aws configuration for %s to %s" % (UserName, UserName+'-credentials'))
        s = get_input("print environment variable exports? Y/n")
        if s == "" or s.startswith('y'):
            print("export AWS_ACCESS_KEY_ID=%s\nexport AWS_SECRET_ACCESS_KEY=%s\n" %
                  (AccessKeyId, SecretKey))


main()
