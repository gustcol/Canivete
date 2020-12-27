import os


def lambda_handler(event, context):
    # Setup the defaults for our response
    response = {
        'Status': 'SUCCESS',
        'UserName': os.urandom(16).encode('hex')
    }

    return response
