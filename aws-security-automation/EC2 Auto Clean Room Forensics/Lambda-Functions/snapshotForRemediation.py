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
import os

def lambda_handler(event, context):
    # TODO implement
    print (event)
    client = boto3.client('ec2')
    instanceID = event.get('instanceID')
    response = client.describe_instances(

        InstanceIds=[
            instanceID
        ]
    )
    volumeID = response['Reservations'][0]['Instances'][0]['BlockDeviceMappings'][0]['Ebs']['VolumeId']
    print (volumeID)
    SnapShotDetails = client.create_snapshot(
        Description='Isolated Instance',
        VolumeId=volumeID
    )
    # TODO Dump Response into S3 - response
    # TODO Dump Response details into Snapshot - SnapShotDetails['SnapshotId']

    print (response)
    print (SnapShotDetails['SnapshotId'])

    response = client.modify_instance_attribute(

        Groups=[
            os.environ['ISOLATED_SECUTRITYGROUP'],
        ],
        InstanceId=instanceID
    )

    tagresponse = client.create_tags(

        Resources=[
            instanceID,
        ],
        Tags=[
            {
                'Key': 'IsIsolated',
                'Value': 'InstanceIsolated'
            },
        ]
    )

    waiter = client.get_waiter('snapshot_completed')
    waiter.wait(
        SnapshotIds=[
            SnapShotDetails['SnapshotId'],
        ]
    )
    # event['SnapshotId'] = SnapShotDetails['SnapshotId']
    return SnapShotDetails['SnapshotId']
