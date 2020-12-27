
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
ec2client = boto3.client('ec2')

def lambda_handler(event, context):

    #Create Instances 
    response = ec2client.run_instances(
            ImageId=os.environ['AMI_ID'],
            InstanceType='t2.small',
            MaxCount=1,
            MinCount=1,
            Monitoring={
                'Enabled': True
            },

            IamInstanceProfile={
                'Arn': os.environ['INSTANCE_PROFILE']
            },
            # UserData = '#!/bin/bash \n cd /tmp \n sudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_386/amazon-ssm-agent.rpm \n sudo amazon-ssm-agent start',

            UserData = "#!/bin/bash \n export instancehostname=$(hostname) \n sudo sed -i -e 's/127.0.0.1 localhost/127.0.0.1 localhost '$instancehostname'/g' /etc/hosts \n mkdir /tmp/ssm \n cd /tmp/ssm \n wget https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb \n sudo dpkg -i amazon-ssm-agent.deb \n sudo systemctl enable amazon-ssm-agent \n sudo systemctl start amazon-ssm-agent \n",
            KeyName = os.environ['EC2_KEYPAIR'],
            NetworkInterfaces = [
                {
                    'AssociatePublicIpAddress': True,
                    'DeviceIndex': 0,
                    'SubnetId': os.environ['SUBNET_ID'],
                    'Groups': [
                        os.environ['FORENSIC_SECUTRITYGROUP'],
                    ],
                }
            ],
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': 'InstanceUnderForensics'
                        },{
                            'Key': 'IsInstanceTested',
                            'Value': 'Yes'
                        },
                    ]
                },
            ]
    )
    print (response['Instances'][0]['Placement']['AvailabilityZone'])
    # Wait for instanca to be in runnign state

    waiter = ec2client.get_waiter('instance_running')
    waiter.wait(InstanceIds=[response['Instances'][0]['InstanceId']])
    event['ForensicInstanceId'] = response['Instances'][0]['InstanceId']
    event['availabilityZone'] = response['Instances'][0]['Placement']['AvailabilityZone']
    event['SSM_STATUS'] ='WAIT'
    return event
