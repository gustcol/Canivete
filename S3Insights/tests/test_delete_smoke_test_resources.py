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

from s3insights.lib import awshelper
from s3insights.lib import config
from s3insights.lib import s3
from s3insights.lib import smoketest
from s3insights.lib import utility


def test_delete_smoke_test_resources(initialize_environment_smoke_test):
    encountered_exception = False
    try:
        smoketest.cleanup_and_verify()
    except Exception:
        encountered_exception = True
    assert encountered_exception is True


def test_delete_smoke_test_resources_success(initialize_environment_smoke_test):
    input_parameters = initialize_environment_smoke_test.input_parameters
    s3_client = awshelper.get_client(awshelper.ServiceName.s3)
    consolidated_bucket_name = config.DeploymentDetails.consolidated_inventory_bucket_name
    object_path = s3.get_inventory_prefix_at_consolidated_bucket(input_parameters.run_id) + utility.random_string()
    body = bytes('hello world', 'utf-8')
    s3_client.put_object(
        Bucket=consolidated_bucket_name,
        Key=object_path,
        Body=body)

    encountered_exception = False
    try:
        smoketest.cleanup_and_verify()
    except Exception:
        encountered_exception = True
    assert encountered_exception is False
