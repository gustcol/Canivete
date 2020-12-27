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
from s3insights.lib import s3

import conftest


def get_bucket_count():
    s3_client = awshelper.get_client(awshelper.ServiceName.s3)
    response = s3_client.list_buckets()
    return len(response['Buckets'])


def test_delete_destination_buckets(initialize_environment_smoke_test):
    prev_object_count = conftest.get_object_count(conftest.TestValues.regional_inventory_destination_bucket_name)
    input_parameters = initialize_environment_smoke_test.input_parameters
    s3.delete_regional_s3_inventory_bucket(input_parameters, 'us-west-2')
    cur_object_count = conftest.get_object_count(conftest.TestValues.regional_inventory_destination_bucket_name)
    assert cur_object_count == 0
    assert cur_object_count < prev_object_count
