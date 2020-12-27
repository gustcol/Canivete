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
from s3insights.lib import ddb
from s3insights.lib import s3
import conftest


def mock_db_update():
    ddb.update_source_bucket_inventory_status(conftest.TestValues.test_bucket_1_name, ddb.BucketInventoryStatus.in_progress)
    ddb.update_source_bucket_inventory_status(conftest.TestValues.test_bucket_2_name, ddb.BucketInventoryStatus.in_progress)


def test_detect_bucket_updates(initialize_environment_smoke_test):
    mock_db_update()
    input_parameters = initialize_environment_smoke_test.input_parameters
    s3_client = awshelper.get_client(awshelper.ServiceName.s3)
    s3_client.delete_object(
        Bucket=conftest.TestValues.test_bucket_1_name,
        Key='sampleobject')
    s3_client.delete_bucket(Bucket=conftest.TestValues.test_bucket_1_name)
    s3.update_source_bucket_inventory_status(
        input_parameters,
        conftest.TestValues.test_account_id)
    assert conftest.find_ddb_bucket(conftest.TestValues.test_bucket_1_name, ddb.BucketInventoryStatus.bucket_not_available)
    assert conftest.find_ddb_bucket(conftest.TestValues.test_bucket_2_name, ddb.BucketInventoryStatus.bucket_is_empty)
