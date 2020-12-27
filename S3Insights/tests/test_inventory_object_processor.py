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

import json

from s3insights.lib import config
from s3insights.lib import ddb
from s3insights.lib import s3
from s3insights.lib import utility

import conftest


def get_test_s3_notification(test_key):
    notification_file_path = utility.get_file_path(__file__, "data/samples3notificationinventoryobject.json")
    with open(notification_file_path, "r") as notification_file:
        notification_content = notification_file.read()
        notification_content = notification_content.replace('{BUCKET_NAME}', conftest.TestValues.regional_inventory_destination_bucket_name)
        notification_content = notification_content.replace('{KEY}', test_key)
        return json.loads(notification_content)


def mock_db_update():
    ddb.update_source_bucket_inventory_status(conftest.TestValues.test_bucket_1_name, ddb.BucketInventoryStatus.in_progress)
    ddb.update_source_bucket_inventory_status(conftest.TestValues.test_bucket_2_name, ddb.BucketInventoryStatus.in_progress)


def verify_s3_copy():
    notification = get_test_s3_notification(conftest.TestValues.sample_inventory_object_key)
    prev_object_count = conftest.get_object_count(config.DeploymentDetails.consolidated_inventory_bucket_name)
    s3.process_inventory_object(notification)
    new_object_count = conftest.get_object_count(config.DeploymentDetails.consolidated_inventory_bucket_name)
    assert new_object_count > prev_object_count


def test_copy_inventory_object(initialize_environment_smoke_test):
    mock_db_update()
    verify_s3_copy()


def test_detect_inventory_completion(initialize_environment_smoke_test):
    mock_db_update()
    notification = get_test_s3_notification(conftest.TestValues.sample_inventory_manifest_key)
    s3.process_inventory_object(notification)
    assert conftest.find_ddb_bucket(conftest.TestValues.test_bucket_1_name, ddb.BucketInventoryStatus.done)


def test_inventory_processor_out_of_order(initialize_environment_smoke_test):
    test_detect_inventory_completion(initialize_environment_smoke_test)
    verify_s3_copy()
