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

from s3insights.lib import account_iterator
from s3insights.lib import config
from s3insights.lib import ddb
from s3insights.lib import sqs

import conftest


def test_are_inventories_ready_true(initialize_environment_smoke_test):
    ready_status = ddb.have_inventory_jobs_finished() and sqs.is_notification_queue_empty()
    assert ready_status is True


def test_are_inventories_ready_false(initialize_environment_smoke_test):
    ddb.update_source_bucket_inventory_status(conftest.TestValues.test_bucket_1_name, ddb.BucketInventoryStatus.in_progress)
    ddb.update_source_bucket_inventory_status(conftest.TestValues.test_bucket_2_name, ddb.BucketInventoryStatus.in_progress)
    ready_status = ddb.have_inventory_jobs_finished() and sqs.is_notification_queue_empty()
    assert ready_status is False


def test_inventory_monitor_loop(initialize_environment_smoke_test):
    iterator = account_iterator.iterate_to_track_progress_of_inventory_jobs()
    assert iterator[config.ServiceParameters.iterator_continue_key_name] is False
