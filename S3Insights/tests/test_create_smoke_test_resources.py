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

from s3insights.lib import config
from s3insights.lib import ddb
from s3insights.lib import smoketest
import conftest


def test_simulate_smoke_test(initialize_environment_smoke_test, monkeypatch):
    monkeypatch.setattr(smoketest.config.ServiceParameters, 'smoke_test_sleep_time_in_seconds', 0)
    ddb.update_source_bucket_inventory_status(conftest.TestValues.test_bucket_1_name, ddb.BucketInventoryStatus.in_progress)
    prev_object_count = conftest.get_object_count(conftest.TestValues.regional_inventory_destination_bucket_name)
    input_parameters = initialize_environment_smoke_test.input_parameters
    smoketest.simulate(input_parameters)
    cur_object_count = conftest.get_object_count(conftest.TestValues.regional_inventory_destination_bucket_name)
    assert cur_object_count > prev_object_count
