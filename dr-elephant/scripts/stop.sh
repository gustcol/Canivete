#!/usr/bin/env bash

#
# Copyright 2016 LinkedIn Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
#

# Navigate to project root dir
script_dir=`which $0`
script_dir=`dirname $script_dir`
project_root=$script_dir/../
cd $project_root

# If file RUNNING_PID exists, it means Dr. Elephant is running
if [ -f RUNNING_PID ];
then
  echo "Dr.Elephant is running."
else
  echo "Dr.Elephant is not running."
  exit 1
fi

# RUNNING_PID contains PID of our Dr. Elephant instance
proc=`cat RUNNING_PID`

echo "Killing Dr.Elephant...."
kill $proc

# Wait for a while
sleep 1

# Play should remove RUNNING_PID when we kill the running process
if [ ! -f RUNNING_PID ];
then
  echo "Dr.Elephant is killed."
else
  echo "Failed to kill Dr.Elephant."
  exit 1
fi
