#!/usr/bin/env bash
#  vim:ts=4:sts=4:sw=4:et
#
#  Author: Hari Sekhon
#  Date: 2015-05-25 01:38:24 +0100 (Mon, 25 May 2015)
#
#  https://github.com/harisekhon/nagios-plugin-kafka
#
#  License: see accompanying Hari Sekhon LICENSE file
#
#  If you're using my code you're welcome to connect with me on LinkedIn and optionally send me feedback to help improve or steer this or other code I publish
#
#  http://www.linkedin.com/in/harisekhon
#

set -euo pipefail
[ -n "${DEBUG:-}" ] && set -x
srcdir_nagios_plugin_kafka_help="${srcdir:-}"
srcdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd "$srcdir/..";

# shellcheck disable=SC1091
. ./tests/utils.sh

section "Testing --help"

help_start_time="$(start_timer)"

test_help(){
    local prog="$1"
    echo "./$prog --help"
    set +e
    "./$prog" --help # >/dev/null
    status=$?
    set -e
    [ $status = 3 ] || { echo "status code for $prog --help was $status not expected 3"; exit 1; }
}

test_help check_kafka

srcdir="$srcdir_nagios_plugin_kafka_help"

time_taken "$help_start_time" "Help Checks Completed in"
section2 "Help integration test completed with expected exit code 3"
echo
