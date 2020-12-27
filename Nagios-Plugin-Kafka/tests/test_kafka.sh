#!/usr/bin/env bash
#  vim:ts=4:sts=4:sw=4:et
#
#  Author: Hari Sekhon
#  Date: 2016-01-26 23:36:03 +0000 (Tue, 26 Jan 2016)
#
#  https://github.com/harisekhon/nagios-plugin-kafka
#
#  License: see accompanying Hari Sekhon LICENSE file
#
#  If you're using my code you're welcome to connect with me on LinkedIn and optionally send me feedback
#
#  https://www.linkedin.com/in/harisekhon
#

set -euo pipefail
[ -n "${DEBUG:-}" ] && set -x

srcdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd "$srcdir/.."

# shellcheck disable=SC1090
. "$srcdir/utils.sh"

echo "
# ============================================================================ #
#                                   K a f k a
# ============================================================================ #
"

# TODO: latest container 2.11_0.10 doesn't work yet, no leader takes hold
#export KAFKA_VERSIONS="2.11_0.10 2.11_0.10 latest"
export KAFKA_VERSIONS="${*:-latest 2.10-0.8 2.11-0.8 2.10-0.9 2.11-0.9}"
# TODO: hangs on 0.8, fix later
export KAFKA_VERSIONS="${*:-2.10-0.9}"

if ! is_docker_available; then
    echo 'WARNING: Docker not found, skipping Kafka checks!!!'
    exit 0
fi

KAFKA_HOST="${DOCKER_HOST:-${KAFKA_HOST:-${HOST:-localhost}}}"
KAFKA_HOST="${KAFKA_HOST##*/}"
KAFKA_HOST="${KAFKA_HOST%%:*}"
export KAFKA_HOST

export ZOOKEEPER_PORT="${ZOOKEEPER_PORT:-2181}"
export KAFKA_PORT="${KAFKA_PORT:-9092}"

export DOCKER_IMAGE="harisekhon/kafka"
export DOCKER_CONTAINER="nagios-plugins-kafka-test"

export KAFKA_TOPIC="nagios-plugins-kafka-test"

check_docker_available

# needs to be longer than 10 to allow Kafka to settle so topic creation works
startupwait 20

test_kafka(){
    local version="$1"
    echo "Setting up Apache Kafka $version test container"
    hr
    export ADVERTISED_HOSTNAME="$KAFKA_HOST"
    docker_compose_pull
    VERSION="$version" docker-compose up -d
    hr
    # startupwait assigned in lib
    # shellcheck disable=SC2154
    when_ports_available "$startupwait" "$KAFKA_HOST" "$KAFKA_PORT"
    hr
    echo "checking if Kafka topic already exists:"
    set +o pipefail
    # false positive - not an array but a regex with kafka topic var followed by character class
    # shellcheck disable=SC1087
    if docker-compose exec "$DOCKER_SERVICE" kafka-topics.sh --zookeeper localhost:2181 --list | tee /dev/stderr | grep -q "^[[:space:]]*$KAFKA_TOPIC[[:space:]]*$"; then
        echo "Kafka topic $KAFKA_TOPIC already exists, continuing"
    else
        echo "creating Kafka test topic:"
        for i in {1..20}; do
            echo "try $i / 20"
            # Older versions of Kafka eg. 0.8 seem to return 0 even when this fails so check the output instead
            if docker-compose exec "$DOCKER_SERVICE" kafka-topics.sh --zookeeper localhost:2181 --create --replication-factor 1 --partitions 1 --topic "$KAFKA_TOPIC" | tee /dev/stderr | grep -q -e 'Created topic' -e 'already exists'; then
                break
            fi
            echo
            sleep 1
        done
    fi
    set -o pipefail
    if [ -n "${NOTESTS:-}" ]; then
        return 0
    fi
    hr
    # 'scala' command not found on Travis CI
    ./check_kafka -B "$KAFKA_HOST:$KAFKA_PORT" -T "$KAFKA_TOPIC"
    hr
    [ -n "${KEEPDOCKER:-}" ] ||
    docker-compose down
    echo
}

# want splitting
# shellcheck disable=SC2086
for version in $(ci_sample $KAFKA_VERSIONS); do
    test_kafka $version
done
