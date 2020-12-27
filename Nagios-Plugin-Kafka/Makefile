#  vim:ts=4:sts=4:sw=4:noet
#
#  Author: Hari Sekhon
#  Date: 2016-06-06 22:57:08 +0100 (Mon, 06 Jun 2016)
#
#  https://github.com/harisekhon/nagios-plugin-kafka
#
#  License: see accompanying Hari Sekhon LICENSE file
#
#  If you're using my code you're welcome to connect with me on LinkedIn
#  and optionally send me feedback to help improve or steer this or other code I publish
#
#  https://www.linkedin.com/in/harisekhon
#

ifneq ("$(wildcard bash-tools/Makefile.in)", "")
	include bash-tools/Makefile.in
endif

# breaks in Alpine
#SHELL := /bin/bash
SHELL := sh

REPO := HariSekhon/Nagios-Plugin-Kafka

CODE_FILES := $(shell find . -type f -name '*.java' -o -type f -name '*.scala' | grep -v -e bash-tools -e /lib/)

ARGS=localhost:9092 test

DOCKER_IMAGE := harisekhon/nagios-plugin-kafka

# ===================
# bootstrap commands:

# Alpine:
#
#   apk add --no-cache git make && git clone https://github.com/harisekhon/nagios-plugin-kafka && cd nagios-plugin-kafka && make

# Debian / Ubuntu:
#
#   apt-get update && apt-get install -y make git && git clone https://github.com/harisekhon/nagios-plugin-kafka && cd nagios-plugin-kafka && make

# RHEL / CentOS:
#
#   yum install -y make git && git clone https://github.com/harisekhon/nagios-plugin-kafka && cd nagios-plugin-kafka && make

# ===================

.PHONY: build
build:
	$(MAKE) init
	$(MAKE) gradle

.PHONY: init
init:
	git submodule update --init --recursive

# used by CI
.PHONY: random-build
random-build:
	@# SBT + Maven Surefire plugin both get buffer overflow on openjdk7 :-/
	@x=$$(bash-tools/random_select.sh build mvn gradle sbt); echo $(MAKE) $$x; $(MAKE) $$x

.PHONY: maven
maven: mvn
	@:

.PHONY: mvn
mvn: init
	@echo ===================================
	@echo Nagios Plugin - Kafka - Maven Build
	@echo ===================================
	@$(MAKE) git-summary
	$(MAKE) lib-mvn
	./mvnw clean package
	ln -sfv target/check_kafka-*.jar check_kafka.jar

.PHONY: gradle
gradle: init
	@echo ====================================
	@echo Nagios Plugin - Kafka - Gradle Build
	@echo ====================================
	@$(MAKE) git-summary
	$(MAKE) lib-gradle
	./gradlew clean shadowJar
	ln -sfv build/libs/check_kafka-*.jar check_kafka.jar

.PHONY: sbt
sbt: init
	@echo =================================
	@echo Nagios Plugin - Kafka - SBT Build
	@echo =================================
	@$(MAKE) git-summary
	$(MAKE) lib-sbt
	sbt clean assembly
	ln -sfv target/scala-*/check_kafka-assembly-*.jar check_kafka.jar

# for testing
.PHONY: all
all:
	$(MAKE) mvn
	$(MAKE) gradle
	$(MAKE) sbt

.PHONY: lib-mvn
lib-mvn:
	cd lib && $(MAKE) mvn

.PHONY: lib-gradle
lib-gradle:
	cd lib && $(MAKE) gradle

.PHONY: lib-sbt
lib-sbt:
	cd lib && $(MAKE) sbt
	@#sbt eclipse || echo "Ignore this last error, you simply don't have the SBT eclipse plugin, it's optional"

.PHONY: clean
clean:
	cd lib && $(MAKE) clean
	./mvnw clean || :
	sbt clean || :
	./gradlew clean || :
	rm -f check_kafka.jar

.PHONY: deep-clean
deep-clean:
	$(MAKE) clean
	cd lib && $(MAKE) deep-clean
	@# done in lib
	@#rm -rf .gradle ~/.gradle/{caches,native,wrapper} ~/.m2/{repository,wrapper} ~/.ivy2 ~/.sbt/boot

# useful for quicker compile testing
.PHONY: p
p:
	$(MAKE) package
.PHONY: package
package:
	$(MAKE) lib
	sbt package

.PHONY: gradle-sonar
gradle-sonar:
	@# calls compileJava
	./gradlew sonarqube

.PHONY: mvn-sonar
mvn-sonar:
	./mvnw sonar:sonar

.PHONY: sonar-scanner
sonar-scanner:
	sonar-scanner

.PHONY: test
test:
	tests/all.sh

# make exec ARGS="<args>"
.PHONY: exec
exec:
	$(MAKE) run

# make run ARGS="<args>"
# clashes with bash-tools/Makefile.in
#.PHONY: run
#run:
#	$(MAKE) gradle-run

.PHONY: gradle-run
gradle-run:
	./gradlew run -P ARGS="${ARGS}"

.PHONY: mvn-exec
mvn-exec:
	./mvnw exec:java -Dexec.args="${ARGS}"

# make sbt-run ARGS="192.168.99.100:9092 test"
.PHONY: sbt-run
sbt-run:
	sbt "run ${ARGS}"

.PHONY: findbugs
findbugs:
	./mvnw compile
	./mvnw findbugs:findbugs
	./mvnw findbugs:gui

.PHONY: versioneye
versioneye:
	$(MAKE) mvn-versioneye
	$(MAKE) gradle-versioneye
	$(MAKE) sbt-versioneye

.PHONY: mvn-versioneye
mvn-versioneye:
	./mvnw versioneye:update

.PHONY: gradle-versioneye
gradle-versioneye:
	./gradlew versionEyeUpdate

.PHONY: sbt-versioneye
sbt-versioneye:
	sbt versioneye:updateProject

.PHONY: scalastyle
scalastyle:
	sbt scalastyle
