#
#  Author: Hari Sekhon
#  Date: 2020-12-07 23:55:13 +0000 (Mon, 07 Dec 2020)
#
#  vim:ts=4:sts=4:sw=4:noet
#
#  https://github.com/HariSekhon/TeamCity-CI
#
#  If you're using my code you're welcome to connect with me on LinkedIn and optionally send me feedback to help steer this or other code I publish
#
#  https://www.linkedin.com/in/HariSekhon
#

# For serious Makefiles see the DevOps Bash tools repo:
#
#	https://github.com/HariSekhon/DevOps-Bash-tools
#
#	Makefile
#	Makefile.in - generic include file with lots of Make targets


# only works in GNU make - is ignored by Mac's built-in make - not portable, should avoid and call bash scripts instead
#.ONESHELL:
# make oneshell exit on first error
#.SHELLFLAGS = -e

SHELL = /usr/bin/env bash

BASH_TOOLS :=

ifneq ("$(wildcard $(HOME)/github/bash-tools)", "")
    BASH_TOOLS := $(HOME)/github/bash-tools
else
# neither command nor comments must not be indented otherwise gets this error:
# *** commands commence before first target.  Stop.
$(error BASH_TOOLS is not set and was not found adjacent to this repo)
endif

.PHONY: build
build: exports
	@:

.PHONY: exports
exports: export
	@:

.PHONY: export
export:
	@echo
	@echo "Running Exports of JSON format configs to exports/ directory using TeamCity API scripts from DevOps Bash tools repo"
	@#@echo
	@# set in heading variable and glob test for this $HOME/github/bash-tools path
	@#@echo "DevOps Bash tools repo is assumed to be available at \$$HOME/github/bash-tools"
	@echo
	# teamcity_local() is a function in DevOps Bash tools .bash.d/teamcity.sh
	# that figures out the TeamCity API token used in the API scripts below
	. $(BASH_TOOLS)/.bash.d/teamcity.sh && \
	teamcity_local && \
	cd exports/GitHub/ && \
		$(BASH_TOOLS)/teamcity_projects_download.sh && \
		mv -v GitHub.json project-config.json && \
		rm -f _Root.json && \
	cd buildTypes && \
		$(BASH_TOOLS)/teamcity_buildtypes_download.sh && \
	cd ../vcsRoots && \
		$(BASH_TOOLS)/teamcity_vcs_roots_download.sh && \
	rm -f TeamCity.json

.PHONY: wc
wc:
	find  .teamcity/GitHub/ -type f | xargs wc -l
