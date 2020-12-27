TeamCity CI Config
==================

[![TeamCity](https://img.shields.io/badge/TeamCity-Configs-blue?logo=teamcity)](https://github.com/HariSekhon/TeamCity-CI)
[![CI Builds Overview](https://img.shields.io/badge/CI%20Builds-Overview%20Page-blue?logo=circleci)](https://bitbucket.org/harisekhon/devops-bash-tools/src/master/STATUS.md)
[![Repo on Azure DevOps](https://img.shields.io/badge/repo-Azure%20DevOps-0078D7?logo=azure%20devops)](https://dev.azure.com/harisekhon/GitHub/_git/TeamCity-CI)
[![Repo on GitHub](https://img.shields.io/badge/repo-GitHub-2088FF?logo=github)](https://github.com/HariSekhon/TeamCity-CI)
[![Repo on GitLab](https://img.shields.io/badge/repo-GitLab-FCA121?logo=gitlab)](https://gitlab.com/HariSekhon/TeamCity-CI)
[![Repo on BitBucket](https://img.shields.io/badge/repo-BitBucket-0052CC?logo=bitbucket)](https://bitbucket.org/HariSekhon/TeamCity-CI)

[![Linux](https://img.shields.io/badge/OS-Linux-blue?logo=linux)]()
[![Mac](https://img.shields.io/badge/OS-Mac-blue?logo=apple)]()
[![GitHub Last Commit](https://img.shields.io/github/last-commit/HariSekhon/TeamCity-CI?logo=github)](https://github.com/HariSekhon/TeamCity-CI/commits/master)

[TeamCity](https://www.jetbrains.com/teamcity/) CI configurations, synchronized from my automated TeamCity cluster.


### TeamCity configuration

- `.teamcity/` - XML format live sync'd
- `exports/` - JSON exports using API scripts in [DevOps Bash tools](https://github.com/HariSekhon/DevOps-Bash-tools) repo
- `.teamcity.vcs.json` - VCS connection to this repo
- `kotlin/` - Kotlin exports from UI


### Automation:

- [DevOps Bash tools](https://github.com/HariSekhon/DevOps-Bash-tools):
  - `teamcity.sh` - create your own [TeamCity](https://www.jetbrains.com/teamcity/) cluster in 1 command
    - auto-loads VCS root to this repo which then loads a dozen more buildTypes and VCS roots
  - `teamcity_api.sh` - query the [TeamCity API](https://www.jetbrains.com/help/teamcity/rest-api.html), handling authentication and other details
  - `jenkins.sh` - one-touch [Jenkins CI](https://jenkins.io/) instance
     - auto-loads and builds a pipeline from `Jenkinsfile` if available
  - `concourse.sh` - one-touch [Concourse CI](https://concourse-ci.org/) instance
    - auto-loads and builds a pipeline from `.concourse.yml` if available
  - `gocd.sh` - one-touch [GoCD CI](https://www.gocd.org/) cluster
    - auto-loads and builds a pipeline from a config repo if available


### See Also

- [Templates](https://github.com/HariSekhon/Templates) - templates for many CI systems, code and configs eg. Jenkinsfile, GitHub Actions, Travis CI, CircleCI, GCP Cloud Build, Makefile, Vagrantfile, Dockerfile, docker-compose.yml etc.

- [Advanced Nagios Plugins](https://github.com/HariSekhon/Nagios-Plugins) - 450+ production monitoring checks including for the Jenkins API


### CI Systems

All my [major GitHub repos](https://github.com/HariSekhon) contain fully working live configs for most major CI system out there:

##### Local CI:

You can boot any of these CI and run the repo's build with a single short one-word command using the scripts above.

- [Jenkins](https://www.jenkins.io/) - `Jenkinsfile` at the top of each repo
- [Concourse](https://concourse-ci.org/) - `.concourse.yml` at the top of each repo
- [GoCD](https://www.gocd.org/) - `setup/gocd_config_repo.json` in each repo
- [TeamCity](https://www.jetbrains.com/teamcity/) - `.teamcity.vcs.json` connection to this repo

##### Hosted CI:

- [AppVeyor](https://www.appveyor.com/)
- [AWS CodeBuild](https://aws.amazon.com/codebuild/)
- [Azure DevOps Pipelines](https://dev.azure.com/)
- [BitBucket Pipelines](https://bitbucket.org/product/features/pipelines)
- [Buddy](https://buddy.works/)
- [BuildKite](https://buildkite.com/)
- [Circle CI](https://circleci.com/)
- [Cirrus CI](https://cirrus-ci.org/)
- [CodeShip](https://codeship.com/)
- [Codefresh](https://codefresh.io/)
- [Drone.io](https://drone.io/)
- [GCP Cloud Build](https://cloud.google.com/cloud-build)
- [GitHub Actions Workflows](https://github.com/features/actions)
- [GitLab CI](https://docs.gitlab.com/ee/ci/)
- [Semaphore CI](https://semaphoreci.com/)
- [Shippable](https://www.shippable.com/)
- [Travis CI](https://travis-ci.org/)
- [Wercker](https://app.wercker.com/)
