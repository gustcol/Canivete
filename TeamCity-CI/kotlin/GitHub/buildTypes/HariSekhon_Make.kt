package GitHub.buildTypes

import jetbrains.buildServer.configs.kotlin.v2019_2.*
import jetbrains.buildServer.configs.kotlin.v2019_2.buildSteps.ScriptBuildStep
import jetbrains.buildServer.configs.kotlin.v2019_2.buildSteps.script
import jetbrains.buildServer.configs.kotlin.v2019_2.triggers.vcs

object HariSekhon_Make : Template({
    uuid = "6772834c-5c5a-4839-a1e5-ef02de94f568"
    name = "Make"
    description = "Standard 'make' build"

    allowExternalStatus = true
    publishArtifacts = PublishMode.SUCCESSFUL

    vcs {
        branchFilter = "+:refs/origin/master"
    }

    steps {
        script {
            name = "CI Bootstrap"
            id = "RUNNER_0"
            scriptContent = "setup/ci_bootstrap.sh"
        }
        script {
            name = "Make"
            id = "RUNNER_1"
            scriptContent = "make"
            dockerImagePlatform = ScriptBuildStep.ImagePlatform.Linux
        }
        script {
            name = "Make Test"
            id = "RUNNER_2"
            scriptContent = "make test"
        }
    }

    triggers {
        vcs {
            id = "vcsTrigger"
            branchFilter = "+:refs/heads/master"
        }
    }

    failureConditions {
        executionTimeoutMin = 120
    }
})
