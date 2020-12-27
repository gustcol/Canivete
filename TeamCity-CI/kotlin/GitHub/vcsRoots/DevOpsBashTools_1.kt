package GitHub.vcsRoots

import jetbrains.buildServer.configs.kotlin.v2019_2.*
import jetbrains.buildServer.configs.kotlin.v2019_2.vcs.GitVcsRoot

object DevOpsBashTools_1 : GitVcsRoot({
    uuid = "0d2b8ed7-dd0f-444b-a439-a38993ed20f6"
    id("DevOpsBashTools")
    name = "https://github.com/HariSekhon/DevOps-Bash-tools"
    url = "https://github.com/HariSekhon/DevOps-Bash-tools"
    branch = "refs/heads/master"
})
