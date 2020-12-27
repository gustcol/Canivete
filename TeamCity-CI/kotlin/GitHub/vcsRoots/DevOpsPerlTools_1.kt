package GitHub.vcsRoots

import jetbrains.buildServer.configs.kotlin.v2019_2.*
import jetbrains.buildServer.configs.kotlin.v2019_2.vcs.GitVcsRoot

object DevOpsPerlTools_1 : GitVcsRoot({
    uuid = "316cf6b2-a4d7-4b2e-a389-51dda7e8f083"
    id("DevOpsPerlTools")
    name = "https://github.com/HariSekhon/DevOps-Perl-tools"
    url = "https://github.com/HariSekhon/DevOps-Perl-tools"
    branch = "refs/heads/master"
})
