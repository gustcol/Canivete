package GitHub.vcsRoots

import jetbrains.buildServer.configs.kotlin.v2019_2.*
import jetbrains.buildServer.configs.kotlin.v2019_2.vcs.GitVcsRoot

object DevOpsPythonTools_1 : GitVcsRoot({
    uuid = "df811a05-a76b-45fb-9726-e22fb61f496c"
    id("DevOpsPythonTools")
    name = "https://github.com/HariSekhon/DevOps-Python-tools"
    url = "https://github.com/HariSekhon/DevOps-Python-tools"
    branch = "refs/heads/master"
})
