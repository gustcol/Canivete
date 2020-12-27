package GitHub.vcsRoots

import jetbrains.buildServer.configs.kotlin.v2019_2.*
import jetbrains.buildServer.configs.kotlin.v2019_2.vcs.GitVcsRoot

object Dockerfiles_1 : GitVcsRoot({
    uuid = "c7f78004-2cbb-4aee-abf4-491fbbc77dde"
    id("Dockerfiles")
    name = "https://github.com/HariSekhon/Dockerfiles"
    url = "https://github.com/HariSekhon/Dockerfiles"
    branch = "refs/heads/master"
})
