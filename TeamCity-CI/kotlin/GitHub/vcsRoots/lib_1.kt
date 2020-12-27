package GitHub.vcsRoots

import jetbrains.buildServer.configs.kotlin.v2019_2.*
import jetbrains.buildServer.configs.kotlin.v2019_2.vcs.GitVcsRoot

object lib_1 : GitVcsRoot({
    uuid = "7f1650ea-ef19-4960-a326-31b56d8df836"
    id("lib")
    name = "https://github.com/HariSekhon/lib"
    url = "https://github.com/HariSekhon/lib"
    branch = "refs/heads/master"
})
