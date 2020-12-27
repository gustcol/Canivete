package GitHub.vcsRoots

import jetbrains.buildServer.configs.kotlin.v2019_2.*
import jetbrains.buildServer.configs.kotlin.v2019_2.vcs.GitVcsRoot

object HAProxyConfigs_1 : GitVcsRoot({
    uuid = "52539268-d78d-4d47-9271-d3b546e34f2a"
    id("HAProxyConfigs")
    name = "https://github.com/HariSekhon/HAProxy-Configs"
    url = "https://github.com/HariSekhon/HAProxy-Configs"
    branch = "refs/heads/master"
})
