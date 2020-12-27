package GitHub.vcsRoots

import jetbrains.buildServer.configs.kotlin.v2019_2.*
import jetbrains.buildServer.configs.kotlin.v2019_2.vcs.GitVcsRoot

object Pylib : GitVcsRoot({
    uuid = "392f4ec8-3a57-421c-a91d-3bbda511d258"
    name = "https://github.com/HariSekhon/pylib"
    url = "https://github.com/HariSekhon/pylib"
    branch = "refs/heads/master"
})
