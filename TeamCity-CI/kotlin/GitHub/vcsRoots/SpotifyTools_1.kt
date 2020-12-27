package GitHub.vcsRoots

import jetbrains.buildServer.configs.kotlin.v2019_2.*
import jetbrains.buildServer.configs.kotlin.v2019_2.vcs.GitVcsRoot

object SpotifyTools_1 : GitVcsRoot({
    uuid = "0757fd51-fd5d-450e-b44b-dab3c063e4ad"
    id("SpotifyTools")
    name = "https://github.com/HariSekhon/Spotify-tools"
    url = "https://github.com/HariSekhon/Spotify-tools"
    branch = "refs/heads/master"
})
