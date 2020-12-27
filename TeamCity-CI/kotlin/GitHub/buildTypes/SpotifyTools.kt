package GitHub.buildTypes

import jetbrains.buildServer.configs.kotlin.v2019_2.*

object SpotifyTools : BuildType({
    templates(HariSekhon_Make)
    uuid = "3054519b-53b6-4d2a-a6fb-0df5842b1cb0"
    name = "Spotify tools"
    description = "Spotify Tools - Playlists Backups, Spotify CLI, URI translator, duplication detection / removal, API search queries, API automation etc."

    vcs {
        root(GitHub.vcsRoots.SpotifyTools_1)

        branchFilter = ""
    }
})
