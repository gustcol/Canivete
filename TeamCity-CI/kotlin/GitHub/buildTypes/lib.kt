package GitHub.buildTypes

import jetbrains.buildServer.configs.kotlin.v2019_2.*

object lib : BuildType({
    templates(HariSekhon_Make)
    uuid = "94a22678-b401-4751-b10b-9dc5e64a2668"
    name = "lib"
    description = "Perl Utility Library for my other repos"

    vcs {
        root(GitHub.vcsRoots.lib_1)

        branchFilter = ""
    }
})
