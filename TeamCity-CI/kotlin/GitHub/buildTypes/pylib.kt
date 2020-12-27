package GitHub.buildTypes

import jetbrains.buildServer.configs.kotlin.v2019_2.*

object pylib : BuildType({
    templates(HariSekhon_Make)
    uuid = "c5c58ca8-dc4c-42d5-ad18-6e0e0e06f2c5"
    name = "pylib"
    description = "Python / Jython Utility Library for my other repos"

    vcs {
        root(GitHub.vcsRoots.Pylib)

        branchFilter = ""
    }
})
