package GitHub.buildTypes

import jetbrains.buildServer.configs.kotlin.v2019_2.*

object libjava : BuildType({
    templates(HariSekhon_Make)
    uuid = "41e229ba-c593-4eea-b5c2-bfb4edeab3d4"
    name = "lib-java"
    description = "Java Utility library for my other repos"

    vcs {
        root(GitHub.vcsRoots.LibJava)

        branchFilter = ""
    }
})
