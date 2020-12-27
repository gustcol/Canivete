package GitHub

import GitHub.buildTypes.*
import GitHub.vcsRoots.*
import jetbrains.buildServer.configs.kotlin.v2019_2.*
import jetbrains.buildServer.configs.kotlin.v2019_2.Project
import jetbrains.buildServer.configs.kotlin.v2019_2.projectFeatures.VersionedSettings
import jetbrains.buildServer.configs.kotlin.v2019_2.projectFeatures.versionedSettings

object Project : Project({
    uuid = "c1d58244-9121-4df0-8ffd-57966bb7c3ab"
    id("GitHub")
    parentId("_Root")
    name = "Hari Sekhon GitHub Projects"
    description = "HariSekhon's GitHub Projects Builds"
    defaultTemplate = AbsoluteId("HariSekhon_Make")

    vcsRoot(DevOpsBashTools_1)
    vcsRoot(NagiosPluginKafka_1)
    vcsRoot(Pylib)
    vcsRoot(lib_1)
    vcsRoot(DevOpsPerlTools_1)
    vcsRoot(DevOpsPythonTools_1)
    vcsRoot(NagiosPlugins_1)
    vcsRoot(SpotifyTools_1)
    vcsRoot(HAProxyConfigs_1)
    vcsRoot(LibJava)
    vcsRoot(Dockerfiles_1)

    buildType(DevOpsBashTools)
    buildType(NagiosPluginKafka)
    buildType(libjava)
    buildType(lib)
    buildType(DevOpsPerlTools)
    buildType(DevOpsPythonTools)
    buildType(NagiosPlugins)
    buildType(SpotifyTools)
    buildType(HAProxyConfigs)
    buildType(pylib)
    buildType(Dockerfiles)

    template(HariSekhon_Make)

    features {
        versionedSettings {
            id = "PROJECT_EXT_4"
            mode = VersionedSettings.Mode.ENABLED
            buildSettingsMode = VersionedSettings.BuildSettingsMode.PREFER_CURRENT_SETTINGS
            rootExtId = "TeamCity"
            showChanges = false
            storeSecureParamsOutsideOfVcs = true
        }
    }
})
