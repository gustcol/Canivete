package GitHub.buildTypes

import jetbrains.buildServer.configs.kotlin.v2019_2.*

object NagiosPluginKafka : BuildType({
    templates(HariSekhon_Make)
    uuid = "162394d7-0752-4b92-bc0c-7714599d9c66"
    name = "Nagios Plugin Kafka"
    description = "Kafka Scala API CLI / Advanced Nagios Plugin, with Kerberos support (uses Kafka 0.9+ native Java API)"

    vcs {
        root(GitHub.vcsRoots.NagiosPluginKafka_1)

        branchFilter = ""
    }
})
