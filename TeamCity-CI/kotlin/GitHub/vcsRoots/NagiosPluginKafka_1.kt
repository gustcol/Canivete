package GitHub.vcsRoots

import jetbrains.buildServer.configs.kotlin.v2019_2.*
import jetbrains.buildServer.configs.kotlin.v2019_2.vcs.GitVcsRoot

object NagiosPluginKafka_1 : GitVcsRoot({
    uuid = "c18c1609-321b-4ad0-b5b5-f0570cb244f3"
    id("NagiosPluginKafka")
    name = "https://github.com/HariSekhon/Nagios-Plugin-Kafka"
    url = "https://github.com/HariSekhon/Nagios-Plugin-Kafka"
    branch = "refs/heads/master"
})
