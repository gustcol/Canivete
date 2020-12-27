package GitHub.buildTypes

import jetbrains.buildServer.configs.kotlin.v2019_2.*

object HAProxyConfigs : BuildType({
    templates(HariSekhon_Make)
    uuid = "72a47a17-8f51-4391-b027-ac47a74e2e56"
    name = "HAProxy Configs"
    description = "80+ HAProxy Configs for Hadoop, Big Data, NoSQL, Docker, Elasticsearch, SolrCloud, HBase, MySQL, PostgreSQL, Apache Drill, Hive, Presto, Impala, Hue, ZooKeeper, SSH, RabbitMQ, Redis, Riak, Cloudera, OpenTSDB, InfluxDB, Prometheus, Kibana, Graphite, Rancher etc."

    vcs {
        root(GitHub.vcsRoots.HAProxyConfigs_1)

        branchFilter = ""
    }
})
