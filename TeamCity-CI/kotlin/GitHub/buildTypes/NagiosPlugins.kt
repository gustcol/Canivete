package GitHub.buildTypes

import jetbrains.buildServer.configs.kotlin.v2019_2.*

object NagiosPlugins : BuildType({
    templates(HariSekhon_Make)
    uuid = "34cdfa04-13fe-4da9-a863-658cef27ff3e"
    name = "Nagios Plugins"
    description = "450+ AWS, Hadoop, Cloud, Kafka, Docker, Elasticsearch, RabbitMQ, Redis, HBase, Solr, Cassandra, ZooKeeper, HDFS, Yarn, Hive, Presto, Drill, Impala, Consul, Spark, Jenkins, Travis CI, Git, MySQL, Linux, DNS, Whois, SSL Certs, Yum Security Updates, Kubernetes, Cloudera etc..."

    vcs {
        root(GitHub.vcsRoots.NagiosPlugins_1)

        branchFilter = ""
    }
})
