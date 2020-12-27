package GitHub.buildTypes

import jetbrains.buildServer.configs.kotlin.v2019_2.*

object Dockerfiles : BuildType({
    templates(HariSekhon_Make)
    uuid = "4a56dded-b4d2-460b-9e8b-7fea3036b19b"
    name = "Dockerfiles"
    description = "50+ DockerHub public images for Docker & Kubernetes - Hadoop, Kafka, ZooKeeper, HBase, Cassandra, Solr, SolrCloud, Presto, Apache Drill, Nifi, Spark, Consul, Riak, and DevOps tools built various distros: Alpine, CentOS, Debian, Fedora, Ubuntu"

    vcs {
        root(GitHub.vcsRoots.Dockerfiles_1)

        branchFilter = ""
    }
})
