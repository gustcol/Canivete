package GitHub.buildTypes

import jetbrains.buildServer.configs.kotlin.v2019_2.*

object DevOpsPerlTools : BuildType({
    templates(HariSekhon_Make)
    uuid = "5ddbebf9-71f4-46de-ba15-c125395d1642"
    name = "DevOps Perl tools"
    description = "25+ DevOps CLI Tools - Kubernetes & Code templates, Log Anonymizer, SQL ReCaser (MySQL, PostgreSQL, AWS Redshift, Snowflake, Apache Drill, Hive, Impala, Cassandra CQL, Microsoft SQL Server, Oracle, Couchbase N1QL, Dockerfiles), Hadoop HDFS & Hive tools, Solr/SolrCloud CLI, Nginx stats & HTTP(S) URL watchers for load-balanced web farms, Linux tools etc."

    vcs {
        root(GitHub.vcsRoots.DevOpsPerlTools_1)

        branchFilter = ""
    }
})
