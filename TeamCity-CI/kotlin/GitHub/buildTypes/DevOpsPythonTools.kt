package GitHub.buildTypes

import jetbrains.buildServer.configs.kotlin.v2019_2.*

object DevOpsPythonTools : BuildType({
    templates(HariSekhon_Make)
    uuid = "9328cdb2-0efa-403d-a02c-f4a6d19ab4e0"
    name = "DevOps Python tools"
    description = "80+ DevOps & Data CLI Tools - AWS, GCP, GCF Python Cloud Function, Log Anonymizer, Spark, Hadoop, HBase, Hive, Impala, Linux, Docker, Spark Data Converters & Validators (Avro/Parquet/JSON/CSV/INI/XML/YAML), Travis CI, AWS CloudFormation, Elasticsearch, Solr etc."

    vcs {
        root(GitHub.vcsRoots.DevOpsPythonTools_1)

        branchFilter = ""
    }
})
