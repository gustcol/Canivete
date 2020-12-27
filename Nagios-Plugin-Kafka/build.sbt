//
//  Author: Hari Sekhon
//  Date: 2016-06-06 22:51:45 +0100 (Mon, 06 Jun 2016)
//
//  vim:ts=4:sts=4:sw=4:et:filetype=java
//
//  https://github.com/harisekhon/nagios-plugin-kafka
//
//  License: see accompanying Hari Sekhon LICENSE file
//
//  If you're using my code you're welcome to connect with me on LinkedIn and optionally send me feedback to help improve or steer this or other code I publish
//
//  http://www.linkedin.com/in/harisekhon
//

name := "check_kafka"

version := "0.1.0"

// this must align with lib-java
scalaVersion := "2.12.8"

mainClass := Some("com.linkedin.harisekhon.kafka.CheckKafka")

//enablePlugins(VersionEyePlugin)

// existingProjectId in versioneye := "57616d340a82b200276f6669"
// baseUrl in versioneye := "https://www.versioneye.com"
// apiPath in versioneye := "/api/v2"
// publishCrossVersion in versioneye := true

// unmanagedBase := baseDirectory.value / "lib/target"

libraryDependencies ++= Seq (
    "com.linkedin.harisekhon" %% "harisekhon-utils" % "1.17.6",
    // Kafka 0.10 API bug:
    // Cannot auto-commit offsets for group ... since the coordinator is unknown
    "org.apache.kafka" %% "kafka" % "2.2.2",
    //"net.sf.jopt-simple" % "jopt-simple" % "4.9"
    "org.scalatest" %% "scalatest" % "3.0.4" % "test"
)
