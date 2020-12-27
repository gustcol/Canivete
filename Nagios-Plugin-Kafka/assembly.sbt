//
//  Author: Hari Sekhon
//  Date: 2015-05-25 23:27:15 +0100 (Mon, 25 May 2015)
//
//  vim:ts=4:sts=4:sw=4:et
//
//  https://github.com/harisekhon/nagios-plugin-kafka
//
//  License: see accompanying Hari Sekhon LICENSE file
//
//  If you're using my code you're welcome to connect with me on LinkedIn and optionally send me feedback to help improve or steer this or other code I publish
//
//  https://www.linkedin.com/in/harisekhon
//

// https://github.com/sbt/sbt-assembly

assemblyMergeStrategy in assembly := {
    case PathList("META-INF", "maven","org.slf4j","slf4j-api", p) if p.startsWith("pom")        => MergeStrategy.discard
    case PathList("META-INF", "maven","commons-lang","commons-lang", p) if p.startsWith("pom")  => MergeStrategy.discard
    case PathList("com", "google", "common", "base", p)                                         => MergeStrategy.first
    case PathList("org", "apache", "commons", p @ _*)                                           => MergeStrategy.first
    case PathList("jline", p @ _*)    => MergeStrategy.first
    case PathList("log4j.properties") => MergeStrategy.first
	//case x =>
	//	val oldStrategy = (assemblyMergeStrategy in assembly).value
	//	oldStrategy(x)
    case PathList("META-INF", xs @ _*) => MergeStrategy.discard
    case x => MergeStrategy.first
}
