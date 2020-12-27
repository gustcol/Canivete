/*
 * Copyright 2016 LinkedIn Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package com.linkedin.drelephant.analysis;

import org.apache.hadoop.conf.Configuration;


/**
 * Hadoop System Information
 */
public final class HadoopSystemContext {

  private static final String MAPREDUCE_FRAMEWORK_NAME_PROP = "mapreduce.framework.name";
  private static final String YARN = "yarn";

  /**
   * Detect if the current Hadoop environment is 2.x
   *
   * @return true if it is Hadoop 2 env, else false
   */
  public static boolean isHadoop2Env() {
    Configuration hadoopConf = new Configuration();
    String hadoopVersion = hadoopConf.get(MAPREDUCE_FRAMEWORK_NAME_PROP);
    return hadoopVersion != null && hadoopVersion.equals(YARN);
  }

  /**
   * Check if a Hadoop version matches the current Hadoop environment
   *
   * @param majorVersion the major version number of hadoop
   * @return true if we have a major version match else false
   */
  public static boolean matchCurrentHadoopVersion(int majorVersion) {
    return majorVersion == 2 && isHadoop2Env();
  }
}
