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

import java.util.Properties;
import java.util.regex.Pattern;


/**
 * Job Type holder. Includes for each Job type, the configuration key that uniquely identifies that type and the
 * regex pattern to match the property.
 */
public class JobType {
  private final String _name;
  private final String _confName;
  private final Pattern _confPattern;

  /**
   * Constructor for a JobType
   *
   * @param name The name of the job type
   * @param confName The configuration to look into
   * @param confPattern The regex pattern to match the configuration property
   */
  public JobType(String name, String confName, String confPattern) {
    _name = name;
    _confName = confName;
    _confPattern = Pattern.compile(confPattern);
  }

  /**
   * Check if a JobType matches a property
   *
   * @param jobProp The properties to match
   * @return true if matched else false
   */
  public boolean matchType(Properties jobProp) {
    // Always return false if confName/confPattern is undefined,
    // which means we cannot tell if the properties are matching the pattern
    if (_confName == null || _confPattern == null) {
      return false;
    }

    return jobProp.containsKey(_confName) && _confPattern.matcher((String) jobProp.get(_confName)).matches();
  }

  /**
   * Get the name of the job type
   *
   * @return The name
   */
  public String getName() {
    return _name;
  }

  @Override
  public String toString() {
    return getName();
  }
}
