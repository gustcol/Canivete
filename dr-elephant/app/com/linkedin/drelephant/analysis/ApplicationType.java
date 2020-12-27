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

/**
 * Manages and represents supported application types.
 */
public class ApplicationType {
  private final String _name;

  public ApplicationType(String name) {
    _name = name.toUpperCase();
  }

  @Override
  public int hashCode() {
    return _name.hashCode();
  }

  @Override
  public boolean equals(Object other) {
    if (other instanceof ApplicationType) {
      return ((ApplicationType) other).getName().equals(getName());
    }
    return false;
  }

  /**
   * Get the name
   *
   * @return the name of the application type
   */
  public String getName() {
    return _name;
  }
}
