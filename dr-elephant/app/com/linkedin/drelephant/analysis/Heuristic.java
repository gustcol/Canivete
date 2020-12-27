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

import com.linkedin.drelephant.configurations.heuristic.HeuristicConfigurationData;


/**
 * This interface defines the Heuristic rule interface.
 *
 * @param <T> An implementation that extends from HadoopApplicationData
 */
public interface Heuristic<T extends HadoopApplicationData> {
  /**
   * Given an application data instance, returns the analyzed heuristic result.
   *
   * @param data The data to analyze
   * @return The heuristic result
   */
  public HeuristicResult apply(T data);

  /**
   * Get the heuristic Configuration
   *
   * @return the heuristic configuration data
   */
  public HeuristicConfigurationData getHeuristicConfData();
}
