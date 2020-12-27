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

package com.linkedin.drelephant.configurations.fetcher;

import com.linkedin.drelephant.analysis.ApplicationType;
import java.util.Map;


/**
 * The Fetcher Configuration Holder
 */
public class FetcherConfigurationData {
  private final String _className;
  private final ApplicationType _appType;
  private final Map<String, String> _paramMap;

  public FetcherConfigurationData(String className, ApplicationType appType, Map<String, String> paramMap) {
    _className = className;
    _appType = appType;
    _paramMap = paramMap;
  }

  public String getClassName() {
    return _className;
  }

  public ApplicationType getAppType() {
    return _appType;
  }

  public Map<String, String> getParamMap() {
    return _paramMap;
  }
}
