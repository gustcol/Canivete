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

package com.linkedin.drelephant.util;

import java.net.MalformedURLException;
import java.net.URL;


/**
 * This provide URLs for YARN APIs.
 */
public class YarnURLUtils {
  private static final String MAPREDUCE_JOBS_PATH = "/ws/v1/history/mapreduce/jobs";
  private static final String JOB_DETAIL_PATH = "/jobhistory/job";

  public static String getMapreduceJobsURLString(String historyServerRoot) {
    return "http://" + historyServerRoot + "/ws/v1/history/mapreduce/jobs";
  }

  public static URL getMapreduceJobsURL(String historyServerRoot, long startTime, long endTime)
      throws MalformedURLException {
    return new URL(String.format("%s?finishedTimeBegin=%s&finishedTimeEnd=%s&state=SUCCEEDED",
        getMapreduceJobsURLString(historyServerRoot), startTime, endTime));
  }

  public static String getJobDetailURLString(String historyServerRoot, String jobId) {
    return historyServerRoot + "/jobhistory/job/" + jobId;
  }

  public static URL getJobConfigURL(String historyServerRoot, String jobId)
      throws MalformedURLException {
    return new URL(getMapreduceJobsURLString(historyServerRoot) + "/" + jobId + "/conf");
  }

  public static URL getJobCounterURL(String historyServerRoot, String jobId)
      throws MalformedURLException {
    return new URL(getMapreduceJobsURLString(historyServerRoot) + "/" + jobId + "/counters");
  }

  public static URL getTaskListURL(String historyServerRoot, String jobId)
      throws MalformedURLException {
    return new URL(getMapreduceJobsURLString(historyServerRoot) + "/" + jobId + "/tasks");
  }

  public static URL getTaskCounterURL(String historyServerRoot, String jobId, String taskId)
      throws MalformedURLException {
    return new URL(getMapreduceJobsURLString(historyServerRoot) + "/" + jobId + "/tasks/" + taskId + "/counters");
  }

  public static URL getTaskAttemptURL(String historyServerRoot, String jobId, String taskId, String attemptId)
      throws MalformedURLException {
    return new URL(
        getMapreduceJobsURLString(historyServerRoot) + "/" + jobId + "/tasks/" + taskId + "/attempts/" + attemptId);
  }
}
