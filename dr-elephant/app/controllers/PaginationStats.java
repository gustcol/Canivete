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

package controllers;

/**
 * This class handles the pagination of results in search page
 */
public class PaginationStats {
  public int currentPage = 1;
  public int paginationBarStartIndex = 1;
  public int paginationBarEndIndex = 1;
  public int pageLength;
  public int pageBarLength;
  public String queryString = null;

  /**
   * The constructor for the PaginationStats
   *
   * @param pageLength The number of results per page
   * @param pageBarLength The Length of the pagination bar at the bottom
   */
  public PaginationStats(int pageLength, int pageBarLength) {
    this.pageLength = pageLength;
    this.pageBarLength = pageBarLength;
  }

  /**
   * Return the current page number
   * @return page number
   */
  public int getCurrentPage() {
    return currentPage;
  }

  /**
   * Set the current page number
   * @param currentPage The number to set
   */
  public void setCurrentPage(int currentPage) {
    if (currentPage < 1) {
      this.currentPage = 1;
    } else {
      this.currentPage = currentPage;
    }
  }

  /**
   * Computes the paginationBarStartIndex. It is computed such that the currentPage
   * remains at the center of the Pagination Bar.
   *
   * @return The start Index of the Pagination bar
   */
  public int getPaginationBarStartIndex() {
    this.paginationBarStartIndex = Math.max(this.currentPage - this.pageBarLength / 2, 1);
    return this.paginationBarStartIndex;
  }

  /**
   * Compute the Pagination Bar end index depending on the number of serach results
   * to be displayed.
   *
   * @param resultSize The fetched result size
   * @return The end index of the Pagination bar
   */
  public int computePaginationBarEndIndex(int resultSize) {
    this.paginationBarEndIndex = this.paginationBarStartIndex + (resultSize - 1) / this.pageLength;
    return this.paginationBarEndIndex;
  }

  /**
   * Returns the pagination bar end Index
   */
  public int getPaginationBarEndIndex() {
    return this.paginationBarEndIndex;
  }

  /**
   * Returns the query string
   */
  public String getQueryString() {
    return queryString;
  }

  /**
   * Sets the query string
   */
  public void setQueryString(String queryString) {
    this.queryString = queryString;
  }

  /**
   * Returns the Pagination bar length
   */
  public int getPageBarLength() {
    return pageBarLength;
  }

  /**
   * Returns the number of results per page
   */
  public int getPageLength() {
    return pageLength;
  }
}
