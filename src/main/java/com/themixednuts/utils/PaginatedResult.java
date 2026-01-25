package com.themixednuts.utils;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * A generic wrapper for results that support pagination using a cursor.
 *
 * @param <T> The type of the items in the results list.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PaginatedResult<T> {

  @JsonProperty("results")
  public final List<T> results;

  /**
   * The cursor to use for fetching the next page of results. This field will be present only if
   * there are more results available. MCP clients should use this value in the 'cursor' parameter
   * of the next request.
   */
  @JsonProperty("next_cursor")
  public final String nextCursor;

  public PaginatedResult(List<T> results, String nextCursor) {
    this.results = results;
    this.nextCursor = nextCursor;
  }
}
