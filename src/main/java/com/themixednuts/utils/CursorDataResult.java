package com.themixednuts.utils;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A generic wrapper for results that need a top-level cursor but whose payload is not a list.
 *
 * @param <T> The type of the payload.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CursorDataResult<T> {

  @JsonProperty("data")
  public final T data;

  @JsonProperty("next_cursor")
  public final String nextCursor;

  public CursorDataResult(T data, String nextCursor) {
    this.data = data;
    this.nextCursor = nextCursor;
  }
}
