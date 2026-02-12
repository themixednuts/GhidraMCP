package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.List;
import java.util.Optional;

/**
 * Standard response envelope for MCP tool responses.
 *
 * @param <T> The type of data contained in the response
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"success", "data", "next_cursor", "duration_ms", "error"})
public class McpResponse<T> {

  private final T data; // result data
  private final String nextCursor; // next page cursor
  private final Long durationMs; // duration in milliseconds
  private final GhidraMcpError error;

  private McpResponse(Builder<T> builder) {
    this.data = builder.data;
    this.nextCursor = builder.nextCursor;
    this.durationMs = builder.durationMs;
    this.error = builder.error;
  }

  // =================== Getters ===================

  /** Checks if the response is successful (has no error message). */
  @JsonProperty("success")
  public boolean isSuccess() {
    return error == null;
  }

  @JsonProperty("data")
  public T getData() {
    return data;
  }

  @JsonProperty("next_cursor")
  public String getNextCursor() {
    return nextCursor;
  }

  @JsonProperty("duration_ms")
  public Long getDurationMs() {
    return durationMs;
  }

  @JsonProperty("error")
  public GhidraMcpError getError() {
    return error;
  }

  // =================== Static Factory Methods ===================

  /** Creates a successful response with data. */
  public static <T> McpResponse<T> success(String tool, String operation, T data) {
    return new Builder<T>().data(data).build();
  }

  /** Creates a successful response with data and timing. */
  public static <T> McpResponse<T> success(String tool, String operation, T data, long ms) {
    return new Builder<T>().data(data).durationMs(ms).build();
  }

  /** Creates a successful paginated response. */
  public static <T> McpResponse<List<T>> paginated(
      String tool, String operation, List<T> items, String cursor, Integer totalCount) {
    return new Builder<List<T>>().data(items).nextCursor(cursor).build();
  }

  /** Creates a successful paginated response with timing. */
  public static <T> McpResponse<List<T>> paginated(
      String tool, String operation, List<T> items, String cursor, Integer totalCount, long ms) {
    return new Builder<List<T>>().data(items).nextCursor(cursor).durationMs(ms).build();
  }

  /** Creates an error response. */
  public static <T> McpResponse<T> error(String tool, String operation, GhidraMcpError err) {
    return new Builder<T>().error(err).build();
  }

  /** Creates an error response with timing. */
  public static <T> McpResponse<T> error(
      String tool, String operation, GhidraMcpError err, long ms) {
    return new Builder<T>().error(err).durationMs(ms).build();
  }

  // =================== Builder ===================

  public static class Builder<T> {
    private T data;
    private String nextCursor;
    private Long durationMs;
    private GhidraMcpError error;

    public Builder<T> data(T data) {
      this.data = data;
      return this;
    }

    public Builder<T> nextCursor(String cursor) {
      this.nextCursor = cursor;
      return this;
    }

    public Builder<T> durationMs(Long ms) {
      this.durationMs = ms;
      return this;
    }

    public Builder<T> error(GhidraMcpError error) {
      this.error = error;
      return this;
    }

    public McpResponse<T> build() {
      return new McpResponse<>(this);
    }
  }

  // =================== Utility Methods ===================

  /** Checks if this response has more pages. */
  public boolean hasMorePages() {
    return nextCursor != null && !nextCursor.isEmpty();
  }

  /** Gets data as Optional. */
  public Optional<T> getDataOptional() {
    return Optional.ofNullable(data);
  }

  /** Gets error message as Optional. */
  public Optional<String> getErrorMessageOptional() {
    return Optional.ofNullable(error).map(GhidraMcpError::getMessage);
  }
}
