package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.List;
import java.util.Optional;

/**
 * Streamlined response envelope for MCP tool responses. Uses short field names to minimize token
 * count.
 *
 * @param <T> The type of data contained in the response
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"data", "cursor", "ms", "msg", "hint"})
public class McpResponse<T> {

  private final T data; // result data
  private final String cursor; // next page cursor
  private final Long ms; // duration in milliseconds
  private final String msg; // error message
  private final String hint; // error hint

  private McpResponse(Builder<T> builder) {
    this.data = builder.data;
    this.cursor = builder.cursor;
    this.ms = builder.ms;
    this.msg = builder.msg;
    this.hint = builder.hint;
  }

  // =================== Getters ===================

  /** Checks if the response is successful (has no error message). */
  public boolean isOk() {
    return msg == null;
  }

  // Alias for compatibility
  public boolean isSuccess() {
    return isOk();
  }

  @JsonProperty("data")
  public T getData() {
    return data;
  }

  @JsonProperty("cursor")
  public String getCursor() {
    return cursor;
  }

  // Alias
  public String getNextCursor() {
    return cursor;
  }

  @JsonProperty("ms")
  public Long getMs() {
    return ms;
  }

  // Alias
  public Long getDurationMs() {
    return ms;
  }

  @JsonProperty("msg")
  public String getMsg() {
    return msg;
  }

  @JsonProperty("hint")
  public String getHint() {
    return hint;
  }

  // =================== Static Factory Methods ===================

  /** Creates a successful response with data. */
  public static <T> McpResponse<T> success(String tool, String operation, T data) {
    return new Builder<T>().data(data).build();
  }

  /** Creates a successful response with data and timing. */
  public static <T> McpResponse<T> success(String tool, String operation, T data, long ms) {
    return new Builder<T>().data(data).ms(ms).build();
  }

  /** Creates a successful paginated response. */
  public static <T> McpResponse<List<T>> paginated(
      String tool, String operation, List<T> items, String cursor, Integer totalCount) {
    return new Builder<List<T>>().data(items).cursor(cursor).build();
  }

  /** Creates a successful paginated response with timing. */
  public static <T> McpResponse<List<T>> paginated(
      String tool, String operation, List<T> items, String cursor, Integer totalCount, long ms) {
    return new Builder<List<T>>().data(items).cursor(cursor).ms(ms).build();
  }

  /** Creates an error response. */
  public static <T> McpResponse<T> error(String tool, String operation, GhidraMcpError err) {
    return new Builder<T>().msg(err.getMsg()).hint(err.getHint()).build();
  }

  /** Creates an error response with timing. */
  public static <T> McpResponse<T> error(
      String tool, String operation, GhidraMcpError err, long ms) {
    return new Builder<T>().msg(err.getMsg()).hint(err.getHint()).ms(ms).build();
  }

  // =================== Builder ===================

  public static class Builder<T> {
    private T data;
    private String cursor;
    private Long ms;
    private String msg;
    private String hint;

    public Builder<T> data(T data) {
      this.data = data;
      return this;
    }

    public Builder<T> cursor(String cursor) {
      this.cursor = cursor;
      return this;
    }

    // Alias
    public Builder<T> nextCursor(String cursor) {
      return cursor(cursor);
    }

    public Builder<T> ms(Long ms) {
      this.ms = ms;
      return this;
    }

    // Alias
    public Builder<T> durationMs(Long ms) {
      return ms(ms);
    }

    public Builder<T> msg(String msg) {
      this.msg = msg;
      return this;
    }

    public Builder<T> hint(String hint) {
      this.hint = hint;
      return this;
    }

    public McpResponse<T> build() {
      return new McpResponse<>(this);
    }
  }

  // =================== Utility Methods ===================

  /** Checks if this response has more pages. */
  public boolean hasMorePages() {
    return cursor != null && !cursor.isEmpty();
  }

  /** Gets data as Optional. */
  public Optional<T> getDataOptional() {
    return Optional.ofNullable(data);
  }

  /** Gets error message as Optional. */
  public Optional<String> getMsgOptional() {
    return Optional.ofNullable(msg);
  }
}
