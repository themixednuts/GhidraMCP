package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.themixednuts.utils.JsonMapperHolder;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.annotation.JsonSerialize;
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.databind.ser.std.StdSerializer;

/**
 * Standard response envelope for MCP tool responses.
 *
 * @param <T> The type of data contained in the response
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonSerialize(using = McpResponse.McpResponseSerializer.class)
public class McpResponse<T> {

  private final T data; // result data
  private final String nextCursor; // next page cursor
  private final Long durationMs; // duration in milliseconds (server-side telemetry only)
  private final GhidraMcpError error;

  private McpResponse(Builder<T> builder) {
    this.data = builder.data;
    this.nextCursor = builder.nextCursor;
    this.durationMs = builder.durationMs;
    this.error = builder.error;
  }

  // =================== Getters ===================

  /**
   * Whether the response represents a success. Excluded from the wire: failure is signaled by
   * {@code CallToolResult.isError} and by the presence of error fields. Available in-process for
   * log lines and tests.
   */
  @JsonIgnore
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

  /**
   * Server-side execution time. Excluded from JSON because agents never reason about it. Logged
   * server-side instead.
   */
  @JsonIgnore
  public Long getDurationMs() {
    return durationMs;
  }

  /**
   * Error payload — flattened into the parent JSON via {@link JsonUnwrapped}. Failure is already
   * signaled by {@code CallToolResult.isError}, so the {@code message}/{@code hint}/ {@code
   * suggestions} fields sit at the structured root rather than under a separate {@code error}
   * object. Null on success.
   */
  @JsonUnwrapped
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
  @JsonIgnore
  public Optional<T> getDataOptional() {
    return Optional.ofNullable(data);
  }

  /** Gets error message as Optional. */
  @JsonIgnore
  public Optional<String> getErrorMessageOptional() {
    return Optional.ofNullable(error).map(GhidraMcpError::getMessage);
  }

  /**
   * Serializer that flattens object-shaped {@code data} into the parent JSON, leaving the
   * envelope-level fields ({@code next_cursor} and the unwrapped error fields) at the same level.
   * Behavior by data shape:
   *
   * <ul>
   *   <li>{@code Map} or POJO &rarr; fields merged into the root object.
   *   <li>{@code List} / array &rarr; emitted as {@code "data": [...]}; arrays cannot merge.
   *   <li>{@code String} / number / boolean / etc. &rarr; emitted as {@code "data": ...};
   *       primitives need a key to coexist with {@code next_cursor}.
   * </ul>
   */
  public static final class McpResponseSerializer extends StdSerializer<McpResponse<?>> {
    @SuppressWarnings({"unchecked", "rawtypes"})
    public McpResponseSerializer() {
      super((Class<McpResponse<?>>) (Class) McpResponse.class);
    }

    @Override
    public void serialize(McpResponse<?> value, JsonGenerator gen, SerializationContext ctx) {
      gen.writeStartObject();

      Object data = value.getData();
      if (data != null) {
        JsonNode dataNode = JsonMapperHolder.getMapper().valueToTree(data);
        if (dataNode instanceof ObjectNode obj) {
          Iterator<Map.Entry<String, JsonNode>> fields = obj.properties().iterator();
          while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            gen.writeName(field.getKey());
            gen.writePOJO(field.getValue());
          }
        } else {
          // Arrays / strings / primitives can't merge into an object — keep them under `data`.
          gen.writeName("data");
          gen.writePOJO(dataNode);
        }
      }

      String nextCursor = value.getNextCursor();
      if (nextCursor != null) {
        gen.writeStringProperty("next_cursor", nextCursor);
      }

      GhidraMcpError error = value.getError();
      if (error != null) {
        // Hoist error properties to the root, matching the @JsonUnwrapped declaration.
        JsonNode errorNode = JsonMapperHolder.getMapper().valueToTree(error);
        if (errorNode instanceof ObjectNode obj) {
          Iterator<Map.Entry<String, JsonNode>> fields = obj.properties().iterator();
          while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            gen.writeName(field.getKey());
            gen.writePOJO(field.getValue());
          }
        }
      }

      gen.writeEndObject();
    }
  }
}
