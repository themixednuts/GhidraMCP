package com.themixednuts.models;

import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * Streamlined response envelope for MCP tool responses.
 * Uses short field names to minimize token count.
 *
 * @param <T> The type of data contained in the response
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({ "ok", "data", "cursor", "ms", "err" })
public class McpResponse<T> {

    private final boolean ok;           // success
    private final T data;               // result data
    private final String cursor;        // next page cursor
    private final Long ms;              // duration in milliseconds
    private final GhidraMcpError err;   // error details

    private McpResponse(Builder<T> builder) {
        this.ok = builder.ok;
        this.data = builder.data;
        this.cursor = builder.cursor;
        this.ms = builder.ms;
        this.err = builder.err;
    }

    // =================== Getters ===================

    @JsonProperty("ok")
    public boolean isOk() {
        return ok;
    }

    // Alias for compatibility
    public boolean isSuccess() {
        return ok;
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

    @JsonProperty("err")
    public GhidraMcpError getErr() {
        return err;
    }

    // Alias
    public GhidraMcpError getError() {
        return err;
    }

    // =================== Static Factory Methods ===================

    /**
     * Creates a successful response with data.
     */
    public static <T> McpResponse<T> success(String tool, String operation, T data) {
        return new Builder<T>()
                .ok(true)
                .data(data)
                .build();
    }

    /**
     * Creates a successful response with data and timing.
     */
    public static <T> McpResponse<T> success(String tool, String operation, T data, long ms) {
        return new Builder<T>()
                .ok(true)
                .data(data)
                .ms(ms)
                .build();
    }

    /**
     * Creates a successful paginated response.
     */
    public static <T> McpResponse<List<T>> paginated(String tool, String operation, List<T> items,
            String cursor, Integer totalCount) {
        return new Builder<List<T>>()
                .ok(true)
                .data(items)
                .cursor(cursor)
                .build();
    }

    /**
     * Creates a successful paginated response with timing.
     */
    public static <T> McpResponse<List<T>> paginated(String tool, String operation, List<T> items,
            String cursor, Integer totalCount, long ms) {
        return new Builder<List<T>>()
                .ok(true)
                .data(items)
                .cursor(cursor)
                .ms(ms)
                .build();
    }

    /**
     * Creates an error response.
     */
    public static <T> McpResponse<T> error(String tool, String operation, GhidraMcpError err) {
        return new Builder<T>()
                .ok(false)
                .err(err)
                .build();
    }

    /**
     * Creates an error response with timing.
     */
    public static <T> McpResponse<T> error(String tool, String operation, GhidraMcpError err, long ms) {
        return new Builder<T>()
                .ok(false)
                .err(err)
                .ms(ms)
                .build();
    }

    // =================== Builder ===================

    public static class Builder<T> {
        private boolean ok;
        private T data;
        private String cursor;
        private Long ms;
        private GhidraMcpError err;

        public Builder<T> ok(boolean ok) {
            this.ok = ok;
            return this;
        }

        // Alias
        public Builder<T> success(boolean ok) {
            return ok(ok);
        }

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

        public Builder<T> err(GhidraMcpError err) {
            this.err = err;
            return this;
        }

        // Alias
        public Builder<T> error(GhidraMcpError err) {
            return err(err);
        }

        // Ignored - tool/operation not included in output
        public Builder<T> tool(String tool) {
            return this;
        }

        public Builder<T> operation(String operation) {
            return this;
        }

        public Builder<T> totalCount(Integer count) {
            return this;  // Not included in streamlined output
        }

        public McpResponse<T> build() {
            return new McpResponse<>(this);
        }
    }

    // =================== Utility Methods ===================

    /**
     * Checks if this response has more pages.
     */
    public boolean hasMorePages() {
        return cursor != null && !cursor.isEmpty();
    }

    /**
     * Gets data as Optional.
     */
    public Optional<T> getDataOptional() {
        return Optional.ofNullable(data);
    }

    /**
     * Gets error as Optional.
     */
    public Optional<GhidraMcpError> getErrorOptional() {
        return Optional.ofNullable(err);
    }
}
