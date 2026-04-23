package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.McpResponse;
import com.themixednuts.utils.OpaqueCursorCodec;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.ToolOutputStore;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.Locale;
import java.util.Map;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Read Tool Output",
    description = "Read oversized tool output from session storage in paginated chunks.",
    mcpName = "read_tool_output",
    title = "Read Tool Output",
    readOnlyHint = true,
    idempotentHint = true,
    mcpDescription =
        """
        <use_case>
        Retrieve oversized tool responses that were stored out-of-band when they exceeded
        the inline response size limit. This enables composable workflows without blowing
        token budgets.
        </use_case>

        <important_notes>
        - Use action=list_sessions to discover available sessions.
        - Use action=list_outputs with session_id to browse stored outputs.
        - Use action=read with session_id plus output_id or output_file_name to fetch chunks.
        - read defaults to the output's preferred agent-facing view, usually plain text when available.
        - Set view=json when you need the original stored MCP response envelope.
        - Read chunks are best-effort capped so the serialized MCP response stays inline-safe.
        - List cursors are opaque v1 values.
        </important_notes>
        """)
public class ReadToolOutputTool extends BaseMcpTool {
  private static final int SAFE_INLINE_RESPONSE_CHAR_LIMIT = INLINE_RESPONSE_CHAR_LIMIT - 1_024;

  private static final String ACTION_LIST_SESSIONS = "list_sessions";
  private static final String ACTION_LIST_OUTPUTS = "list_outputs";
  private static final String ACTION_READ = "read";

  private static final String ARG_SESSION_ID = "session_id";
  private static final String ARG_OUTPUT_ID = "output_id";
  private static final String ARG_OUTPUT_FILE_NAME = "output_file_name";
  private static final String ARG_MAX_CHARS = "max_chars";
  private static final String ARG_VIEW = "view";
  private static final String VIEW_AUTO = "auto";

  @Override
  protected java.util.Optional<String> createSuccessTextContent(
      McpResponse<?> response, Map<String, Object> args, String toolName, String operation) {
    Object data = response.getData();

    if (ACTION_READ.equals(operation) && data instanceof ToolOutputStore.OutputChunk chunk) {
      return java.util.Optional.ofNullable(chunk.content()).filter(content -> !content.isBlank());
    }

    if (ACTION_LIST_OUTPUTS.equals(operation) && data instanceof java.util.List<?> rows) {
      String rendered =
          rows.stream()
              .filter(ToolOutputStore.OutputInfo.class::isInstance)
              .map(ToolOutputStore.OutputInfo.class::cast)
              .map(this::renderOutputInfo)
              .reduce((left, right) -> left + "\n" + right)
              .orElse("");
      return java.util.Optional.of(rendered).filter(text -> !text.isBlank());
    }

    if (ACTION_LIST_SESSIONS.equals(operation) && data instanceof java.util.List<?> rows) {
      String rendered =
          rows.stream()
              .filter(ToolOutputStore.SessionInfo.class::isInstance)
              .map(ToolOutputStore.SessionInfo.class::cast)
              .map(
                  session ->
                      session.sessionId()
                          + " outputs="
                          + session.outputCount()
                          + " last_accessed_ms="
                          + session.lastAccessedAtMs())
              .reduce((left, right) -> left + "\n" + right)
              .orElse("");
      return java.util.Optional.of(rendered).filter(text -> !text.isBlank());
    }

    return java.util.Optional.empty();
  }

  @Override
  public JsonSchema schema() {
    IObjectSchemaBuilder schemaRoot = createBaseSchemaNode();

    schemaRoot.property(
        ARG_ACTION,
        SchemaBuilder.string(mapper)
            .enumValues(ACTION_LIST_SESSIONS, ACTION_LIST_OUTPUTS, ACTION_READ)
            .description("Operation to perform"));

    schemaRoot.property(
        ARG_SESSION_ID,
        SchemaBuilder.string(mapper).description("Tool output session ID (ses_...)"));

    schemaRoot.property(
        ARG_OUTPUT_ID, SchemaBuilder.string(mapper).description("Output identifier (out_...)"));

    schemaRoot.property(
        ARG_OUTPUT_FILE_NAME,
        SchemaBuilder.string(mapper)
            .description("Stored output file name (alternative to output_id)"));

    schemaRoot.property(
        ARG_VIEW,
        SchemaBuilder.string(mapper)
            .enumValues(VIEW_AUTO, ToolOutputStore.VIEW_TEXT, ToolOutputStore.VIEW_JSON)
            .description(
                "Preferred representation for read action. 'auto' uses the output's preferred"
                    + " agent-facing view.")
            .defaultValue(VIEW_AUTO));

    schemaRoot.property(
        ARG_CURSOR,
        SchemaBuilder.string(mapper)
            .description(
                "Pagination cursor for list_sessions/list_outputs (format:"
                    + " v1:<base64url_store_cursor_key>)"));

    schemaRoot.property(
        ARG_PAGE_SIZE,
        SchemaBuilder.integer(mapper)
            .description(
                "Page size for list operations (default: "
                    + ToolOutputStore.DEFAULT_LIST_PAGE_SIZE
                    + ", max: "
                    + ToolOutputStore.MAX_LIST_PAGE_SIZE
                    + ")")
            .minimum(1)
            .maximum(ToolOutputStore.MAX_LIST_PAGE_SIZE));

    schemaRoot.property(
        ARG_OFFSET,
        SchemaBuilder.integer(mapper)
            .description("Character offset for read action")
            .minimum(0)
            .defaultValue(0));

    schemaRoot.property(
        ARG_MAX_CHARS,
        SchemaBuilder.integer(mapper)
            .description(
                "Maximum raw characters to return in read action (default: "
                    + ToolOutputStore.DEFAULT_READ_CHUNK_CHARS
                    + ", max: "
                    + ToolOutputStore.MAX_READ_CHUNK_CHARS
                    + "). The tool may return fewer characters if needed to keep the inline MCP"
                    + " response under the transport size budget."
                    + ")")
            .minimum(1)
            .maximum(ToolOutputStore.MAX_READ_CHUNK_CHARS)
            .defaultValue(ToolOutputStore.DEFAULT_READ_CHUNK_CHARS));

    schemaRoot.requiredProperty(ARG_ACTION);
    return schemaRoot.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    return Mono.fromCallable(
        () -> {
          String action = getRequiredStringArgument(args, ARG_ACTION);
          return switch (action.toLowerCase(Locale.ROOT)) {
            case ACTION_LIST_SESSIONS -> listSessions(args);
            case ACTION_LIST_OUTPUTS -> listOutputs(args);
            case ACTION_READ -> readOutput(args);
            default ->
                throw new GhidraMcpException(
                    GhidraMcpError.invalid(
                        ARG_ACTION,
                        action,
                        "must be one of: "
                            + ACTION_LIST_SESSIONS
                            + ", "
                            + ACTION_LIST_OUTPUTS
                            + ", "
                            + ACTION_READ));
          };
        });
  }

  private PaginatedResult<ToolOutputStore.SessionInfo> listSessions(Map<String, Object> args) {
    String cursor =
        getOptionalStringArgument(args, ARG_CURSOR)
            .map(
                value ->
                    decodeOpaqueCursorSingleV1(
                        value, ARG_CURSOR, "v1:<base64url_store_cursor_key>"))
            .orElse(null);
    int pageSize =
        getBoundedIntArgumentOrDefault(
            args,
            ARG_PAGE_SIZE,
            ToolOutputStore.DEFAULT_LIST_PAGE_SIZE,
            1,
            ToolOutputStore.MAX_LIST_PAGE_SIZE);

    PaginatedResult<ToolOutputStore.SessionInfo> result =
        ToolOutputStore.listSessions(cursor, pageSize);
    String nextCursor =
        result.nextCursor != null ? OpaqueCursorCodec.encodeV1(result.nextCursor) : null;
    return new PaginatedResult<>(result.results, nextCursor);
  }

  private PaginatedResult<ToolOutputStore.OutputInfo> listOutputs(Map<String, Object> args)
      throws GhidraMcpException {
    String sessionId = getRequiredStringArgument(args, ARG_SESSION_ID);
    String cursor =
        getOptionalStringArgument(args, ARG_CURSOR)
            .map(
                value ->
                    decodeOpaqueCursorSingleV1(
                        value, ARG_CURSOR, "v1:<base64url_store_cursor_key>"))
            .orElse(null);
    int pageSize =
        getBoundedIntArgumentOrDefault(
            args,
            ARG_PAGE_SIZE,
            ToolOutputStore.DEFAULT_LIST_PAGE_SIZE,
            1,
            ToolOutputStore.MAX_LIST_PAGE_SIZE);

    PaginatedResult<ToolOutputStore.OutputInfo> result =
        ToolOutputStore.listOutputs(sessionId, cursor, pageSize);
    String nextCursor =
        result.nextCursor != null ? OpaqueCursorCodec.encodeV1(result.nextCursor) : null;
    return new PaginatedResult<>(result.results, nextCursor);
  }

  private ToolOutputStore.OutputChunk readOutput(Map<String, Object> args)
      throws GhidraMcpException {
    String sessionId = getRequiredStringArgument(args, ARG_SESSION_ID);
    String outputId = getOptionalStringArgument(args, ARG_OUTPUT_ID).orElse(null);
    String outputFileName = getOptionalStringArgument(args, ARG_OUTPUT_FILE_NAME).orElse(null);
    String view = getOptionalStringArgument(args, ARG_VIEW).orElse(VIEW_AUTO);

    int offset = getBoundedIntArgumentOrDefault(args, ARG_OFFSET, 0, 0, Integer.MAX_VALUE);
    int maxChars =
        getBoundedIntArgumentOrDefault(
            args,
            ARG_MAX_CHARS,
            ToolOutputStore.DEFAULT_READ_CHUNK_CHARS,
            1,
            ToolOutputStore.MAX_READ_CHUNK_CHARS);

    ToolOutputStore.OutputChunk chunk =
        ToolOutputStore.readOutput(sessionId, outputId, outputFileName, view, offset, maxChars);
    return trimChunkForInlineBudget(chunk);
  }

  private ToolOutputStore.OutputChunk trimChunkForInlineBudget(ToolOutputStore.OutputChunk chunk) {
    if (estimateInlineResponseSize(chunk) <= SAFE_INLINE_RESPONSE_CHAR_LIMIT) {
      return chunk;
    }

    int low = 0;
    int high = chunk.content().length();
    ToolOutputStore.OutputChunk best = null;

    while (low <= high) {
      int mid = (low + high) >>> 1;
      ToolOutputStore.OutputChunk candidate = resizeChunk(chunk, mid);

      if (estimateInlineResponseSize(candidate) <= SAFE_INLINE_RESPONSE_CHAR_LIMIT) {
        best = candidate;
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }

    return best != null ? best : resizeChunk(chunk, 0);
  }

  private int estimateInlineResponseSize(ToolOutputStore.OutputChunk chunk) {
    try {
      return mapper
          .writeValueAsString(McpResponse.success(getMcpName(), ACTION_READ, chunk, 0L))
          .length();
    } catch (Exception e) {
      return Integer.MAX_VALUE;
    }
  }

  private ToolOutputStore.OutputChunk resizeChunk(
      ToolOutputStore.OutputChunk original, int contentLength) {
    int safeLength = Math.max(0, Math.min(contentLength, original.content().length()));
    String resizedContent = original.content().substring(0, safeLength);
    int nextOffsetValue = original.offset() + safeLength;
    boolean hasMore = nextOffsetValue < original.totalChars();

    return new ToolOutputStore.OutputChunk(
        original.sessionId(),
        original.outputId(),
        original.fileName(),
        original.toolName(),
        original.operation(),
        original.view(),
        original.contentFormat(),
        original.preferredView(),
        original.availableViews(),
        original.offset(),
        original.requestedChars(),
        resizedContent.length(),
        original.totalChars(),
        Math.max(0, original.totalChars() - nextOffsetValue),
        hasMore,
        hasMore ? nextOffsetValue : null,
        resizedContent);
  }

  private String renderOutputInfo(ToolOutputStore.OutputInfo info) {
    StringBuilder builder =
        new StringBuilder(
            info.outputId()
                + " "
                + info.toolName()
                + "."
                + info.operation()
                + " preferred="
                + info.preferredView()
                + " views="
                + String.join("/", info.availableViews())
                + " chars=");

    Integer preferredChars = info.preferredTotalChars();
    builder.append(preferredChars != null ? preferredChars : info.totalChars());

    if (info.textAvailable() && info.textTotalChars() != null) {
      builder.append(" text_chars=").append(info.textTotalChars());
    }
    builder.append(" stored_chars=").append(info.totalChars());
    return builder.toString();
  }
}
