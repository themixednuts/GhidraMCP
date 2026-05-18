package com.themixednuts.tools;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.themixednuts.McpOutputOptions;
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
        - For multi-chunk reads, pass the previous read response's next_cursor as cursor.
        - read defaults to the output's preferred agent-facing view, usually plain text when available,
          otherwise the original tool data serialized as JSON.
        - Set view=json when you want the stored tool payload as JSON.
        - Set view=envelope_json when you need the original stored structured response envelope.
        - Read chunks are best-effort capped so the serialized MCP response stays inline-safe.
        - List cursors are opaque v1 values.
        </important_notes>
        """)
public class ReadToolOutputTool extends BaseMcpTool {
  private static final int READ_CHUNK_SERIALIZATION_OVERHEAD = 1_024;

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

    if (ACTION_READ.equals(operation) && data instanceof ReadChunk chunk) {
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
    return schema(null);
  }

  @Override
  public JsonSchema schema(PluginTool tool) {
    McpOutputOptions.Limits outputLimits = McpOutputOptions.from(tool);
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
            .enumValues(
                VIEW_AUTO,
                ToolOutputStore.VIEW_TEXT,
                ToolOutputStore.VIEW_JSON,
                ToolOutputStore.VIEW_ENVELOPE_JSON)
            .description(
                "Preferred representation for read action. 'auto' uses the output's preferred"
                    + " agent-facing view.")
            .defaultValue(VIEW_AUTO));

    schemaRoot.property(
        ARG_CURSOR,
        SchemaBuilder.string(mapper)
            .description(
                "Pagination cursor. For list_sessions/list_outputs use the previous list"
                    + " next_cursor (format: v1:<base64url_store_cursor_key>). For read, use"
                    + " the previous read next_cursor (format: v1:<base64url_offset>)."));

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
                    + outputLimits.defaultReadChunkChars()
                    + ", max: "
                    + outputLimits.maxReadChunkChars()
                    + "). The tool may return fewer characters if needed to keep the inline MCP"
                    + " response under the transport size budget."
                    + ")")
            .minimum(1)
            .maximum(outputLimits.maxReadChunkChars())
            .defaultValue(outputLimits.defaultReadChunkChars()));

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
            case ACTION_READ -> readOutput(args, tool);
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

  private ReadChunk readOutput(Map<String, Object> args, PluginTool tool)
      throws GhidraMcpException {
    String sessionId = getRequiredStringArgument(args, ARG_SESSION_ID);
    String outputId = getOptionalStringArgument(args, ARG_OUTPUT_ID).orElse(null);
    String outputFileName = getOptionalStringArgument(args, ARG_OUTPUT_FILE_NAME).orElse(null);
    String view = getOptionalStringArgument(args, ARG_VIEW).orElse(VIEW_AUTO);
    McpOutputOptions.Limits outputLimits = McpOutputOptions.from(tool);

    int offset = getReadOffset(args);
    int maxChars =
        getBoundedIntArgumentOrDefault(
            args,
            ARG_MAX_CHARS,
            outputLimits.defaultReadChunkChars(),
            1,
            outputLimits.maxReadChunkChars());

    ToolOutputStore.OutputChunk chunk =
        ToolOutputStore.readOutput(
            sessionId,
            outputId,
            outputFileName,
            view,
            offset,
            maxChars,
            outputLimits.defaultReadChunkChars(),
            outputLimits.maxReadChunkChars());
    return toReadChunk(
        trimChunkForInlineBudget(chunk, offset, outputLimits.inlineResponseCharLimit()));
  }

  private int getReadOffset(Map<String, Object> args) {
    java.util.Optional<String> cursor = getOptionalStringArgument(args, ARG_CURSOR);
    if (cursor.isEmpty()) {
      return getBoundedIntArgumentOrDefault(args, ARG_OFFSET, 0, 0, Integer.MAX_VALUE);
    }

    String decodedOffset =
        decodeOpaqueCursorSingleV1(cursor.get(), ARG_CURSOR, "v1:<base64url_offset>");
    try {
      int offset = Integer.parseInt(decodedOffset);
      if (offset < 0) {
        throw new NumberFormatException("negative offset");
      }
      return offset;
    } catch (NumberFormatException e) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              ARG_CURSOR, cursor.get(), "read cursor contains an invalid offset"));
    }
  }

  private ToolOutputStore.OutputChunk trimChunkForInlineBudget(
      ToolOutputStore.OutputChunk chunk, int chunkStart, int inlineResponseCharLimit) {
    int safeInlineResponseCharLimit =
        Math.max(0, inlineResponseCharLimit - READ_CHUNK_SERIALIZATION_OVERHEAD);
    if (estimateInlineResponseSize(chunk) <= safeInlineResponseCharLimit) {
      return chunk;
    }

    int low = 0;
    int high = chunk.content().length();
    ToolOutputStore.OutputChunk best = null;

    while (low <= high) {
      int mid = (low + high) >>> 1;
      ToolOutputStore.OutputChunk candidate = resizeChunk(chunk, mid, chunkStart);

      if (estimateInlineResponseSize(candidate) <= safeInlineResponseCharLimit) {
        best = candidate;
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }

    return best != null ? best : resizeChunk(chunk, 0, chunkStart);
  }

  private int estimateInlineResponseSize(ToolOutputStore.OutputChunk chunk) {
    try {
      return mapper
          .writeValueAsString(
              McpResponse.success(getMcpName(), ACTION_READ, toReadChunk(chunk), 0L))
          .length();
    } catch (Exception e) {
      return Integer.MAX_VALUE;
    }
  }

  private ToolOutputStore.OutputChunk resizeChunk(
      ToolOutputStore.OutputChunk original, int contentLength, int chunkStart) {
    int safeLength = Math.max(0, Math.min(contentLength, original.content().length()));
    String resizedContent = original.content().substring(0, safeLength);
    int dropped = original.content().length() - safeLength;

    Integer nextOffset;
    if (original.nextOffset() != null) {
      // Upstream knew more bytes follow this chunk. We dropped {dropped} from the tail, so the
      // new resume point shifts back by that much.
      nextOffset = original.nextOffset() - dropped;
    } else if (dropped > 0) {
      // Upstream read all the way to EOF, but we just trimmed bytes off the tail. The trimmed
      // bytes become the new resume window, starting at chunkStart + safeLength.
      nextOffset = chunkStart + safeLength;
    } else {
      nextOffset = null;
    }
    return new ToolOutputStore.OutputChunk(resizedContent, nextOffset);
  }

  private ReadChunk toReadChunk(ToolOutputStore.OutputChunk chunk) {
    return new ReadChunk(chunk.content(), encodeReadCursor(chunk.nextOffset()));
  }

  private String encodeReadCursor(Integer nextOffset) {
    return nextOffset != null ? OpaqueCursorCodec.encodeV1(Integer.toString(nextOffset)) : null;
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

    Integer preferredChars = info.viewTotalChars().get(info.preferredView());
    builder.append(preferredChars != null ? preferredChars : 0);
    builder.append(" by_view=").append(info.viewTotalChars());
    return builder.toString();
  }

  record ReadChunk(String content, @JsonProperty("next_cursor") String nextCursor) {}
}
