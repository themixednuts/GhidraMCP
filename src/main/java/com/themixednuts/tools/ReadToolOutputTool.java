package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
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
        - Read chunks are limited in size to keep responses token-safe.
        </important_notes>
        """)
public class ReadToolOutputTool extends BaseMcpTool {

  private static final String ACTION_LIST_SESSIONS = "list_sessions";
  private static final String ACTION_LIST_OUTPUTS = "list_outputs";
  private static final String ACTION_READ = "read";

  private static final String ARG_SESSION_ID = "session_id";
  private static final String ARG_OUTPUT_ID = "output_id";
  private static final String ARG_OUTPUT_FILE_NAME = "output_file_name";
  private static final String ARG_MAX_CHARS = "max_chars";

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
        ARG_CURSOR,
        SchemaBuilder.string(mapper)
            .description("Pagination cursor for list_sessions/list_outputs"));

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
                "Maximum characters to return in read action (default: "
                    + ToolOutputStore.DEFAULT_READ_CHUNK_CHARS
                    + ", max: "
                    + ToolOutputStore.MAX_READ_CHUNK_CHARS
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
    String cursor = getOptionalStringArgument(args, ARG_CURSOR).orElse(null);
    int pageSize =
        parseBoundedInt(
            args,
            ARG_PAGE_SIZE,
            ToolOutputStore.DEFAULT_LIST_PAGE_SIZE,
            1,
            ToolOutputStore.MAX_LIST_PAGE_SIZE);
    return ToolOutputStore.listSessions(cursor, pageSize);
  }

  private PaginatedResult<ToolOutputStore.OutputInfo> listOutputs(Map<String, Object> args)
      throws GhidraMcpException {
    String sessionId = getRequiredStringArgument(args, ARG_SESSION_ID);
    String cursor = getOptionalStringArgument(args, ARG_CURSOR).orElse(null);
    int pageSize =
        parseBoundedInt(
            args,
            ARG_PAGE_SIZE,
            ToolOutputStore.DEFAULT_LIST_PAGE_SIZE,
            1,
            ToolOutputStore.MAX_LIST_PAGE_SIZE);
    return ToolOutputStore.listOutputs(sessionId, cursor, pageSize);
  }

  private ToolOutputStore.OutputChunk readOutput(Map<String, Object> args)
      throws GhidraMcpException {
    String sessionId = getRequiredStringArgument(args, ARG_SESSION_ID);
    String outputId = getOptionalStringArgument(args, ARG_OUTPUT_ID).orElse(null);
    String outputFileName = getOptionalStringArgument(args, ARG_OUTPUT_FILE_NAME).orElse(null);

    int offset = parseBoundedInt(args, ARG_OFFSET, 0, 0, Integer.MAX_VALUE);
    int maxChars =
        parseBoundedInt(
            args,
            ARG_MAX_CHARS,
            ToolOutputStore.DEFAULT_READ_CHUNK_CHARS,
            1,
            ToolOutputStore.MAX_READ_CHUNK_CHARS);

    return ToolOutputStore.readOutput(sessionId, outputId, outputFileName, offset, maxChars);
  }

  private int parseBoundedInt(
      Map<String, Object> args, String argumentName, int defaultValue, int minValue, int maxValue) {
    int value = getOptionalIntArgument(args, argumentName).orElse(defaultValue);
    if (value < minValue || value > maxValue) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              argumentName,
              value,
              "must be between " + minValue + " and " + maxValue + " (inclusive)"));
    }
    return value;
  }
}
