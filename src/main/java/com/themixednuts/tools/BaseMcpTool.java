package com.themixednuts.tools;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.McpResponse;
import com.themixednuts.utils.GhidraMcpErrorUtils;
import com.themixednuts.utils.GhidraStateUtils;
import com.themixednuts.utils.JsonMapperHolder;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.ToolOutputStore;
import com.themixednuts.utils.jsonschema.JsonSchema;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import io.modelcontextprotocol.spec.McpSchema.ToolAnnotations;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Abstract base class for all Ghidra MCP tools. Provides standardized handling for:
 *
 * <ul>
 *   <li>Error normalization - all exceptions are converted to structured GhidraMcpException
 *   <li>Argument parsing - with proper exception handling
 *   <li>Transaction management - with clean commit/rollback semantics
 *   <li>Response envelope - consistent McpResponse wrapper
 *   <li>Timing - automatic duration tracking
 * </ul>
 *
 * <p>Tools should extend this class and implement:
 *
 * <ul>
 *   <li>{@link #schema()} - Define the JSON schema for tool arguments
 *   <li>{@link #execute(McpTransportContext, Map, PluginTool)} - Core execution logic
 * </ul>
 */
public abstract class BaseMcpTool {

  // =================== Static Configuration ===================
  protected static final ObjectMapper mapper = JsonMapperHolder.getMapper();

  private static final Object PROGRAM_TRACKER_CONTEXT_KEY = new Object();

  private static final class ProgramResourceTracker {
    private final List<Program> programs = new CopyOnWriteArrayList<>();

    void track(Program program) {
      if (program != null) {
        programs.add(program);
      }
    }

    void releaseAll(Object consumer) {
      for (Program program : programs) {
        try {
          program.release(consumer);
        } catch (Throwable t) {
          Msg.error(BaseMcpTool.class, "Failed to release program resource", t);
        }
      }
      programs.clear();
    }
  }

  /** Default page size for paginated results */
  protected static final int DEFAULT_PAGE_LIMIT = 50;

  protected static final int MAX_PAGE_LIMIT = 500;

  private static final int INLINE_RESPONSE_CHAR_LIMIT = 16_000;
  private static final String TOOL_OUTPUT_READER_NAME = "read_tool_output";
  private static final java.util.Set<String> SUPPORTED_TOP_LEVEL_SCHEMA_KEYS =
      java.util.Set.of(
          "type", "properties", "required", "additionalProperties", "$defs", "definitions");
  private static final Map<String, Object> DEFAULT_OUTPUT_SCHEMA = createDefaultOutputSchema();

  // =================== Argument Name Constants (snake_case) ===================

  public static final String ARG_FILE_NAME = "file_name";
  public static final String ARG_ADDRESS = "address";
  public static final String ARG_CATEGORY_PATH = "category_path";
  public static final String ARG_COMMENT = "comment";
  public static final String ARG_CURRENT_NAME = "current_name";
  public static final String ARG_CURSOR = "cursor";
  public static final String ARG_DATA_TYPE = "data_type";
  public static final String ARG_DATA_TYPE_PATH = "data_type_path";
  public static final String ARG_DATA_TYPE_ID = "data_type_id";
  public static final String ARG_ENUM_PATH = "enum_path";
  public static final String ARG_FILTER = "filter";
  public static final String ARG_FUNC_DEF_PATH = "function_definition_path";
  public static final String ARG_FUNCTION_ADDRESS = "function_address";
  public static final String ARG_FUNCTION_NAME = "function_name";
  public static final String ARG_FUNCTION_SYMBOL_ID = "function_symbol_id";
  public static final String ARG_LENGTH = "length";
  public static final String ARG_NAME = "name";
  public static final String ARG_NEW_NAME = "new_name";
  public static final String ARG_NEXT_CURSOR = "next_cursor";
  public static final String ARG_OFFSET = "offset";
  public static final String ARG_PATH = "path";
  public static final String ARG_SIZE = "size";
  public static final String ARG_STORAGE_STRING = "storage_string";
  public static final String ARG_STRUCT_PATH = "struct_path";
  public static final String ARG_SYMBOL_ID = "symbol_id";
  public static final String ARG_TYPEDEF_PATH = "typedef_path";
  public static final String ARG_UNION_PATH = "union_path";
  public static final String ARG_USE_DECOMPILER_VIEW = "use_decompiler_view";
  public static final String ARG_VALUE = "value";
  public static final String ARG_VARIABLE_IDENTIFIER = "variable_identifier";
  public static final String ARG_VARIABLE_SYMBOL_ID = "variable_symbol_id";
  public static final String ARG_PACKING_VALUE = "packing_value";
  public static final String ARG_ALIGNMENT_VALUE = "alignment_value";
  public static final String ARG_ACTION = "action";
  public static final String ARG_NAMESPACE = "namespace";
  public static final String ARG_NAME_PATTERN = "name_pattern";
  public static final String ARG_PAGE_SIZE = "page_size";
  public static final String ARG_TOOL_OUTPUT_SESSION_ID = "tool_output_session_id";

  // =================== Abstract Methods ===================

  /**
   * Defines the JSON input schema for this tool. The schema dictates the expected structure and
   * types of the arguments map passed to the {@link #execute} method.
   *
   * @return The {@link JsonSchema} representing the JSON schema definition.
   */
  public abstract JsonSchema schema();

  /**
   * Executes the core logic of the tool asynchronously. This method should return the raw result
   * object (e.g., List, Map, POJO, String). Errors should be signalled via Mono.error() with a
   * GhidraMcpException.
   *
   * @param context The MCP transport context
   * @param args A map containing the arguments passed to the tool
   * @param tool The current Ghidra PluginTool context
   * @return A {@link Mono} emitting the raw result object upon successful execution, or signalling
   *     an error via {@code Mono.error()}
   */
  public abstract Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool);

  // =================== Tool Specification Generation ===================

  /**
   * Generates the MCP {@link AsyncToolSpecification} for this tool. This defines how the tool
   * appears to MCP clients.
   *
   * @param tool The current Ghidra PluginTool context
   * @return An AsyncToolSpecification or null if the specification cannot be created
   */
  public AsyncToolSpecification specification(PluginTool tool) {
    return Optional.ofNullable(this.getClass().getAnnotation(GhidraMcpTool.class))
        .map(annotation -> createToolSpecification(annotation, tool))
        .orElseGet(
            () -> {
              Msg.error(
                  this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
              return null;
            });
  }

  private AsyncToolSpecification createToolSpecification(
      GhidraMcpTool annotation, PluginTool tool) {
    return convertToMcpSchema(schema(), annotation)
        .map(
            mcpSchema ->
                new AsyncToolSpecification(
                    Tool.builder()
                        .name(annotation.mcpName())
                        .description(annotation.mcpDescription())
                        .inputSchema(mcpSchema)
                        .outputSchema(outputSchema())
                        .title(annotation.title().isEmpty() ? null : annotation.title())
                        .annotations(createToolAnnotations(annotation))
                        .build(),
                    (ctx, request) ->
                        executeWithEnvelope(ctx, request.arguments(), tool, annotation)))
        .orElse(null);
  }

  /** Returns the MCP output schema advertised for this tool. */
  protected Map<String, Object> outputSchema() {
    return DEFAULT_OUTPUT_SCHEMA;
  }

  private static Map<String, Object> createDefaultOutputSchema() {
    Map<String, Object> errorSchema = new LinkedHashMap<>();
    errorSchema.put("type", "object");
    errorSchema.put(
        "properties",
        Map.of(
            "message", Map.of("type", "string"),
            "hint", Map.of("type", "string"),
            "error_type", Map.of("type", "string"),
            "error_code", Map.of("type", "string"),
            "context", Map.of("type", "object"),
            "related_resources", Map.of("type", "array"),
            "suggestions", Map.of("type", "array")));
    errorSchema.put("additionalProperties", true);

    Map<String, Object> responseSchema = new LinkedHashMap<>();
    responseSchema.put("type", "object");
    responseSchema.put("required", List.of("success"));
    responseSchema.put(
        "properties",
        Map.of(
            "success", Map.of("type", "boolean"),
            "data", Map.of(),
            "next_cursor", Map.of("type", "string"),
            "duration_ms", Map.of("type", "number"),
            "error", errorSchema));
    responseSchema.put("additionalProperties", false);
    return responseSchema;
  }

  /**
   * Creates ToolAnnotations from the @GhidraMcpTool annotation hints. Returns null if all hints are
   * at their default values.
   */
  private ToolAnnotations createToolAnnotations(GhidraMcpTool annotation) {
    boolean hasTitle = !annotation.title().isEmpty();
    boolean hasReadOnly = annotation.readOnlyHint();
    boolean hasDestructive = annotation.destructiveHint();
    boolean hasIdempotent = annotation.idempotentHint();
    boolean hasOpenWorld = annotation.openWorldHint();

    // Only create annotations if at least one hint is set
    if (!hasTitle && !hasReadOnly && !hasDestructive && !hasIdempotent && !hasOpenWorld) {
      return null;
    }

    return new ToolAnnotations(
        hasTitle ? annotation.title() : null,
        hasReadOnly ? Boolean.TRUE : null,
        hasDestructive ? Boolean.TRUE : null,
        hasIdempotent ? Boolean.TRUE : null,
        hasOpenWorld ? Boolean.TRUE : null,
        null // returnDirect - not exposed in annotation
        );
  }

  /** Wraps execution with timing, error normalization, and response envelope. */
  private Mono<CallToolResult> executeWithEnvelope(
      McpTransportContext ctx,
      Map<String, Object> args,
      PluginTool tool,
      GhidraMcpTool annotation) {

    long startTime = System.currentTimeMillis();
    String toolName = annotation.mcpName();
    String operation = getOperationFromArgs(args);
    ProgramResourceTracker tracker = new ProgramResourceTracker();

    return execute(ctx, args, tool)
        .map(
            result -> {
              long duration = System.currentTimeMillis() - startTime;
              McpResponse<?> response;

              // Handle PaginatedResult specially to flatten cursor to root level
              if (result instanceof PaginatedResult<?> paginated) {
                response =
                    McpResponse.paginated(
                        toolName,
                        operation,
                        paginated.results,
                        paginated.nextCursor,
                        null,
                        duration);
              } else {
                response = McpResponse.success(toolName, operation, result, duration);
              }

              return createSuccessResultInternal(response, args, toolName, operation);
            })
        .onErrorResume(
            t -> {
              long duration = System.currentTimeMillis() - startTime;
              GhidraMcpException normalized = normalizeException(t, toolName, operation);
              McpResponse<?> response =
                  McpResponse.error(toolName, operation, normalized.getErr(), duration);
              return createErrorResultInternal(response, normalized);
            })
        .contextWrite(context -> context.put(PROGRAM_TRACKER_CONTEXT_KEY, tracker))
        .doFinally(signal -> tracker.releaseAll(this));
  }

  /** Extracts operation type from args (for action-based tools). */
  private String getOperationFromArgs(Map<String, Object> args) {
    Object action = args.get(ARG_ACTION);
    if (action instanceof String) {
      return (String) action;
    }
    return "execute";
  }

  // =================== Error Normalization ===================

  /**
   * Normalizes any exception to a GhidraMcpException with structured error info. This ensures all
   * errors returned to API consumers are properly structured.
   *
   * @param t The throwable to normalize
   * @param toolName The tool name for error context
   * @param operation The operation being performed
   * @return A GhidraMcpException with structured error information
   */
  protected GhidraMcpException normalizeException(Throwable t, String toolName, String operation) {
    // Already structured - return as-is
    if (t instanceof GhidraMcpException) {
      return (GhidraMcpException) t;
    }

    // RuntimeException wrapping a GhidraMcpException - unwrap
    if (t instanceof RuntimeException && t.getCause() instanceof GhidraMcpException) {
      return (GhidraMcpException) t.getCause();
    }

    // IllegalArgumentException - convert to validation error
    if (t instanceof IllegalArgumentException) {
      GhidraMcpError error =
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
              .message(t.getMessage())
              .context(
                  new GhidraMcpError.ErrorContext(
                      toolName,
                      operation,
                      null,
                      null,
                      Map.of("exception_type", "IllegalArgumentException")))
              .build();
      return new GhidraMcpException(error);
    }

    // NullPointerException - convert to validation error
    if (t instanceof NullPointerException) {
      GhidraMcpError error =
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
              .message("Null value encountered: " + t.getMessage())
              .context(
                  new GhidraMcpError.ErrorContext(
                      toolName,
                      operation,
                      null,
                      null,
                      Map.of("exception_type", "NullPointerException")))
              .build();
      return new GhidraMcpException(error);
    }

    // All other exceptions - convert to internal error
    GhidraMcpError error = GhidraMcpErrorUtils.unexpectedError(toolName, operation, t);
    return new GhidraMcpException(error);
  }

  // =================== Result Creation ===================

  private CallToolResult createSuccessResultInternal(
      McpResponse<?> response, Map<String, Object> args, String toolName, String operation) {
    try {
      String jsonResult = mapper.writeValueAsString(response);

      if (jsonResult.length() > INLINE_RESPONSE_CHAR_LIMIT) {
        String requestedSessionId =
            getOptionalStringArgument(args, ARG_TOOL_OUTPUT_SESSION_ID).orElse(null);
        ToolOutputStore.StoredOutputRef outputRef =
            ToolOutputStore.store(requestedSessionId, toolName, operation, jsonResult);
        response = wrapOversizedOutput(response, outputRef);
      }

      return buildStructuredToolResult(response, false);
    } catch (JsonProcessingException e) {
      Msg.error(this, "Error serializing response to JSON: " + e.getMessage());

      McpResponse<?> errorResponse =
          McpResponse.error(
              toolName,
              operation,
              GhidraMcpError.internal()
                  .message("Failed to serialize tool response")
                  .context(
                      new GhidraMcpError.ErrorContext(
                          toolName,
                          operation,
                          null,
                          null,
                          Map.of("exception_type", e.getClass().getSimpleName())))
                  .build());
      return buildStructuredToolResult(errorResponse, true);
    }
  }

  private CallToolResult buildStructuredToolResult(McpResponse<?> response, boolean isError) {
    return CallToolResult.builder().structuredContent(response).isError(isError).build();
  }

  private McpResponse<?> wrapOversizedOutput(
      McpResponse<?> originalResponse, ToolOutputStore.StoredOutputRef outputRef) {
    Map<String, Object> inlineNotice =
        Map.of(
            "message",
            "Output exceeded inline size and was stored for chunked retrieval.",
            "retrieval_tool",
            TOOL_OUTPUT_READER_NAME,
            "session_id",
            outputRef.sessionId(),
            "output_id",
            outputRef.outputId(),
            "output_file_name",
            outputRef.fileName(),
            "tool_name",
            outputRef.toolName(),
            "operation",
            outputRef.operation(),
            "total_chars",
            outputRef.totalChars(),
            "inline_limit_chars",
            INLINE_RESPONSE_CHAR_LIMIT);

    return new McpResponse.Builder<Object>()
        .data(inlineNotice)
        .nextCursor(originalResponse.getNextCursor())
        .durationMs(originalResponse.getDurationMs())
        .error(originalResponse.getError())
        .build();
  }

  private Mono<CallToolResult> createErrorResultInternal(
      McpResponse<?> response, GhidraMcpException exception) {
    Msg.error(
        this,
        "Tool error - "
            + exception.getErrorType()
            + " ["
            + exception.getErrorCode()
            + "]: "
            + exception.getMessage());

    return Mono.just(buildStructuredToolResult(response, true));
  }

  // =================== Argument Parsing (throws GhidraMcpException) ===================

  /**
   * Retrieves an optional string argument from the provided map.
   *
   * @param args The map of arguments
   * @param argumentName The name of the argument to retrieve
   * @return An Optional containing the non-blank string value if present
   */
  protected Optional<String> getOptionalStringArgument(
      Map<String, Object> args, String argumentName) {
    return Optional.ofNullable(args.get(argumentName))
        .filter(String.class::isInstance)
        .map(String.class::cast)
        .filter(value -> !value.isBlank());
  }

  /**
   * Retrieves a required non-blank string argument from the provided map.
   *
   * @param args The map of arguments
   * @param argumentName The name of the required argument
   * @return The non-blank string value
   * @throws GhidraMcpException If the argument is missing, blank, or not a String
   */
  protected String getRequiredStringArgument(Map<String, Object> args, String argumentName)
      throws GhidraMcpException {
    return getOptionalStringArgument(args, argumentName)
        .orElseThrow(
            () ->
                new GhidraMcpException(
                    GhidraMcpErrorUtils.missingRequiredArgument(getMcpName(), argumentName)));
  }

  /** Retrieves an optional integer argument from the provided map. */
  protected Optional<Integer> getOptionalIntArgument(
      Map<String, Object> args, String argumentName) {
    return Optional.ofNullable(args.get(argumentName))
        .flatMap(
            valueNode -> {
              Optional<Long> strictLong = parseStrictIntegralValue(valueNode);
              if (strictLong.isEmpty()) {
                return Optional.empty();
              }

              long parsed = strictLong.get();
              if (parsed < Integer.MIN_VALUE || parsed > Integer.MAX_VALUE) {
                return Optional.empty();
              }
              return Optional.of((int) parsed);
            });
  }

  /**
   * Retrieves a required integer argument from the provided map.
   *
   * @throws GhidraMcpException If the argument is missing or invalid
   */
  protected Integer getRequiredIntArgument(Map<String, Object> args, String argumentName)
      throws GhidraMcpException {
    Object rawValue = args.get(argumentName);
    if (rawValue == null) {
      throw new GhidraMcpException(
          GhidraMcpErrorUtils.missingRequiredArgument(getMcpName(), argumentName));
    }

    return getOptionalIntArgument(args, argumentName)
        .orElseThrow(
            () ->
                new GhidraMcpException(
                    GhidraMcpError.invalid(
                        argumentName, rawValue, "must be a valid 32-bit integer value")));
  }

  /** Retrieves an optional long argument from the provided map. */
  protected Optional<Long> getOptionalLongArgument(Map<String, Object> args, String argumentName) {
    return Optional.ofNullable(args.get(argumentName)).flatMap(this::parseStrictIntegralValue);
  }

  private Optional<Long> parseStrictIntegralValue(Object valueNode) {
    if (valueNode == null) {
      return Optional.empty();
    }

    String rawValue =
        valueNode instanceof String ? ((String) valueNode).trim() : valueNode.toString().trim();
    if (rawValue.isEmpty() || !rawValue.matches("[-+]?\\d+")) {
      return Optional.empty();
    }

    try {
      return Optional.of(Long.parseLong(rawValue));
    } catch (NumberFormatException e) {
      return Optional.empty();
    }
  }

  /**
   * Retrieves a required long argument from the provided map.
   *
   * @throws GhidraMcpException If the argument is missing or invalid
   */
  protected Long getRequiredLongArgument(Map<String, Object> args, String argumentName)
      throws GhidraMcpException {
    Object rawValue = args.get(argumentName);
    if (rawValue == null) {
      throw new GhidraMcpException(
          GhidraMcpErrorUtils.missingRequiredArgument(getMcpName(), argumentName));
    }

    return getOptionalLongArgument(args, argumentName)
        .orElseThrow(
            () ->
                new GhidraMcpException(
                    GhidraMcpError.invalid(
                        argumentName, rawValue, "must be a valid 64-bit integer value")));
  }

  /** Retrieves an optional boolean argument from the provided map. */
  protected Optional<Boolean> getOptionalBooleanArgument(
      Map<String, Object> args, String argumentName) {
    return Optional.ofNullable(args.get(argumentName))
        .flatMap(
            valueNode -> {
              if (valueNode instanceof Boolean) {
                return Optional.of((Boolean) valueNode);
              } else if (valueNode instanceof String) {
                String value = ((String) valueNode).trim();
                if ("true".equalsIgnoreCase(value)) {
                  return Optional.of(true);
                } else if ("false".equalsIgnoreCase(value)) {
                  return Optional.of(false);
                }
              }
              return Optional.empty();
            });
  }

  /**
   * Retrieves a required boolean argument from the provided map.
   *
   * @throws GhidraMcpException If the argument is missing or invalid
   */
  protected Boolean getRequiredBooleanArgument(Map<String, Object> args, String argumentName)
      throws GhidraMcpException {
    Object rawValue = args.get(argumentName);
    if (rawValue == null) {
      throw new GhidraMcpException(
          GhidraMcpErrorUtils.missingRequiredArgument(getMcpName(), argumentName));
    }

    return getOptionalBooleanArgument(args, argumentName)
        .orElseThrow(
            () ->
                new GhidraMcpException(
                    GhidraMcpError.invalid(argumentName, rawValue, "must be true or false")));
  }

  /** Retrieves an optional ObjectNode (JSON object) argument. */
  protected Optional<ObjectNode> getOptionalObjectNodeArgument(
      Map<String, Object> args, String argumentName) {
    return Optional.ofNullable(args.get(argumentName))
        .filter(ObjectNode.class::isInstance)
        .map(ObjectNode.class::cast);
  }

  /**
   * Retrieves a required ObjectNode (JSON object) argument.
   *
   * @throws GhidraMcpException If the argument is missing or not an ObjectNode
   */
  protected ObjectNode getRequiredObjectNodeArgument(Map<String, Object> args, String argumentName)
      throws GhidraMcpException {
    return getOptionalObjectNodeArgument(args, argumentName)
        .orElseThrow(
            () ->
                new GhidraMcpException(
                    GhidraMcpErrorUtils.missingRequiredArgument(getMcpName(), argumentName)));
  }

  /** Retrieves an optional ArrayNode (JSON array) argument. */
  protected Optional<ArrayNode> getOptionalArrayNodeArgument(
      Map<String, Object> args, String argumentName) {
    return Optional.ofNullable(args.get(argumentName))
        .filter(ArrayNode.class::isInstance)
        .map(ArrayNode.class::cast);
  }

  /**
   * Retrieves a required ArrayNode (JSON array) argument.
   *
   * @throws GhidraMcpException If the argument is missing or not an ArrayNode
   */
  protected ArrayNode getRequiredArrayNodeArgument(Map<String, Object> args, String argumentName)
      throws GhidraMcpException {
    return getOptionalArrayNodeArgument(args, argumentName)
        .orElseThrow(
            () ->
                new GhidraMcpException(
                    GhidraMcpErrorUtils.missingRequiredArgument(getMcpName(), argumentName)));
  }

  /** Retrieves an optional List of Maps argument. */
  @SuppressWarnings("unchecked")
  protected Optional<List<Map<String, Object>>> getOptionalListArgument(
      Map<String, Object> args, String argumentName) {
    return Optional.ofNullable(args.get(argumentName))
        .filter(List.class::isInstance)
        .map(List.class::cast)
        .flatMap(
            list -> {
              try {
                return Optional.of((List<Map<String, Object>>) list);
              } catch (ClassCastException e) {
                Msg.warn(this, "Argument '" + argumentName + "' contains unexpected types.", e);
                return Optional.empty();
              }
            });
  }

  /** Retrieves an optional Map<String, Object> argument. */
  @SuppressWarnings("unchecked")
  protected Optional<Map<String, Object>> getOptionalMapArgument(
      Map<String, Object> args, String argumentName) {
    return Optional.ofNullable(args.get(argumentName))
        .filter(Map.class::isInstance)
        .map(Map.class::cast)
        .flatMap(
            map -> {
              try {
                return Optional.of((Map<String, Object>) map);
              } catch (ClassCastException e) {
                Msg.warn(this, "Argument '" + argumentName + "' cast failed.", e);
                return Optional.empty();
              }
            });
  }

  // =================== Program Access ===================

  /**
   * Gets the currently active Program from the arguments.
   *
   * @param args The tool arguments map, expected to contain "file_name"
   * @param tool The current Ghidra PluginTool
   * @return A Mono emitting the active Program
   */
  protected Mono<Program> getProgram(Map<String, Object> args, PluginTool tool) {
    return Mono.deferContextual(
        contextView ->
            Mono.fromCallable(
                () -> {
                  DomainFile domainFile = getDomainFile(args, tool);
                  Program program = getProgramFromDomainFile(domainFile);
                  ProgramResourceTracker tracker =
                      contextView.getOrDefault(PROGRAM_TRACKER_CONTEXT_KEY, null);
                  if (tracker != null) {
                    tracker.track(program);
                  }
                  return program;
                }));
  }

  /** Retrieves a DomainFile based on the "file_name" argument. */
  protected DomainFile getDomainFile(Map<String, Object> args, PluginTool tool)
      throws GhidraMcpException {
    String fileName =
        getOptionalStringArgument(args, ARG_FILE_NAME)
            .orElseThrow(
                () ->
                    new GhidraMcpException(
                        GhidraMcpErrorUtils.missingRequiredArgument(getMcpName(), ARG_FILE_NAME)));
    return GhidraStateUtils.findDomainFile(fileName);
  }

  /** Retrieves the Program object from a DomainFile. */
  protected Program getProgramFromDomainFile(DomainFile domainFile) throws GhidraMcpException {
    return GhidraStateUtils.getProgramFromFile(domainFile, this);
  }

  // =================== Transaction Management ===================

  /**
   * Executes work within a Ghidra transaction on the Swing EDT. Transaction is committed only if
   * work succeeds; otherwise rolled back.
   *
   * @param program The Program to operate on
   * @param transactionName A descriptive name for the transaction
   * @param work The work to execute
   * @param <T> The result type
   * @return A Mono emitting the result of the work
   */
  protected <T> Mono<T> executeInTransaction(
      Program program, String transactionName, Callable<T> work) {
    return Mono.<T>create(
            sink -> {
              Swing.runNow(
                  () -> {
                    int txId = -1;
                    try {
                      txId = program.startTransaction(transactionName);
                      T result = work.call();
                      program.endTransaction(txId, true);
                      sink.success(result);
                    } catch (Throwable t) {
                      if (txId != -1) {
                        try {
                          program.endTransaction(txId, false);
                        } catch (Exception endTxError) {
                          Msg.error(
                              this, "Failed to abort transaction: " + endTxError.getMessage());
                        }
                      }
                      // Normalize the exception before passing to sink
                      GhidraMcpException normalized =
                          normalizeException(t, getMcpName(), transactionName);
                      sink.error(normalized);
                    }
                  });
            })
        .subscribeOn(Schedulers.boundedElastic());
  }

  /**
   * Executes read/write work on the Swing EDT without opening a transaction.
   *
   * <p>Use this for operations that must run on EDT but should not create nested or synthetic
   * transactions (e.g. undo/redo).
   */
  protected <T> Mono<T> executeOnEdt(String operationName, Callable<T> work) {
    return Mono.<T>create(
            sink -> {
              Swing.runNow(
                  () -> {
                    try {
                      T result = work.call();
                      sink.success(result);
                    } catch (Throwable t) {
                      sink.error(normalizeException(t, getMcpName(), operationName));
                    }
                  });
            })
        .subscribeOn(Schedulers.boundedElastic());
  }

  /**
   * Resolves a data type name/path using Ghidra's parser with conservative fallbacks.
   *
   * <p>Supports primitives, pointers, arrays, templates, namespace-qualified names, and category
   * paths.
   */
  protected DataType resolveDataTypeWithFallback(DataTypeManager dtm, String typeName) {
    if (dtm == null || typeName == null || typeName.trim().isEmpty()) {
      return null;
    }

    String trimmedName = typeName.trim();
    LinkedHashSet<String> attempted = new LinkedHashSet<>();

    // Phase 1: native resolution of exact user input.
    DataType exact = tryResolveNativeCandidate(dtm, trimmedName, attempted);
    if (exact != null) {
      return exact;
    }

    // Phase 2: native resolution of conservative syntax normalization.
    String collapsedWhitespace = collapseWhitespace(trimmedName);
    DataType collapsed = tryResolveNativeCandidate(dtm, collapsedWhitespace, attempted);
    if (collapsed != null) {
      return collapsed;
    }

    String normalizedArraySpacing = normalizeArraySpacing(collapsedWhitespace);
    DataType normalizedArray = tryResolveNativeCandidate(dtm, normalizedArraySpacing, attempted);
    if (normalizedArray != null) {
      return normalizedArray;
    }

    // Phase 3: extension layer on top of native helpers (slash/no-slash variants).
    LinkedHashSet<String> extensionCandidates =
        buildExtendedDataTypeCandidates(collapsedWhitespace, normalizedArraySpacing);
    for (String candidate : extensionCandidates) {
      DataType resolved = tryResolveNativeCandidate(dtm, candidate, attempted);
      if (resolved != null) {
        return resolved;
      }
    }

    // Phase 4: array reconstruction for edge forms (e.g. "/MyStruct [2]").
    LinkedHashSet<String> arrayCandidates = new LinkedHashSet<>();
    addCandidate(arrayCandidates, trimmedName);
    addCandidate(arrayCandidates, collapsedWhitespace);
    addCandidate(arrayCandidates, normalizedArraySpacing);
    arrayCandidates.addAll(extensionCandidates);

    for (String candidate : arrayCandidates) {
      DataType arrayResolved = tryResolveArrayExpression(dtm, candidate);
      if (arrayResolved != null) {
        return arrayResolved;
      }
    }

    return null;
  }

  private LinkedHashSet<String> buildExtendedDataTypeCandidates(
      String collapsedWhitespace, String normalizedArraySpacing) {
    LinkedHashSet<String> candidates = new LinkedHashSet<>();

    addCandidate(candidates, collapsedWhitespace);
    addCandidate(candidates, normalizedArraySpacing);

    if (collapsedWhitespace.startsWith("/")) {
      addCandidate(candidates, collapsedWhitespace.substring(1));
    } else {
      addCandidate(candidates, "/" + collapsedWhitespace);
    }

    if (normalizedArraySpacing.startsWith("/")) {
      addCandidate(candidates, normalizedArraySpacing.substring(1));
    } else {
      addCandidate(candidates, "/" + normalizedArraySpacing);
    }

    return candidates;
  }

  private DataType tryResolveNativeCandidate(
      DataTypeManager dtm, String expression, LinkedHashSet<String> attempted) {
    if (expression == null) {
      return null;
    }

    String candidate = expression.trim();
    if (candidate.isEmpty() || !attempted.add(candidate)) {
      return null;
    }

    DataType parsed = tryParseDataType(dtm, candidate);
    if (parsed != null) {
      return parsed;
    }

    DataType primitive = DataTypeUtilities.getCPrimitiveDataType(candidate);
    if (primitive != null) {
      return primitive;
    }

    DataType direct = tryLookupDataType(dtm, candidate);
    if (direct != null) {
      return direct;
    }

    if (candidate.contains("::")) {
      DataType namespaceQualified =
          DataTypeUtilities.findNamespaceQualifiedDataType(dtm, candidate, null);
      if (namespaceQualified != null) {
        return namespaceQualified;
      }
    }

    return null;
  }

  private void addCandidate(LinkedHashSet<String> candidates, String candidate) {
    if (candidate == null) {
      return;
    }
    String value = candidate.trim();
    if (!value.isEmpty()) {
      candidates.add(value);
    }
  }

  private String collapseWhitespace(String expression) {
    return expression.replaceAll("\\s+", " ").trim();
  }

  private String normalizeArraySpacing(String expression) {
    return expression.replaceAll("\\s*\\[\\s*", "[").replaceAll("\\s*\\]\\s*", "]");
  }

  private DataType tryParseDataType(DataTypeManager dtm, String expression) {
    try {
      DataTypeParser parser = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL);
      return parser.parse(expression);
    } catch (Exception ignored) {
      return null;
    }
  }

  private DataType tryLookupDataType(DataTypeManager dtm, String expression) {
    try {
      return dtm.getDataType(expression);
    } catch (Exception ignored) {
      return null;
    }
  }

  private DataType tryResolveArrayExpression(DataTypeManager dtm, String expression) {
    String normalized = normalizeArraySpacing(expression);
    int firstBracket = normalized.indexOf('[');
    if (firstBracket <= 0 || !normalized.endsWith("]")) {
      return null;
    }

    String baseExpression = normalized.substring(0, firstBracket).trim();
    String arraySuffix = normalized.substring(firstBracket);
    if (baseExpression.isEmpty() || !arraySuffix.matches("(\\[[0-9]+\\])+")) {
      return null;
    }

    DataType baseType = resolveBaseDataTypeExpression(dtm, baseExpression);
    if (baseType == null) {
      return null;
    }

    LinkedHashSet<String> arrayCandidates = new LinkedHashSet<>();
    addCandidate(arrayCandidates, baseType.getPathName() + arraySuffix);
    addCandidate(arrayCandidates, baseType.getDisplayName() + arraySuffix);
    addCandidate(arrayCandidates, baseType.getName() + arraySuffix);

    for (String arrayCandidate : arrayCandidates) {
      DataType parsed = tryParseDataType(dtm, arrayCandidate);
      if (parsed != null) {
        return parsed;
      }
    }

    return null;
  }

  private DataType resolveBaseDataTypeExpression(DataTypeManager dtm, String baseExpression) {
    if (baseExpression == null || baseExpression.trim().isEmpty()) {
      return null;
    }

    String trimmedBase = baseExpression.trim();
    String collapsedWhitespace = collapseWhitespace(trimmedBase);
    String normalizedArraySpacing = normalizeArraySpacing(collapsedWhitespace);
    LinkedHashSet<String> attempted = new LinkedHashSet<>();

    DataType exact = tryResolveNativeCandidate(dtm, trimmedBase, attempted);
    if (exact != null) {
      return exact;
    }

    DataType collapsed = tryResolveNativeCandidate(dtm, collapsedWhitespace, attempted);
    if (collapsed != null) {
      return collapsed;
    }

    DataType normalized = tryResolveNativeCandidate(dtm, normalizedArraySpacing, attempted);
    if (normalized != null) {
      return normalized;
    }

    LinkedHashSet<String> extensionCandidates =
        buildExtendedDataTypeCandidates(collapsedWhitespace, normalizedArraySpacing);
    for (String candidate : extensionCandidates) {
      DataType resolved = tryResolveNativeCandidate(dtm, candidate, attempted);
      if (resolved != null) {
        return resolved;
      }
    }

    return null;
  }

  // =================== Address Parsing ===================

  /** Result object containing a parsed address and its original string representation. */
  public static class AddressResult {
    private final Address address;
    private final String addressString;

    public AddressResult(Address address, String addressString) {
      this.address = address;
      this.addressString = addressString;
    }

    public Address getAddress() {
      return address;
    }

    public String getAddressString() {
      return addressString;
    }
  }

  /**
   * Parses an address string into an Address object.
   *
   * @param program The program containing the address factory
   * @param addressStr The address string to parse
   * @param operation The operation being performed (for error context)
   * @return A Mono emitting the AddressResult
   */
  protected Mono<AddressResult> parseAddress(Program program, String addressStr, String operation) {
    return Mono.fromCallable(
        () -> {
          Address address = program.getAddressFactory().getAddress(addressStr);
          if (address == null) {
            throw new GhidraMcpException(
                GhidraMcpErrorUtils.addressParseError(
                    addressStr, getMcpName() + "." + operation, null));
          }
          return new AddressResult(address, addressStr);
        });
  }

  // =================== Tool Information ===================

  /** Gets the tool's MCP name from the @GhidraMcpTool annotation. */
  public String getMcpName() {
    GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
    return annotation != null ? annotation.mcpName() : this.getClass().getSimpleName();
  }

  /** Gets the annotation for this tool. */
  protected GhidraMcpTool getAnnotation() {
    return this.getClass().getAnnotation(GhidraMcpTool.class);
  }

  // =================== Schema Helpers ===================

  /**
   * Creates a base schema node using Google AI API format. Use this for basic schemas without
   * conditionals.
   */
  protected static com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder
      createBaseSchemaNode() {
    return com.themixednuts.utils.jsonschema.google.SchemaBuilder.object(mapper);
  }

  /**
   * Creates a schema node using JSON Schema Draft 7 format. Use this for tools with conditional
   * parameter requirements.
   */
  protected static com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.IObjectSchemaBuilder
      createDraft7SchemaNode() {
    return com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.object(mapper);
  }

  // =================== Schema Conversion ===================

  private Optional<McpSchema.JsonSchema> convertToMcpSchema(
      JsonSchema schema, GhidraMcpTool annotation) {
    return Optional.ofNullable(schema)
        .flatMap(s -> s.toJsonString(mapper))
        .flatMap(schemaString -> convertSchemaString(schemaString, annotation))
        .or(
            () -> {
              Msg.error(
                  this,
                  "Failed to generate schema for tool '"
                      + annotation.mcpName()
                      + "'. Tool will be disabled.");
              return Optional.empty();
            });
  }

  private Optional<McpSchema.JsonSchema> convertSchemaString(
      String schemaString, GhidraMcpTool annotation) {
    try {
      Map<String, Object> schemaMap =
          mapper.readValue(schemaString, new TypeReference<Map<String, Object>>() {});

      String type = (String) schemaMap.get("type");
      @SuppressWarnings("unchecked")
      Map<String, Object> properties = (Map<String, Object>) schemaMap.get("properties");
      @SuppressWarnings("unchecked")
      List<String> required = (List<String>) schemaMap.get("required");
      Boolean additionalProperties = (Boolean) schemaMap.get("additionalProperties");
      @SuppressWarnings("unchecked")
      Map<String, Object> defs = (Map<String, Object>) schemaMap.get("$defs");
      @SuppressWarnings("unchecked")
      Map<String, Object> definitions = (Map<String, Object>) schemaMap.get("definitions");

      Map<String, Object> unsupportedTopLevelKeys = new java.util.LinkedHashMap<>();
      for (Map.Entry<String, Object> entry : schemaMap.entrySet()) {
        if (!SUPPORTED_TOP_LEVEL_SCHEMA_KEYS.contains(entry.getKey())) {
          unsupportedTopLevelKeys.put(entry.getKey(), entry.getValue());
        }
      }

      if (!unsupportedTopLevelKeys.isEmpty()) {
        Msg.warn(
            this,
            "Schema for tool '"
                + annotation.mcpName()
                + "' uses unsupported top-level JSON schema keywords for MCP conversion: "
                + unsupportedTopLevelKeys.keySet()
                + ". Supported keys are "
                + SUPPORTED_TOP_LEVEL_SCHEMA_KEYS
                + ". Tool registration will continue, but these keywords are not enforced by MCP"
                + " input schema validation.");

        Map<String, Object> definitionCopy =
            definitions == null
                ? new java.util.LinkedHashMap<>()
                : new java.util.LinkedHashMap<>(definitions);
        definitionCopy.put("x_mcp_unsupported_keywords", unsupportedTopLevelKeys);
        definitions = definitionCopy;
      }

      return Optional.of(
          new McpSchema.JsonSchema(
              type, properties, required, additionalProperties, defs, definitions));
    } catch (IOException e) {
      Msg.error(
          this,
          "Failed to convert schema for tool '" + annotation.mcpName() + "': " + e.getMessage(),
          e);
      return Optional.empty();
    }
  }

  // =================== Utility Methods ===================

  /** Extracts text from CallToolResult content. */
  protected String getTextFromCallToolResult(CallToolResult result) {
    String textContent =
        Optional.ofNullable(result)
            .map(CallToolResult::content)
            .filter(content -> content != null && !content.isEmpty())
            .map(
                content ->
                    content.stream()
                        .filter(TextContent.class::isInstance)
                        .map(TextContent.class::cast)
                        .map(TextContent::text)
                        .filter(text -> text != null)
                        .collect(Collectors.joining("\n")))
            .orElse("");

    if (!textContent.isBlank()) {
      return textContent;
    }

    return Optional.ofNullable(result)
        .map(CallToolResult::structuredContent)
        .map(
            structured -> {
              try {
                return mapper.writeValueAsString(structured);
              } catch (JsonProcessingException e) {
                return "";
              }
            })
        .orElse("");
  }
}
