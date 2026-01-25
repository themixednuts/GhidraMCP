package com.themixednuts.tools;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.json.JsonWriteFeature;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.McpResponse;
import com.themixednuts.utils.GhidraMcpErrorUtils;
import com.themixednuts.utils.jsonschema.JsonSchema;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import io.modelcontextprotocol.spec.McpSchema.ToolAnnotations;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
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

  private static ObjectMapper createAndConfigureMapper() {
    ObjectMapper configuredMapper = new ObjectMapper();
    configuredMapper
        .getFactory()
        .configure(JsonWriteFeature.ESCAPE_NON_ASCII.mappedFeature(), true);
    configuredMapper.registerModule(new com.fasterxml.jackson.datatype.jdk8.Jdk8Module());
    return configuredMapper;
  }

  protected static final ObjectMapper mapper = createAndConfigureMapper();

  /** Default page size for paginated results */
  protected static final int DEFAULT_PAGE_LIMIT = 50;

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
                        .title(annotation.title().isEmpty() ? null : annotation.title())
                        .annotations(createToolAnnotations(annotation))
                        .build(),
                    (ctx, request) ->
                        executeWithEnvelope(ctx, request.arguments(), tool, annotation)))
        .orElse(null);
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

    return execute(ctx, args, tool)
        .map(
            result -> {
              long duration = System.currentTimeMillis() - startTime;
              McpResponse<?> response = McpResponse.success(toolName, operation, result, duration);
              return createSuccessResultInternal(response);
            })
        .onErrorResume(
            t -> {
              long duration = System.currentTimeMillis() - startTime;
              GhidraMcpException normalized = normalizeException(t, toolName, operation);
              McpResponse<?> response =
                  McpResponse.error(toolName, operation, normalized.getErr(), duration);
              return createErrorResultInternal(response, normalized);
            });
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
                      Map.of("exceptionType", "IllegalArgumentException")))
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
                      Map.of("exceptionType", "NullPointerException")))
              .build();
      return new GhidraMcpException(error);
    }

    // All other exceptions - convert to internal error
    GhidraMcpError error = GhidraMcpErrorUtils.unexpectedError(toolName, operation, t);
    return new GhidraMcpException(error);
  }

  // =================== Result Creation ===================

  private CallToolResult createSuccessResultInternal(McpResponse<?> response) {
    try {
      String jsonResult = mapper.writeValueAsString(response);
      return CallToolResult.builder()
          .content(Collections.singletonList(new TextContent(jsonResult)))
          .isError(Boolean.FALSE)
          .build();
    } catch (JsonProcessingException e) {
      Msg.error(this, "Error serializing response to JSON: " + e.getMessage());
      return CallToolResult.builder()
          .content(
              Collections.singletonList(
                  new TextContent("Error serializing response: " + e.getMessage())))
          .isError(Boolean.TRUE)
          .build();
    }
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

    try {
      String jsonResult = mapper.writeValueAsString(response);
      return Mono.just(
          CallToolResult.builder()
              .content(Collections.singletonList(new TextContent(jsonResult)))
              .isError(Boolean.TRUE)
              .build());
    } catch (JsonProcessingException e) {
      Msg.error(this, "Error serializing error response: " + e.getMessage());
      return Mono.just(
          CallToolResult.builder()
              .content(Collections.singletonList(new TextContent(exception.getMessage())))
              .isError(Boolean.TRUE)
              .build());
    }
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
              if (valueNode instanceof Number) {
                return Optional.of(((Number) valueNode).intValue());
              } else if (valueNode instanceof String) {
                String value = (String) valueNode;
                if (value.isBlank()) {
                  return Optional.empty();
                }
                try {
                  return Optional.of(Integer.parseInt(value));
                } catch (NumberFormatException e) {
                  return Optional.empty();
                }
              }
              return Optional.empty();
            });
  }

  /**
   * Retrieves a required integer argument from the provided map.
   *
   * @throws GhidraMcpException If the argument is missing or invalid
   */
  protected Integer getRequiredIntArgument(Map<String, Object> args, String argumentName)
      throws GhidraMcpException {
    return getOptionalIntArgument(args, argumentName)
        .orElseThrow(
            () ->
                new GhidraMcpException(
                    GhidraMcpErrorUtils.missingRequiredArgument(getMcpName(), argumentName)));
  }

  /** Retrieves an optional long argument from the provided map. */
  protected Optional<Long> getOptionalLongArgument(Map<String, Object> args, String argumentName) {
    return Optional.ofNullable(args.get(argumentName))
        .flatMap(
            valueNode -> {
              if (valueNode instanceof Number) {
                return Optional.of(((Number) valueNode).longValue());
              } else if (valueNode instanceof String) {
                String value = (String) valueNode;
                if (value.isBlank()) {
                  return Optional.empty();
                }
                try {
                  return Optional.of(Long.parseLong(value));
                } catch (NumberFormatException e) {
                  return Optional.empty();
                }
              }
              return Optional.empty();
            });
  }

  /**
   * Retrieves a required long argument from the provided map.
   *
   * @throws GhidraMcpException If the argument is missing or invalid
   */
  protected Long getRequiredLongArgument(Map<String, Object> args, String argumentName)
      throws GhidraMcpException {
    return getOptionalLongArgument(args, argumentName)
        .orElseThrow(
            () ->
                new GhidraMcpException(
                    GhidraMcpErrorUtils.missingRequiredArgument(getMcpName(), argumentName)));
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
    return getOptionalBooleanArgument(args, argumentName)
        .orElseThrow(
            () ->
                new GhidraMcpException(
                    GhidraMcpErrorUtils.missingRequiredArgument(getMcpName(), argumentName)));
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
    return Mono.fromCallable(
        () -> {
          DomainFile domainFile = getDomainFile(args, tool);
          return getProgramFromDomainFile(domainFile);
        });
  }

  /** Retrieves a DomainFile based on the "file_name" argument. */
  protected DomainFile getDomainFile(Map<String, Object> args, PluginTool tool)
      throws GhidraMcpException {
    ghidra.framework.model.Project project = ghidra.framework.main.AppInfo.getActiveProject();
    if (project == null) {
      throw new GhidraMcpException(
          GhidraMcpError.permissionState()
              .errorCode(GhidraMcpError.ErrorCode.PROGRAM_NOT_OPEN)
              .message("No active project found in the application")
              .build());
    }
    String fileName = getRequiredStringArgument(args, ARG_FILE_NAME);
    return findDomainFile(project, fileName);
  }

  private DomainFile findDomainFile(ghidra.framework.model.Project project, String fileNameStr)
      throws GhidraMcpException {
    // First check if the file is already open (fast path)
    Optional<DomainFile> openFile =
        project.getOpenData().stream().filter(f -> f.getName().equals(fileNameStr)).findFirst();

    if (openFile.isPresent()) {
      return openFile.get();
    }

    // Search the entire project recursively
    List<DomainFile> allFiles = new ArrayList<>();
    collectDomainFilesRecursive(project.getProjectData().getRootFolder(), allFiles);

    return allFiles.stream()
        .filter(f -> f.getName().equals(fileNameStr))
        .findFirst()
        .orElseThrow(() -> createFileNotFoundError(project, fileNameStr));
  }

  private void collectDomainFilesRecursive(DomainFolder folder, List<DomainFile> files) {
    files.addAll(List.of(folder.getFiles()));
    for (DomainFolder subfolder : folder.getFolders()) {
      collectDomainFilesRecursive(subfolder, files);
    }
  }

  private GhidraMcpException createFileNotFoundError(
      ghidra.framework.model.Project project, String fileNameStr) {
    List<String> openFiles =
        project.getOpenData().stream()
            .map(DomainFile::getName)
            .sorted()
            .collect(Collectors.toList());

    GhidraMcpError error = GhidraMcpErrorUtils.fileNotFound(fileNameStr, openFiles, getMcpName());
    return new GhidraMcpException(error);
  }

  /** Retrieves the Program object from a DomainFile. */
  protected Program getProgramFromDomainFile(DomainFile domainFile) throws GhidraMcpException {
    try {
      DomainObject obj = domainFile.getDomainObject(this, true, false, null);
      if (obj instanceof Program) {
        return (Program) obj;
      }
      String actualType = obj != null ? obj.getClass().getName() : "null";
      if (obj != null) {
        obj.release(this);
      }
      throw new GhidraMcpException(
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
              .message(
                  "File '"
                      + domainFile.getName()
                      + "' does not contain a Program. Found: "
                      + actualType)
              .build());
    } catch (Exception e) {
      if (e instanceof GhidraMcpException) {
        throw (GhidraMcpException) e;
      }
      throw new GhidraMcpException(
          GhidraMcpErrorUtils.unexpectedError(getMcpName(), "file access", e));
    }
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
    return Optional.ofNullable(result)
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
  }
}
