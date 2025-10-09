package com.themixednuts.tools;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.json.JsonWriteFeature;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.GhidraMcpErrorUtils;
import com.themixednuts.utils.jsonschema.JsonSchema;
import io.modelcontextprotocol.spec.McpSchema;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import ghidra.program.model.address.Address;

/**
 * Base interface for all Ghidra MCP tool specifications.
 * Provides core methods for tool registration, execution, and common Ghidra
 * operations.
 */
public interface IGhidraMcpSpecification {
    private static ObjectMapper createAndConfigureMapper() {
        ObjectMapper configuredMapper = new ObjectMapper();
        configuredMapper
                .getFactory()
                .configure(JsonWriteFeature.ESCAPE_NON_ASCII.mappedFeature(), true);
        // Register Jdk8Module for Optional support
        configuredMapper.registerModule(new com.fasterxml.jackson.datatype.jdk8.Jdk8Module());
        return configuredMapper;
    }

    static final ObjectMapper mapper = createAndConfigureMapper();

    /** Default page size for paginated results */
    static final int DEFAULT_PAGE_LIMIT = 50;

    // ===================================================================================
    // Common Argument Name Constants
    // ===================================================================================
    public static final String ARG_ADDRESS = "address";
    public static final String ARG_CATEGORY_PATH = "categoryPath";
    public static final String ARG_COMMENT = "comment";
    public static final String ARG_CURRENT_NAME = "currentName";
    public static final String ARG_CURSOR = "cursor";
    public static final String ARG_DATA_TYPE = "dataType";
    public static final String ARG_DATA_TYPE_PATH = "dataTypePath";
    public static final String ARG_ENUM_PATH = "enumPath";
    public static final String ARG_FILE_NAME = "fileName";
    public static final String ARG_FILTER = "filter";
    public static final String ARG_FUNC_DEF_PATH = "functionDefinitionPath";
    public static final String ARG_FUNCTION_ADDRESS = "functionAddress";
    public static final String ARG_FUNCTION_NAME = "functionName";
    public static final String ARG_FUNCTION_SYMBOL_ID = "functionSymbolId";
    public static final String ARG_LENGTH = "length";
    public static final String ARG_NAME = "name";
    public static final String ARG_NEW_NAME = "newName";
    public static final String ARG_NEXT_CURSOR = "nextCursor";
    public static final String ARG_OFFSET = "offset";
    public static final String ARG_PATH = "path";
    public static final String ARG_SIZE = "size";
    public static final String ARG_STORAGE_STRING = "storageString";
    public static final String ARG_STRUCT_PATH = "structPath";
    public static final String ARG_SYMBOL_ID = "symbolId";
    public static final String ARG_TYPEDEF_PATH = "typedefPath";
    public static final String ARG_UNION_PATH = "unionPath";
    public static final String ARG_USE_DECOMPILER_VIEW = "useDecompilerView";
    public static final String ARG_VALUE = "value";
    public static final String ARG_VARIABLE_IDENTIFIER = "variableIdentifier";
    public static final String ARG_VARIABLE_SYMBOL_ID = "variableSymbolId";

    // Arguments for struct packing and alignment
    public static final String ARG_PACKING_VALUE = "packingValue";
    public static final String ARG_ALIGNMENT_VALUE = "alignmentValue";

    // ===================================================================================

    // ===================================================================================
    // Core Interface Methods
    // ===================================================================================

    /**
     * Generates the MCP {@link AsyncToolSpecification} for this tool.
     * This defines how the tool appears to MCP clients, including its name,
     * description, and input schema.
     *
     * @param tool The current Ghidra {@link PluginTool} context, providing access
     *             to project data and other services.
     * @return An {@code AsyncToolSpecification} containing the tool's definition
     *         and
     *         execution logic, or {@code null} if the specification cannot be
     *         created
     *         (e.g., missing annotation or schema error).
     */
    default AsyncToolSpecification specification(PluginTool tool) {
        return Optional.ofNullable(this.getClass().getAnnotation(GhidraMcpTool.class))
                .map(annotation -> createToolSpecification(annotation, tool))
                .orElseGet(() -> {
                    Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
                    return null;
                });
    }

    /**
     * Creates an AsyncToolSpecification from the annotation and tool context.
     * 
     * @param annotation The GhidraMcpTool annotation containing tool metadata
     * @param tool       The PluginTool context
     * @return The AsyncToolSpecification or null if schema conversion fails
     */
    private AsyncToolSpecification createToolSpecification(GhidraMcpTool annotation, PluginTool tool) {
        return convertToMcpSchema(schema(), annotation)
                .map(mcpSchema -> new AsyncToolSpecification(
                        Tool.builder()
                                .name(annotation.mcpName())
                                .description(annotation.mcpDescription())
                                .inputSchema(mcpSchema)
                                .build(),
                        (ex, request) -> execute(ex, request.arguments(), tool)
                                .flatMap(this::createSuccessResult)
                                .onErrorResume(this::createErrorResult)))
                .orElse(null);
    }

    /**
     * Executes the core logic of the tool asynchronously.
     * This method should return the raw result object (e.g., List, Map, POJO,
     * String).
     * Errors should be signalled via Mono.error().
     *
     * @param ex   The MCP Async Server Exchange context.
     * @param args A map containing the arguments passed to the tool.
     * @param tool The current Ghidra PluginTool context.
     * @return A {@link Mono} emitting the raw result object upon successful
     *         execution,
     *         or signalling an error via {@code Mono.error()}.
     */
    Mono<? extends Object> execute(
            McpTransportContext ex,
            Map<String, Object> args,
            PluginTool tool);

    /**
     * Defines the JSON input schema for this tool.
     * The schema dictates the expected structure and types of the arguments
     * map passed to the {@link #execute} method.
     *
     * @return The {@link JsonSchema} representing the JSON schema definition.
     */
    JsonSchema schema();

    // ===================================================================================
    // Static Schema Helper
    // ===================================================================================

    /**
     * Creates a base {@link ObjectNode} for a tool schema using a fluent builder.
     * Configures the underlying ObjectMapper to escape non-ASCII characters.
     *
     * @return An {@link IObjectSchemaBuilder} to start building the schema.
     */
    /**
     * Creates a base schema node using Google AI API format (simplified, no
     * conditionals).
     * Use this for basic schemas without action-specific requirements.
     * 
     * @return An IObjectSchemaBuilder for Google AI compatible schemas
     */
    static com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder createBaseSchemaNode() {
        return com.themixednuts.utils.jsonschema.google.SchemaBuilder.object(mapper);
    }

    /**
     * Creates a schema node using JSON Schema Draft 7 format (with conditional
     * support).
     * Use this for tools with action-specific or conditional parameter
     * requirements.
     * 
     * Example:
     * 
     * <pre>
     * var schema = createDraft7SchemaNode();
     * schema.property(ARG_ACTION, ...)
     *       .addConditionals(
     *           conditional("action", "create").require("data_type_kind", "members"),
     *           conditional("action", "update").require("data_type_kind", "name")
     *       );
     * </pre>
     * 
     * @return An IJsonSchemaDraft7ObjectSchemaBuilder with conditional support
     */
    static com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.IJsonSchemaDraft7ObjectSchemaBuilder createDraft7SchemaNode() {
        return com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper);
    }

    // ===================================================================================
    // Ghidra Execution Helpers
    // ===================================================================================

    /**
     * Executes a given piece of work within a Ghidra transaction on the Swing Event
     * Dispatch Thread (EDT).
     * <p>
     * This method handles starting and ending the transaction correctly.
     * The transaction is committed only if the {@code work} Callable executes
     * successfully and its returned {@code Mono} completes successfully.
     * Otherwise, the transaction is aborted.
     * <p>
     * Exceptions thrown by the {@code work} Callable or signalled by its
     * {@code Mono} are propagated.
     *
     * @param program         The Ghidra {@link Program} instance to operate on.
     *                        Must not be null.
     * @param transactionName A descriptive name for the Ghidra transaction (e.g.,
     *                        "Rename Function").
     * @param work            A {@link Callable} that performs the Ghidra operations
     *                        and returns a {@code Mono<Object>}. The success or
     *                        error
     *                        signal of this Mono determines if the transaction is
     *                        committed.
     * @return A {@code Mono<Object>} that emits the result of the successful work
     *         or signals an error if the work failed or the transaction could not
     *         be
     *         committed.
     */
    default Mono<? extends Object> executeInTransaction(
            Program program,
            String transactionName,
            Callable<? extends Object> work) {
        return Mono.fromCallable(() -> {
            // Use AtomicReferences to capture result or exception from EDT
            AtomicReference<Object> resultRef = new AtomicReference<>();
            AtomicReference<Throwable> exceptionRef = new AtomicReference<>();

            Swing.runNow(() -> {
                // This still runs its lambda on the EDT
                int txId = -1;
                boolean success = false; // Assume failure initially
                try {
                    txId = program.startTransaction(transactionName);
                    resultRef.set(work.call()); // work.call() runs on EDT
                    success = true;
                } catch (Throwable t) {
                    // Capture the exception to be handled by the Mono
                    exceptionRef.set(t);
                    // Optionally, log it here too if desired, but primary handling will be via Mono
                    Msg.error(
                            this,
                            "Throwable during Ghidra transaction work '" +
                                    transactionName +
                                    "': " +
                                    t.getMessage());
                } finally {
                    if (txId != -1) {
                        try {
                            // Only commit if work.call() succeeded AND no prior exception was captured from
                            // it.
                            program.endTransaction(
                                    txId,
                                    success && exceptionRef.get() == null);
                        } catch (Exception e) {
                            Msg.error(
                                    this,
                                    "Failed to end transaction '" +
                                            transactionName +
                                            "' (intended success: " +
                                            (success && exceptionRef.get() == null) +
                                            ")");
                            // If ending the transaction fails, this is a new error or compounds an existing
                            // one.
                            // Prioritize the original exception from work.call() if one exists.
                            if (exceptionRef.get() == null) {
                                exceptionRef.set(
                                        new RuntimeException(
                                                "Failed to end transaction after successful work: " +
                                                        e.getMessage(),
                                                e));
                            }
                        }
                    }
                }
            });

            // After Swing.runNow completes (or times out, which Ghidra's Swing.runNow
            // handles internally by potentially throwing RuntimeException):
            // Check if an exception was captured from the EDT execution of work.call() or
            // from endTransaction.
            if (exceptionRef.get() != null) {
                // Propagate the captured exception to the Mono stream
                Throwable capturedError = exceptionRef.get();
                if (capturedError instanceof RuntimeException) {
                    throw (RuntimeException) capturedError;
                }
                throw new RuntimeException(
                        "Error during EDT execution: " + capturedError.getMessage(),
                        capturedError);
            }
            return resultRef.get(); // Return the result from work.call() if no exception occurred
        }).subscribeOn(Schedulers.boundedElastic()); // Ensures the fromCallable body runs on a worker thread
    }

    // ===================================================================================
    // Ghidra Context Retrieval Helpers
    // ===================================================================================

    /**
     * Gets the currently active {@link Program} associated with the given
     * arguments and PluginTool context.
     * Typically extracts a file name from arguments and finds the corresponding
     * open DomainFile in the tool's project.
     *
     * @param args The tool arguments map, expected to contain a "fileName" entry.
     * @param tool The current Ghidra {@link PluginTool} providing project context.
     * @return A {@link Mono} emitting the active {@link Program}.
     * @throws IllegalArgumentException if the "fileName" argument is missing,
     *                                  invalid, or does not correspond to an open
     *                                  DomainFile in the tool's project.
     * @throws Exception                if the DomainFile does not contain a Program
     *                                  or if access fails.
     */
    default Mono<Program> getProgram(
            Map<String, Object> args,
            PluginTool tool) {
        return Mono.fromCallable(() -> {
            DomainFile domainFile = getDomainFile(args, tool);
            return getProgramFromDomainFile(domainFile, this);
        });
    }

    /**
     * Retrieves an open {@link DomainFile} based on the "fileName" argument
     * within the application's active project context.
     *
     * @param args The tool arguments map, expected to contain a non-blank
     *             String entry for "fileName".
     * @param tool The current Ghidra {@link PluginTool} (may be null in headless
     *             mode).
     * @return The matching open {@link DomainFile}.
     * @throws IllegalArgumentException if the "fileName" argument is missing,
     *                                  not a non-blank String, or does not match
     *                                  any open DomainFile in the project.
     * @throws NullPointerException     if no active project is found.
     * @throws Exception                Potentially other exceptions from project
     *                                  access.
     */
    default DomainFile getDomainFile(Map<String, Object> args, PluginTool tool)
            throws Exception {
        // Use AppInfo.getActiveProject() for headless mode compatibility
        ghidra.framework.model.Project project = ghidra.framework.main.AppInfo.getActiveProject();
        if (project == null) {
            throw new NullPointerException("No active project found in the application.");
        }
        return findDomainFile(project, getRequiredStringArgument(args, "fileName"));
    }

    /**
     * Finds a domain file by name within the project (searches both open and closed
     * files).
     * Searches the entire project recursively to support headless mode.
     *
     * @param project     The Ghidra project to search in
     * @param fileNameStr The name of the file to find
     * @return The DomainFile if found
     * @throws Exception If the file is not found or an error occurs
     */
    private DomainFile findDomainFile(ghidra.framework.model.Project project, String fileNameStr) throws Exception {
        // First check if the file is already open (fast path)
        Optional<DomainFile> openFile = project.getOpenData().stream()
                .filter(f -> f.getName().equals(fileNameStr))
                .findFirst();

        if (openFile.isPresent()) {
            return openFile.get();
        }

        // If not open, search the entire project recursively
        List<DomainFile> allFiles = new ArrayList<>();
        collectDomainFilesRecursive(project.getProjectData().getRootFolder(), allFiles);

        return allFiles.stream()
                .filter(f -> f.getName().equals(fileNameStr))
                .findFirst()
                .orElseThrow(() -> createFileNotFoundError(project, fileNameStr));
    }

    /**
     * Recursively collect all domain files from a folder and its subfolders.
     */
    private void collectDomainFilesRecursive(DomainFolder folder, List<DomainFile> files) {
        files.addAll(List.of(folder.getFiles()));
        for (DomainFolder subfolder : folder.getFolders()) {
            collectDomainFilesRecursive(subfolder, files);
        }
    }

    /**
     * Creates a detailed file not found error with available files information.
     * 
     * @param project     The Ghidra project containing the open and closed files
     * @param fileNameStr The name of the file that was not found
     * @return A GhidraMcpException with structured error and list of open programs
     */
    private GhidraMcpException createFileNotFoundError(ghidra.framework.model.Project project, String fileNameStr) {
        // Get list of all open programs
        List<String> openFiles = project.getOpenData().stream()
                .map(DomainFile::getName)
                .sorted()
                .collect(Collectors.toList());

        // Use the structured error utility
        GhidraMcpError error = GhidraMcpErrorUtils.fileNotFound(
                fileNameStr,
                openFiles,
                "program_access");

        return new GhidraMcpException(error);
    }

    /**
     * Retrieves the {@link Program} object contained within a {@link DomainFile}.
     * This method handles acquiring the domain object and ensures it is a Program.
     * It uses the DomainFile's ability to restore the object if necessary.
     *
     * @param domainFile The {@link DomainFile} expected to contain the Program.
     * @param consumer   The object requesting access (typically the implementing
     *                   tool instance, passed as {@code this}). This is used
     *                   for Ghidra's object ownership tracking.
     * @return The {@link Program} object from the DomainFile.
     * @throws Exception If the DomainFile does not contain a {@code Program} (e.g.,
     *                   it's a folder or other data type), or if there is an error
     *                   accessing the domain object.
     */
    default Program getProgramFromDomainFile(
            DomainFile domainFile,
            Object consumer) throws Exception {
        return Optional.ofNullable(domainFile.getDomainObject(consumer, true, false, null))
                .filter(Program.class::isInstance)
                .map(Program.class::cast)
                .orElseThrow(() -> handleNonProgramObject(domainFile, consumer));
    }

    /**
     * Handles the case where a DomainFile does not contain a Program object.
     * 
     * @param domainFile The DomainFile that was expected to contain a Program
     * @param consumer   The object requesting access (for resource cleanup)
     * @return An IllegalArgumentException with details about the actual object type
     */
    private IllegalArgumentException handleNonProgramObject(DomainFile domainFile, Object consumer) {
        DomainObject domainObj = null;
        try {
            domainObj = domainFile.getDomainObject(consumer, true, false, null);
        } catch (Exception e) {
            // Ignore - we'll handle it below
        }

        String actualType = Optional.ofNullable(domainObj)
                .map(obj -> obj.getClass().getName())
                .orElse("null");

        Optional.ofNullable(domainObj)
                .ifPresent(obj -> obj.release(consumer));

        return new IllegalArgumentException(
                "File '" + domainFile.getName() + "' does not contain a Program. Found: " + actualType);
    }

    // ===================================================================================
    // Argument Parsing Helpers (Map<String, Object> based)
    // ===================================================================================

    // --- String ---
    /**
     * Retrieves an optional string argument from the provided map.
     *
     * @param args         The map of arguments.
     * @param argumentName The name of the argument to retrieve.
     * @return An {@link Optional} containing the non-blank string value if present
     *         and valid, otherwise {@link Optional#empty()}.
     */
    default Optional<String> getOptionalStringArgument(
            Map<String, Object> args,
            String argumentName) {
        return Optional.ofNullable(args.get(argumentName))
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .filter(value -> !value.isBlank());
    }

    /**
     * Retrieves a required non-blank string argument from the provided map.
     *
     * @param args         The map of arguments.
     * @param argumentName The name of the required argument.
     * @return The non-blank string value of the argument.
     * @throws IllegalArgumentException If the argument is missing, blank, or not a
     *                                  String.
     */
    default String getRequiredStringArgument(
            Map<String, Object> args,
            String argumentName) throws IllegalArgumentException {
        return getOptionalStringArgument(args, argumentName).orElseThrow(() -> new IllegalArgumentException(
                "Missing, blank, or invalid type for required argument '" +
                        argumentName +
                        "'. Expected non-blank String."));
    }

    // --- Integer ---
    /**
     * Retrieves an optional integer argument from the provided map.
     * Handles values provided as {@link Number} or as numeric Strings.
     *
     * @param args         The map of arguments.
     * @param argumentName The name of the argument to retrieve.
     * @return An {@link Optional} containing the integer value if present and
     *         valid, otherwise {@link Optional#empty()}.
     */
    default Optional<Integer> getOptionalIntArgument(
            Map<String, Object> args,
            String argumentName) {
        return Optional.ofNullable(args.get(argumentName))
                .flatMap(valueNode -> {
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
     * Handles values provided as {@link Number} or as numeric Strings.
     *
     * @param args         The map of arguments.
     * @param argumentName The name of the required argument.
     * @return The integer value of the argument.
     * @throws IllegalArgumentException If the argument is missing or not a valid
     *                                  Integer or numeric String.
     */
    default Integer getRequiredIntArgument(
            Map<String, Object> args,
            String argumentName) throws IllegalArgumentException {
        return getOptionalIntArgument(args, argumentName).orElseThrow(() -> new IllegalArgumentException(
                "Missing or invalid type for required argument '" +
                        argumentName +
                        "'. Expected Integer or numeric String."));
    }

    // --- Long ---
    /**
     * Retrieves an optional long argument from the provided map.
     * Handles values provided as {@link Number} or as numeric Strings.
     *
     * @param args         The map of arguments.
     * @param argumentName The name of the argument to retrieve.
     * @return An {@link Optional} containing the long value if present and valid,
     *         otherwise {@link Optional#empty()}.
     */
    default Optional<Long> getOptionalLongArgument(
            Map<String, Object> args,
            String argumentName) {
        return Optional.ofNullable(args.get(argumentName))
                .flatMap(valueNode -> {
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
     * Handles values provided as {@link Number} or as numeric Strings.
     *
     * @param args         The map of arguments.
     * @param argumentName The name of the required argument.
     * @return The long value of the argument.
     * @throws IllegalArgumentException If the argument is missing or not a valid
     *                                  Long
     *                                  or numeric String.
     */
    default Long getRequiredLongArgument(
            Map<String, Object> args,
            String argumentName) throws IllegalArgumentException {
        return getOptionalLongArgument(args, argumentName).orElseThrow(() -> new IllegalArgumentException(
                "Missing or invalid type for required argument '" +
                        argumentName +
                        "'. Expected Long or numeric String."));
    }

    // --- Boolean ---
    /**
     * Retrieves an optional boolean argument from the provided map.
     * Handles values provided as {@link Boolean} or as case-insensitive "true" or
     * "false" Strings.
     *
     * @param args         The map of arguments.
     * @param argumentName The name of the argument to retrieve.
     * @return An {@link Optional} containing the boolean value if present and
     *         valid, otherwise {@link Optional#empty()}.
     */
    default Optional<Boolean> getOptionalBooleanArgument(
            Map<String, Object> args,
            String argumentName) {
        return Optional.ofNullable(args.get(argumentName))
                .flatMap(valueNode -> {
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
     * Handles values provided as {@link Boolean} or as case-insensitive "true" or
     * "false" Strings.
     *
     * @param args         The map of arguments.
     * @param argumentName The name of the required argument.
     * @return The boolean value of the argument.
     * @throws IllegalArgumentException If the argument is missing or not a valid
     *                                  Boolean or case-insensitive "true"/"false"
     *                                  String.
     */
    default Boolean getRequiredBooleanArgument(
            Map<String, Object> args,
            String argumentName) throws IllegalArgumentException {
        return getOptionalBooleanArgument(args, argumentName).orElseThrow(() -> new IllegalArgumentException(
                "Missing or invalid type for required argument '" +
                        argumentName +
                        "'. Expected Boolean or case-insensitive 'true'/'false' String."));
    }

    // --- ObjectNode ---
    /**
     * Retrieves an optional {@link ObjectNode} (JSON object) argument from the
     * provided map.
     *
     * @param args         The map of arguments.
     * @param argumentName The name of the argument to retrieve.
     * @return An {@link Optional} containing the {@code ObjectNode} if present and
     *         of the correct type, otherwise {@link Optional#empty()}.
     */
    default Optional<ObjectNode> getOptionalObjectNodeArgument(
            Map<String, Object> args,
            String argumentName) {
        return Optional.ofNullable(args.get(argumentName))
                .filter(ObjectNode.class::isInstance)
                .map(ObjectNode.class::cast);
    }

    /**
     * Retrieves a required {@link ObjectNode} (JSON object) argument from the
     * provided map.
     *
     * @param args         The map of arguments.
     * @param argumentName The name of the required argument.
     * @return The {@link ObjectNode} value of the argument.
     * @throws IllegalArgumentException If the argument is missing or not an
     *                                  {@code ObjectNode}.
     */
    default ObjectNode getRequiredObjectNodeArgument(
            Map<String, Object> args,
            String argumentName) throws IllegalArgumentException {
        return getOptionalObjectNodeArgument(args, argumentName).orElseThrow(
                () -> new IllegalArgumentException(
                        "Missing or invalid type for required argument '" +
                                argumentName +
                                "'. Expected JSON object (ObjectNode)."));
    }

    // --- ArrayNode ---
    /**
     * Retrieves an optional {@link ArrayNode} (JSON array) argument from the
     * provided map.
     *
     * @param args         The map of arguments.
     * @param argumentName The name of the argument to retrieve.
     * @return An {@link Optional} containing the {@code ArrayNode} if present and
     *         of the correct type, otherwise {@link Optional#empty()}.
     */
    default Optional<ArrayNode> getOptionalArrayNodeArgument(
            Map<String, Object> args,
            String argumentName) {
        return Optional.ofNullable(args.get(argumentName))
                .filter(ArrayNode.class::isInstance)
                .map(ArrayNode.class::cast);
    }

    /**
     * Retrieves a required {@link ArrayNode} (JSON array) argument from the
     * provided map.
     *
     * @param args         The map of arguments.
     * @param argumentName The name of the required argument.
     * @return The {@link ArrayNode} value of the argument.
     * @throws IllegalArgumentException If the argument is missing or not an
     *                                  {@code ArrayNode}.
     */
    default ArrayNode getRequiredArrayNodeArgument(
            Map<String, Object> args,
            String argumentName) throws IllegalArgumentException {
        return getOptionalArrayNodeArgument(args, argumentName).orElseThrow(
                () -> new IllegalArgumentException(
                        "Missing or invalid type for required argument '" +
                                argumentName +
                                "'. Expected JSON array (ArrayNode)."));
    }

    // --- List<Map<String, Object>> ---
    /**
     * Retrieves an optional List of Maps argument from the provided map.
     * This is useful for handling lists of objects, common in grouped operations.
     *
     * @param args         The map of arguments.
     * @param argumentName The name of the argument to retrieve.
     * @return An {@link Optional} containing the List if present and valid,
     *         otherwise {@link Optional#empty()}.
     */
    @SuppressWarnings("unchecked")
    default Optional<List<Map<String, Object>>> getOptionalListArgument(
            Map<String, Object> args,
            String argumentName) {
        return Optional.ofNullable(args.get(argumentName))
                .filter(List.class::isInstance)
                .map(List.class::cast)
                .flatMap(list -> {
                    try {
                        return Optional.of((List<Map<String, Object>>) list);
                    } catch (ClassCastException e) {
                        Msg.warn(
                                this,
                                "Argument '" + argumentName + "' is a List, but contains unexpected types.",
                                e);
                        return Optional.empty();
                    }
                });
    }

    // --- Map<String, Object> ---
    /**
     * Retrieves an optional Map<String, Object> argument from the provided map.
     * This is useful for handling nested object arguments.
     *
     * @param args         The map of arguments.
     * @param argumentName The name of the argument to retrieve.
     * @return An {@link Optional} containing the Map if present and valid,
     *         otherwise {@link Optional#empty()}.
     */
    @SuppressWarnings("unchecked")
    default Optional<Map<String, Object>> getOptionalMapArgument(
            Map<String, Object> args,
            String argumentName) {
        return Optional.ofNullable(args.get(argumentName))
                .filter(Map.class::isInstance)
                .map(Map.class::cast)
                .flatMap(map -> {
                    try {
                        return Optional.of((Map<String, Object>) map);
                    } catch (ClassCastException e) {
                        Msg.warn(
                                this,
                                "Argument '" + argumentName + "' failed cast to Map<String, Object> unexpectedly.",
                                e);
                        return Optional.empty();
                    }
                });
    }

    // ===================================================================================
    // Argument Parsing Helpers (JsonNode based)
    // ===================================================================================

    // --- String ---
    /**
     * Retrieves an optional string argument from the provided {@link JsonNode}.
     *
     * @param node         The {@code JsonNode} containing the arguments.
     * @param argumentName The name of the argument field to retrieve.
     * @return An {@link Optional} containing the non-blank string value if present
     *         and valid, otherwise {@link Optional#empty()}.
     */
    default Optional<String> getOptionalStringArgument(
            JsonNode node,
            String argumentName) {
        return Optional.ofNullable(node.path(argumentName))
                .filter(valueNode -> !valueNode.isMissingNode() && !valueNode.isNull() && valueNode.isTextual())
                .map(JsonNode::asText)
                .filter(value -> !value.isBlank());
    }

    /**
     * Retrieves a required non-blank string argument from the provided
     * {@link JsonNode}.
     *
     * @param node         The {@code JsonNode} containing the arguments.
     * @param argumentName The name of the required argument field.
     * @return The non-blank string value of the argument.
     * @throws IllegalArgumentException If the argument field is missing, blank,
     *                                  or not textual.
     */
    default String getRequiredStringArgument(JsonNode node, String argumentName)
            throws IllegalArgumentException {
        return getOptionalStringArgument(node, argumentName).orElseThrow(() -> new IllegalArgumentException(
                "Missing, blank, or invalid type for required argument '" +
                        argumentName +
                        "'. Expected non-blank String."));
    }

    // --- Integer --- (from JsonNode)
    /**
     * Retrieves an optional integer argument from the provided {@link JsonNode}.
     * Handles values provided as JSON numbers or as numeric Strings.
     *
     * @param node         The {@code JsonNode} containing the arguments.
     * @param argumentName The name of the argument field to retrieve.
     * @return An {@link Optional} containing the integer value if present and
     *         valid, otherwise {@link Optional#empty()}.
     */
    default Optional<Integer> getOptionalIntArgument(
            JsonNode node,
            String argumentName) {
        return Optional.ofNullable(node.path(argumentName))
                .filter(valueNode -> !valueNode.isMissingNode() && !valueNode.isNull())
                .flatMap(valueNode -> {
                    if (valueNode.isInt()) {
                        return Optional.of(valueNode.asInt());
                    } else if (valueNode.isTextual()) {
                        String textValue = valueNode.asText();
                        if (textValue.isBlank()) {
                            return Optional.empty();
                        }
                        try {
                            return Optional.of(Integer.parseInt(textValue));
                        } catch (NumberFormatException e) {
                            return Optional.empty();
                        }
                    }
                    return Optional.empty();
                });
    }

    /**
     * Retrieves a required integer argument from the provided {@link JsonNode}.
     * Handles values provided as JSON numbers or as numeric Strings.
     *
     * @param node         The {@code JsonNode} containing the arguments.
     * @param argumentName The name of the required argument field.
     * @return The integer value of the argument.
     * @throws IllegalArgumentException If the argument field is missing or not a
     *                                  valid
     *                                  Integer or numeric String.
     */
    default Integer getRequiredIntArgument(JsonNode node, String argumentName)
            throws IllegalArgumentException {
        return getOptionalIntArgument(node, argumentName).orElseThrow(() -> new IllegalArgumentException(
                "Missing or invalid type for required argument '" +
                        argumentName +
                        "'. Expected Integer or numeric String."));
    }

    // --- Long --- (from JsonNode)
    /**
     * Retrieves an optional long argument from the provided {@link JsonNode}.
     * Handles values provided as JSON integral numbers or as numeric Strings.
     *
     * @param node         The {@code JsonNode} containing the arguments.
     * @param argumentName The name of the argument field to retrieve.
     * @return An {@link Optional} containing the long value if present and valid,
     *         otherwise {@link Optional#empty()}.
     */
    default Optional<Long> getOptionalLongArgument(
            JsonNode node,
            String argumentName) {
        return Optional.ofNullable(node.path(argumentName))
                .filter(valueNode -> !valueNode.isMissingNode() && !valueNode.isNull())
                .flatMap(valueNode -> {
                    if (valueNode.isIntegralNumber() && valueNode.canConvertToLong()) {
                        return Optional.of(valueNode.asLong());
                    } else if (valueNode.isTextual()) {
                        String textValue = valueNode.asText();
                        if (textValue.isBlank()) {
                            return Optional.empty();
                        }
                        try {
                            return Optional.of(Long.parseLong(textValue));
                        } catch (NumberFormatException e) {
                            return Optional.empty();
                        }
                    }
                    return Optional.empty();
                });
    }

    /**
     * Retrieves a required long argument from the provided {@link JsonNode}.
     * Handles values provided as JSON integral numbers or as numeric Strings.
     *
     * @param node         The {@code JsonNode} containing the arguments.
     * @param argumentName The name of the required argument field.
     * @return The long value of the argument.
     * @throws IllegalArgumentException If the argument field is missing or not a
     *                                  valid
     *                                  Long or numeric String.
     */
    default Long getRequiredLongArgument(JsonNode node, String argumentName)
            throws IllegalArgumentException {
        return getOptionalLongArgument(node, argumentName).orElseThrow(() -> new IllegalArgumentException(
                "Missing or invalid type for required argument '" +
                        argumentName +
                        "'. Expected Long or numeric String."));
    }

    // ===================================================================================
    // Result Creation Helpers
    // ===================================================================================

    /**
     * Helper method to serialize a result object to JSON and wrap it in a
     * successful {@link CallToolResult} with {@link TextContent}.
     * The resultData is serialized directly to a JSON string.
     *
     * @param resultData The object containing the successful result data. Can be
     *                   a POJO, List, Map, String, Boolean, Number, etc.
     * @return A successful {@code CallToolResult} containing the JSON string,
     *         or an error {@code CallToolResult} if serialization fails.
     */
    default Mono<CallToolResult> createSuccessResult(Object resultData) {
        try {
            // Serialize the raw result data directly to a JSON string
            String jsonResult = IGhidraMcpSpecification.mapper.writeValueAsString(resultData);
            TextContent textContent = new TextContent(jsonResult);
            CallToolResult result = CallToolResult
                    .builder()
                    .content(Collections.singletonList(textContent))
                    .isError(Boolean.FALSE)
                    .build();
            return Mono.just(result);
        } catch (JsonProcessingException e) {
            // Log the serialization error
            Msg.error(
                    this,
                    "Error serializing result data to JSON: " + e.getMessage());
            // Return an error CallToolResult using the error helper
            return createErrorResult(
                    new RuntimeException(
                            "Error serializing result data: " + e.getMessage(),
                            e)); // Wrap
                                 // exception
        }
    }

    /**
     * Helper method to create an error {@link CallToolResult} from a Throwable.
     * If the throwable is a {@link GhidraMcpException}, the structured error
     * information
     * is serialized as JSON. Otherwise, a simple error message is generated from
     * the
     * throwable's class name and message and wrapped in {@link TextContent}.
     * The error is also logged using Msg.error.
     *
     * @param t The throwable that occurred.
     * @return An error {@code CallToolResult} containing the generated error
     *         message or structured error information.
     */
    default Mono<CallToolResult> createErrorResult(Throwable t) {
        return Optional.ofNullable(t)
                .map(this::handleStructuredError)
                .orElseGet(() -> createSimpleErrorResult("An unknown error occurred."));
    }

    /**
     * Handles structured error processing for GhidraMcpException instances.
     * 
     * @param t The throwable to process
     * @return A Mono containing the appropriate error CallToolResult
     */
    private Mono<CallToolResult> handleStructuredError(Throwable t) {
        return Optional.of(t)
                .filter(GhidraMcpException.class::isInstance)
                .map(GhidraMcpException.class::cast)
                .map(this::serializeStructuredError)
                .orElseGet(() -> createSimpleErrorResult(t));
    }

    /**
     * Serializes a GhidraMcpException to JSON format for error reporting.
     * 
     * @param mcpException The structured exception to serialize
     * @return A Mono containing the serialized error result
     */
    private Mono<CallToolResult> serializeStructuredError(GhidraMcpException mcpException) {
        try {
            String structuredErrorJson = IGhidraMcpSpecification.mapper.writeValueAsString(mcpException.getErr());
            Msg.error(this, "Structured error - " + mcpException.getErrorType() +
                    " [" + mcpException.getErrorCode() + "]: " + mcpException.getMessage());
            return Mono.just(buildErrorResult(new TextContent(structuredErrorJson)));
        } catch (JsonProcessingException e) {
            Msg.error(this, "Failed to serialize structured error, falling back to simple message: " + e.getMessage());
            return createSimpleErrorResult("Structured error serialization failed: " + mcpException.getMessage());
        }
    }

    /**
     * Creates a simple error result from a Throwable.
     * 
     * @param t The throwable to convert to an error result
     * @return A Mono containing the error CallToolResult
     */
    private Mono<CallToolResult> createSimpleErrorResult(Throwable t) {
        String throwableType = t.getClass().getSimpleName();
        String errorMessage = Optional.ofNullable(t.getMessage())
                .filter(message -> !message.isBlank())
                .map(message -> throwableType + ": " + message)
                .orElse(throwableType);
        return createSimpleErrorResult(errorMessage);
    }

    /**
     * Creates a simple error result from an error message string.
     * 
     * @param errorMessage The error message to include in the result
     * @return A Mono containing the error CallToolResult
     */
    private Mono<CallToolResult> createSimpleErrorResult(String errorMessage) {
        Msg.error(this, errorMessage);
        return Mono.just(buildErrorResult(new TextContent(errorMessage)));
    }

    /**
     * Helper method to create an error {@link CallToolResult} with a base message
     * and additional data that needs to be serialized to JSON and appended.
     * Handles potential JsonProcessingException during serialization.
     * The final error message is logged using Msg.error.
     *
     * @param baseMessage  The base error message string.
     * @param dataToAppend The object to serialize and append to the message.
     * @return An error {@code CallToolResult} containing the combined message.
     */
    default Mono<CallToolResult> createErrorResult(
            String baseMessage,
            Object dataToAppend) {
        String finalErrorMessage = Optional.ofNullable(dataToAppend)
                .flatMap(data -> {
                    try {
                        String jsonData = IGhidraMcpSpecification.mapper.writeValueAsString(data);
                        return Optional.of((baseMessage != null ? baseMessage : "Error") + ": " + jsonData);
                    } catch (JsonProcessingException e) {
                        String serializationErrorMsg = "Failed to serialize data for error message: " + e.getMessage();
                        Msg.error(this, serializationErrorMsg);
                        return Optional.of((baseMessage != null ? baseMessage : "Error") +
                                " (Failed to serialize details: " + e.getMessage() + ")");
                    }
                })
                .orElse(baseMessage != null ? baseMessage : "Error");
        // Use the existing String helper (which now logs) to create the final error
        // result
        return createErrorResult(finalErrorMessage); // Calls the String overload
    }

    /**
     * Helper method to create an error {@link CallToolResult} with a given message.
     * The message is wrapped in {@link TextContent} and logged using Msg.error.
     *
     * @param errorMessage The error message string.
     * @return An error {@code CallToolResult} containing the error message.
     */
    default Mono<CallToolResult> createErrorResult(String errorMessage) {
        String finalMessage = Optional.ofNullable(errorMessage)
                .orElse("An unspecified error occurred.");

        Msg.error(this, finalMessage);
        TextContent errorContent = new TextContent(finalMessage);
        return Mono.just(buildErrorResult(errorContent));
    }

    /**
     * Builds a CallToolResult with error content.
     * 
     * @param errorContent The TextContent containing the error message
     * @return A CallToolResult marked as an error
     */
    private CallToolResult buildErrorResult(TextContent errorContent) {
        return CallToolResult
                .builder()
                .content(Collections.singletonList(errorContent))
                .isError(Boolean.TRUE)
                .build();
    }

    // ===================================================================================
    // Tool Information Helpers
    // ===================================================================================

    /**
     * Gets the tool's MCP name from the @GhidraMcpTool annotation.
     * This provides consistent access to the tool's MCP identifier for error
     * reporting
     * and other purposes without requiring each tool to implement its own method.
     *
     * @return The MCP name from the annotation.
     */
    default String getMcpName() {
        return getMcpName(this.getClass());
    }

    /**
     * Gets the tool's MCP name from the @GhidraMcpTool annotation on a given class.
     * This provides consistent access to a tool's MCP identifier for error
     * reporting
     * and other purposes.
     *
     * @param toolClass The class of the tool.
     * @return The MCP name from the annotation, or a fallback if not found.
     */
    default String getMcpName(
            Class<? extends IGhidraMcpSpecification> toolClass) {
        return getMcpNameForTool(toolClass);
    }

    static String getMcpNameForTool(
            Class<? extends IGhidraMcpSpecification> toolClass) {
        return toolClass.getAnnotation(GhidraMcpTool.class).mcpName();
    }

    // ===================================================================================
    // Other Utility Helpers
    // ===================================================================================

    /**
     * Parses the generated {@link JsonSchema} object into a JSON string using the
     * interface's shared {@link ObjectMapper}.
     *
     * @param schema The {@link JsonSchema} object to serialize.
     * @return An {@link Optional} containing the JSON string representation of the
     *         schema, or {@link Optional#empty()} if serialization fails (errors
     *         are logged
     *         by the {@code JsonSchema.toJsonString} method).
     */
    default Optional<String> parseSchema(JsonSchema schema) {
        return schema.toJsonString(mapper);
    }

    /**
     * Converts the project's {@link JsonSchema} representation to the MCP SDK's
     * {@link McpSchema.JsonSchema} format.
     *
     * @param schema     The custom JsonSchema to convert.
     * @param annotation The {@link GhidraMcpTool} annotation for logging context.
     * @return An {@link Optional} containing the converted schema, or empty if
     *         conversion fails.
     */
    default Optional<McpSchema.JsonSchema> convertToMcpSchema(JsonSchema schema, GhidraMcpTool annotation) {
        return Optional.ofNullable(schema)
                .flatMap(this::parseSchema)
                .flatMap(schemaString -> convertSchemaString(schemaString, annotation))
                .or(() -> {
                    Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName()
                            + "'. Tool will be disabled.");
                    return Optional.empty();
                });
    }

    /**
     * Converts a JSON schema string to MCP JsonSchema format.
     * 
     * @param schemaString The JSON schema as a string
     * @param annotation   The tool annotation for error context
     * @return An Optional containing the converted schema or empty if conversion
     *         fails
     */
    private Optional<McpSchema.JsonSchema> convertSchemaString(String schemaString, GhidraMcpTool annotation) {
        try {
            return Optional.of(parseSchemaMap(schemaString));
        } catch (IOException e) {
            Msg.error(this,
                    "Failed to convert schema to MCP format for tool '" + annotation.mcpName() + "': " + e.getMessage(),
                    e);
            return Optional.empty();
        }
    }

    /**
     * Parses a JSON schema string into a Map and creates an MCP JsonSchema.
     * 
     * @param schemaString The JSON schema as a string
     * @return The parsed MCP JsonSchema
     * @throws IOException If JSON parsing fails
     */
    private McpSchema.JsonSchema parseSchemaMap(String schemaString) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> schemaMap = mapper.readValue(schemaString, new TypeReference<Map<String, Object>>() {
        });

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

        return new McpSchema.JsonSchema(type, properties, required, additionalProperties, defs, definitions);
    }

    /**
     * Extracts and concatenates text from all {@code TextContent} elements within
     * a {@link CallToolResult}.
     * Useful for getting a simple string representation of a tool's output when
     * only text content is expected or relevant.
     *
     * @param result The {@code CallToolResult} to process.
     * @return A string containing the joined text (separated by newlines) from all
     *         {@code TextContent} elements. Returns an empty string if the result
     *         is null, has no content list, or contains no {@code TextContent}.
     */
    default String getTextFromCallToolResult(CallToolResult result) {
        return Optional.ofNullable(result)
                .map(CallToolResult::content)
                .filter(content -> content != null && !content.isEmpty())
                .map(content -> content
                        .stream()
                        .filter(TextContent.class::isInstance)
                        .map(TextContent.class::cast)
                        .map(TextContent::text)
                        .filter(text -> text != null)
                        .collect(Collectors.joining("\n")))
                .orElse("");

    }

    /**
     * Result object containing a parsed address and its original string
     * representation.
     */
    class AddressResult {
        private final Address address;
        private final String addressString;

        /**
         * Creates an AddressResult with the parsed address and original string.
         * 
         * @param address       The parsed Ghidra Address object
         * @param addressString The original address string that was parsed
         */
        AddressResult(Address address, String addressString) {
            this.address = address;
            this.addressString = addressString;
        }

        /**
         * Gets the parsed Ghidra Address object.
         * 
         * @return The Address object
         */
        public Address getAddress() {
            return address;
        }

        /**
         * Gets the original address string that was parsed.
         * 
         * @return The original address string
         */
        public String getAddressString() {
            return addressString;
        }
    }

    default Mono<AddressResult> parseAddress(Program program, Map<String, Object> args, String addressStr,
            String operation, GhidraMcpTool annotation) throws GhidraMcpException {
        return Mono.fromCallable(() -> createAddressResult(program, addressStr, operation, annotation, args))
                .onErrorMap(throwable -> mapToGhidraMcpException(throwable, addressStr, operation, annotation, args));
    }

    /**
     * Creates an AddressResult by parsing an address string using the program's
     * address factory.
     * 
     * @param program    The Ghidra program containing the address factory
     * @param addressStr The address string to parse
     * @param operation  The operation being performed (for error context)
     * @param annotation The tool annotation (for error context)
     * @param args       The tool arguments (for error context)
     * @return An AddressResult containing the parsed address
     * @throws GhidraMcpException If the address cannot be parsed
     */
    private AddressResult createAddressResult(Program program, String addressStr, String operation,
            GhidraMcpTool annotation, Map<String, Object> args) throws GhidraMcpException {
        return Optional.ofNullable(program.getAddressFactory().getAddress(addressStr))
                .map(address -> new AddressResult(address, addressStr))
                .orElseThrow(
                        () -> new GhidraMcpException(buildAddressError(addressStr, operation, annotation, args, null)));
    }

    /**
     * Maps a throwable to a GhidraMcpException if it isn't already one.
     * 
     * @param throwable  The original throwable
     * @param addressStr The address string (for error context)
     * @param operation  The operation being performed (for error context)
     * @param annotation The tool annotation (for error context)
     * @param args       The tool arguments (for error context)
     * @return The original throwable if it's already a GhidraMcpException,
     *         otherwise a new GhidraMcpException
     */
    private Throwable mapToGhidraMcpException(Throwable throwable, String addressStr, String operation,
            GhidraMcpTool annotation, Map<String, Object> args) {
        return Optional.of(throwable)
                .filter(GhidraMcpException.class::isInstance)
                .orElseGet(() -> new GhidraMcpException(
                        buildAddressError(addressStr, operation, annotation, args, throwable)));
    }

    /**
     * Builds a structured error for address parsing failures.
     * 
     * @param addressStr The address string that failed to parse
     * @param operation  The operation being performed
     * @param annotation The tool annotation
     * @param args       The tool arguments
     * @param cause      The underlying cause of the parsing failure
     * @return A GhidraMcpError with structured error information
     */
    private GhidraMcpError buildAddressError(String addressStr, String operation, GhidraMcpTool annotation,
            Map<String, Object> args, Throwable cause) {
        return GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
                .message("Invalid address: " + addressStr)
                .context(new GhidraMcpError.ErrorContext(
                        annotation.mcpName(),
                        operation,
                        args,
                        Map.of("address", addressStr),
                        Map.of("parseError", cause != null ? cause.getMessage() : "unknown")))
                .suggestions(List.of(
                        new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                "Use valid address format",
                                "Provide a properly formatted hexadecimal address",
                                List.of("0x401000", "0x10040a0", "401000", "ram:00401000"),
                                null)))
                .build();
    }
}
