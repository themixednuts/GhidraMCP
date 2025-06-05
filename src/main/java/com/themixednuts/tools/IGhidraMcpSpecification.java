package com.themixednuts.tools;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.json.JsonWriteFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Base interface for all Ghidra MCP tool specifications.
 * Defines the core methods required for tool registration and execution,
 * along with helper methods for common Ghidra operations and argument parsing.
 */
public interface IGhidraMcpSpecification {

	// Helper method to create and configure the ObjectMapper instance.
	private static ObjectMapper createAndConfigureMapper() {
		ObjectMapper configuredMapper = new ObjectMapper();
		configuredMapper.getFactory().configure(JsonWriteFeature.ESCAPE_NON_ASCII.mappedFeature(), true);
		return configuredMapper;
	}

	/** Shared Jackson ObjectMapper instance for JSON processing. */
	// Initialize the static final mapper by calling the configuration method.
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
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		JsonSchema schemaObject = schema();
		Optional<String> schemaStringOpt = parseSchema(schemaObject);
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}
		String schemaJson = schemaStringOpt.get();

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson),
				(ex, args) -> execute(ex, args, tool).flatMap(this::createSuccessResult)
						.onErrorResume(this::createErrorResult));
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
	Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool);

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
	static IObjectSchemaBuilder createBaseSchemaNode() {
		return JsonSchemaBuilder.object(mapper);
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
	default Mono<? extends Object> executeInTransaction(Program program, String transactionName,
			Callable<? extends Object> work) {
		return Mono.fromCallable(() -> {
			// Use AtomicReferences to capture result or exception from EDT
			AtomicReference<Object> resultRef = new AtomicReference<>();
			AtomicReference<Throwable> exceptionRef = new AtomicReference<>();

			Swing.runNow(() -> { // This still runs its lambda on the EDT
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
					Msg.error(this, "Throwable during Ghidra transaction work '" + transactionName + "': " + t.getMessage());
				} finally {
					if (txId != -1) {
						try {
							// Only commit if work.call() succeeded AND no prior exception was captured from
							// it.
							program.endTransaction(txId, success && exceptionRef.get() == null);
						} catch (Exception e) {
							Msg.error(this, "Failed to end transaction '" + transactionName + "' (intended success: "
									+ (success && exceptionRef.get() == null) + ")");
							// If ending the transaction fails, this is a new error or compounds an existing
							// one.
							// Prioritize the original exception from work.call() if one exists.
							if (exceptionRef.get() == null) {
								exceptionRef
										.set(new RuntimeException("Failed to end transaction after successful work: " + e.getMessage(), e));
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
				throw new RuntimeException("Error during EDT execution: " + capturedError.getMessage(), capturedError);
			}
			return resultRef.get(); // Return the result from work.call() if no exception occurred
		})
				.subscribeOn(Schedulers.boundedElastic()); // Ensures the fromCallable body runs on a worker thread

	}

	// ===================================================================================
	// Ghidra Context Retrieval Helpers
	// ===================================================================================

	/**
	 * Gets the currently active {@link Program} associated with the given
	 * arguments and {@link PluginTool} context.
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
	default Mono<Program> getProgram(Map<String, Object> args, PluginTool tool) {
		return Mono.fromCallable(() -> {
			DomainFile domainFile = getDomainFile(args, tool); // Pass tool here
			return getProgramFromDomainFile(domainFile, this); // 'this' is the consumer
		});
	}

	/**
	 * Retrieves an open {@link DomainFile} based on the "fileName" argument
	 * within the provided {@link PluginTool}'s project context.
	 *
	 * @param args The tool arguments map, expected to contain a non-blank
	 *             String entry for "fileName".
	 * @param tool The current Ghidra {@link PluginTool} providing project context.
	 * @return The matching open {@link DomainFile}.
	 * @throws IllegalArgumentException if the "fileName" argument is missing,
	 *                                  not a non-blank String, or does not match
	 *                                  any open DomainFile in the project.
	 * @throws NullPointerException     if tool or tool.getProject() is null.
	 * @throws Exception                Potentially other exceptions from project
	 *                                  access.
	 */
	default DomainFile getDomainFile(Map<String, Object> args, PluginTool tool) throws Exception {
		if (tool == null) {
			throw new NullPointerException("PluginTool cannot be null.");
		}
		ghidra.framework.model.Project project = tool.getProject(); // Get project from tool
		if (project == null) {
			throw new NullPointerException("No active project found in the provided PluginTool.");
		}

		// Use helper to get required string argument, handling null/blank/type checks
		String fileNameStr = getRequiredStringArgument(args, "fileName");

		// Use project obtained from tool
		DomainFile domainFile = project.getOpenData().stream().filter(f -> f.getName().equals(fileNameStr))
				.findFirst().orElse(null);

		if (domainFile == null) {
			// Throw specific exception type if file not found/open
			List<String> openFiles = project.getOpenData().stream().map(DomainFile::getName).collect(Collectors.toList());
			String availableFiles = openFiles.isEmpty() ? "No files are open."
					: "Open files: " + String.join(", ", openFiles);
			throw new IllegalArgumentException("File not found or not open: " + fileNameStr + ". " +
					"Use the 'list_files' tool to see available files. " + availableFiles);
		}

		return domainFile;
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
	default Program getProgramFromDomainFile(DomainFile domainFile, Object consumer) throws Exception {
		// The 'restore' parameter is true, meaning Ghidra *should* handle
		// restoring the object state, implying we don't need explicit release *if
		// successful*.
		DomainObject domainObj = domainFile.getDomainObject(consumer, true, false, null);

		if (domainObj instanceof Program) {
			return (Program) domainObj;
		} else {
			// If it's not a program, we *must* release the object we acquired.
			String actualType = (domainObj != null) ? domainObj.getClass().getName() : "null";
			if (domainObj != null) { // Avoid NullPointerException if getDomainObject returned null
				domainObj.release(consumer); // Release the non-program object
			}
			// Throw a specific exception
			throw new IllegalArgumentException(
					"File '" + domainFile.getName() + "' does not contain a Program. Found: " + actualType);
		}
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
	default Optional<String> getOptionalStringArgument(Map<String, Object> args, String argumentName) {
		Object valueNode = args.get(argumentName);
		if (valueNode == null || !(valueNode instanceof String)) {
			return Optional.empty();
		}
		String value = (String) valueNode;
		// Return empty if blank, otherwise return the value
		return value.isBlank() ? Optional.empty() : Optional.of(value);
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
	default String getRequiredStringArgument(Map<String, Object> args, String argumentName)
			throws IllegalArgumentException {
		return getOptionalStringArgument(args, argumentName)
				.orElseThrow(() -> new IllegalArgumentException(
						"Missing, blank, or invalid type for required argument '" + argumentName
								+ "'. Expected non-blank String."));
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
	default Optional<Integer> getOptionalIntArgument(Map<String, Object> args, String argumentName) {
		Object valueNode = args.get(argumentName);
		if (valueNode == null) {
			return Optional.empty();
		}
		// Handle both Number types (like Integer, Long from JSON) and String types
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
				// Log potentially? For now, just return empty for invalid format.
				return Optional.empty(); // Not a valid integer string
			}
		} else {
			return Optional.empty(); // Invalid type
		}
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
	default Integer getRequiredIntArgument(Map<String, Object> args, String argumentName)
			throws IllegalArgumentException {
		return getOptionalIntArgument(args, argumentName)
				.orElseThrow(() -> new IllegalArgumentException(
						"Missing or invalid type for required argument '" + argumentName
								+ "'. Expected Integer or numeric String."));
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
	default Optional<Long> getOptionalLongArgument(Map<String, Object> args, String argumentName) {
		Object valueNode = args.get(argumentName);
		if (valueNode == null) {
			return Optional.empty();
		}
		if (valueNode instanceof Number) {
			// Handle potential Integer, Long, etc.
			return Optional.of(((Number) valueNode).longValue());
		} else if (valueNode instanceof String) {
			String value = (String) valueNode;
			if (value.isBlank()) {
				return Optional.empty();
			}
			try {
				return Optional.of(Long.parseLong(value));
			} catch (NumberFormatException e) {
				return Optional.empty(); // Not a valid long string
			}
		} else {
			return Optional.empty(); // Invalid type
		}
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
	default Long getRequiredLongArgument(Map<String, Object> args, String argumentName)
			throws IllegalArgumentException {
		return getOptionalLongArgument(args, argumentName)
				.orElseThrow(() -> new IllegalArgumentException(
						"Missing or invalid type for required argument '" + argumentName + "'. Expected Long or numeric String."));
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
	default Optional<Boolean> getOptionalBooleanArgument(Map<String, Object> args, String argumentName) {
		Object valueNode = args.get(argumentName);
		if (valueNode instanceof Boolean) {
			return Optional.of((Boolean) valueNode);
		} else if (valueNode instanceof String) {
			// Allow "true" or "false" strings (case-insensitive)
			String value = ((String) valueNode).trim();
			if ("true".equalsIgnoreCase(value)) {
				return Optional.of(true);
			} else if ("false".equalsIgnoreCase(value)) {
				return Optional.of(false);
			}
		}
		return Optional.empty(); // Missing or invalid type/value
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
	default Boolean getRequiredBooleanArgument(Map<String, Object> args, String argumentName)
			throws IllegalArgumentException {
		return getOptionalBooleanArgument(args, argumentName)
				.orElseThrow(() -> new IllegalArgumentException(
						"Missing or invalid type for required argument '" + argumentName
								+ "'. Expected Boolean or case-insensitive 'true'/'false' String."));
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
	default Optional<ObjectNode> getOptionalObjectNodeArgument(Map<String, Object> args, String argumentName) {
		Object valueNode = args.get(argumentName);
		// Check specifically for ObjectNode, as Map might be used for other things
		if (valueNode instanceof ObjectNode) {
			return Optional.of((ObjectNode) valueNode);
		} else {
			return Optional.empty();
		}
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
	default ObjectNode getRequiredObjectNodeArgument(Map<String, Object> args, String argumentName)
			throws IllegalArgumentException {
		return getOptionalObjectNodeArgument(args, argumentName)
				.orElseThrow(() -> new IllegalArgumentException(
						"Missing or invalid type for required argument '" + argumentName
								+ "'. Expected JSON object (ObjectNode)."));
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
	default Optional<ArrayNode> getOptionalArrayNodeArgument(Map<String, Object> args, String argumentName) {
		Object valueNode = args.get(argumentName);
		// Check specifically for ArrayNode
		if (valueNode instanceof ArrayNode) {
			return Optional.of((ArrayNode) valueNode);
		} else {
			return Optional.empty();
		}
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
	default ArrayNode getRequiredArrayNodeArgument(Map<String, Object> args, String argumentName)
			throws IllegalArgumentException {
		return getOptionalArrayNodeArgument(args, argumentName)
				.orElseThrow(() -> new IllegalArgumentException(
						"Missing or invalid type for required argument '" + argumentName + "'. Expected JSON array (ArrayNode)."));
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
	default Optional<List<Map<String, Object>>> getOptionalListArgument(Map<String, Object> args, String argumentName) {
		Object valueNode = args.get(argumentName);
		if (valueNode == null || !(valueNode instanceof List)) {
			return Optional.empty();
		}
		try {
			// Perform a cast and basic check - assumes the List contains Maps
			List<Map<String, Object>> list = (List<Map<String, Object>>) valueNode;
			// Could add further validation here if needed (e.g., check if all elements are
			// Maps)
			return Optional.of(list);
		} catch (ClassCastException e) {
			// If the cast fails (e.g., List contains Strings instead of Maps)
			Msg.warn(this, "Argument '" + argumentName + "' is a List, but contains unexpected types.", e);
			return Optional.empty();
		}
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
	default Optional<Map<String, Object>> getOptionalMapArgument(Map<String, Object> args, String argumentName) {
		Object valueNode = args.get(argumentName);
		if (valueNode == null || !(valueNode instanceof Map)) {
			return Optional.empty();
		}
		try {
			// Perform the cast
			return Optional.of((Map<String, Object>) valueNode);
		} catch (ClassCastException e) {
			// Should not happen if instanceof check passes, but include for safety
			Msg.warn(this, "Argument '" + argumentName + "' failed cast to Map<String, Object> unexpectedly.", e);
			return Optional.empty();
		}
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
	default Optional<String> getOptionalStringArgument(JsonNode node, String argumentName) {
		JsonNode valueNode = node.path(argumentName); // Use path to avoid nulls
		if (valueNode.isMissingNode() || valueNode.isNull() || !valueNode.isTextual()) {
			return Optional.empty();
		}
		String value = valueNode.asText();
		// Return empty if blank, otherwise return the value
		return value.isBlank() ? Optional.empty() : Optional.of(value);
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
		return getOptionalStringArgument(node, argumentName)
				.orElseThrow(() -> new IllegalArgumentException(
						"Missing, blank, or invalid type for required argument '" + argumentName
								+ "'. Expected non-blank String."));
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
	default Optional<Integer> getOptionalIntArgument(JsonNode node, String argumentName) {
		JsonNode valueNode = node.path(argumentName);
		if (valueNode.isMissingNode() || valueNode.isNull()) {
			return Optional.empty();
		}
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
				return Optional.empty(); // Not a valid integer string
			}
		} else {
			return Optional.empty(); // Not an integer or a string representation
		}
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
		return getOptionalIntArgument(node, argumentName)
				.orElseThrow(() -> new IllegalArgumentException(
						"Missing or invalid type for required argument '" + argumentName
								+ "'. Expected Integer or numeric String."));
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
	default Optional<Long> getOptionalLongArgument(JsonNode node, String argumentName) {
		JsonNode valueNode = node.path(argumentName);
		if (valueNode.isMissingNode() || valueNode.isNull()) {
			return Optional.empty();
		}
		// Check if it's an integral number representable as long
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
				return Optional.empty(); // Not a valid long string
			}
		} else {
			return Optional.empty(); // Invalid type
		}
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
		return getOptionalLongArgument(node, argumentName)
				.orElseThrow(() -> new IllegalArgumentException(
						"Missing or invalid type for required argument '" + argumentName + "'. Expected Long or numeric String."));
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
			// Create TextContent containing the raw JSON string
			TextContent textContent = new TextContent(jsonResult);
			// Build the CallToolResult with the TextContent
			return Mono.just(new CallToolResult(Collections.singletonList(textContent), false));
		} catch (JsonProcessingException e) {
			// Log the serialization error
			Msg.error(this, "Error serializing result data to JSON: " + e.getMessage());
			// Return an error CallToolResult using the error helper
			return createErrorResult(new RuntimeException("Error serializing result data: " + e.getMessage(), e)); // Wrap
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
		if (t == null) {
			String errorMessage = "An unknown error occurred.";
			Msg.error(this, errorMessage);
			TextContent errorContent = new TextContent(errorMessage);
			return Mono.just(new CallToolResult(Collections.singletonList(errorContent), true));
		}

		// Check if this is a structured GhidraMcpException
		if (t instanceof GhidraMcpException) {
			GhidraMcpException mcpException = (GhidraMcpException) t;
			try {
				// Serialize the structured error as JSON
				String structuredErrorJson = IGhidraMcpSpecification.mapper
						.writeValueAsString(mcpException.getStructuredError());
				// Log the structured error message for Ghidra's internal logging
				Msg.error(this, "Structured error - " + mcpException.getErrorType() + " [" +
						mcpException.getErrorCode() + "]: " + mcpException.getMessage());
				// Return the structured error as JSON content
				TextContent errorContent = new TextContent(structuredErrorJson);
				return Mono.just(new CallToolResult(Collections.singletonList(errorContent), true));
			} catch (JsonProcessingException e) {
				// If we can't serialize the structured error, fall back to simple message
				Msg.error(this, "Failed to serialize structured error, falling back to simple message: " + e.getMessage());
				String fallbackMessage = "Structured error serialization failed: " + mcpException.getMessage();
				TextContent errorContent = new TextContent(fallbackMessage);
				return Mono.just(new CallToolResult(Collections.singletonList(errorContent), true));
			}
		}

		// Handle regular exceptions
		String throwableType = t.getClass().getSimpleName();
		String throwableMessage = t.getMessage();
		String errorMessage = throwableType
				+ (throwableMessage != null && !throwableMessage.isBlank() ? ": " + throwableMessage : "");
		// Log the error with the throwable for stack trace
		Msg.error(this, errorMessage);
		// Create TextContent containing the generated error message
		TextContent errorContent = new TextContent(errorMessage);
		// Build the CallToolResult with isError=true
		return Mono.just(new CallToolResult(Collections.singletonList(errorContent), true));
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
	default Mono<CallToolResult> createErrorResult(String baseMessage, Object dataToAppend) {
		String finalErrorMessage;
		try {
			// Attempt to serialize the data
			String jsonData = IGhidraMcpSpecification.mapper.writeValueAsString(dataToAppend);
			finalErrorMessage = (baseMessage != null ? baseMessage : "Error") + ": " + jsonData;
		} catch (JsonProcessingException e) {
			// If serialization fails, log the *serialization* error specifically
			String serializationErrorMsg = "Failed to serialize data for error message: " + e.getMessage();
			Msg.error(this, serializationErrorMsg);
			// Construct a final message indicating the failure
			finalErrorMessage = (baseMessage != null ? baseMessage : "Error") + " (Failed to serialize details: "
					+ e.getMessage() + ")";
		}
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
		String finalMessage = errorMessage != null ? errorMessage : "An unspecified error occurred.";
		// Log the error message
		Msg.error(this, finalMessage);
		// Create TextContent containing the error message
		TextContent errorContent = new TextContent(finalMessage);
		// Build the CallToolResult with isError=true
		return Mono.just(new CallToolResult(Collections.singletonList(errorContent), true));
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
	default String getMcpName(Class<? extends IGhidraMcpSpecification> toolClass) {
		return getMcpNameForTool(toolClass);
	}

	static String getMcpNameForTool(Class<? extends IGhidraMcpSpecification> toolClass) {
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
		// Delegate serialization to the JsonSchema object, using the interface's
		// mapper.
		// Error logging is handled within JsonSchema.toJsonString.
		return schema.toJsonString(mapper);
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
		if (result == null || result.content() == null || result.content().isEmpty()) {
			return ""; // Return empty string for null/empty results
		}

		// Filter for TextContent, extract text, and join with newlines.
		return result.content().stream()
				.filter(c -> c instanceof TextContent)
				.map(c -> ((TextContent) c).text())
				.filter(text -> text != null) // Ensure text is not null
				.collect(Collectors.joining("\n")); // Join with newline
	}

}
