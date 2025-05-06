package com.themixednuts.tools.grouped;

import java.util.List;
import java.util.ServiceLoader;
import java.util.ServiceLoader.Provider;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.Map;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import ghidra.util.Msg;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.spec.McpSchema.LoggingLevel;

/**
 * Marker interface for grouped operation tools.
 * Tools implementing this interface bundle multiple related granular operations
 * and will only be registered when grouping mode is enabled.
 */
public interface IGroupedTool {

	// Constants for common grouped arguments
	public static final String ARG_OPERATION = "operation";
	public static final String ARG_ARGUMENTS = "arguments";
	public static final String ARG_OPERATIONS = "operations";

	/**
	 * Finds the classes of granular tools belonging to the specified target
	 * category.
	 *
	 * @param targetCategory The category name string to filter granular tools by.
	 * @return A list of classes for the granular tools.
	 */
	public static List<Class<? extends IGhidraMcpSpecification>> getGranularToolClasses(String targetCategory) {
		return getFilteredProviders(targetCategory)
				.map(Provider::type) // Get the class type
				.collect(Collectors.toList());
	}

	// Helper method to perform common loading and filtering
	private static Stream<ServiceLoader.Provider<IGhidraMcpSpecification>> getFilteredProviders(String targetCategory) {
		ServiceLoader<IGhidraMcpSpecification> loader = ServiceLoader.load(IGhidraMcpSpecification.class);

		// Validate targetCategory
		if (targetCategory == null || targetCategory.trim().isEmpty()) {
			Msg.error(IGroupedTool.class,
					"Target category provided to getFilteredProviders cannot be null or empty.");
			return Stream.empty();
		}

		return loader.stream()
				// Filter out grouped tools themselves
				.filter(specProvider -> !IGroupedTool.class.isAssignableFrom(specProvider.type()))
				// Filter based on matching the target category annotation
				.filter(specProvider -> hasMatchingCategory(specProvider, targetCategory));
	}

	private static boolean hasMatchingCategory(ServiceLoader.Provider<IGhidraMcpSpecification> specProvider,
			String targetCategory) {
		Class<?> specClass = specProvider.type();
		GhidraMcpTool specAnnotation = specClass.getAnnotation(GhidraMcpTool.class);

		if (specAnnotation == null) {
			Msg.warn(IGroupedTool.class, "Service " + specClass.getName()
					+ " implements IGhidraMcpSpecification but lacks @GhidraMcpTool annotation. Skipping for grouping.");
			return false;
		}

		ToolCategory specCategoryEnum = specAnnotation.category();
		if (specCategoryEnum == null || specCategoryEnum == ToolCategory.UNCATEGORIZED
				|| specCategoryEnum == ToolCategory.GROUPED) {
			return false;
		}
		return specCategoryEnum.getCategoryName().equals(targetCategory.trim());
	}

	/**
	 * Static helper method to create the specific JSON schema ObjectNode for a
	 * single
	 * operation variant used within the 'anyOf' array.
	 *
	 * @param toolClass        The class of the granular tool.
	 * @param mapper           ObjectMapper instance for JSON node creation.
	 * @param argOperationName The constant name for the 'operation' argument (e.g.,
	 *                         "operation").
	 * @param argArgumentsName The constant name for the 'arguments' argument (e.g.,
	 *                         "arguments").
	 * @return The ObjectNode representing the schema for this operation variant, or
	 *         null if an error occurs.
	 */
	static ObjectNode createSchemaVariantForTool(Class<? extends IGhidraMcpSpecification> toolClass,
			ObjectMapper mapper, String argOperationName, String argArgumentsName) {
		try {
			// Instantiate the granular tool to get its details
			IGhidraMcpSpecification toolInstance = toolClass.getDeclaredConstructor().newInstance();
			GhidraMcpTool toolAnnotation = toolClass.getAnnotation(GhidraMcpTool.class);
			JsonSchema granularSchema = toolInstance.schema(); // Get the tool's own schema

			if (toolAnnotation == null || toolAnnotation.mcpName().isBlank() || granularSchema == null) {
				Msg.warn(IGroupedTool.class,
						"Skipping tool in grouped schema generation due to missing info: " + toolClass.getName());
				return null; // Skip this tool if info is missing
			}
			String operationName = toolAnnotation.mcpName();
			ObjectNode argumentsSchemaNode = granularSchema.getNode(); // Get the raw node

			// Build the schema for this specific operation item using 'anyOf' structure
			IObjectSchemaBuilder operationItemSchema = JsonSchemaBuilder.object(mapper)
					.property(argOperationName,
							JsonSchemaBuilder.string(mapper)
									.description("Must be '" + operationName + "'.")
									.enumValues(operationName)) // Restrict enum to only this operation
					.property(argArgumentsName, argumentsSchemaNode) // Use the ORIGINAL arguments schema node
					.requiredProperty(argOperationName)
					.requiredProperty(argArgumentsName);

			return operationItemSchema.build().getNode(); // Return the ObjectNode for this variant

		} catch (Exception e) {
			// Handle reflection errors during instantiation
			Msg.error(IGroupedTool.class, "Failed to instantiate or get schema for tool: " + toolClass.getName(),
					e);
			return null; // Skip this tool on error
		}
	}

	/**
	 * Abstract method that implementing grouped tools must provide.
	 * Returns the map used to look up granular tool classes based on their MCP
	 * name.
	 *
	 * @return A map where keys are MCP tool names (e.g., "get_function_by_name")
	 *         and values are the corresponding tool implementation classes.
	 */
	Map<String, Class<? extends IGhidraMcpSpecification>> getToolClassMap();

	// ===================================================================================
	// Nested POJOs for Grouped Results
	// ===================================================================================

	/**
	 * Represents the outcome of a single operation within a grouped tool execution.
	 * Contains either the successful result data or an error message.
	 */
	@JsonPropertyOrder({ "operationName", "status", "data", "error" })
	@JsonInclude(JsonInclude.Include.NON_NULL) // Don't serialize null fields (data or error)
	public static class OperationResult {

		private final String operationName;
		private final OperationStatus status;
		private final Object data; // Holds the successful result object (POJO, List, Map, String, etc.)
		private final String error; // Holds the error message string
		private final Map<String, Object> arguments; // Added field for arguments

		/**
		 * Enum representing the status of an operation.
		 */
		public enum OperationStatus {
			SUCCESS, ERROR
		}

		// Single private constructor
		private OperationResult(String operationName, OperationStatus status, Map<String, Object> arguments, Object data,
				String error) {
			this.operationName = operationName;
			this.status = status;
			this.arguments = arguments; // Set arguments
			this.data = data;
			this.error = error;
		}

		public String getOperationName() {
			return operationName;
		}

		public OperationStatus getStatus() {
			return status;
		}

		public Object getData() {
			return data;
		}

		public String getError() {
			return error;
		}

		public Map<String, Object> getArguments() { // Added getter
			return arguments;
		}

		// Static factory for creating error result from Throwable
		public static OperationResult error(String operationName, Map<String, Object> arguments, Throwable throwable) {
			String errorMessage = (throwable != null)
					? throwable.getClass().getSimpleName() + ": " + throwable.getMessage()
					: "Unknown error";
			return new OperationResult(operationName, OperationStatus.ERROR, arguments, null, errorMessage);
		}

		// Static factory for creating success result
		public static OperationResult success(String operationName, Map<String, Object> arguments, Object data) {
			return new OperationResult(operationName, OperationStatus.SUCCESS, arguments, data, null);
		}
	}

	/**
	 * Represents the collected results of executing a group of operations.
	 * Contains a list of individual {@link OperationResult} objects.
	 */
	public static class GroupedOperationResult {

		private final List<OperationResult> results;

		/**
		 * Constructor for the grouped result.
		 *
		 * @param results A list containing the outcome of each individual operation.
		 */
		public GroupedOperationResult(List<OperationResult> results) {
			this.results = results;
		}

		// --- Getter ---

		public List<OperationResult> getResults() {
			return results;
		}
	}

	// ===================================================================================
	// Default Schema Generation Logic
	// ===================================================================================

	/**
	 * Default implementation for generating the JSON schema for a grouped tool.
	 * This dynamically builds the schema based on the granular tools discovered
	 * via {@link #getToolClassMap()}.
	 *
	 * @return The {@link JsonSchema} for the grouped tool.
	 */
	default JsonSchema getGroupedSchema(ToolCategory targetCategory) {
		// Start with the base schema node (assuming implementer also implements
		// IGhidraMcpSpecification for mapper)
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		// Generate the schema variants for each valid granular tool
		List<ObjectNode> specificOperationSchemas = getGranularToolClasses(targetCategory.getCategoryName()).stream()
				.map(toolClass -> IGroupedTool.createSchemaVariantForTool(toolClass, IGhidraMcpSpecification.mapper,
						ARG_OPERATION,
						ARG_ARGUMENTS))
				.filter(Objects::nonNull) // Filter out any nulls from errors/skips
				.collect(Collectors.toList());

		if (specificOperationSchemas.isEmpty()) {
			Msg.warn(this, "No valid granular tool schemas found for grouped tool: " + this.getClass().getSimpleName());
			// Return a minimal schema indicating failure or an empty array
			return JsonSchemaBuilder.object(IGhidraMcpSpecification.mapper)
					.description("Warning: No operations defined or discovered for this group.").build();
		}

		// Define the main 'operations' array property using the generated anyOf list
		schemaRoot.property(ARG_OPERATIONS,
				JsonSchemaBuilder.array(IGhidraMcpSpecification.mapper)
						.description("An ordered list of operations to execute.")
						.items(JsonSchemaBuilder.object(IGhidraMcpSpecification.mapper)
								.anyOf(specificOperationSchemas.toArray(ObjectNode[]::new))) // Use anyOf here
						.minItems(1)); // Require at least one operation

		schemaRoot.requiredProperty(ARG_OPERATIONS);

		return schemaRoot.build();
	}

	// ===================================================================================
	// Default Execution Logic
	// ===================================================================================

	/**
	 * Default implementation for executing a list of grouped operations.
	 * This method parses the 'operations' list, iterates through each, finds the
	 * corresponding
	 * granular tool using {@link #getToolClassMap()}, instantiates it, executes it,
	 * collects
	 * the results, and returns a final summary.
	 *
	 * @param ex   The async server exchange.
	 * @param args The arguments map for the grouped tool call.
	 * @param tool The Ghidra PluginTool.
	 * @return A Mono containing the CallToolResult with a summary of all operation
	 *         outcomes.
	 */
	default Mono<Object> executeGroupedOperations(McpAsyncServerExchange ex, Map<String, Object> args,
			PluginTool tool) {
		// Get the list of operations using helper from IGhidraMcpSpecification
		IGhidraMcpSpecification specHelpers = (IGhidraMcpSpecification) this; // Cast once
		List<Map<String, Object>> operations = specHelpers
				.getOptionalListArgument(args, ARG_OPERATIONS)
				.orElse(null);

		if (operations == null || operations.isEmpty()) {
			return Mono.error(new IllegalArgumentException("'operations' list cannot be null or empty."));
		}

		Map<String, Class<? extends IGhidraMcpSpecification>> toolClassMap = getToolClassMap();

		// Process each operation, resulting in a stream of OperationResult objects
		return Flux.fromIterable(operations)
				.index()
				.concatMap(indexedOperation -> { // Use concatMap to preserve order
					long index = indexedOperation.getT1();
					Map<String, Object> opArgs = indexedOperation.getT2();

					String operationName = specHelpers.getOptionalStringArgument(opArgs, ARG_OPERATION).orElse(null);
					Map<String, Object> granularArgs = specHelpers.getOptionalMapArgument(opArgs, ARG_ARGUMENTS)
							.orElse(null);

					// Use operationName if available, otherwise construct an error key
					final String opKey = operationName != null ? operationName : "invalid_op_at_index_" + index;

					// --- Handle Validation Errors ---
					if (operationName == null || granularArgs == null) {
						Throwable error = new IllegalArgumentException(
								"Operation entry at index " + index + " is missing 'operation' or 'arguments'.");
						// Directly return an OperationResult for validation errors
						// Pass opArgs (the raw operation request map) as arguments for context
						return Mono.just(OperationResult.error(opKey, opArgs, error));
					}

					Class<? extends IGhidraMcpSpecification> targetToolClass = toolClassMap.get(operationName);
					if (targetToolClass == null) {
						Throwable error = new IllegalArgumentException("Unknown operation '" + operationName
								+ "' at index " + index + ". Known operations: " + toolClassMap.keySet());
						// Directly return an OperationResult for validation errors
						// Pass opArgs (the raw operation request map) as arguments for context
						return Mono.just(OperationResult.error(opKey, opArgs, error));
					}

					// --- Defer Instantiation and Execution ---
					return Mono.defer(() -> {
						try {
							IGhidraMcpSpecification targetToolInstance = targetToolClass.getDeclaredConstructor().newInstance();
							String attemptMessage = String.format("Attempting operation '%s' (index %d).", opKey, index);
							ex.loggingNotification(McpSchema.LoggingMessageNotification.builder()
									.level(LoggingLevel.INFO).logger(this.getClass().getSimpleName()).data(attemptMessage).build());

							// Execute and log success
							return targetToolInstance.execute(ex, granularArgs, tool)
									.doOnSuccess(rawResult -> {
										String successMessage = String.format("Successfully executed operation '%s' (index %d).", opKey,
												index);
										ex.loggingNotification(McpSchema.LoggingMessageNotification.builder()
												.level(LoggingLevel.INFO).logger(this.getClass().getSimpleName()).data(successMessage).build());
									});
						} catch (Exception e) { // Catch instantiation exceptions
							Msg.error(IGroupedTool.class, "Failed to instantiate tool '" + targetToolClass.getSimpleName()
									+ "' for operation '" + operationName + "'", e);
							return Mono.error(e); // Signal error for onErrorResume below
						}
					}).map(rawResult -> OperationResult.success(opKey, granularArgs, rawResult)).onErrorResume(error -> {
						String errorMsg = String.format("Error processing operation '%s' (index %d): %s", opKey, index,
								error.getMessage());
						ghidra.util.Msg.error(this, errorMsg, error);
						return Mono.just(OperationResult.error(opKey, granularArgs, error));
					});
				}).collectList().map(GroupedOperationResult::new).cast(Object.class);
	}

}