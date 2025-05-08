package com.themixednuts.tools.grouped;

import java.util.List;
import java.util.ServiceLoader;
import java.util.ServiceLoader.Provider;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IBuildableSchemaType;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import ghidra.util.Msg;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.spec.McpSchema.LoggingLevel;
import ghidra.framework.options.ToolOptions;
import com.themixednuts.GhidraMCPPlugin;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.Tool;

/**
 * Marker interface for grouped operation tools.
 * Tools implementing this interface bundle multiple related granular operations
 * and will only be registered when grouping mode is enabled.
 */
public interface IGroupedTool extends IGhidraMcpSpecification {

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
	 * Static helper method to create the specific JSON schema Builder for a
	 * single operation variant used within the 'anyOf' array.
	 * 
	 * @param toolClass        The class of the granular tool.
	 * @param mapper           ObjectMapper instance for JSON node creation.
	 * @param argOperationName The constant name for the 'operation' argument (e.g.,
	 *                         "operation").
	 * @param argArgumentsName The constant name for the 'arguments' argument (e.g.,
	 *                         "arguments").
	 * @return The IObjectSchemaBuilder representing the schema for this operation
	 *         variant,
	 *         or null if an error occurs.
	 */
	static IObjectSchemaBuilder createSchemaVariantForTool( // Return IObjectSchemaBuilder
			Class<? extends IGhidraMcpSpecification> toolClass) {
		try {
			IGhidraMcpSpecification toolInstance = toolClass.getDeclaredConstructor().newInstance();
			GhidraMcpTool toolAnnotation = toolClass.getAnnotation(GhidraMcpTool.class);
			JsonSchema granularSchema = toolInstance.schema();
			if (toolAnnotation == null || toolAnnotation.mcpName().isBlank() || granularSchema == null) {
				Msg.warn(IGroupedTool.class, "Skip schema gen: " + toolClass.getName());
				return null;
			}
			String operationName = toolAnnotation.mcpName();
			ObjectNode argumentsSchemaNode = granularSchema.getNode(); // Still need the node for arguments

			IObjectSchemaBuilder operationItemSchema = JsonSchemaBuilder.object(mapper)
					.property(ARG_OPERATION, JsonSchemaBuilder.string(mapper)
							.description("Must be '" + operationName + "'.")
							.enumValues(operationName), true)
					.property(ARG_ARGUMENTS, argumentsSchemaNode, true);

			return operationItemSchema; // Return the builder itself

		} catch (Exception e) {
			Msg.error(IGroupedTool.class, "Fail schema gen: " + toolClass.getName(), e);
			return null;
		}
	}

	ToolCategory getTargetCategory();

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
	 * Default implementation for generating the JSON schema for a grouped tool,
	 * considering enabled status of granular tools.
	 * This dynamically builds the schema based on the granular tools discovered.
	 *
	 * @param targetCategory The category this grouped tool manages.
	 * @param tool           The Ghidra PluginTool, used to access ToolOptions for
	 *                       filtering.
	 * @return The {@link JsonSchema} for the grouped tool.
	 */
	default JsonSchema getGroupedSchema(ToolCategory targetCategory, PluginTool tool) {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		ToolOptions options = tool.getOptions(GhidraMCPPlugin.MCP_TOOL_OPTIONS_CATEGORY);
		String categoryName = targetCategory.getCategoryName();

		// 1. Get builders for enabled granular tools
		List<IObjectSchemaBuilder> specificOperationSchemaBuilders = // Changed type
				getGranularToolClasses(categoryName).stream()
						.filter(toolClass -> { // Filter by enabled
							GhidraMcpTool specAnnotation = toolClass.getAnnotation(GhidraMcpTool.class);
							if (specAnnotation == null) {
								Msg.warn(this, "Granular tool " + toolClass.getSimpleName() + " missing @GhidraMcpTool. Exclude.");
								return false;
							}
							String baseKey = specAnnotation.name();
							ToolCategory granularCat = specAnnotation.category();
							String fullKey = baseKey;
							if (granularCat != null && granularCat != ToolCategory.UNCATEGORIZED
									&& granularCat != ToolCategory.GROUPED) {
								fullKey = granularCat.getCategoryName() + "." + baseKey;
							}
							boolean isEnabled = options.getBoolean(fullKey, true);
							if (!isEnabled) {
								Msg.info(this, "Granular tool '" + fullKey + "' disabled. Exclude from grouped schema "
										+ this.getClass().getSimpleName());
							}
							return isEnabled;
						})
						.map(IGroupedTool::createSchemaVariantForTool)
						.filter(Objects::nonNull)
						.collect(Collectors.toList());

		if (specificOperationSchemaBuilders.isEmpty()) {
			Msg.warn(this,
					"No *enabled* granular tools for grouped tool: " + this.getClass().getSimpleName() + " cat: " + categoryName);
			return JsonSchemaBuilder.object(IGhidraMcpSpecification.mapper)
					.description("Warn: No enabled operations for group '" + categoryName + "'. Check options: '"
							+ GhidraMCPPlugin.MCP_TOOL_OPTIONS_CATEGORY + "'.")
					.build();
		}

		// Create a schema for the items of the array.
		// This item schema will be an object schema that itself uses 'anyOf'.
		// Each schema in specificOperationSchemaBuilders is already an
		// IObjectSchemaBuilder.
		// JsonSchemaBuilder.object().anyOf(...) creates a schema like:
		// { "type": "object", "anyOf": [ ... ] }
		// This is what we want for the "items" definition.
		IBuildableSchemaType itemSchema = JsonSchemaBuilder.object(IGhidraMcpSpecification.mapper)
				.anyOf(specificOperationSchemaBuilders);

		// IObjectSchemaBuilder operationSchema = JsonSchemaBuilder.object(mapper)
		// .description("A single datatype operation.")
		// .property(ARG_OPERATION,
		// JsonSchemaBuilder.string(mapper)
		// .description("The specific granular tool mcpName to execute.")
		// .enumValues(availableOps))
		// .property(ARG_ARGUMENTS,
		// JsonSchemaBuilder.object(mapper)
		// .description("The arguments specific to the chosen operation (tool)."))
		// .requiredProperty(ARG_OPERATION)
		// .requiredProperty(ARG_ARGUMENTS);

		schemaRoot.property(ARG_OPERATIONS, JsonSchemaBuilder.array(IGhidraMcpSpecification.mapper)
				.description(
						"An ordered list of operations to execute. Each operation must conform to one of the enabled operation schemas.")
				.items(itemSchema) // Apply the itemSchema (which contains anyOf) here
				.minItems(1), true); // Mark ARG_OPERATIONS as required

		return schemaRoot.build();
	}

	// ===================================================================================
	// Default Specification Generation for Grouped Tools
	// ===================================================================================

	/**
	 * Default implementation for generating the full {@link AsyncToolSpecification}
	 * for a grouped tool.
	 * This method uses the dynamic, filtered schema and sets up the execution path.
	 * Concrete grouped tools should call this from their overridden
	 * {@code specification(PluginTool tool)} method.
	 *
	 * @param targetCategory          The {@link ToolCategory} this grouped tool is
	 *                                responsible for.
	 * @param tool                    The current Ghidra {@link PluginTool} context.
	 * @param thisGroupedToolInstance The instance of the concrete grouped tool
	 *                                (passed as 'this').
	 *                                It must implement
	 *                                {@link IGhidraMcpSpecification}.
	 * @return The fully constructed {@link AsyncToolSpecification} for the grouped
	 *         tool, or {@code null} if an error occurs.
	 */
	default AsyncToolSpecification getGroupedSpecification(
			ToolCategory targetCategory,
			PluginTool tool,
			IGhidraMcpSpecification thisGroupedToolInstance) {

		GhidraMcpTool annotation = thisGroupedToolInstance.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(thisGroupedToolInstance,
					"Missing @GhidraMcpTool annotation on " + thisGroupedToolInstance.getClass().getSimpleName());
			return null;
		}

		// Get the dynamic schema (already filters by enabled tools)
		JsonSchema schemaObject = getGroupedSchema(targetCategory, tool);

		// Use parseSchema from the IGhidraMcpSpecification context of the concrete tool
		// instance
		Optional<String> schemaStringOpt = thisGroupedToolInstance.parseSchema(schemaObject);

		if (schemaStringOpt.isEmpty()) {
			Msg.error(thisGroupedToolInstance,
					"Failed to generate dynamic schema for grouped tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}
		String schemaJson = schemaStringOpt.get();

		// The execute method called here will be the one implemented in the concrete
		// grouped tool,
		// which should delegate to IGroupedTool.executeGroupedOperations.
		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson),
				(ex, args) -> thisGroupedToolInstance.execute(ex, args, tool)
						.flatMap(thisGroupedToolInstance::createSuccessResult)
						.onErrorResume(thisGroupedToolInstance::createErrorResult));
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
	default Mono<? extends Object> executeGroupedOperations(McpAsyncServerExchange ex, Map<String, Object> args,
			PluginTool tool) {
		// Get the list of operations using helper from IGhidraMcpSpecification
		IGhidraMcpSpecification specHelpers = (IGhidraMcpSpecification) this; // Cast once
		List<Map<String, Object>> operations = specHelpers
				.getOptionalListArgument(args, ARG_OPERATIONS)
				.orElse(null);

		if (operations == null || operations.isEmpty()) {
			return Mono.error(new IllegalArgumentException("'operations' list cannot be null or empty."));
		}

		Map<String, Class<? extends IGhidraMcpSpecification>> toolClassMap = getToolClassMap(tool);

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
				}).collectList().map(GroupedOperationResult::new);
	}

	// Default implementation for IGhidraMcpSpecification.specification
	@Override
	default AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		// Get the dynamic schema using the filtered getGroupedSchema
		JsonSchema schemaObject = getGroupedSchema(getTargetCategory(), tool); // `this` is implicit for default method call
		Optional<String> schemaStringOpt = parseSchema(schemaObject); // `this.parseSchema` from IGhidraMcpSpecification

		if (schemaStringOpt.isEmpty()) {
			Msg.error(this,
					"Failed to generate dynamic schema for grouped tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}
		String schemaJson = schemaStringOpt.get();
		Msg.info(this, schemaJson);

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson),
				(ex, args) -> this.execute(ex, args, tool)
						.flatMap(this::createSuccessResult) // from IGhidraMcpSpecification
						.onErrorResume(this::createErrorResult) // from IGhidraMcpSpecification
		);
	}

	// Default implementation for IGhidraMcpSpecification.execute
	@Override
	default Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return executeGroupedOperations(ex, args, tool);
	}

	// NEW Default implementation for IGhidraMcpSpecification.schema
	@Override
	default JsonSchema schema() {
		throw new UnsupportedOperationException("Schema is not implemented for grouped tools.");
	}

	// Default implementation for getToolClassMap (cleaned up)
	default Map<String, Class<? extends IGhidraMcpSpecification>> getToolClassMap(PluginTool tool) {
		ToolCategory currentTargetCategory = getTargetCategory();
		ToolOptions options = tool.getOptions(GhidraMCPPlugin.MCP_TOOL_OPTIONS_CATEGORY);
		String categoryName = currentTargetCategory.getCategoryName(); // Cache for logging

		return IGroupedTool.getGranularToolClasses(categoryName).stream()
				// 1. Filter by enabled status in options
				.filter(toolClass -> {
					GhidraMcpTool specAnnotation = toolClass.getAnnotation(GhidraMcpTool.class);
					if (specAnnotation == null) {
						Msg.warn(this, "Tool class " + toolClass.getSimpleName() + " (cat: " + categoryName
								+ ") missing @GhidraMcpTool. Exclude from map.");
						return false;
					}
					String baseKey = specAnnotation.name();
					ToolCategory granularCat = specAnnotation.category();
					String fullOptionKey = baseKey;
					if (granularCat != null && granularCat != ToolCategory.UNCATEGORIZED && granularCat != ToolCategory.GROUPED) {
						fullOptionKey = granularCat.getCategoryName() + "." + baseKey;
					}
					boolean isEnabled = options.getBoolean(fullOptionKey, true);
					if (!isEnabled) {
						Msg.info(this, "Granular tool '" + fullOptionKey + "' disabled, not adding to toolClassMap for "
								+ this.getClass().getSimpleName());
					}
					return isEnabled;
				})
				// 2. Filter by presence of required annotation/mcpName for mapping
				.filter(toolClass -> {
					GhidraMcpTool annotation = toolClass.getAnnotation(GhidraMcpTool.class);
					// Check annotation and mcpName presence. Annotation presence is already checked
					// above,
					// but checking mcpName specifically before toMap is good practice.
					if (annotation == null || annotation.mcpName().isBlank()) {
						Msg.warn(this, "Tool " + toolClass.getSimpleName() + " (cat: " + categoryName
								+ ") enabled but missing MCP name in annotation. Cannot map.");
						return false;
					}
					return true;
				})
				// 3. Collect into Map
				.collect(Collectors.toMap(
						// Key extractor: mcpName (safe due to filter above)
						toolClass -> toolClass.getAnnotation(GhidraMcpTool.class).mcpName(),
						// Value extractor: the Class itself
						toolClass -> toolClass,
						// Merge function for duplicates
						(existingValue, newValue) -> {
							String mcpName = "<unknown_mcp_name>";
							GhidraMcpTool ann = existingValue.getAnnotation(GhidraMcpTool.class);
							if (ann != null && !ann.mcpName().isBlank()) {
								mcpName = ann.mcpName();
							}
							Msg.warn(this, "Duplicate MCP name '" + mcpName + "' for category " + categoryName + ". Keeping: "
									+ existingValue.getSimpleName());
							return existingValue;
						}));
	}
}