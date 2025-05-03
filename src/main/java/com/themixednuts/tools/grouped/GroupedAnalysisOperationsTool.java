package com.themixednuts.tools.grouped;

import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Grouped Analysis Operations", category = ToolCategory.GROUPED, description = "Performs multiple related analysis/scripting operations.", mcpName = "grouped_analysis_operations", mcpDescription = "Accepts a list of analysis/scripting operations to perform as a group (e.g., trigger analysis).")
public class GroupedAnalysisOperationsTool implements IGhidraMcpSpecification, IGroupedTool {
	// Define the functional category this tool groups
	private static final ToolCategory TARGET_CATEGORY = ToolCategory.ANALYSIS;

	// Store classes and a map for quick lookup
	private List<Class<? extends IGhidraMcpSpecification>> granularToolClasses = IGroupedTool
			.getGranularToolClasses(TARGET_CATEGORY.getCategoryName());

	private Map<String, Class<? extends IGhidraMcpSpecification>> toolClassMap = this.granularToolClasses.stream()
			.filter(clazz -> clazz.getAnnotation(GhidraMcpTool.class) != null)
			.collect(Collectors.toMap(
					clazz -> clazz.getAnnotation(GhidraMcpTool.class).mcpName(),
					clazz -> clazz,
					(existing, replacement) -> existing // Handle potential duplicates
			));

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		// Ensure classes were loaded
		if (this.granularToolClasses.isEmpty()) {
			Msg.warn(this, "No granular tool classes found for category: " + TARGET_CATEGORY.getCategoryName());
			// Allow continuing even if empty, schema will reflect this.
		}

		Optional<String> schemaStringOpt = parseSchema(schema());
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}
		String schemaJson = schemaStringOpt.get();

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file (passed to all operations)."));

		// Build enum from the stored classes
		List<String> availableOps = granularToolClasses.stream()
				.map(clazz -> clazz.getAnnotation(GhidraMcpTool.class))
				.filter(ann -> ann != null && ann.mcpName() != null && !ann.mcpName().isBlank())
				.map(GhidraMcpTool::mcpName)
				.sorted()
				.toList();

		IObjectSchemaBuilder operationSchema = JsonSchemaBuilder.object(mapper)
				.description("A single analysis/scripting operation.")
				.property(ARG_OPERATION,
						JsonSchemaBuilder.string(mapper)
								.description("The specific granular tool mcpName to execute.")
								.enumValues(availableOps))
				.property(ARG_ARGUMENTS,
						JsonSchemaBuilder.object(mapper)
								.description(
										"The arguments specific to the chosen operation (tool). 'fileName' is automatically added if not present."))
				.requiredProperty(ARG_OPERATION)
				.requiredProperty(ARG_ARGUMENTS);

		schemaRoot.property(ARG_OPERATIONS,
				JsonSchemaBuilder.array(mapper)
						.items(operationSchema)
						.description("A list of analysis/scripting operations to perform."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_OPERATIONS);

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		String fileName = getOptionalStringArgument(args, ARG_FILE_NAME).orElse(null);
		List<Map<String, Object>> operations = getOptionalListArgument(args, ARG_OPERATIONS).orElse(null);

		if (operations == null || operations.isEmpty()) {
			return createErrorResult("No operations provided.");
		}

		// Use Flux to process operations sequentially
		return Flux.fromIterable(operations)
				.index() // Get index for unique IDs
				.flatMap(indexedOperation -> {
					long index = indexedOperation.getT1();
					Map<String, Object> operationArgs = indexedOperation.getT2();
					String operationName = getOptionalStringArgument(operationArgs, ARG_OPERATION).orElse(null);
					Map<String, Object> granularArgs = getOptionalMapArgument(operationArgs, ARG_ARGUMENTS).orElse(null);
					final String opId = (operationName != null ? operationName : ARG_OPERATION) + "_" + index;

					// Validate operation structure
					if (operationName == null || granularArgs == null) {
						return createErrorResult(
								"Invalid operation format at index " + index + ": missing '" + ARG_OPERATION + "' or '" + ARG_ARGUMENTS
										+ "' field.")
								.map(errorResult -> Map.entry(opId, errorResult));
					}

					// Find the target tool class
					Class<? extends IGhidraMcpSpecification> targetToolClass = toolClassMap.get(operationName);
					if (targetToolClass == null) {
						return createErrorResult("Unknown operation/tool named '" + operationName + "' at index " + index + ".")
								.map(errorResult -> Map.entry(opId, errorResult));
					}

					// Inject top-level fileName if not present in granular args
					if (fileName != null && !granularArgs.containsKey(ARG_FILE_NAME)) {
						granularArgs.put(ARG_FILE_NAME, fileName);
					}

					// Instantiate and execute the granular tool
					try {
						IGhidraMcpSpecification targetToolInstance = targetToolClass.getDeclaredConstructor().newInstance();
						return targetToolInstance.execute(ex, granularArgs, tool)
								.map(result -> Map.entry(opId, result)) // Map success to Map.Entry
								.onErrorResume(execError -> createErrorResult(
										"Execution error in '" + operationName + "': " + execError.getMessage())
										.map(errorResult -> Map.entry(opId, errorResult)));
					} catch (NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException
							| SecurityException e) {
						return createErrorResult("Instantiation error for '" + operationName + "': " + e.getMessage())
								.map(errorResult -> Map.entry(opId, errorResult));
					}
				})
				.collectList() // Collect results: List<Map.Entry<String, CallToolResult>>
				.flatMap(resultsList -> {
					// Convert the list of entries into a Map for the final result
					Map<String, CallToolResult> resultMap = resultsList.stream()
							.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
					return createSuccessResult(resultMap); // Return the map as the success result
				})
				.onErrorResume(e -> createErrorResult(e));
	}
}