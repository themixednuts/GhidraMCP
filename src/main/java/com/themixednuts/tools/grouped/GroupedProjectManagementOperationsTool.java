package com.themixednuts.tools.grouped;

import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.Optional;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
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

// Import the enum
import com.themixednuts.tools.ToolCategory;

// Category is omitted to use default (UNCATEGORIZED) for options registration
@GhidraMcpTool(key = "Grouped Project Management Operations", description = "Performs multiple related project management operations.", mcpName = "grouped_project_management_operations", mcpDescription = "Accepts a list of project management operations to perform as a group.")
public class GroupedProjectManagementOperationsTool implements IGhidraMcpSpecification, IGroupedTool {
	// Define the functional category this tool groups
	private static final ToolCategory TARGET_CATEGORY = ToolCategory.PROJECT_MANAGEMENT;

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
			// Use the category from the annotation for the warning
			Msg.warn(this, "No granular tool classes found for category: " + annotation.category());
			// Optionally re-attempt loading here if needed
		}

		// Call the corrected schema() method which returns JsonSchema
		JsonSchema schemaObject = schema();
		// Call the correct parseSchema overload
		Optional<String> schemaStringOpt = parseSchema(schemaObject);
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}
		String schemaJson = schemaStringOpt.get();

		return new AsyncToolSpecification(
				// Use the parsed schema string
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	// Change return type to JsonSchema
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The optional name of a program file to operate on, if relevant to the operation."));

		// Build enum from the stored classes
		List<String> availableOps = granularToolClasses.stream()
				.map(clazz -> clazz.getAnnotation(GhidraMcpTool.class))
				.filter(ann -> ann != null && ann.mcpName() != null && !ann.mcpName().isBlank())
				.map(GhidraMcpTool::mcpName)
				.sorted()
				.toList();

		IObjectSchemaBuilder operationSchema = JsonSchemaBuilder.object(mapper)
				.description("A single project management operation.")
				.property(ARG_OPERATION,
						JsonSchemaBuilder.string(mapper)
								.description("The specific granular tool mcpName to execute.")
								.enumValues(availableOps))
				.property(ARG_ARGUMENTS,
						JsonSchemaBuilder.object(mapper)
								.description("The arguments specific to the chosen operation (tool)."))
				.requiredProperty(ARG_OPERATION)
				.requiredProperty(ARG_ARGUMENTS);

		schemaRoot.property(ARG_OPERATIONS,
				JsonSchemaBuilder.array(mapper)
						.items(operationSchema)
						.description("A list of project management operations to perform."));

		// Only require operations, fileName is optional for project management
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

		return Flux.fromIterable(operations)
				.index()
				.flatMap(indexedOperation -> { // Expects Mono<Map.Entry<String, CallToolResult>>
					long index = indexedOperation.getT1();
					Map<String, Object> operationArgs = indexedOperation.getT2();
					String operationName = getOptionalStringArgument(operationArgs, ARG_OPERATION).orElse(null);
					Map<String, Object> granularArgs = getOptionalMapArgument(operationArgs, ARG_ARGUMENTS).orElse(null);
					final String opId = (operationName != null ? operationName : ARG_OPERATION) + "_" + index;

					if (operationName == null || granularArgs == null) {
						return createErrorResult(
								"Invalid operation format at index " + index + ": missing '" + ARG_OPERATION + "' or '" + ARG_ARGUMENTS
										+ "' field.")
								.map(errorResult -> Map.entry(opId, errorResult));
					}

					Class<? extends IGhidraMcpSpecification> targetToolClass = toolClassMap.get(operationName);
					if (targetToolClass == null) {
						return createErrorResult("Unknown operation/tool named '" + operationName + "' at index " + index + ".")
								.map(errorResult -> Map.entry(opId, errorResult));
					}

					// Conditionally add fileName if present and not already in granular args
					if (fileName != null && !granularArgs.containsKey(ARG_FILE_NAME)) {
						granularArgs.put(ARG_FILE_NAME, fileName);
					}

					// Instantiate and execute
					try {
						IGhidraMcpSpecification targetToolInstance = targetToolClass.getDeclaredConstructor().newInstance();
						// Execute the instantiated tool
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
				.flatMap(results -> { // Build final summary
					ArrayNode successDetails = mapper.createArrayNode();
					ArrayNode errorDetails = mapper.createArrayNode();
					boolean overallSuccess = true;

					for (Map.Entry<String, CallToolResult> entry : results) {
						String opIdentifier = entry.getKey();
						CallToolResult result = entry.getValue();
						ObjectNode detailNode = mapper.createObjectNode();
						detailNode.put("operationIdentifier", opIdentifier);
						detailNode.put("resultPayload", getTextFromCallToolResult(result));

						if (result.isError()) {
							overallSuccess = false;
							errorDetails.add(detailNode);
						} else {
							successDetails.add(detailNode);
						}
					}

					ObjectNode finalJson = mapper.createObjectNode();
					finalJson.put("overallSuccess", overallSuccess);
					finalJson.set("successfulOperations", successDetails);
					finalJson.set("failedOperations", errorDetails);

					return createSuccessResult(finalJson);
				})
				.onErrorResume(e -> createErrorResult(e));
	}
}