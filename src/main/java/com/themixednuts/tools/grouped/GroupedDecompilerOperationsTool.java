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

@GhidraMcpTool(key = "Grouped Decompiler Operations", category = "Decompiler", description = "Performs multiple related decompiler operations.", mcpName = "grouped_decompiler_operations", mcpDescription = "Accepts a list of decompiler operations to perform as a group.")
public class GroupedDecompilerOperationsTool implements IGhidraMcpSpecification, IGroupedTool {
	// Store classes and a map for quick lookup
	private List<Class<? extends IGhidraMcpSpecification>> granularToolClasses = IGroupedTool
			.getGranularToolClasses(this.getClass());

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
			Msg.warn(this, "No granular tool classes found for category: " + annotation.category());
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
		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));

		// Build enum from the stored classes
		List<String> availableOps = granularToolClasses.stream()
				.map(clazz -> clazz.getAnnotation(GhidraMcpTool.class))
				.filter(ann -> ann != null && ann.mcpName() != null && !ann.mcpName().isBlank())
				.map(GhidraMcpTool::mcpName)
				.sorted()
				.toList();

		IObjectSchemaBuilder operationSchema = JsonSchemaBuilder.object(mapper)
				.description("A single decompiler operation.")
				.property("operation",
						JsonSchemaBuilder.string(mapper)
								.description("The specific granular tool mcpName to execute.")
								.enumValues(availableOps.toArray(new String[0])))
				.property("arguments",
						JsonSchemaBuilder.object(mapper)
								.description("The arguments specific to the chosen operation (tool)."))
				.requiredProperty("operation")
				.requiredProperty("arguments");

		schemaRoot.property("operations",
				JsonSchemaBuilder.array(mapper)
						.items(operationSchema)
						.description("A list of decompiler operations to perform."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("operations");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		String fileName = getOptionalStringArgument(args, "fileName").orElse(null);
		List<Map<String, Object>> operations = getOptionalListArgument(args, "operations").orElse(null);

		if (operations == null || operations.isEmpty()) {
			return createErrorResult("No operations provided.");
		}

		return Flux.fromIterable(operations)
				.index()
				.flatMap(indexedOperation -> { // Expects Mono<Map.Entry<String, CallToolResult>>
					long index = indexedOperation.getT1();
					Map<String, Object> operationArgs = indexedOperation.getT2();
					String operationName = getOptionalStringArgument(operationArgs, "operation").orElse(null);
					Map<String, Object> granularArgs = getOptionalMapArgument(operationArgs, "arguments").orElse(null);
					final String opId = (operationName != null ? operationName : "operation") + "_" + index;

					if (operationName == null || granularArgs == null) {
						return createErrorResult(
								"Invalid operation format at index " + index + ": missing 'operation' or 'arguments' field.")
								.map(errorResult -> Map.entry(opId, errorResult));
					}

					Class<? extends IGhidraMcpSpecification> targetToolClass = toolClassMap.get(operationName);
					if (targetToolClass == null) {
						return createErrorResult("Unknown operation/tool named '" + operationName + "' at index " + index + ".")
								.map(errorResult -> Map.entry(opId, errorResult));
					}

					if (fileName != null && !granularArgs.containsKey("fileName")) {
						granularArgs.put("fileName", fileName);
					}

					// Instantiate and execute
					try {
						IGhidraMcpSpecification targetToolInstance = targetToolClass.getDeclaredConstructor().newInstance();
						// Execute the instantiated tool
						return targetToolInstance.execute(ex, granularArgs, tool)
								.map(result -> Map.entry(opId, result)) // Map success to Map.Entry
								.onErrorResume(execError -> { // Catch execution error
									Msg.error(this, "Error executing granular tool '" + operationName + "' at index " + index, execError);
									return createErrorResult("Execution error in '" + operationName + "': " + execError.getMessage())
											.map(errorResult -> Map.entry(opId, errorResult));
								});
					} catch (NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException
							| SecurityException e) {
						// Handle instantiation errors
						Msg.error(this, "Failed to instantiate tool '" + operationName + "' at index " + index, e);
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
						try {
							detailNode.put("resultPayload", getTextFromCallToolResult(result));
						} catch (Exception e) {
							Msg.error(this, "Error parsing result payload: " + e.getMessage(), e);
							detailNode.put("resultPayload", "<Error parsing result payload>");
						}

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
				.onErrorResume(e -> { // Catch outer Flux processing errors
					Msg.error(this, "Error processing grouped decompiler operations stream", e);
					return createErrorResult("Stream processing error: " + e.getMessage());
				});
	}
}