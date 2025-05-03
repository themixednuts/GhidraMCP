package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraDataTypeInfo;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Union;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Get Union Definition", category = "Data Types", description = "Enable the MCP tool to retrieve the definition of a union.", mcpName = "get_union_definition", mcpDescription = "Retrieves the definition (including path, size, alignment, and members) for the specified union data type.")
public class GhidraGetUnionDefinitionTool implements IGhidraMcpSpecification {

	public GhidraGetUnionDefinitionTool() {
	}

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		String schema = parseSchema(schema()).orElse(null);
		if (schema == null) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schema),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public ObjectNode schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property("unionPath",
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the union to retrieve (e.g., /MyCategory/MyUnion)"));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("unionPath");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			// Setup: Parse args, find union, check type
			// Argument parsing errors caught by onErrorResume
			String unionPath = getRequiredStringArgument(args, "unionPath");
			DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(unionPath);

			if (dt == null) {
				// Use helper directly
				return createErrorResult("Data type not found at path: " + unionPath);
			}

			if (!(dt instanceof Union)) {
				// Use helper directly
				return createErrorResult("Data type at path '" + unionPath + "' is not a Union.");
			}

			// Convert to POJO
			GhidraDataTypeInfo info = new GhidraDataTypeInfo(dt);

			// Use helper directly
			return createSuccessResult(info);

		}).onErrorResume(e -> {
			// Catch errors from getProgram, setup (incl. arg parsing)
			// Logging handled by createErrorResult
			return createErrorResult(e);
		});
	}
}