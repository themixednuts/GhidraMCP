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
import ghidra.program.model.data.FunctionDefinition;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Get Function Definition", category = "Data Types", description = "Enable the MCP tool to retrieve the definition of a function signature.", mcpName = "get_function_definition", mcpDescription = "Retrieves details (return type, parameters, calling convention, etc.) for the specified function definition data type.")
public class GhidraGetFunctionDefinitionTool implements IGhidraMcpSpecification {

	public GhidraGetFunctionDefinitionTool() {
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

		schemaRoot.property("functionDefinitionPath",
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the function definition data type (e.g., /MyTypes/MyFunctionSig)"));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("functionDefinitionPath");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String functionDefinitionPath = getRequiredStringArgument(args, "functionDefinitionPath");
			DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(functionDefinitionPath);

			if (dt == null) {
				return createErrorResult("Data type not found at path: " + functionDefinitionPath);
			}

			if (!(dt instanceof FunctionDefinition)) {
				return createErrorResult(
						"Data type at path '" + functionDefinitionPath + "' is not a Function Definition.");
			}

			GhidraDataTypeInfo info = new GhidraDataTypeInfo(dt);
			return createSuccessResult(info);

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}
}