package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraDataTypeInfo;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Get Enum Definition", category = "Data Types", description = "Enable the MCP tool to retrieve the definition of an enum.", mcpName = "get_enum_definition", mcpDescription = "Retrieves the definition (including path, size, and entries) for the specified enum data type.")
public class GhidraGetEnumDefinitionTool implements IGhidraMcpSpecification {

	public GhidraGetEnumDefinitionTool() {
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

		schemaRoot.property("enumPath",
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the enum to retrieve (e.g., /MyCategory/MyEnum)"));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("enumPath");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			// Setup: Parse args, find enum, check type
			// Argument parsing errors caught by onErrorResume
			String enumPath = getRequiredStringArgument(args, "enumPath");
			DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(enumPath);

			if (dt == null) {
				// Use helper directly
				return createErrorResult("Data type not found at path: " + enumPath);
			}
			if (!(dt instanceof EnumDataType)) {
				// Use helper directly
				return createErrorResult("Data type at path '" + enumPath + "' is not an Enum.");
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