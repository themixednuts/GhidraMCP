package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Rename Type", category = "Data Types", description = "Rename a specific data type.", mcpName = "rename_data_type", mcpDescription = "Renames an existing data type.")
public class GhidraRenameTypeTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		JsonSchema schemaObject = schema();
		Optional<String> schemaStringOpt = schemaObject.toJsonString(mapper);
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to serialize schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
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
		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property("originalTypeName",
				JsonSchemaBuilder.string(mapper)
						.description("The current full path name of the data type to rename (e.g., '/MyCategory/OldName')."));
		schemaRoot.property("newTypeName",
				JsonSchemaBuilder.string(mapper)
						.description("The desired new name for the data type (without path)."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("originalTypeName")
				.requiredProperty("newTypeName");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String originalTypeName = getRequiredStringArgument(args, "originalTypeName");
			String newTypeName = getRequiredStringArgument(args, "newTypeName");
			DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(originalTypeName);

			if (dt == null) {
				return createErrorResult("Data type not found: " + originalTypeName);
			}

			return executeInTransaction(program, "Rename Data Type: " + originalTypeName, () -> {
				dt.setName(newTypeName);
				return createSuccessResult(
						"Data type '" + originalTypeName + "' renamed to '" + newTypeName + "' successfully.");
			});
		}).onErrorResume(e -> createErrorResult(e));
	}
}
