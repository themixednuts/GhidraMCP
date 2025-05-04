package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Rename Data Type", category = ToolCategory.DATATYPES, description = "Renames an existing data type.", mcpName = "rename_data_type", mcpDescription = "Renames a user-defined data type (struct, enum, etc.).")
public class GhidraRenameDataTypeTool implements IGhidraMcpSpecification {

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
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The current full path of the data type to rename (e.g., /MyCategory/MyType)."));
		schemaRoot.property(ARG_NEW_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The desired new name for the data type (just the name, not the full path)."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_PATH)
				.requiredProperty(ARG_NEW_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String oldPathString = getRequiredStringArgument(args, ARG_PATH);
			final String newName = getRequiredStringArgument(args, ARG_NEW_NAME);

			DataTypeManager dtm = program.getDataTypeManager();
			final DataType dataType = dtm.getDataType(oldPathString);

			if (dataType == null) {
				return createErrorResult("Data type not found at path: " + oldPathString);
			}

			return executeInTransaction(program, "MCP - Rename Data Type", () -> {
				dataType.setName(newName);
				String newPath = dataType.getPathName();
				return createSuccessResult("Data type renamed successfully to: " + newPath);
			});

		}).onErrorResume(e -> createErrorResult(e));
	}
}