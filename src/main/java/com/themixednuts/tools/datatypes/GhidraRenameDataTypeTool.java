package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import ghidra.program.model.data.*;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(key = "Rename Data Type", category = "Data Types", description = "Enable the MCP tool to rename an existing data type.", mcpName = "rename_data_type", mcpDescription = "Renames an existing data type (struct, enum, typedef, etc.) identified by its current path.")
public class GhidraRenameDataTypeTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		String schema = parseSchema(schema()).orElse(null);
		if (schema == null) {
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

		schemaRoot.property("currentPath",
				JsonSchemaBuilder.string(mapper)
						.description("The current full path of the data type to rename (e.g., /MyCategory/MyOldName)"));

		schemaRoot.property("newName",
				JsonSchemaBuilder.string(mapper)
						.description("The new name for the data type (without category path)."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("currentPath")
				.requiredProperty("newName");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String currentPathString = getRequiredStringArgument(args, "currentPath");
			final String newName = getRequiredStringArgument(args, "newName");

			if (newName.contains("/") || newName.contains(":")) {
				return createErrorResult("Invalid newName: Contains forbidden characters like '/' or ':'.");
			}

			DataTypeManager dtm = program.getDataTypeManager();
			final DataType dt = dtm.getDataType(currentPathString);

			if (dt == null) {
				return createErrorResult("Data type not found at path: " + currentPathString);
			}

			return executeInTransaction(program, "MCP - Rename Data Type", () -> {
				dt.setName(newName);
				String finalPath = dt.getPathName();
				return createSuccessResult("Data type renamed successfully to: " + finalPath);
			});

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}
}