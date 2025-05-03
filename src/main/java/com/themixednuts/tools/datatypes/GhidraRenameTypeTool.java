package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Rename Data Type", category = "Data Types", description = "Enable the MCP tool to rename an existing data type.", mcpName = "rename_data_type", mcpDescription = "Renames an existing data type (struct, union, enum, typedef, etc.).")
public class GhidraRenameTypeTool implements IGhidraMcpSpecification {

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

		schemaRoot.property("oldPath",
				JsonSchemaBuilder.string(mapper)
						.description("The current full path of the data type to rename (e.g., /MyCategory/MyType)."));

		schemaRoot.property("newName",
				JsonSchemaBuilder.string(mapper)
						.description("The desired new name for the data type (just the name, not the full path)."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("oldPath")
				.requiredProperty("newName");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String oldPathString = getRequiredStringArgument(args, "oldPath");
			final String newName = getRequiredStringArgument(args, "newName");

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

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}
}
