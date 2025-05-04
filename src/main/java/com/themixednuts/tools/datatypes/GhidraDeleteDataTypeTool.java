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
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.program.model.data.*;
import ghidra.program.model.data.SourceArchive;
import com.themixednuts.utils.GhidraMcpTaskMonitor;

@GhidraMcpTool(name = "Delete Data Type", category = ToolCategory.DATATYPES, description = "Deletes an existing data type.", mcpName = "delete_data_type", mcpDescription = "Removes a user-defined data type (struct, enum, etc.).")
public class GhidraDeleteDataTypeTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		JsonSchema schemaObject = schema();
		Optional<String> schemaStringOpt = parseSchema(schemaObject);
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
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property(ARG_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the data type to delete (e.g., /MyCategory/MyType)"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String pathString = getRequiredStringArgument(args, ARG_PATH);

			final DataTypeManager dtm = program.getDataTypeManager();
			final DataType dt = dtm.getDataType(pathString);

			if (dt == null) {
				return createSuccessResult("Data type not found (or already deleted) at path: " + pathString);
			}

			SourceArchive sourceArchive = dt.getSourceArchive();
			SourceArchive builtInArchive = IntegerDataType.dataType.getSourceArchive();

			if (builtInArchive != null && builtInArchive.equals(sourceArchive)) {
				return createErrorResult("Cannot delete built-in data type: " + pathString);
			}

			final String finalPathString = pathString;
			GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex, this.getClass().getSimpleName());
			return executeInTransaction(program, "Delete Data Type " + finalPathString, () -> {
				boolean removed = dtm.remove(dt, monitor);

				if (removed) {
					return createSuccessResult("Data type '" + finalPathString + "' deleted successfully.");
				} else {
					return createErrorResult("Failed to delete data type '" + finalPathString + "'. It might be in use.");
				}
			});

		}).onErrorResume(e -> createErrorResult(e));
	}
}