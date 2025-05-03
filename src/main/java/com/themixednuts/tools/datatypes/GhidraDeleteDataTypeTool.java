package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

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
import reactor.core.publisher.Mono;
import ghidra.program.model.data.*;
import ghidra.program.model.data.SourceArchive;
import ghidra.util.task.TaskMonitor;

@GhidraMcpTool(key = "Delete Data Type", category = "Data Types", description = "Enable the MCP tool to delete an existing data type.", mcpName = "delete_data_type", mcpDescription = "Deletes an existing data type (struct, enum, typedef, etc.) identified by its path.")
public class GhidraDeleteDataTypeTool implements IGhidraMcpSpecification {

	public GhidraDeleteDataTypeTool() {
	}

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

		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property("path",
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the data type to delete (e.g., /MyCategory/MyType)"));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("path");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			// Setup: Parse args, find data type, check if built-in
			// Argument parsing errors caught by onErrorResume
			String pathString = getRequiredStringArgument(args, "path");

			final DataTypeManager dtm = program.getDataTypeManager(); // Final for lambda
			final DataType dt = dtm.getDataType(pathString); // Final for lambda

			// If not found, treat as success (already deleted)
			if (dt == null) {
				return createSuccessResult("Data type not found (or already deleted) at path: " + pathString);
			}

			// Check if it's a built-in type
			SourceArchive sourceArchive = dt.getSourceArchive();
			SourceArchive builtInArchive = IntegerDataType.dataType.getSourceArchive(); // Get a known built-in for comparison

			if (builtInArchive != null && builtInArchive.equals(sourceArchive)) {
				return createErrorResult("Cannot delete built-in data type: " + pathString);
			}

			// --- Execute modification in transaction ---
			final String finalPathString = pathString; // Capture for message
			return executeInTransaction(program, "MCP - Delete Data Type", () -> {
				// Inner Callable logic (just the modification):
				// Let executeInTransaction handle potential exceptions
				boolean removed = dtm.remove(dt, TaskMonitor.DUMMY);

				if (removed) {
					// Return success
					return createSuccessResult("Data type '" + finalPathString + "' deleted successfully.");
				} else {
					// Return error if remove failed (e.g., type is in use)
					return createErrorResult("Failed to delete data type '" + finalPathString + "'. It might be in use.");
				}
			}); // End of Callable for executeInTransaction

		}).onErrorResume(e -> {
			// Catch errors from getProgram, setup (incl. arg parsing), or transaction
			// execution
			// Logging handled by createErrorResult
			return createErrorResult(e);
		});
	}
}