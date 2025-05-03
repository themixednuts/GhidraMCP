package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.program.model.data.*;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(key = "Delete Enum Entry", category = ToolCategory.DATATYPES, description = "Deletes an entry from an existing enum.", mcpName = "delete_enum_entry", mcpDescription = "Removes an entry (by name) from an existing enum data type.")
public class GhidraDeleteEnumEntryTool implements IGhidraMcpSpecification {

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
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property(ARG_ENUM_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the enum containing the entry (e.g., /MyCategory/MyEnum)"));

		schemaRoot.property(ARG_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the enum entry to delete."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ENUM_PATH)
				.requiredProperty(ARG_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			// Setup: Parse args, find enum, check entry exists
			// Argument parsing errors caught by onErrorResume
			String enumPathString = getRequiredStringArgument(args, ARG_ENUM_PATH);
			final String entryName = getRequiredStringArgument(args, ARG_NAME); // Final for lambda

			DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(enumPathString);

			if (dt == null) {
				return createErrorResult("Enum not found at path: " + enumPathString);
			}
			if (!(dt instanceof EnumDataType)) {
				return createErrorResult("Data type at path is not an Enum: " + enumPathString);
			}
			final EnumDataType enumDt = (EnumDataType) dt; // Final for lambda

			// Check existence before trying to delete
			if (!enumDt.contains(entryName)) {
				return createErrorResult("Entry '" + entryName + "' not found in enum " + enumPathString);
			}

			// --- Execute modification in transaction ---
			final String finalEnumPathString = enumPathString; // Capture for message
			return executeInTransaction(program, "MCP - Delete Enum Entry", () -> {
				// Inner Callable logic (just the modification):
				enumDt.remove(entryName);
				// Return success
				return createSuccessResult(
						"Enum entry '" + entryName + "' deleted successfully from " + finalEnumPathString + ".");
			}); // End of Callable for executeInTransaction

		}).onErrorResume(e -> {
			// Catch errors from getProgram, setup (incl. arg parsing), or transaction
			// execution
			// Logging handled by createErrorResult
			return createErrorResult(e);
		});
	}

}