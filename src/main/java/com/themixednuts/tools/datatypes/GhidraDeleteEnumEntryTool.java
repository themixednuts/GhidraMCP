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
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.program.model.data.*;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(key = "Delete Enum Entry", category = "Data Types", description = "Enable the MCP tool to delete an entry from an existing enum.", mcpName = "delete_enum_entry", mcpDescription = "Deletes an entry specified by its name from an existing enum.")
public class GhidraDeleteEnumEntryTool implements IGhidraMcpSpecification {

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
						.description("The full path of the enum containing the entry (e.g., /MyCategory/MyEnum)"));

		schemaRoot.property("entryName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the enum entry to delete."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("enumPath")
				.requiredProperty("entryName");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			// Setup: Parse args, find enum, check entry exists
			// Argument parsing errors caught by onErrorResume
			String enumPathString = getRequiredStringArgument(args, "enumPath");
			final String entryName = getRequiredStringArgument(args, "entryName"); // Final for lambda

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