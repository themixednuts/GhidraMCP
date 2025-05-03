package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

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

@GhidraMcpTool(key = "Edit Enum Entry", category = "Data Types", description = "Enable the MCP tool to edit an existing enum entry.", mcpName = "edit_enum_entry", mcpDescription = "Edits the name, value, and/or comment of an existing entry within an enum.")
public class GhidraEditEnumEntryTool implements IGhidraMcpSpecification {

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

		schemaRoot.property("enumPath",
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the enum containing the entry (e.g., /MyCategory/MyEnum)"));

		schemaRoot.property("entryName",
				JsonSchemaBuilder.string(mapper)
						.description("The current name of the entry to edit."));

		schemaRoot.property("newEntryName",
				JsonSchemaBuilder.string(mapper)
						.description("Optional: The new name for the entry."));

		schemaRoot.property("newEntryValue",
				JsonSchemaBuilder.integer(mapper) // Use integer for schema
						.description("Optional: The new integer value for the entry."));

		schemaRoot.property("newEntryComment",
				JsonSchemaBuilder.string(mapper)
						.description("Optional: The new comment for the entry. Use empty string \"\" to clear."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("enumPath")
				.requiredProperty("entryName");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String enumPathString = getRequiredStringArgument(args, "enumPath");
			String entryName = getRequiredStringArgument(args, "entryName");
			Optional<String> newNameOpt = getOptionalStringArgument(args, "newEntryName");
			Optional<Long> newValueOpt = getOptionalLongArgument(args, "newEntryValue");
			Optional<String> newCommentOpt = getOptionalStringArgument(args, "newEntryComment");

			if (newNameOpt.isEmpty() && newValueOpt.isEmpty() && newCommentOpt.isEmpty()) {
				return createErrorResult(
						"No changes specified. Provide at least one of newEntryName, newEntryValue, or newEntryComment.");
			}

			DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(enumPathString);

			if (dt == null) {
				return createErrorResult("Enum not found at path: " + enumPathString);
			}
			if (!(dt instanceof EnumDataType)) {
				return createErrorResult("Data type at path is not an Enum: " + enumPathString);
			}
			final EnumDataType enumDt = (EnumDataType) dt; // Make final for lambda

			if (!enumDt.contains(entryName)) {
				return createErrorResult("Entry '" + entryName + "' not found in enum " + enumPathString);
			}

			// Get current value/comment (safe now)
			final long currentValue = enumDt.getValue(entryName);
			final String currentComment = enumDt.getComment(entryName);

			// Determine final values (make final for lambda)
			final String finalName = newNameOpt.orElse(entryName);
			final long finalValue = newValueOpt.orElse(currentValue);
			final String finalComment = newCommentOpt.orElse(currentComment);

			// Now execute the modification within a transaction
			return executeInTransaction(program, "MCP - Edit Enum Entry", () -> {
				enumDt.add(finalName, finalValue, finalComment);
				return createSuccessResult("Enum entry '" + entryName + "' updated successfully.");
			});

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}
}