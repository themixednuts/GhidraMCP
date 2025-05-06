package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.listing.Program;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(name = "Update Enum Entry", mcpName = "update_enum_entry", category = ToolCategory.DATATYPES, description = "Modifies the name, value, or comment of an existing entry in an enum data type.", mcpDescription = "Modifies the name, value or comment of an existing entry in an enum data type, identified by its current name.")
public class GhidraUpdateEnumEntryTool implements IGhidraMcpSpecification {

	private static record EnumUpdateContext(
			Program program,
			EnumDataType enumDt,
			String oldName,
			String newName,
			long newValue,
			String newComment) {
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
						.description("The current name of the entry to edit."));

		schemaRoot.property(ARG_NEW_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("Optional: The new name for the entry."));

		schemaRoot.property(ARG_VALUE,
				JsonSchemaBuilder.integer(mapper) // Use integer for schema
						.description("Optional: The new integer value for the entry."));

		schemaRoot.property(ARG_COMMENT,
				JsonSchemaBuilder.string(mapper)
						.description("Optional: The new comment for the entry. Use empty string \"\" to clear."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ENUM_PATH)
				.requiredProperty(ARG_NAME);
		// Require at least one update argument? No, let execute handle that.

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> { // .map for synchronous setup
					String enumPathString = getRequiredStringArgument(args, ARG_ENUM_PATH);
					String entryName = getRequiredStringArgument(args, ARG_NAME);
					Optional<String> newNameOpt = getOptionalStringArgument(args, ARG_NEW_NAME);
					Optional<Long> newValueOpt = getOptionalLongArgument(args, ARG_VALUE);
					Optional<String> newCommentOpt = getOptionalStringArgument(args, ARG_COMMENT);

					if (newNameOpt.isEmpty() && newValueOpt.isEmpty() && newCommentOpt.isEmpty()) {
						throw new IllegalArgumentException(
								"No changes specified. Provide at least one of newName, value, or comment.");
					}

					DataType dt = program.getDataTypeManager().getDataType(enumPathString);

					if (dt == null) {
						throw new IllegalArgumentException("Enum not found at path: " + enumPathString);
					}
					if (!(dt instanceof EnumDataType)) {
						throw new IllegalArgumentException("Data type at path is not an Enum: " + enumPathString);
					}
					EnumDataType enumDt = (EnumDataType) dt;

					if (!enumDt.contains(entryName)) {
						throw new IllegalArgumentException("Entry '" + entryName + "' not found in enum " + enumPathString);
					}

					// Get current value/comment before potential modification
					long currentValue = enumDt.getValue(entryName);
					String currentComment = enumDt.getComment(entryName);

					// Determine final values
					String finalNewName = newNameOpt.orElse(entryName); // If new name not provided, use old name
					long finalNewValue = newValueOpt.orElse(currentValue);
					// Handle empty string for comment clearing
					String finalNewComment = newCommentOpt.orElse(currentComment);

					return new EnumUpdateContext(program, enumDt, entryName, finalNewName, finalNewValue, finalNewComment);
				})
				.flatMap(context -> { // .flatMap for transaction
					return executeInTransaction(context.program(), "Update Enum Entry " + context.oldName(), () -> {
						// Remove the old entry first, if the name or value is changing
						if (!context.oldName().equals(context.newName())
								|| context.enumDt().getValue(context.oldName()) != context.newValue()) {
							context.enumDt().remove(context.oldName());
						}
						// Add the new/updated entry
						context.enumDt().add(context.newName(), context.newValue(), context.newComment());

						return "Enum entry '" + context.oldName() + "' updated successfully to (Name: " + context.newName()
								+ ", Value: " + context.newValue() + ").";
					});
				});
	}
}