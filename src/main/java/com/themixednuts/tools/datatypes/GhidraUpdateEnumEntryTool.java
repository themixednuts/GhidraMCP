package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Update Enum Entries", mcpName = "update_enum_entries", category = ToolCategory.DATATYPES, description = "Updates one or more entries (name/value pairs) in an existing enum data type.", mcpDescription = "Updates the name, value, and/or comment of one or more existing entries in an enum.")
public class GhidraUpdateEnumEntryTool implements IGhidraMcpSpecification {

	// Argument for the array of entry updates
	public static final String ARG_ENTRY_UPDATES = "entryUpdates";
	// Arguments for identifying the entry and the updates
	// Use standard ARG_NAME and ARG_VALUE for identification
	public static final String ARG_NEW_NAME = "newName";
	public static final String ARG_NEW_VALUE = "newValue";
	public static final String ARG_NEW_COMMENT = "newComment";

	private static record EnumEntryUpdateDefinition(
			Optional<String> name,
			Optional<Long> value,
			Optional<String> newName,
			Optional<Long> newValue,
			Optional<String> newComment) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		// Schema for a single entry update definition
		IObjectSchemaBuilder updateSchema = JsonSchemaBuilder.object(mapper)
				.description("Definition of updates for a single enum entry.")
				// Identification (choose one)
				.property(ARG_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("Current name of the entry to update. Required if 'value' is not provided."))
				.property(ARG_VALUE,
						JsonSchemaBuilder.integer(mapper)
								.description("Current value of the entry to update. Required if 'name' is not provided."))
				// Optional Updates
				.property(ARG_NEW_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("Optional: New name for the entry."))
				.property(ARG_NEW_VALUE,
						JsonSchemaBuilder.integer(mapper)
								.description("Optional: New value for the entry."))
				.property(ARG_NEW_COMMENT,
						JsonSchemaBuilder.string(mapper)
								.description("Optional: New comment for the entry. An empty string clears the comment."))
				.requiredProperty(ARG_NAME);

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));
		schemaRoot.property(ARG_ENUM_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the enum to modify (e.g., /MyCategory/MyEnum)"));
		// Add the array property
		schemaRoot.property(ARG_ENTRY_UPDATES,
				JsonSchemaBuilder.array(mapper)
						.description("An array of entry update definitions.")
						.items(updateSchema)
						.minItems(1)); // Require at least one update

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ENUM_PATH)
				.requiredProperty(ARG_ENTRY_UPDATES);

		return schemaRoot.build();
	}

	// Context to hold details needed for the transaction
	private static record EnumEntryUpdateBatchContext(
			Program program,
			Enum targetEnum,
			List<EnumEntryUpdateDefinition> entryUpdateDefs) {
	}

	private boolean processSingleEnumEntryUpdate(Enum targetEnum, EnumEntryUpdateDefinition updateDef,
			String enumPathStringForError) {
		// Identify the entry
		String currentName;
		long currentValue;
		String currentComment;

		if (updateDef.name().isPresent()) {
			currentName = updateDef.name().get();
			if (!targetEnum.contains(currentName)) {
				throw new IllegalArgumentException(
						"Entry with name '" + currentName + "' not found in enum '" + enumPathStringForError + "'.");
			}
			currentValue = targetEnum.getValue(currentName);
			currentComment = targetEnum.getComment(currentName);
			if (updateDef.value().isPresent() && updateDef.value().get() != currentValue) {
				throw new IllegalArgumentException(
						"Provided value " + updateDef.value().get() + " for entry '" + currentName
								+ "' does not match actual value " + currentValue + ".");
			}
		} else if (updateDef.value().isPresent()) {
			currentValue = updateDef.value().get();
			currentName = targetEnum.getName(currentValue);
			if (currentName == null) {
				throw new IllegalArgumentException(
						"Entry with value " + currentValue + " not found in enum '" + enumPathStringForError + "'.");
			}
			currentComment = targetEnum.getComment(currentName);
		} else {
			// Should be caught by pre-validation, but as a safeguard within the helper:
			throw new IllegalStateException("Missing identifier (name or value) for an enum entry update.");
		}

		// Determine final state for the update
		String finalNewName = updateDef.newName().orElse(currentName);
		long finalNewValue = updateDef.newValue().orElse(currentValue);
		// If newCommentOpt is present (even empty string), it's an intentional update.
		// Otherwise, keep the original comment.
		String finalNewComment = updateDef.newComment().orElse(currentComment);

		boolean nameChanged = !finalNewName.equals(currentName);
		boolean valueChanged = finalNewValue != currentValue;
		// An explicit comment update occurs if newCommentOpt was provided AND it's
		// different
		// Or if newCommentOpt was provided as an empty string to clear an existing
		// comment.
		boolean commentChanged = updateDef.newComment().isPresent() && !finalNewComment.equals(currentComment);

		if (!nameChanged && !valueChanged && !commentChanged) {
			return false; // No actual change to apply for this entry
		}

		// Perform the update: Ghidra's Enum requires remove then add for any
		// modification.
		targetEnum.remove(currentName); // Remove by the original name identified
		targetEnum.add(finalNewName, finalNewValue, finalNewComment);

		return true; // An update was made
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> { // .map for synchronous setup
					String enumPathString = getRequiredStringArgument(args, ARG_ENUM_PATH);
					List<Map<String, Object>> rawEntryUpdates = getOptionalListArgument(args, ARG_ENTRY_UPDATES)
							.orElseThrow(
									() -> new IllegalArgumentException("Missing required argument: '" + ARG_ENTRY_UPDATES + "'"));

					if (rawEntryUpdates.isEmpty()) {
						throw new IllegalArgumentException("Argument '" + ARG_ENTRY_UPDATES + "' cannot be empty.");
					}

					List<EnumEntryUpdateDefinition> entryUpdateDefs = rawEntryUpdates.stream()
							.map(rawDef -> new EnumEntryUpdateDefinition(
									getOptionalStringArgument(rawDef, ARG_NAME),
									getOptionalLongArgument(rawDef, ARG_VALUE),
									getOptionalStringArgument(rawDef, ARG_NEW_NAME),
									getOptionalLongArgument(rawDef, ARG_NEW_VALUE),
									getOptionalStringArgument(rawDef, ARG_NEW_COMMENT)))
							.collect(Collectors.toList());

					DataType dt = program.getDataTypeManager().getDataType(enumPathString);
					if (dt == null) {
						throw new IllegalArgumentException("Enum not found at path: " + enumPathString);
					}
					if (!(dt instanceof Enum)) {
						throw new IllegalArgumentException("Data type at path is not an Enum: " + enumPathString);
					}
					Enum targetEnum = (Enum) dt;

					// --- Basic Pre-transaction Input Validation --- (More detailed validation in
					// helper)
					for (EnumEntryUpdateDefinition updateDef : entryUpdateDefs) {
						if (updateDef.name().isEmpty() && updateDef.value().isEmpty()) {
							throw new IllegalArgumentException(
									"Missing identifier for an entry. Must provide either '" + ARG_NAME + "' or '" + ARG_VALUE + "'.");
						}
						if (updateDef.newName().isEmpty() && updateDef.newValue().isEmpty() && updateDef.newComment().isEmpty()) {
							throw new IllegalArgumentException(
									"No updates specified for an entry. Provide at least '" + ARG_NEW_NAME + "', '" + ARG_NEW_VALUE
											+ "', or '" + ARG_NEW_COMMENT + "'.");
						}
					}
					// --- End of Basic Pre-transaction Input Validation ---

					return new EnumEntryUpdateBatchContext(program, targetEnum, entryUpdateDefs);
				})
				.flatMap(context -> { // .flatMap for transaction
					String transactionName = "Update Enum Entries in " + context.targetEnum().getName();
					String enumPathName = context.targetEnum().getPathName();

					return executeInTransaction(context.program(), transactionName, () -> {
						int localEntriesUpdatedCount = 0;

						for (EnumEntryUpdateDefinition updateDef : context.entryUpdateDefs()) {
							// Call the helper method to process each entry
							// The helper will throw an exception if anything goes wrong, aborting the
							// transaction.
							if (processSingleEnumEntryUpdate(context.targetEnum(), updateDef, enumPathName)) {
								localEntriesUpdatedCount++;
							}
						} // End for loop

						if (localEntriesUpdatedCount > 0) {
							return "Successfully updated " + localEntriesUpdatedCount + " entr(y/ies) in enum '" + enumPathName
									+ "'.";
						} else {
							return "No effective changes applied to enum '" + enumPathName
									+ "'. Entries might have matched desired state or no update fields provided.";
						}
					}); // End executeInTransaction
				}); // End flatMap
	}
}