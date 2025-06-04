package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
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

	/**
	 * Get available entry names for error suggestions
	 */
	private List<String> getAvailableEntryNames(Enum targetEnum) {
		return java.util.Arrays.stream(targetEnum.getNames())
				.limit(20) // Limit suggestions
				.collect(Collectors.toList());
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
				List<String> availableNames = getAvailableEntryNames(targetEnum);
				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
						.message("Entry with name '" + currentName + "' not found in enum '" + enumPathStringForError + "'")
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"enum entry lookup by name",
								Map.of(ARG_NAME, currentName, ARG_ENUM_PATH, enumPathStringForError),
								Map.of("entryName", currentName, "enumPath", enumPathStringForError),
								Map.of("entryExists", false, "availableEntries", availableNames)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Use an existing entry name",
										"Choose from the available entry names",
										availableNames.stream().map(name -> "\"" + name + "\"").collect(Collectors.toList()),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}
			currentValue = targetEnum.getValue(currentName);
			currentComment = targetEnum.getComment(currentName);
			if (updateDef.value().isPresent() && updateDef.value().get() != currentValue) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
						.message("Provided value " + updateDef.value().get() + " for entry '" + currentName
								+ "' does not match actual value " + currentValue)
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"entry value validation",
								Map.of(ARG_NAME, currentName, ARG_VALUE, updateDef.value().get()),
								Map.of("entryName", currentName, "providedValue", updateDef.value().get(), "actualValue", currentValue),
								Map.of("valuesMatch", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Use the correct value",
										"Update the value to match the entry's actual value",
										List.of("\"" + ARG_VALUE + "\": " + currentValue),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}
		} else if (updateDef.value().isPresent()) {
			currentValue = updateDef.value().get();
			currentName = targetEnum.getName(currentValue);
			if (currentName == null) {
				List<String> availableNames = getAvailableEntryNames(targetEnum);
				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
						.message("Entry with value " + currentValue + " not found in enum '" + enumPathStringForError + "'")
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"enum entry lookup by value",
								Map.of(ARG_VALUE, currentValue, ARG_ENUM_PATH, enumPathStringForError),
								Map.of("entryValue", currentValue, "enumPath", enumPathStringForError),
								Map.of("entryExists", false, "availableEntries", availableNames)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Use an existing entry",
										"Choose from the available entry names and their values",
										availableNames,
										null)))
						.build();
				throw new GhidraMcpException(error);
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
							.orElseThrow(() -> {
								GhidraMcpError error = GhidraMcpError.validation()
										.errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
										.message("Missing required argument: '" + ARG_ENTRY_UPDATES + "'")
										.context(new GhidraMcpError.ErrorContext(
												getMcpName(),
												"entry updates validation",
												args,
												Map.of("entryUpdatesProvided", false),
												Map.of("requiredArgument", ARG_ENTRY_UPDATES)))
										.suggestions(List.of(
												new GhidraMcpError.ErrorSuggestion(
														GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
														"Provide entry updates",
														"Include at least one entry update in the array",
														List.of("\"" + ARG_ENTRY_UPDATES + "\": [{ \"name\": \"ENTRY_NAME\", \"newValue\": 123 }]"),
														null)))
										.build();
								return new GhidraMcpException(error);
							});

					if (rawEntryUpdates.isEmpty()) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Argument '" + ARG_ENTRY_UPDATES + "' cannot be empty")
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"entry updates validation",
										Map.of(ARG_ENTRY_UPDATES, rawEntryUpdates),
										Map.of("entryUpdatesSize", 0),
										Map.of("isEmpty", true, "minimumRequired", 1)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Provide at least one entry update",
												"Include at least one entry update definition in the array",
												List.of("{ \"name\": \"ENTRY_NAME\", \"newValue\": 123 }",
														"{ \"value\": 456, \"newName\": \"NEW_NAME\" }"),
												null)))
								.build();
						throw new GhidraMcpException(error);
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
						GhidraMcpError error = GhidraMcpError.resourceNotFound()
								.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
								.message("Enum not found at path: " + enumPathString)
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"enum lookup",
										Map.of(ARG_ENUM_PATH, enumPathString),
										Map.of("enumPath", enumPathString),
										Map.of("enumExists", false)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"List available data types",
												"Check what enums exist",
												null,
												List.of(getMcpName(GhidraListDataTypesTool.class)))))
								.build();
						throw new GhidraMcpException(error);
					}
					if (!(dt instanceof Enum)) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Data type at path is not an Enum: " + enumPathString)
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"data type validation",
										Map.of(ARG_ENUM_PATH, enumPathString),
										Map.of("enumPath", enumPathString, "actualDataType", dt.getDisplayName()),
										Map.of("isEnum", false, "actualTypeName", dt.getClass().getSimpleName())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use an enum data type",
												"Ensure the path points to an enum, not " + dt.getClass().getSimpleName(),
												null,
												null)))
								.build();
						throw new GhidraMcpException(error);
					}
					Enum targetEnum = (Enum) dt;

					// --- Basic Pre-transaction Input Validation --- (More detailed validation in
					// helper)
					for (EnumEntryUpdateDefinition updateDef : entryUpdateDefs) {
						if (updateDef.name().isEmpty() && updateDef.value().isEmpty()) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
									.message(
											"Missing identifier for an entry. Must provide either '" + ARG_NAME + "' or '" + ARG_VALUE + "'")
									.context(new GhidraMcpError.ErrorContext(
											getMcpName(),
											"entry identifier validation",
											Map.of("entryDefinition", updateDef),
											Map.of("nameProvided", false, "valueProvided", false),
											Map.of("identifiersProvided", 0, "minimumRequired", 1)))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Provide an identifier",
													"Include either name or value to identify the entry",
													List.of("\"" + ARG_NAME + "\": \"ENTRY_NAME\"", "\"" + ARG_VALUE + "\": 123"),
													null)))
									.build();
							throw new GhidraMcpException(error);
						}
						if (updateDef.newName().isEmpty() && updateDef.newValue().isEmpty() && updateDef.newComment().isEmpty()) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
									.message("No updates specified for an entry. Provide at least '" + ARG_NEW_NAME + "', '"
											+ ARG_NEW_VALUE + "', or '" + ARG_NEW_COMMENT + "'")
									.context(new GhidraMcpError.ErrorContext(
											getMcpName(),
											"entry update validation",
											Map.of("entryDefinition", updateDef),
											Map.of("newNameProvided", false, "newValueProvided", false, "newCommentProvided", false),
											Map.of("updateFieldsProvided", 0, "minimumRequired", 1)))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Provide at least one update",
													"Include at least one field to update",
													List.of("\"" + ARG_NEW_NAME + "\": \"NEW_NAME\"", "\"" + ARG_NEW_VALUE + "\": 456",
															"\"" + ARG_NEW_COMMENT + "\": \"New comment\""),
													null)))
									.build();
							throw new GhidraMcpException(error);
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