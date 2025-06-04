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

@GhidraMcpTool(name = "Create Enum Entries", mcpName = "create_enum_entries", category = ToolCategory.DATATYPES, description = "Adds one or more new entries (name/value pairs) to an existing enum data type.", mcpDescription = "Adds one or more new entries (name/value pairs) to an existing enum data type.")
public class GhidraCreateEnumEntryTool implements IGhidraMcpSpecification {

	// Argument for the array of entries
	public static final String ARG_ENTRIES = "entries";

	private static record EnumEntryDefinition(
			String name,
			long value,
			Optional<String> comment) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		// Schema for a single entry definition
		IObjectSchemaBuilder entrySchema = JsonSchemaBuilder.object(mapper)
				.description("Definition of a single enum entry to add.")
				.property(ARG_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("Name for the new entry."),
						true)
				.property(ARG_VALUE,
						JsonSchemaBuilder.integer(mapper)
								.description("Value for the new entry."),
						true) // Use integer, Ghidra handles long internally
				.property(ARG_COMMENT,
						JsonSchemaBuilder.string(mapper)
								.description("Optional comment for the new entry."))
				.requiredProperty(ARG_NAME)
				.requiredProperty(ARG_VALUE);

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));
		schemaRoot.property(ARG_ENUM_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the enum to modify (e.g., /MyCategory/MyEnum)"));
		// Add the array property
		schemaRoot.property(ARG_ENTRIES,
				JsonSchemaBuilder.array(mapper)
						.description("An array of entry definitions to add to the enum.")
						.items(entrySchema)
						.minItems(1)); // Require at least one entry

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ENUM_PATH)
				.requiredProperty(ARG_ENTRIES);

		return schemaRoot.build();
	}

	private static record EnumEntryBatchContext(
			Program program,
			Enum targetEnum,
			List<EnumEntryDefinition> entryDefs) {
	}

	private void processSingleEnumEntryCreation(Enum targetEnum, EnumEntryDefinition entryDef) {
		targetEnum.add(entryDef.name(), entryDef.value(), entryDef.comment().orElse(null));
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					String enumPathString = getRequiredStringArgument(args, ARG_ENUM_PATH);
					List<Map<String, Object>> rawEntryDefs = getOptionalListArgument(args, ARG_ENTRIES)
							.orElse(null);

					if (rawEntryDefs == null) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
								.message("Missing required argument: '" + ARG_ENTRIES + "'")
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"argument validation",
										args,
										Map.of(),
										Map.of("requiredArgument", ARG_ENTRIES, "provided", false)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Provide enum entries",
												"Include the entries array with at least one entry definition",
												List.of("\"" + ARG_ENTRIES + "\": [{\"" + ARG_NAME + "\": \"ENTRY_NAME\", \"" + ARG_VALUE
														+ "\": 1}]"),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					if (rawEntryDefs.isEmpty()) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Argument '" + ARG_ENTRIES + "' cannot be empty")
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"argument validation",
										args,
										Map.of(ARG_ENTRIES, rawEntryDefs),
										Map.of("arraySize", 0, "minimumRequired", 1)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Add enum entry definitions",
												"Provide at least one enum entry in the array",
												List.of("\"" + ARG_ENTRIES + "\": [{\"" + ARG_NAME + "\": \"ENTRY_NAME\", \"" + ARG_VALUE
														+ "\": 1}]"),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					List<EnumEntryDefinition> entryDefs = rawEntryDefs.stream()
							.map(rawDef -> new EnumEntryDefinition(
									getRequiredStringArgument(rawDef, ARG_NAME),
									getRequiredLongArgument(rawDef, ARG_VALUE),
									getOptionalStringArgument(rawDef, ARG_COMMENT)))
							.collect(Collectors.toList());

					DataType dt = program.getDataTypeManager().getDataType(enumPathString);

					if (dt == null) {
						GhidraMcpError error = GhidraMcpError.resourceNotFound()
								.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
								.message("Enum not found at path: " + enumPathString)
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"enum lookup",
										args,
										Map.of(ARG_ENUM_PATH, enumPathString),
										Map.of("searchedPath", enumPathString, "dataTypeExists", false)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"Verify the enum path",
												"Check if the enum exists at the specified path",
												null,
												List.of(getMcpName(GhidraListDataTypesTool.class),
														getMcpName(GhidraGetDataTypeTool.class))),
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Check the path format",
												"Ensure the path follows the correct format",
												List.of("/MyCategory/MyEnum", "/BuiltInTypes/SomeEnum"),
												null)))
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
										args,
										Map.of(ARG_ENUM_PATH, enumPathString, "actualDataType", dt.getClass().getSimpleName()),
										Map.of("expectedType", "Enum", "actualType", dt.getClass().getSimpleName(), "dataTypeName",
												dt.getName())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.USE_DIFFERENT_TOOL,
												"Use the appropriate tool for this data type",
												"This data type requires a different creation operation",
												null,
												List.of(getMcpName(GhidraCreateStructMemberTool.class),
														getMcpName(GhidraCreateUnionMemberTool.class))),
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"Verify the data type details",
												"Check the actual type of the data type at this path",
												null,
												List.of(getMcpName(GhidraGetDataTypeTool.class)))))
								.build();
						throw new GhidraMcpException(error);
					}

					Enum targetEnum = (Enum) dt;

					for (EnumEntryDefinition def : entryDefs) {
						if (def.name().isBlank()) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
									.message("Enum entry name cannot be blank")
									.context(new GhidraMcpError.ErrorContext(
											getMcpName(),
											"entry name validation",
											args,
											Map.of(ARG_NAME, def.name(), ARG_VALUE, def.value()),
											Map.of("entryName", def.name(), "nameIsBlank", true)))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Provide a valid entry name",
													"Entry names must contain at least one non-whitespace character",
													List.of("\"" + ARG_NAME + "\": \"VALID_ENTRY_NAME\"", "\"" + ARG_NAME + "\": \"OPTION_A\""),
													null)))
									.build();
							throw new GhidraMcpException(error);
						}
					}

					return new EnumEntryBatchContext(program, targetEnum, entryDefs);
				})
				.flatMap(context -> {
					String transactionName = "Add Enum Entries to " + context.targetEnum().getName();
					String enumPathName = context.targetEnum().getPathName();

					return executeInTransaction(context.program(), transactionName, () -> {
						int localEntriesAddedCount = 0;
						try {
							for (EnumEntryDefinition entryDef : context.entryDefs()) {
								processSingleEnumEntryCreation(context.targetEnum(), entryDef);
								localEntriesAddedCount++;
							}
							return localEntriesAddedCount;
						} catch (GhidraMcpException e) {
							throw e; // Re-throw structured errors as-is
						} catch (Exception e) {
							throw new RuntimeException("Unexpected error processing an enum entry: " + e.getMessage(), e);
						}
					})
							.map(count -> {
								int addedCount = (Integer) count;
								return "Added " + addedCount + " entr(y/ies) to enum '" + enumPathName + "'.";
							});
				});
	}
}