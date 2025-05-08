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
							.orElseThrow(() -> new IllegalArgumentException("Missing required argument: '" + ARG_ENTRIES + "'"));

					if (rawEntryDefs.isEmpty()) {
						throw new IllegalArgumentException("Argument '" + ARG_ENTRIES + "' cannot be empty.");
					}

					List<EnumEntryDefinition> entryDefs = rawEntryDefs.stream()
							.map(rawDef -> new EnumEntryDefinition(
									getRequiredStringArgument(rawDef, ARG_NAME),
									getRequiredLongArgument(rawDef, ARG_VALUE),
									getOptionalStringArgument(rawDef, ARG_COMMENT)))
							.collect(Collectors.toList());

					DataType dt = program.getDataTypeManager().getDataType(enumPathString);

					if (dt == null) {
						throw new IllegalArgumentException("Enum not found at path: " + enumPathString);
					}
					if (!(dt instanceof Enum)) {
						throw new IllegalArgumentException("Data type at path is not an Enum: " + enumPathString);
					}
					Enum targetEnum = (Enum) dt;

					for (EnumEntryDefinition def : entryDefs) {
						if (def.name().isBlank()) {
							throw new IllegalArgumentException("Enum entry name cannot be blank.");
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
						} catch (IllegalArgumentException e) {
							throw new IllegalArgumentException("Error processing an enum entry: " + e.getMessage(), e);
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