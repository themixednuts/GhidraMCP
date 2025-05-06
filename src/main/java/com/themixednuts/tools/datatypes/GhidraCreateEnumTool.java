package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Enum", category = ToolCategory.DATATYPES, description = "Creates a new enumeration data type.", mcpName = "create_enum", mcpDescription = "Create a new enum data type, optionally defining initial entries.")
public class GhidraCreateEnumTool implements IGhidraMcpSpecification {

	public static final String ARG_ENTRIES = "entries";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper).description("The name of the program file."));
		schemaRoot.property(ARG_ENUM_PATH, JsonSchemaBuilder.string(mapper)
				.description("Full category path and name for the new enum (e.g., '/MyEnums/StatusCodes')."));
		schemaRoot.property(ARG_SIZE, JsonSchemaBuilder.integer(mapper)
				.description("Size of the enum in bytes. Must be 1, 2, 4, or 8."));

		IObjectSchemaBuilder entrySchema = JsonSchemaBuilder.object(mapper)
				.property(ARG_NAME, JsonSchemaBuilder.string(mapper).description("Name of the enum entry."))
				.property(ARG_VALUE, JsonSchemaBuilder.integer(mapper)
						.description("Value of the enum entry (long)."))
				.requiredProperty(ARG_NAME)
				.requiredProperty(ARG_VALUE);

		schemaRoot.property(ARG_ENTRIES, JsonSchemaBuilder.array(mapper)
				.description("Optional array of initial enum entries.")
				.items(entrySchema));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ENUM_PATH)
				.requiredProperty(ARG_SIZE);

		return schemaRoot.build();
	}

	private static record EnumCreationContext(Program program, CategoryPath categoryPath, String enumName, int enumSize,
			Optional<List<Map<String, Object>>> entries) {
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> { // .map for synchronous setup
					String enumPathStr = getRequiredStringArgument(args, ARG_ENUM_PATH);
					int enumSize = getRequiredIntArgument(args, ARG_SIZE);
					Optional<List<Map<String, Object>>> entriesOpt = getOptionalListArgument(args, ARG_ENTRIES);

					if (enumSize != 1 && enumSize != 2 && enumSize != 4 && enumSize != 8) {
						throw new IllegalArgumentException("Invalid enumSize: Must be 1, 2, 4, or 8.");
					}

					CategoryPath fullPath = new CategoryPath(enumPathStr); // Create once
					CategoryPath catPath = fullPath.getParent();
					String enumName = fullPath.getName();

					if (enumName.isBlank()) {
						throw new IllegalArgumentException("Enum name cannot be blank in path: " + enumPathStr);
					}

					if (catPath == null) { // Handle root category
						catPath = CategoryPath.ROOT;
					}

					// Don't check existence here
					return new EnumCreationContext(program, catPath, enumName, enumSize, entriesOpt);
				})
				.flatMap(context -> { // .flatMap for transaction
					return executeInTransaction(context.program(), "Create Enum " + context.enumName(), () -> {
						DataTypeManager dtm = context.program().getDataTypeManager();

						// Check existence *inside* transaction
						if (dtm.getDataType(context.categoryPath(), context.enumName()) != null) {
							throw new IllegalArgumentException(
									"Enum already exists (checked in transaction): " + context.categoryPath().getPath() + "/"
											+ context.enumName());
						}

						// Ensure category exists *inside* transaction
						Category category = dtm.createCategory(context.categoryPath());
						if (category == null) {
							category = dtm.getCategory(context.categoryPath()); // Retry get if create failed
							if (category == null) {
								throw new RuntimeException(
										"Failed to create or find category in transaction: " + context.categoryPath());
							}
						}

						// Create the enum using the correct category path
						EnumDataType newEnum = new EnumDataType(category.getCategoryPath(), context.enumName(), context.enumSize(),
								dtm);

						// Add initial entries if present
						if (context.entries().isPresent()) {
							for (Map<String, Object> entryMap : context.entries().get()) {
								String entryName = getRequiredStringArgument(entryMap, ARG_NAME);
								long entryValue = getRequiredLongArgument(entryMap, ARG_VALUE);
								newEnum.add(entryName, entryValue);
							}
						}

						// Add the new enum to the manager using default conflict handler
						EnumDataType resolvedEnum = (EnumDataType) dtm.addDataType(newEnum,
								DataTypeConflictHandler.DEFAULT_HANDLER);
						if (resolvedEnum == null) {
							// This case might indicate a name collision that wasn't caught or other DTM
							// issue
							throw new RuntimeException("Failed to add enum to data type manager: " + newEnum.getPathName());
						}

						return "Enum created successfully: " + resolvedEnum.getPathName();
					});
				});
	}
}