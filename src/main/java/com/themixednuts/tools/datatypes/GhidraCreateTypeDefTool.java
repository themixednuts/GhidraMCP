package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create TypeDef", category = ToolCategory.DATATYPES, description = "Creates a new typedef data type.", mcpName = "create_typedef", mcpDescription = "Defines a new typedef based on an existing data type.")
public class GhidraCreateTypeDefTool implements IGhidraMcpSpecification {

	private static record TypedefContext(
			Program program,
			CategoryPath categoryPath,
			String typedefName,
			DataType underlyingDataType,
			Optional<String> descriptionOpt,
			String originalPath) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property(ARG_TYPEDEF_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path for the new typedef (e.g., /MyTypes/MyIntPtr)"));

		schemaRoot.property(ARG_DATA_TYPE_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("Full path or name of the data type to alias (e.g., 'int *', '/MyStruct')."));

		schemaRoot.property(ARG_COMMENT,
				JsonSchemaBuilder.string(mapper)
						.description("Optional description for the typedef."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_TYPEDEF_PATH)
				.requiredProperty(ARG_DATA_TYPE_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> { // .map for synchronous setup and validation
					String typedefPathString = getRequiredStringArgument(args, ARG_TYPEDEF_PATH);
					String underlyingTypePath = getRequiredStringArgument(args, ARG_DATA_TYPE_PATH);
					Optional<String> descriptionOpt = getOptionalStringArgument(args, ARG_COMMENT);

					// Parse path
					CategoryPath fullPath = new CategoryPath(typedefPathString);
					CategoryPath categoryPath = fullPath.getParent();
					String typedefName = fullPath.getName();

					if (typedefName.isBlank()) {
						throw new IllegalArgumentException("Invalid typedef path: Name cannot be blank.");
					}
					if (categoryPath == null) { // Ensure ROOT if parent is null
						categoryPath = CategoryPath.ROOT;
					}

					DataType underlyingDt = program.getDataTypeManager().getDataType(underlyingTypePath);
					if (underlyingDt == null) {
						throw new IllegalArgumentException("Underlying data type not found: " + underlyingTypePath);
					}

					// Return context for transaction
					return new TypedefContext(program, categoryPath, typedefName, underlyingDt, descriptionOpt,
							typedefPathString);

				})
				.flatMap(context -> { // .flatMap for transaction
					return executeInTransaction(context.program(), "Create Typedef " + context.typedefName(), () -> {
						DataTypeManager dtm = context.program().getDataTypeManager();

						// Check existence *inside* transaction
						if (dtm.getDataType(context.categoryPath(), context.typedefName()) != null) {
							throw new IllegalArgumentException(
									"Typedef already exists (checked in transaction): " + context.originalPath());
						}

						// Ensure category exists *inside* transaction
						Category category = dtm.createCategory(context.categoryPath());
						if (category == null) {
							category = dtm.getCategory(context.categoryPath()); // Try getting if create failed
							if (category == null) {
								throw new RuntimeException(
										"Failed to create or find category in transaction: " + context.categoryPath());
							}
						}

						// Create the new Typedef using the category fetched/created inside the
						// transaction
						TypeDef newTypeDef = new TypedefDataType(category.getCategoryPath(), context.typedefName(),
								context.underlyingDataType(), dtm);

						// Set optional description
						context.descriptionOpt().ifPresent(newTypeDef::setDescription);

						// Add the new typedef to the manager
						DataType addedType = dtm.addDataType(newTypeDef, DataTypeConflictHandler.DEFAULT_HANDLER);

						if (addedType instanceof TypeDef) {
							return "Typedef '" + context.originalPath() + "' created successfully.";
						} else {
							throw new RuntimeException(
									"Failed to add typedef '" + context.originalPath() + "' after creation (unexpected conflict?).");
						}
					}); // End executeInTransaction
				}); // End flatMap
	}
}