package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Rename Data Type", category = ToolCategory.DATATYPES, description = "Renames an existing data type and/or moves it to a new category.", mcpName = "rename_data_type", mcpDescription = "Sets the new name and/or category for a user-defined data type (struct, enum, etc.).")
public class GhidraRenameDataTypeTool implements IGhidraMcpSpecification {

	public static final String ARG_NEW_DATATYPE_PATH = "newDataTypePath";

	private static record RenameContext(
			Program program,
			DataType dataType,
			CategoryPath newCategoryPath,
			String newSimpleName) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_DATA_TYPE_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The current full path of the data type to rename/move (e.g., /MyCategory/MyType).")
						.pattern("^/.*"));
		schemaRoot.property(ARG_NEW_DATATYPE_PATH,
				JsonSchemaBuilder.string(mapper)
						.description(
								"The desired new full path for the data type (e.g., /NewCategory/NewName). This will set both the category and the simple name.")
						.pattern("^/.*"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_DATA_TYPE_PATH)
				.requiredProperty(ARG_NEW_DATATYPE_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> { // .map for sync setup
					String oldPathString = getRequiredStringArgument(args, ARG_DATA_TYPE_PATH);
					String newFullDataTypePath = getRequiredStringArgument(args, ARG_NEW_DATATYPE_PATH);

					DataType dataType = program.getDataTypeManager().getDataType(oldPathString);

					if (dataType == null) {
						throw new IllegalArgumentException("Data type not found at path: " + oldPathString);
					}

					CategoryPath newTargetFullPath = new CategoryPath(newFullDataTypePath);
					CategoryPath newTargetCategoryPath = newTargetFullPath.getParent();
					String newTargetSimpleName = newTargetFullPath.getName();

					if (newTargetSimpleName.isBlank()) {
						throw new IllegalArgumentException(
								"New data type name (derived from path) cannot be blank: " + newFullDataTypePath);
					}

					if (newTargetCategoryPath == null) {
						newTargetCategoryPath = CategoryPath.ROOT;
					}

					return new RenameContext(program, dataType, newTargetCategoryPath, newTargetSimpleName);
				})
				.flatMap(context -> { // .flatMap for transaction
					String oldPath = context.dataType().getPathName(); // Get old path before rename
					return executeInTransaction(context.program(), "Set Data Type Path: " + oldPath, () -> {
						context.dataType().setNameAndCategory(context.newCategoryPath(), context.newSimpleName());
						String finalPath = context.dataType().getPathName(); // Get path after rename/move
						return "Data type '" + oldPath + "' path set successfully to: " + finalPath;
					});
				});
	}
}