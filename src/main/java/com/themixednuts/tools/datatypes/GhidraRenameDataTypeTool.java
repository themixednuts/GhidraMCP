package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Rename Data Type", category = ToolCategory.DATATYPES, description = "Renames an existing data type.", mcpName = "rename_data_type", mcpDescription = "Renames a user-defined data type (struct, enum, etc.).")
public class GhidraRenameDataTypeTool implements IGhidraMcpSpecification {

	private static record RenameContext(
			Program program,
			DataType dataType,
			String newName) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		// Use ARG_DATA_TYPE_PATH for clarity
		schemaRoot.property(ARG_DATA_TYPE_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The current full path of the data type to rename (e.g., /MyCategory/MyType)."));
		schemaRoot.property(ARG_NEW_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The desired new name for the data type (just the name, not the full path)."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_DATA_TYPE_PATH)
				.requiredProperty(ARG_NEW_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> { // .map for sync setup
					String oldPathString = getRequiredStringArgument(args, ARG_DATA_TYPE_PATH);
					String newName = getRequiredStringArgument(args, ARG_NEW_NAME);

					DataType dataType = program.getDataTypeManager().getDataType(oldPathString);

					if (dataType == null) {
						throw new IllegalArgumentException("Data type not found at path: " + oldPathString);
					}

					// Basic validation for new name (e.g., not blank)
					if (newName.isBlank()) {
						throw new IllegalArgumentException("New data type name cannot be blank.");
					}
					// Ghidra's setName will handle more complex validation (invalid chars, etc.)

					return new RenameContext(program, dataType, newName);
				})
				.flatMap(context -> { // .flatMap for transaction
					String oldPath = context.dataType().getPathName(); // Get old path before rename
					return executeInTransaction(context.program(), "Rename Data Type: " + oldPath, () -> {
						context.dataType().setName(context.newName());
						String finalPath = context.dataType().getPathName();
						return "Data type '" + oldPath + "' renamed successfully to: " + finalPath;
					});
				});
	}
}