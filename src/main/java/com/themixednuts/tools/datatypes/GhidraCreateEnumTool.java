package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Enum", mcpName = "create_enum", category = ToolCategory.DATATYPES, description = "Creates a new enum data type.", mcpDescription = "Creates a new enum data type.")
public class GhidraCreateEnumTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper)
				.description("The file name of the Ghidra tool window to target."), true);
		schemaRoot.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
				.description("Name for the new enum (e.g., MyEnum)."), true);
		schemaRoot.property(ARG_PATH, JsonSchemaBuilder.string(mapper)
				.description(
						"Optional category path for the new enum (e.g., /MyCategory). If omitted, uses default/root path."));
		schemaRoot.property(ARG_SIZE, JsonSchemaBuilder.integer(mapper)
				.description("Optional storage size in bytes (1, 2, 4, or 8; defaults to 1)."));
		schemaRoot.property(ARG_COMMENT, JsonSchemaBuilder.string(mapper)
				.description("Optional comment for the new enum."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					String enumName = getRequiredStringArgument(args, ARG_NAME);
					Optional<String> pathOpt = getOptionalStringArgument(args, ARG_PATH);
					CategoryPath categoryPath = pathOpt.map(CategoryPath::new).orElse(CategoryPath.ROOT);
					Optional<Integer> sizeOpt = getOptionalIntArgument(args, ARG_SIZE);
					Optional<String> commentOpt = getOptionalStringArgument(args, ARG_COMMENT);
					String transactionName = "Create Enum: " + enumName;

					return executeInTransaction(program, transactionName, () -> {
						DataTypeManager dtm = program.getDataTypeManager();
						ensureCategoryExists(dtm, categoryPath);
						return createEnumInternal(dtm, enumName, categoryPath, commentOpt, sizeOpt);
					});
				});
	}

	private String createEnumInternal(DataTypeManager dtm, String enumName, CategoryPath categoryPath,
			Optional<String> commentOpt, Optional<Integer> sizeOpt) {
		if (dtm.getDataType(categoryPath, enumName) != null) {
			throw new IllegalArgumentException("Data type already exists: " + categoryPath.getPath()
					+ CategoryPath.DELIMITER_CHAR + enumName);
		}
		int enumSize = sizeOpt.orElse(1); // Default to 1 byte if not specified
		if (enumSize != 1 && enumSize != 2 && enumSize != 4 && enumSize != 8) {
			throw new IllegalArgumentException("Invalid ARG_SIZE for ENUM: Must be 1, 2, 4, or 8. Got: " + enumSize);
		}
		EnumDataType newEnum = new EnumDataType(categoryPath, enumName, enumSize, dtm);
		DataType newDt = dtm.addDataType(newEnum, DataTypeConflictHandler.REPLACE_HANDLER);
		if (newDt == null) {
			throw new RuntimeException("Failed to add enum '" + enumName + "' to data type manager.");
		}
		commentOpt.ifPresent(comment -> newDt.setDescription(comment));
		return "Enum '" + newDt.getPathName() + "' created.";
	}

	private static void ensureCategoryExists(DataTypeManager dtm, CategoryPath categoryPath) {
		if (categoryPath == null || categoryPath.equals(CategoryPath.ROOT)) {
			return;
		}
		if (dtm.getCategory(categoryPath) == null) {
			ghidra.program.model.data.Category created = dtm.createCategory(categoryPath);
			if (created == null) {
				// Attempt to re-fetch in case of race condition
				if (dtm.getCategory(categoryPath) == null) {
					throw new RuntimeException("Failed to create or find category: " + categoryPath.getPath());
				}
			}
		}
	}
}