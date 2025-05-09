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
import ghidra.program.model.data.StructureDataType;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Struct", mcpName = "create_struct", category = ToolCategory.DATATYPES, description = "Creates a new struct data type.", mcpDescription = "Creates a new struct data type.")
public class GhidraCreateStructTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper)
				.description("The file name of the Ghidra tool window to target."), true);
		schemaRoot.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
				.description("Name for the new struct (e.g., MyStruct)."), true);
		schemaRoot.property(ARG_PATH, JsonSchemaBuilder.string(mapper)
				.description(
						"Optional category path for the new struct (e.g., /MyCategory). If omitted, uses default/root path."));
		schemaRoot.property(ARG_SIZE, JsonSchemaBuilder.integer(mapper)
				.description("Optional initial size for the struct (0 for default/growable)."));
		schemaRoot.property(ARG_COMMENT, JsonSchemaBuilder.string(mapper)
				.description("Optional comment for the new struct."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					String structName = getRequiredStringArgument(args, ARG_NAME);
					Optional<String> pathOpt = getOptionalStringArgument(args, ARG_PATH);
					CategoryPath categoryPath = pathOpt.map(CategoryPath::new).orElse(CategoryPath.ROOT);
					Optional<Integer> sizeOpt = getOptionalIntArgument(args, ARG_SIZE);
					Optional<String> commentOpt = getOptionalStringArgument(args, ARG_COMMENT);
					String transactionName = "Create Struct: " + structName;

					return executeInTransaction(program, transactionName, () -> {
						DataTypeManager dtm = program.getDataTypeManager();
						ensureCategoryExists(dtm, categoryPath);
						return createStructInternal(dtm, structName, categoryPath, commentOpt, sizeOpt);
					});
				});
	}

	private String createStructInternal(DataTypeManager dtm, String structName, CategoryPath categoryPath,
			Optional<String> commentOpt, Optional<Integer> sizeOpt) {
		if (dtm.getDataType(categoryPath, structName) != null) {
			throw new IllegalArgumentException("Data type already exists: " + categoryPath.getPath()
					+ CategoryPath.DELIMITER_CHAR + structName);
		}
		StructureDataType newStruct = new StructureDataType(categoryPath, structName,
				sizeOpt.orElse(0), dtm);
		DataType newDt = dtm.addDataType(newStruct, DataTypeConflictHandler.REPLACE_HANDLER);
		if (newDt == null) {
			throw new RuntimeException("Failed to add struct '" + structName + "' to data type manager.");
		}
		commentOpt.ifPresent(comment -> newDt.setDescription(comment));
		return "Struct '" + newDt.getPathName() + "' created.";
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