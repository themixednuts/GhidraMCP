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
import ghidra.program.model.data.DataTypeManager;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Category", mcpName = "create_category", category = ToolCategory.DATATYPES, description = "Creates a new data type category.", mcpDescription = "Creates a new data type category.")
public class GhidraCreateCategoryTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper)
				.description("The file name of the Ghidra tool window to target."), true);
		schemaRoot.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
				.description("Name for the new category (e.g., MyCategoryName)."), true);
		schemaRoot.property(ARG_PATH, JsonSchemaBuilder.string(mapper)
				.description(
						"Optional parent category path for the new category (e.g., /MyParentCategory). If omitted, creates a root category if name is simple, or nested if name contains path separators."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					String categoryName = getRequiredStringArgument(args, ARG_NAME);
					Optional<String> pathOpt = getOptionalStringArgument(args, ARG_PATH);
					CategoryPath parentCategoryPath = pathOpt.map(CategoryPath::new).orElse(CategoryPath.ROOT);
					String transactionName = "Create Category: " + categoryName;

					return executeInTransaction(program, transactionName, () -> {
						DataTypeManager dtm = program.getDataTypeManager();
						return createCategoryInternal(dtm, categoryName, parentCategoryPath);
					});
				});
	}

	private String createCategoryInternal(DataTypeManager dtm, String categoryName, CategoryPath parentPath) {
		// If categoryName itself contains path separators, parentPath is the prefix.
		// If categoryName is simple, it's created under parentPath.
		// DataTypeManager.createCategory handles hierarchical creation.
		CategoryPath newCategoryPath;
		if (categoryName.contains(String.valueOf(CategoryPath.DELIMITER_CHAR))) {
			// If categoryName is like "A/B/C" and parentPath is "/Root"
			// newCategoryPath should be "/Root/A/B/C"
			newCategoryPath = new CategoryPath(parentPath, categoryName);
		} else {
			// If categoryName is "MyCat" and parentPath is "/Root/Sub"
			// newCategoryPath should be "/Root/Sub/MyCat"
			newCategoryPath = parentPath.extend(categoryName);
		}

		if (dtm.getCategory(newCategoryPath) != null) {
			throw new IllegalArgumentException("Category already exists: " + newCategoryPath.getPath());
		}
		ghidra.program.model.data.Category createdCategory = dtm.createCategory(newCategoryPath);
		if (createdCategory == null) {
			// Attempt to re-fetch in case of race condition, though unlikely in transaction
			if (dtm.getCategory(newCategoryPath) == null) {
				throw new RuntimeException("Failed to create category: " + newCategoryPath.getPath());
			}
		}
		return "Category '" + newCategoryPath.getPath() + "' created.";
	}
}