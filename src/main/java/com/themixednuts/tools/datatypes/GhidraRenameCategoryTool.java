package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Rename Category", category = ToolCategory.DATATYPES, description = "Renames an existing category path.", mcpName = "rename_category", mcpDescription = "Renames a category (folder) in the Data Type Manager.")
public class GhidraRenameCategoryTool implements IGhidraMcpSpecification {

	private static record RenameContext(
			Program program,
			Category category,
			String newName) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_CATEGORY_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The current full path of the category to rename (e.g., '/OldCategory/SubCategory')."));
		schemaRoot.property(ARG_NEW_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The desired new name for the category (just the final part of the path)."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_CATEGORY_PATH)
				.requiredProperty(ARG_NEW_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					String originalPathString = getRequiredStringArgument(args, ARG_CATEGORY_PATH);
					String newName = getRequiredStringArgument(args, ARG_NEW_NAME);
					Category category = program.getDataTypeManager().getCategory(new CategoryPath(originalPathString));

					if (category == null) {
						throw new IllegalArgumentException("Category not found at path: " + originalPathString);
					}
					if (category.isRoot()) {
						throw new IllegalArgumentException("Cannot rename the root category.");
					}

					if (newName.isBlank()) {
						throw new IllegalArgumentException("New category name cannot be blank.");
					}

					return new RenameContext(program, category, newName);
				})
				.flatMap(context -> {
					String oldPath = context.category().getCategoryPath().getPath();
					return executeInTransaction(context.program(), "Rename Category: " + oldPath, () -> {
						context.category().setName(context.newName());
						String finalPath = context.category().getCategoryPath().getPath();
						return "Category '" + oldPath + "' renamed successfully to: " + finalPath;
					});
				});
	}
}