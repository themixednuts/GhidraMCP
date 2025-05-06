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
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Move Category", category = ToolCategory.DATATYPES, description = "Moves an existing category to a new parent category.", mcpName = "move_category", mcpDescription = "Moves a category (folder) and its contents to a different location in the Data Type Manager.")
public class GhidraMoveCategoryTool implements IGhidraMcpSpecification {

	public static final String ARG_NEW_PARENT_CATEGORY_PATH = "newParentCategoryPath";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_CATEGORY_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The current full path of the category to move (e.g., '/SourceCategory/MyCategory')."));
		schemaRoot.property(ARG_NEW_PARENT_CATEGORY_PATH,
				JsonSchemaBuilder.string(mapper)
						.description(
								"The full path of the destination parent category (e.g., '/DestinationCategory'). Use '/' for the root."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_CATEGORY_PATH)
				.requiredProperty(ARG_NEW_PARENT_CATEGORY_PATH);

		return schemaRoot.build();
	}

	// Nested record for type-safe context passing
	private static record MoveCategoryContext(
			Program program,
			Category categoryToMove,
			Category newParentCategory) {
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) { // Ensure
																																																								// signature
		return getProgram(args, tool).map(program -> { // .map for sync setup
			String categoryToMovePathString = getRequiredStringArgument(args, ARG_CATEGORY_PATH);
			String newParentPathString = getRequiredStringArgument(args, ARG_NEW_PARENT_CATEGORY_PATH);

			final CategoryPath categoryToMovePath = new CategoryPath(categoryToMovePathString);
			final CategoryPath newParentPath = new CategoryPath(newParentPathString);

			if (categoryToMovePath.isRoot()) {
				throw new IllegalArgumentException("Cannot move the root category.");
			}

			DataTypeManager dtm = program.getDataTypeManager();
			Category categoryToMove = dtm.getCategory(categoryToMovePath);
			if (categoryToMove == null) {
				throw new IllegalArgumentException("Category to move not found: " + categoryToMovePathString);
			}

			Category newParentCategory = dtm.getCategory(newParentPath);
			if (newParentCategory == null) {
				throw new IllegalArgumentException("New parent category not found: " + newParentPathString);
			}

			// Return type-safe context
			return new MoveCategoryContext(program, categoryToMove, newParentCategory);

		}).flatMap(context -> { // .flatMap for transaction
			String originalPath = context.categoryToMove().getCategoryPath().getPath();

			return executeInTransaction(context.program(), "MCP - Move Category: " + originalPath, () -> {
				// Use context fields. Pass null for monitor as progress isn't critical here.
				context.newParentCategory().moveCategory(context.categoryToMove(), null);
				String finalPath = context.categoryToMove().getCategoryPath().getPath();
				return "Category '" + originalPath + "' moved successfully to: " + finalPath;
			});
		});
	}
}