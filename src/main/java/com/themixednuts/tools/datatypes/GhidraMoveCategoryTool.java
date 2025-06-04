package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
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
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
						.message("Cannot move the root category")
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"root category validation",
								Map.of(ARG_CATEGORY_PATH, categoryToMovePathString),
								Map.of("categoryPath", categoryToMovePathString, "isRoot", true),
								Map.of("rootCategory", true)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Choose a non-root category",
										"Select a category other than the root for moving",
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			DataTypeManager dtm = program.getDataTypeManager();
			Category categoryToMove = dtm.getCategory(categoryToMovePath);
			if (categoryToMove == null) {
				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
						.message("Category to move not found: " + categoryToMovePathString)
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"source category lookup",
								Map.of(ARG_CATEGORY_PATH, categoryToMovePathString),
								Map.of("categoryPath", categoryToMovePathString),
								Map.of("categoryExists", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"List available categories",
										"Check what categories exist",
										null,
										List.of(getMcpName(GhidraListCategoriesTool.class)))))
						.build();
				throw new GhidraMcpException(error);
			}

			Category newParentCategory = dtm.getCategory(newParentPath);
			if (newParentCategory == null) {
				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
						.message("New parent category not found: " + newParentPathString)
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"destination category lookup",
								Map.of(ARG_NEW_PARENT_CATEGORY_PATH, newParentPathString),
								Map.of("parentCategoryPath", newParentPathString),
								Map.of("parentCategoryExists", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"List available categories",
										"Check what categories exist for the parent",
										null,
										List.of(getMcpName(GhidraListCategoriesTool.class)))))
						.build();
				throw new GhidraMcpException(error);
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