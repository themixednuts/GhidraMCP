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
						GhidraMcpError error = GhidraMcpError.resourceNotFound()
								.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
								.message("Category not found at path: " + originalPathString)
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"category lookup",
										Map.of(ARG_CATEGORY_PATH, originalPathString),
										Map.of("categoryPath", originalPathString),
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
					if (category.isRoot()) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Cannot rename the root category")
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"root category validation",
										Map.of(ARG_CATEGORY_PATH, originalPathString),
										Map.of("categoryPath", originalPathString, "isRoot", true),
										Map.of("rootCategory", true)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Choose a non-root category",
												"Select a category other than the root for renaming",
												null,
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					if (newName.isBlank()) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("New category name cannot be blank")
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"new name validation",
										Map.of(ARG_NEW_NAME, newName),
										Map.of("newName", newName, "isBlank", true),
										Map.of("nameBlank", true)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Provide a valid name",
												"Enter a non-empty name for the category",
												List.of("\"MyCategory\"", "\"UpdatedCategory\""),
												null)))
								.build();
						throw new GhidraMcpException(error);
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