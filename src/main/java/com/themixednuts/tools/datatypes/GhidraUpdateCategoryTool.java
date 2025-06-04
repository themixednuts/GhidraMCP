package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Update Category", category = ToolCategory.DATATYPES, description = "Updates properties of an existing data type category.", mcpName = "update_category", mcpDescription = "Updates the name of an existing data type category.")
public class GhidraUpdateCategoryTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target."),
				true);
		schemaRoot.property(ARG_CATEGORY_PATH, // Using ARG_CATEGORY_PATH from IGhidraMcpSpecification
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the category to update (e.g., /MyTypes/SubCategory)."),
				true);
		schemaRoot.property(ARG_NEW_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The new name for the category."),
				true); // New name is required for an update operation

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_CATEGORY_PATH);
		schemaRoot.requiredProperty(ARG_NEW_NAME);

		return schemaRoot.build();
	}

	private static record CategoryUpdateContext(
			Program program,
			Category categoryToUpdate,
			String newName,
			String originalPath) {
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			final String categoryPathString = getRequiredStringArgument(args, ARG_CATEGORY_PATH);
			final String newName = getRequiredStringArgument(args, ARG_NEW_NAME);

			DataTypeManager dtm = program.getDataTypeManager();
			Category category = dtm.getCategory(new CategoryPath(categoryPathString));

			if (category == null) {
				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
						.message("Category not found at path: " + categoryPathString)
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"category lookup",
								Map.of(ARG_CATEGORY_PATH, categoryPathString),
								Map.of("categoryPath", categoryPathString),
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

			return new CategoryUpdateContext(program, category, newName, categoryPathString);

		}).flatMap(context -> {
			return executeInTransaction(context.program(), "MCP - Update Category: " + context.originalPath(), () -> {
				DataTypeManager dtmInTx = context.program().getDataTypeManager();
				Category categoryInTx = dtmInTx.getCategory(new CategoryPath(context.originalPath()));
				if (categoryInTx == null) {
					throw new IllegalStateException("Category disappeared before transaction: " + context.originalPath());
				}

				try {
					categoryInTx.setName(context.newName());
				} catch (InvalidNameException | ghidra.util.exception.DuplicateNameException e) {
					GhidraMcpError error = GhidraMcpError.validation()
							.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
							.message("Failed to set new name for category: " + e.getMessage())
							.context(new GhidraMcpError.ErrorContext(
									getMcpName(),
									"category name update",
									Map.of(ARG_NEW_NAME, context.newName(), ARG_CATEGORY_PATH, context.originalPath()),
									Map.of("newName", context.newName(), "categoryPath", context.originalPath()),
									Map.of("nameUpdateFailed", true, "error", e.getMessage())))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
											"Use a valid category name",
											"Ensure the new name is valid and doesn't conflict",
											null,
											null)))
							.build();
					throw new GhidraMcpException(error);
				}

				// If category path changes due to rename, the original path might be misleading
				// for the message
				// But the operation is on the object found by originalPath
				return "Category '" + context.originalPath() + "' renamed to '" + context.newName() + "' successfully.";
			});
		});
	}
}