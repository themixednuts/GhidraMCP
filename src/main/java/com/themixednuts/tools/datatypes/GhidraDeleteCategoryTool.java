package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Delete Category", mcpName = "delete_category", category = ToolCategory.DATATYPES, description = "Deletes an existing empty category.", mcpDescription = "Delete an empty data type category from a Ghidra program. Only categories without any data types or subcategories can be removed.")
public class GhidraDeleteCategoryTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target."),
				true);

		schemaRoot.property(ARG_PATH, JsonSchemaBuilder.string(mapper)
				.description("The full path of the empty category to delete (e.g., /MyProject/MyEmptyCategory)."),
				true);

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					String pathString = getRequiredStringArgument(args, ARG_PATH);
					GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex,
							this.getClass().getAnnotation(GhidraMcpTool.class).mcpName());

					String transactionName = "Delete Category: " + pathString;

					return executeInTransaction(program, transactionName, () -> {
						DataTypeManager dtm = program.getDataTypeManager();
						return deleteCategoryAtPath(dtm, pathString, monitor);
					});
				});
	}

	private String deleteCategoryAtPath(DataTypeManager dtm, String pathString, GhidraMcpTaskMonitor monitor) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		CategoryPath categoryPathToDelete = new CategoryPath(pathString);
		Category catToDelete = dtm.getCategory(categoryPathToDelete);

		if (catToDelete == null) {
			GhidraMcpError error = GhidraMcpError.resourceNotFound()
					.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
					.message("Category not found at path: " + pathString)
					.context(new GhidraMcpError.ErrorContext(
							annotation.mcpName(),
							"category lookup",
							Map.of(ARG_PATH, pathString),
							Map.of("categoryPath", pathString),
							Map.of("categoryExists", false)))
					.suggestions(List.of(
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
									"List available categories",
									"Check what categories exist in the data type manager",
									null,
									List.of(getMcpName(GhidraListCategoriesTool.class)))))
					.build();
			throw new GhidraMcpException(error);
		}

		if (categoryPathToDelete.isRoot()) {
			GhidraMcpError error = GhidraMcpError.validation()
					.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
					.message("Cannot delete the root category ('/') using this tool.")
					.context(new GhidraMcpError.ErrorContext(
							annotation.mcpName(),
							"category validation",
							Map.of(ARG_PATH, pathString),
							Map.of("isRootCategory", true),
							Map.of("providedPath", pathString, "isRoot", true)))
					.suggestions(List.of(
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
									"Use a non-root category path",
									"Provide a specific category path to delete",
									List.of("/MyCategory", "/UserTypes/MyStruct"),
									null)))
					.build();
			throw new GhidraMcpException(error);
		}

		CategoryPath parentPath = categoryPathToDelete.getParent();
		if (parentPath == null) {
			// This case should ideally not be reachable for a non-root path fetched via
			// dtm.getCategory
			throw new IllegalStateException("Could not determine parent path for non-root category: " + pathString);
		}

		Category parentCategory = dtm.getCategory(parentPath);
		if (parentCategory == null) {
			// Should also be unlikely if catToDelete was found, implies concurrent delete
			throw new IllegalStateException(
					"Parent category '" + parentPath.getPath() + "' not found for '" + pathString + "'");
		}

		boolean removed = parentCategory.removeCategory(categoryPathToDelete.getName(), monitor);
		if (removed) {
			return "Category '" + pathString + "' deleted successfully.";
		} else {
			// Category might not be empty, or monitor cancelled, or concurrent modification
			throw new RuntimeException("Failed to delete Category '" + pathString
					+ "'. It might not be empty, was already deleted, or another issue occurred.");
		}
	}
}