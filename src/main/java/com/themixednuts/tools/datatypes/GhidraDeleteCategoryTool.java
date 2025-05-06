package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(name = "Delete Category", category = ToolCategory.DATATYPES, description = "Deletes an existing category path, optionally recursively.", mcpName = "delete_category", mcpDescription = "Deletes a category (folder) and optionally its contents from the Data Type Manager.")
public class GhidraDeleteCategoryTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property(ARG_CATEGORY_PATH,
				JsonSchemaBuilder.string(mapper)
						.description(
								"The full path of the category to delete (e.g., /MyTypes/ToDelete). Cannot be the root '/'.")
						.pattern("^/.+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_CATEGORY_PATH);

		return schemaRoot.build();
	}

	// Nested record for type-safe context passing
	private static record DeleteCategoryContext(
			Program program, // For transaction
			Category parentCategory,
			String categoryName,
			GhidraMcpTaskMonitor monitor,
			String originalPath // For messages
	) {
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) { // Ensure
																																																								// signature
		return getProgram(args, tool).map(program -> { // .map for sync setup
			String categoryPathString = getRequiredStringArgument(args, ARG_CATEGORY_PATH);

			CategoryPath categoryPath;
			try {
				categoryPath = new CategoryPath(categoryPathString);
			} catch (IllegalArgumentException e) {
				throw new IllegalArgumentException("Invalid category path format: " + categoryPathString, e);
			}

			if (categoryPath.isRoot()) {
				throw new IllegalArgumentException("Cannot delete the root category.");
			}

			CategoryPath parentCategoryPath = categoryPath.getParent();
			if (parentCategoryPath == null) { // Should be handled by isRoot check, but defensive
				throw new IllegalArgumentException("Could not determine parent category for: " + categoryPathString);
			}

			DataTypeManager dtm = program.getDataTypeManager();
			Category parentCategory = dtm.getCategory(parentCategoryPath);
			if (parentCategory == null) {
				throw new IllegalArgumentException("Category not found: " + categoryPathString + " (parent '"
						+ parentCategoryPath.getPath() + "' does not exist)");
			}

			String categoryName = categoryPath.getName();

			if (parentCategory.getCategory(categoryName) == null) {
				throw new IllegalArgumentException("Category not found: " + categoryPathString + " (Category '"
						+ categoryName + "' does not exist within parent '"
						+ parentCategoryPath.getPath() + "')");
			}

			GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex,
					this.getClass().getAnnotation(GhidraMcpTool.class).mcpName());

			// Return type-safe context
			return new DeleteCategoryContext(program, parentCategory, categoryName, monitor, categoryPathString);

		}).flatMap(context -> { // .flatMap for transaction
			return executeInTransaction(context.program(), "MCP - Delete Category: " + context.originalPath(), () -> {
				// Use context fields
				if (context.parentCategory().removeCategory(context.categoryName(), context.monitor())) {
					return "Category '" + context.originalPath() + "' deleted successfully.";
				} else {
					// removeCategory returning false usually means it was cancelled or already
					// deleted
					throw new RuntimeException("Failed to delete category '" + context.originalPath()
							+ "'. Check if it was already deleted or if the operation was cancelled.");
				}
			});
		});
	}

}