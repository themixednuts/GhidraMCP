package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(key = "Delete Category", category = "Data Types", description = "Enable the MCP tool to delete a data type category.", mcpName = "delete_category", mcpDescription = "Deletes an existing data type category and all data types and sub-categories within it.")
public class GhidraDeleteCategoryTool implements IGhidraMcpSpecification {

	public GhidraDeleteCategoryTool() {
	}

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		String schema = parseSchema(schema()).orElse(null);
		if (schema == null) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schema),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public ObjectNode schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property("categoryPath",
				JsonSchemaBuilder.string(mapper)
						.description(
								"The full path of the category to delete (e.g., /MyTypes/ToDelete). Cannot be the root '/'.")
						.pattern("^/.+$")); // Must start with / and not be just /

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("categoryPath");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			// Setup: Parse args, resolve path, find parent category
			// Argument parsing errors caught by onErrorResume
			String categoryPathString = getRequiredStringArgument(args, "categoryPath");

			CategoryPath categoryPath;
			try {
				categoryPath = new CategoryPath(categoryPathString);
				if (categoryPath.isRoot()) {
					return createErrorResult("Cannot delete the root category.");
				}
			} catch (IllegalArgumentException e) {
				return createErrorResult("Invalid category path format: " + categoryPathString);
			}

			CategoryPath parentCategoryPath = categoryPath.getParent();
			if (parentCategoryPath == null) {
				// Should not happen for non-root paths, but handle defensively.
				return createErrorResult("Could not determine parent category for: " + categoryPathString);
			}

			DataTypeManager dtm = program.getDataTypeManager();
			final Category parentCategory = dtm.getCategory(parentCategoryPath); // Final for lambda
			if (parentCategory == null) {
				// Parent doesn't exist, implies the child doesn't either.
				// Treat as success (or already deleted) as the end state is the same.
				return createSuccessResult("Category not found (parent missing): " + categoryPathString);
			}

			final String categoryName = categoryPath.getName(); // Final for lambda

			// --- Execute modification in transaction ---
			final String finalCategoryPathString = categoryPathString; // Capture for message
			return executeInTransaction(program, "MCP - Delete Category", () -> {
				// Inner Callable logic (just the modification):
				// Use parentCategory.removeCategory(String name, TaskMonitor monitor)
				// Let executeInTransaction handle potential exceptions
				if (parentCategory.removeCategory(categoryName, TaskMonitor.DUMMY)) {
					return createSuccessResult("Category '" + finalCategoryPathString + "' deleted successfully.");
				} else {
					// This means the category with that name wasn't found in the parent.
					return createSuccessResult("Category not found (or already deleted): " + finalCategoryPathString);
				}
			}); // End of Callable for executeInTransaction

		}).onErrorResume(e -> {
			// Catch errors from getProgram, setup (incl. arg parsing), or transaction
			// execution
			// Logging handled by createErrorResult
			return createErrorResult(e);
		});
	}

}