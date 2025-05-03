package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

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
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(key = "Delete Category", category = ToolCategory.DATATYPES, description = "Deletes an existing category path, optionally recursively.", mcpName = "delete_category", mcpDescription = "Deletes a category (folder) and optionally its contents from the Data Type Manager.")
public class GhidraDeleteCategoryTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		JsonSchema schemaObject = schema();
		Optional<String> schemaStringOpt = schemaObject.toJsonString(mapper);
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to serialize schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}
		String schemaJson = schemaStringOpt.get();

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson),
				(ex, args) -> execute(ex, args, tool));
	}

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

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String categoryPathString = getRequiredStringArgument(args, ARG_CATEGORY_PATH);

			CategoryPath categoryPath;
			categoryPath = new CategoryPath(categoryPathString);
			if (categoryPath.isRoot()) {
				return createErrorResult("Cannot delete the root category.");
			}

			CategoryPath parentCategoryPath = categoryPath.getParent();
			if (parentCategoryPath == null) {
				return createErrorResult("Could not determine parent category for: " + categoryPathString);
			}

			DataTypeManager dtm = program.getDataTypeManager();
			final Category parentCategory = dtm.getCategory(parentCategoryPath);
			if (parentCategory == null) {
				return createSuccessResult("Category not found (parent missing): " + categoryPathString);
			}

			final String categoryName = categoryPath.getName();
			final String finalCategoryPathString = categoryPathString;
			return executeInTransaction(program, "MCP - Delete Category", () -> {

				GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex,
						this.getClass().getAnnotation(GhidraMcpTool.class).mcpName());

				if (parentCategory.removeCategory(categoryName, monitor)) {
					return createSuccessResult("Category '" + finalCategoryPathString + "' deleted successfully.");
				} else {
					return createSuccessResult("Category not found (or already deleted): " + finalCategoryPathString);
				}
			});

		}).onErrorResume(e -> createErrorResult(e));
	}

}