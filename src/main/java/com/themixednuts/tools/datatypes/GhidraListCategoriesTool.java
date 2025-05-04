package com.themixednuts.tools.datatypes;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "List Categories", category = ToolCategory.DATATYPES, description = "Lists all category paths in the Data Type Manager.", mcpName = "list_categories", mcpDescription = "Returns a list of all defined category paths (folders) in the Data Type Manager.")
public class GhidraListCategoriesTool implements IGhidraMcpSpecification {

	// Define a simple POJO for the result
	public static class CategoryInfo {
		@JsonProperty("path")
		public final String path;

		@JsonCreator
		public CategoryInfo(@JsonProperty("path") String path) {
			this.path = path;
		}
	}

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		// Updated schema handling
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
						.description("The name of the program file."));
		schemaRoot.property(ARG_CATEGORY_PATH,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional: The root category path to start listing from (e.g., '/windows'). Defaults to the root '/'."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			DataTypeManager dtm = program.getDataTypeManager();
			String rootPathString = getOptionalStringArgument(args, ARG_CATEGORY_PATH).orElse("/");
			String cursor = getOptionalStringArgument(args, ARG_CURSOR).orElse(null);
			final String finalCursor = cursor;

			Category rootCategory = dtm.getCategory(new CategoryPath(rootPathString));
			if (rootCategory == null) {
				return createErrorResult("Root category not found: " + rootPathString);
			}

			List<Category> allCategories = new ArrayList<>();
			collectCategoriesRecursive(rootCategory, allCategories);

			List<CategoryInfo> limitedCategories = allCategories.stream()
					.map(cat -> new CategoryInfo(cat.getCategoryPath().getPath()))
					.sorted(Comparator.comparing(info -> info.path))
					.dropWhile(info -> finalCursor != null && info.path.compareTo(finalCursor) <= 0)
					.limit(DEFAULT_PAGE_LIMIT + 1)
					.collect(Collectors.toList());

			boolean hasMore = limitedCategories.size() > DEFAULT_PAGE_LIMIT;
			List<CategoryInfo> pageResults = limitedCategories.subList(0,
					Math.min(limitedCategories.size(), DEFAULT_PAGE_LIMIT));

			String nextCursor = null;
			if (hasMore && !pageResults.isEmpty()) {
				nextCursor = pageResults.get(pageResults.size() - 1).path;
			}

			PaginatedResult<CategoryInfo> paginatedResult = new PaginatedResult<>(pageResults, nextCursor);
			return createSuccessResult(paginatedResult);

		}).onErrorResume(e -> createErrorResult(e));
	}

	private void collectCategoriesRecursive(Category category, List<Category> collected) {
		collected.add(category); // Add the category itself
		for (Category subCategory : category.getCategories()) {
			collectCategoriesRecursive(subCategory, collected);
		}
	}
}