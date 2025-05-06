package com.themixednuts.tools.datatypes;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.CategoryInfo;
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
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "List Categories", category = ToolCategory.DATATYPES, description = "Lists all category paths in the Data Type Manager.", mcpName = "list_categories", mcpDescription = "Returns a list of all defined category paths (folders) in the Data Type Manager.")
public class GhidraListCategoriesTool implements IGhidraMcpSpecification {

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
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			DataTypeManager dtm = program.getDataTypeManager();
			String rootPathString = getOptionalStringArgument(args, ARG_CATEGORY_PATH).orElse("/");
			String cursor = getOptionalStringArgument(args, ARG_CURSOR).orElse(null);
			final int limit = IGhidraMcpSpecification.DEFAULT_PAGE_LIMIT;
			final String finalCursor = cursor;

			Category rootCategory = dtm.getCategory(new CategoryPath(rootPathString));
			if (rootCategory == null) {
				throw new IllegalArgumentException("Root category not found: " + rootPathString);
			}

			List<Category> allCategories = new ArrayList<>();
			collectCategoriesRecursive(rootCategory, allCategories);

			List<CategoryInfo> limitedCategories = allCategories.stream()
					.map(cat -> new CategoryInfo(cat.getCategoryPath().getPath()))
					.sorted(Comparator.comparing(info -> info.path))
					.dropWhile(info -> finalCursor != null && info.path.compareTo(finalCursor) <= 0)
					.limit((long) limit + 1)
					.collect(Collectors.toList());

			boolean hasMore = limitedCategories.size() > limit;
			List<CategoryInfo> pageResults = limitedCategories.subList(0, Math.min(limitedCategories.size(), limit));

			String nextCursor = null;
			if (hasMore && !pageResults.isEmpty()) {
				nextCursor = pageResults.get(pageResults.size() - 1).path;
			}

			return new PaginatedResult<>(pageResults, nextCursor);
		});
	}

	private static void collectCategoriesRecursive(Category category, List<Category> collected) {
		collected.add(category); // Add the category itself
		for (Category subCategory : category.getCategories()) {
			collectCategoriesRecursive(subCategory, collected);
		}
	}
}