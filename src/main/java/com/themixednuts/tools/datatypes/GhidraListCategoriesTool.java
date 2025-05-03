package com.themixednuts.tools.datatypes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.Msg;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "List Categories", category = "Data Types", description = "Enable the MCP tool to list data type categories.", mcpName = "list_categories", mcpDescription = "Lists data type categories, optionally filtering by a parent category path. Supports pagination.")
public class GhidraListCategoriesTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		String schema = parseSchema(schema()).orElse(null);
		if (schema == null) {
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

		schemaRoot.property("parentPath",
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional full path of the parent category to list sub-categories from (e.g., /MyTypes). If omitted or '/', lists categories starting from the root.")
						.pattern("^/.*$"));

		schemaRoot.property("recursive",
				JsonSchemaBuilder.bool(mapper)
						.description(
								"If true, recursively list all sub-categories under the parent path. If false (default), only list direct children.")
						.defaultValue(false));

		schemaRoot.requiredProperty("fileName");

		return schemaRoot.build();
	}

	private void collectAllCategoryPaths(Category currentCategory, List<String> paths) {
		paths.add(currentCategory.getCategoryPath().getPath());

		for (Category subCategory : currentCategory.getCategories()) {
			collectAllCategoryPaths(subCategory, paths);
		}
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			Optional<String> parentPathOpt = getOptionalStringArgument(args, "parentPath");
			boolean recursive = getOptionalBooleanArgument(args, "recursive").orElse(false);
			String cursor = getOptionalStringArgument(args, "cursor").orElse(null);
			final String finalCursor = cursor; // Effectively final for lambda

			DataTypeManager dtm = program.getDataTypeManager();
			Category startCategory;

			if (parentPathOpt.isPresent() && !parentPathOpt.get().equals("/")) {
				CategoryPath parentPath = new CategoryPath(parentPathOpt.get());
				startCategory = dtm.getCategory(parentPath);
				if (startCategory == null) {
					return createErrorResult("Parent category not found: " + parentPathOpt.get());
				}
			} else {
				startCategory = dtm.getRootCategory();
			}

			List<String> allCategoryPaths = new ArrayList<>();

			if (recursive) {
				collectAllCategoryPaths(startCategory, allCategoryPaths);
				if (parentPathOpt.isPresent() && !parentPathOpt.get().equals("/") && !allCategoryPaths.isEmpty()) {
					allCategoryPaths.remove(0);
				}
			} else {
				Consumer<Category> categoryConsumer = cat -> allCategoryPaths.add(cat.getCategoryPath().getPath());
				Arrays.stream(startCategory.getCategories()).forEach(categoryConsumer);
			}

			List<String> limitedPaths = allCategoryPaths.stream()
					.sorted() // Sort by path string
					.dropWhile(path -> finalCursor != null && path.compareTo(finalCursor) <= 0) // Use path as cursor key
					.limit(DEFAULT_PAGE_LIMIT + 1)
					.collect(Collectors.toList());

			boolean hasMore = limitedPaths.size() > DEFAULT_PAGE_LIMIT;
			List<String> pageResults = limitedPaths.subList(0, Math.min(limitedPaths.size(), DEFAULT_PAGE_LIMIT));

			String nextCursor = null;
			if (hasMore && !pageResults.isEmpty()) {
				nextCursor = pageResults.get(pageResults.size() - 1);
			}

			PaginatedResult<String> paginatedResult = new PaginatedResult<>(pageResults, nextCursor);

			return createSuccessResult(paginatedResult);

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}
}