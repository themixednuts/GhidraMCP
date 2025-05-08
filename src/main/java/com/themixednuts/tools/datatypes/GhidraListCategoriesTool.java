package com.themixednuts.tools.datatypes;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.CategoryInfo;
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
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "List Categories", category = ToolCategory.DATATYPES, description = "Lists data type categories within a program, with optional filtering.", mcpName = "list_categories", mcpDescription = "Lists data type categories, optionally filtering by path and name fragment.")
public class GhidraListCategoriesTool implements IGhidraMcpSpecification {

	protected static final String ARG_RECURSIVE = "recursive";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target."))
				.property(ARG_PATH,
						JsonSchemaBuilder.string(mapper)
								.description(
										"Optional category path to start listing from (e.g., '/MyCategory'). Defaults to the root ('/').")
								.pattern("^/.*")
								.defaultValue("/"),
						true)
				.property(ARG_FILTER,
						JsonSchemaBuilder.string(mapper)
								.description("Optional case-insensitive substring filter to apply to category names."))
				.description(
						"Lists data type categories under an optional path, optionally filtered by name.");

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					Optional<String> pathOpt = getOptionalStringArgument(args, ARG_PATH);
					Optional<String> filterOpt = getOptionalStringArgument(args, ARG_FILTER);

					return Mono.fromCallable(() -> listCategoriesInternal(program, pathOpt, filterOpt));
				});
	}

	private List<CategoryInfo> listCategoriesInternal(Program program, Optional<String> pathOpt,
			Optional<String> filterOpt) {
		DataTypeManager dtm = program.getDataTypeManager();
		CategoryPath categoryPath = pathOpt.map(CategoryPath::new).orElse(CategoryPath.ROOT);
		Category startCategory = dtm.getCategory(categoryPath);

		if (startCategory == null) {
			throw new IllegalArgumentException("Specified category path not found: " + pathOpt.orElse("/"));
		}

		List<CategoryInfo> categories = new ArrayList<>();
		String filterLower = filterOpt.map(String::toLowerCase).orElse(null);

		collectCategories(startCategory, filterLower, categories);

		return categories.stream()
				.sorted((c1, c2) -> c1.path.compareToIgnoreCase(c2.path))
				.collect(Collectors.toList());
	}

	private void collectCategories(Category currentCategory, String filterLower, List<CategoryInfo> collectedCategories) {
		for (Category child : currentCategory.getCategories()) {
			if (filterLower == null || child.getName().toLowerCase().contains(filterLower)) {
				collectedCategories.add(new CategoryInfo(child.getCategoryPath().getPath()));
			}
		}
	}
}