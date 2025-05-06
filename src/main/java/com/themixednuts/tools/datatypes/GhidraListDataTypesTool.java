package com.themixednuts.tools.datatypes;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Stream;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.models.DataTypeInfo;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "List Data Types", category = ToolCategory.DATATYPES, description = "Lists all data types, optionally filtered by category and/or type.", mcpName = "list_data_types", mcpDescription = "Returns a paginated list of all data types, optionally filtered by category path and/or data type kind.")
public class GhidraListDataTypesTool implements IGhidraMcpSpecification {

	public static final String ARG_TYPE_FILTER = "typeFilter";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_CATEGORY_PATH,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional category path to filter data types (e.g., '/ClassDataTypes/Aws'). Must start with '/'.")
						.pattern("^/.*"));
		schemaRoot.property(ARG_TYPE_FILTER,
				JsonSchemaBuilder.string(mapper)
						.description("Optional type to filter data types by.")
						.enumValues("structure", "union", "enum", "typedef", "pointer", "function_definition",
								"basic"));
		schemaRoot.requiredProperty(ARG_FILE_NAME);
		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			DataTypeManager dtm = program.getDataTypeManager();
			String cursor = getOptionalStringArgument(args, ARG_CURSOR).orElse(null);
			final String finalCursor = cursor;
			Optional<String> categoryPathOpt = getOptionalStringArgument(args, ARG_CATEGORY_PATH);
			Optional<String> typeFilterOpt = getOptionalStringArgument(args, ARG_TYPE_FILTER);

			Stream<DataType> dataTypeStream = StreamSupport
					.stream(Spliterators.spliteratorUnknownSize(dtm.getAllDataTypes(), Spliterator.ORDERED), false);

			// Apply category filter if provided
			if (categoryPathOpt.isPresent() && !categoryPathOpt.get().isBlank()) {
				String categoryPathStr = categoryPathOpt.get().trim();
				// Ensure the path is absolute and normalized (e.g., starts with / and ends
				// without / unless it's the root)
				CategoryPath filterPath = new CategoryPath(categoryPathStr);
				// Manually check if the path starts with '/'
				if (!filterPath.getPath().startsWith("/")) {
					throw new IllegalArgumentException("Category path must be absolute (start with '/'): " + categoryPathStr);
				}
				// Check if the category actually exists (optional, but good practice)
				if (dtm.getCategory(filterPath) == null) {
					throw new IllegalArgumentException("Category not found: " + filterPath.getPath());
				}
				final String normalizedFilterPath = filterPath.getPath(); // Use normalized path for comparison

				dataTypeStream = dataTypeStream.filter(dt -> {
					CategoryPath dtPath = dt.getCategoryPath();
					// Check if the data type's category path starts with the filter path
					// (allowing for subcategories)
					return dtPath != null && dtPath.getPath().startsWith(normalizedFilterPath);
				});
			}

			// Apply type filter if provided
			if (typeFilterOpt.isPresent() && !typeFilterOpt.get().isBlank()) {
				String typeFilter = typeFilterOpt.get().trim().toLowerCase();
				dataTypeStream = dataTypeStream.filter(dt -> {
					switch (typeFilter) {
						case "structure":
							return dt instanceof Structure;
						case "union":
							return dt instanceof Union;
						case "enum":
							// ghidra.program.model.data.Enum is the class for enums
							return dt instanceof ghidra.program.model.data.Enum;
						case "typedef":
							return dt instanceof TypeDef;
						case "pointer":
							return dt instanceof Pointer;
						case "function_definition":
							return dt instanceof FunctionDefinition;
						case "basic":
							// Basic types are not instances of the complex types above
							// and not undefined.
							return !(dt instanceof Structure || dt instanceof Union ||
									dt instanceof ghidra.program.model.data.Enum || dt instanceof TypeDef ||
									dt instanceof Pointer || dt instanceof FunctionDefinition)
									&& !dt.isNotYetDefined(); // Exclude 'undefined' types
						default:
							// If an unknown filter value is provided, it's an error,
							// but schema validation should catch this.
							// For safety, returning false will effectively show no results for an
							// invalid filter.
							// Consider throwing an IllegalArgumentException here if strictness is
							// desired,
							// though schema validation should ideally prevent this.
							return false;
					}
				});
			}

			List<DataTypeInfo> limitedDataTypes = dataTypeStream
					.sorted(Comparator.comparing(DataType::getPathName))
					.dropWhile(dt -> finalCursor != null && dt.getPathName().compareTo(finalCursor) <= 0)
					.limit(DEFAULT_PAGE_LIMIT + 1)
					.map(DataTypeInfo::new)
					.collect(Collectors.toList());

			boolean hasMore = limitedDataTypes.size() > DEFAULT_PAGE_LIMIT;
			List<DataTypeInfo> pageResults = limitedDataTypes.subList(0,
					Math.min(limitedDataTypes.size(), DEFAULT_PAGE_LIMIT));

			String nextCursor = null;
			if (hasMore && !pageResults.isEmpty()) {
				nextCursor = pageResults.get(pageResults.size() - 1).getPathName();
			}

			return new PaginatedResult<>(pageResults, nextCursor);

		});
	}

}
