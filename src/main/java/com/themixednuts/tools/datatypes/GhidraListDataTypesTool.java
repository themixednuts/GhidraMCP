package com.themixednuts.tools.datatypes;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Spliterator;
import java.util.Spliterators;

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
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "List Data Types", category = ToolCategory.DATATYPES, description = "Lists all data types, optionally filtered by category.", mcpName = "list_data_types", mcpDescription = "Returns a paginated list of all data types, optionally filtered by category path.")
public class GhidraListDataTypesTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.requiredProperty(ARG_FILE_NAME);
		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			DataTypeManager dtm = program.getDataTypeManager();
			String cursor = getOptionalStringArgument(args, ARG_CURSOR).orElse(null);
			final String finalCursor = cursor;

			List<DataTypeInfo> limitedDataTypes = StreamSupport
					.stream(Spliterators.spliteratorUnknownSize(dtm.getAllDataTypes(), Spliterator.ORDERED), false)
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
