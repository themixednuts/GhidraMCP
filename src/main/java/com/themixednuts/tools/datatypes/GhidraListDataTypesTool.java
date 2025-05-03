package com.themixednuts.tools.datatypes;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraDataTypeInfo;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "List Data Types", category = "Data Types", description = "Enable the MCP tool to list data types.", mcpName = "list_data_types", mcpDescription = "List all data types (structs, unions, enums, typedefs, pointers, etc.) defined within the specified program, returning detailed information like name, path, category, size, and type flags. Supports pagination.")
public class GhidraListDataTypesTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		String schema = parseSchema(schema()).orElse(null);
		if (schema == null) {
			return null; // Signal failure
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
						.description("The file name of the Ghidra tool window to target."));

		schemaRoot.requiredProperty("fileName");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			DataTypeManager dtm = program.getDataTypeManager();
			String cursor = getOptionalStringArgument(args, "cursor").orElse(null);

			List<DataType> allDataTypes = new ArrayList<>();
			Iterator<DataType> allDataTypesIterator = dtm.getAllDataTypes();
			allDataTypesIterator.forEachRemaining(allDataTypes::add);

			final String finalCursor = cursor; // For lambda capture

			List<DataType> limitedDataTypes = allDataTypes.stream()
					.sorted(Comparator.comparing(DataType::getPathName))
					.dropWhile(dt -> finalCursor != null && dt.getPathName().compareTo(finalCursor) <= 0)
					.limit(DEFAULT_PAGE_LIMIT + 1)
					.collect(Collectors.toList());

			boolean hasMore = limitedDataTypes.size() > DEFAULT_PAGE_LIMIT;

			List<DataType> pageDataTypes = limitedDataTypes.subList(0,
					Math.min(limitedDataTypes.size(), DEFAULT_PAGE_LIMIT));

			List<GhidraDataTypeInfo> pageResults = pageDataTypes.stream()
					.map(GhidraDataTypeInfo::new)
					.collect(Collectors.toList());

			String nextCursor = null;
			if (hasMore && !pageResults.isEmpty()) {
				nextCursor = pageResults.get(pageResults.size() - 1).getPathName();
			}

			PaginatedResult<GhidraDataTypeInfo> paginatedResult = new PaginatedResult<>(pageResults, nextCursor);
			return createSuccessResult(paginatedResult);

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}

}
