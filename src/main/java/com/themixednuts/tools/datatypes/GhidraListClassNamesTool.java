package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "List Class Names", category = ToolCategory.DATATYPES, description = "Lists the names of defined classes (structures).", mcpName = "list_class_names", mcpDescription = "Lists all defined class names (structure names) in the program.")
public class GhidraListClassNamesTool implements IGhidraMcpSpecification {

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
			SymbolTable symbolTable = program.getSymbolTable();
			String cursor = getOptionalStringArgument(args, ARG_CURSOR).orElse(null);
			final String finalCursor = cursor;

			List<String> limitedClassNames = StreamSupport
					.stream(symbolTable.getSymbolIterator(true).spliterator(), false)
					.filter(symbol -> symbol.getSymbolType() == SymbolType.CLASS)
					.map(Symbol::getName)
					.distinct()
					.sorted()
					.dropWhile(name -> finalCursor != null && name.compareTo(finalCursor) <= 0)
					.limit(DEFAULT_PAGE_LIMIT + 1)
					.collect(Collectors.toList());

			boolean hasMore = limitedClassNames.size() > DEFAULT_PAGE_LIMIT;
			List<String> pageResults = limitedClassNames.subList(0,
					Math.min(limitedClassNames.size(), DEFAULT_PAGE_LIMIT));

			String nextCursor = null;
			if (hasMore && !pageResults.isEmpty()) {
				nextCursor = pageResults.get(pageResults.size() - 1);
			}

			return new PaginatedResult<>(pageResults, nextCursor);

		});
	}

}