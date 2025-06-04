package com.themixednuts.tools.memory;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Spliterators;
import java.util.Spliterator;
import java.util.Comparator;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.SymbolInfo;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.PaginatedResult;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "List Imports", category = ToolCategory.MEMORY, description = "Lists all imported libraries and functions.", mcpName = "list_imports", mcpDescription = "Retrieve a paginated list of all external symbols imported by the program. Returns import details including library names, function names, and addresses. Results are sorted by address and name, with cursor-based pagination support.")
public class GhidraListImportsTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper).description("The name of the program file."));
		schemaRoot.requiredProperty(ARG_FILE_NAME);
		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			SymbolTable symbolTable = program.getSymbolTable();
			SymbolIterator externalSymbolsIter = symbolTable.getExternalSymbols();
			Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

			List<SymbolInfo> allImports = StreamSupport.stream(
					Spliterators.spliteratorUnknownSize((java.util.Iterator<Symbol>) externalSymbolsIter, Spliterator.ORDERED),
					false)
					.map(SymbolInfo::new)
					.sorted(Comparator.comparing(SymbolInfo::getAddress).thenComparing(SymbolInfo::getName))
					.collect(Collectors.toList());

			final String finalCursorStr = cursorOpt.orElse(null);

			List<SymbolInfo> paginatedImports = allImports.stream()
					.dropWhile(item -> {
						if (finalCursorStr == null)
							return false;
						String[] parts = finalCursorStr.split(":", 2);
						Address cursorItemAddr = program.getAddressFactory().getAddress(parts[0]);
						String cursorItemName = parts.length > 1 ? parts[1] : "";
						Address itemAddr = program.getAddressFactory().getAddress(item.getAddress());

						int addrCompare = itemAddr.compareTo(cursorItemAddr);
						if (addrCompare < 0)
							return true;
						if (addrCompare == 0)
							return item.getName().compareTo(cursorItemName) <= 0;
						return false;
					})
					.limit(DEFAULT_PAGE_LIMIT + 1)
					.collect(Collectors.toList());

			boolean hasMore = paginatedImports.size() > DEFAULT_PAGE_LIMIT;
			List<SymbolInfo> resultsForPage = paginatedImports.subList(0,
					Math.min(paginatedImports.size(), DEFAULT_PAGE_LIMIT));
			String nextCursor = null;
			if (hasMore && !resultsForPage.isEmpty()) {
				SymbolInfo lastItem = resultsForPage.get(resultsForPage.size() - 1);
				nextCursor = lastItem.getAddress() + ":" + lastItem.getName();
			}

			return new PaginatedResult<>(resultsForPage, nextCursor);
		});
	}
}
