package com.themixednuts.tools.symbols;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.SymbolInfo;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "List All Symbols", category = ToolCategory.SYMBOLS, description = "Lists all symbols defined in the program's main symbol table, with optional filters.", mcpName = "list_all_symbols", mcpDescription = "Retrieves a paginated list of all symbols (labels, functions, globals, etc.) from the program, optionally filtering by name and/or type.")
public class GhidraListAllSymbolsTool implements IGhidraMcpSpecification {
	private static final String ARG_NAME_FILTER = "nameFilter";
	private static final String ARG_TYPE_FILTER = "typeFilter";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_NAME_FILTER,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional case-insensitive filter string. Only symbols whose names contain this string will be returned."));
		schemaRoot.property(ARG_TYPE_FILTER,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional case-insensitive filter for symbol type (e.g., 'Function', 'Label', 'Parameter', 'Local_Variable', 'Class', 'Namespace', 'Import')."));
		schemaRoot.requiredProperty(ARG_FILE_NAME);
		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String cursorStr = getOptionalStringArgument(args, ARG_CURSOR).orElse(null);
			Optional<String> nameFilterOpt = getOptionalStringArgument(args, ARG_NAME_FILTER);
			Optional<String> typeFilterOpt = getOptionalStringArgument(args, ARG_TYPE_FILTER);

			Address cursorAddr = null;
			if (cursorStr != null) {
				cursorAddr = program.getAddressFactory().getAddress(cursorStr);
				if (cursorAddr == null) {
					throw new IllegalArgumentException("Invalid cursor format (could not parse address): " + cursorStr);
				}
			}
			final Address finalCursorAddr = cursorAddr;
			final String nameFilterLower = nameFilterOpt.map(String::toLowerCase).orElse(null);
			final String typeFilterLower = typeFilterOpt.map(String::toLowerCase).orElse(null);

			SymbolTable symbolTable = program.getSymbolTable();
			SymbolIterator symbolIter = symbolTable.getAllSymbols(true); // Get all symbols

			Stream<Symbol> symbolStream = StreamSupport.stream(symbolIter.spliterator(), false);

			if (nameFilterLower != null) {
				symbolStream = symbolStream.filter(symbol -> symbol.getName().toLowerCase().contains(nameFilterLower));
			}
			if (typeFilterLower != null) {
				symbolStream = symbolStream.filter(symbol -> {
					SymbolType type = symbol.getSymbolType();
					return type != null && type.toString().toLowerCase().equals(typeFilterLower);
				});
			}

			List<Symbol> limitedSymbols = symbolStream
					.sorted(Comparator.comparing(Symbol::getAddress))
					.dropWhile(symbol -> finalCursorAddr != null && symbol.getAddress().compareTo(finalCursorAddr) <= 0)
					.limit(DEFAULT_PAGE_LIMIT + 1)
					.collect(Collectors.toList());

			boolean hasMore = limitedSymbols.size() > DEFAULT_PAGE_LIMIT;
			List<Symbol> pageSymbols = limitedSymbols.subList(0, Math.min(limitedSymbols.size(), DEFAULT_PAGE_LIMIT));

			List<SymbolInfo> pageResults = pageSymbols.stream()
					.map(SymbolInfo::new)
					.collect(Collectors.toList());

			String nextCursor = null;
			if (hasMore && !pageResults.isEmpty()) {
				nextCursor = pageResults.get(pageResults.size() - 1).getAddress();
			}

			PaginatedResult<SymbolInfo> paginatedResult = new PaginatedResult<>(pageResults, nextCursor);
			return paginatedResult;

		});
	}
}