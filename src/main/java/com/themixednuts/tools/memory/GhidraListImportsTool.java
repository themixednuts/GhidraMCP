package com.themixednuts.tools.memory;

import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Map;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraSymbolInfo;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "List Imports", category = "Memory", description = "Enable the MCP tool to list imports in a file.", mcpName = "list_imports", mcpDescription = "List the names and details of all imported symbols (functions, data from external libraries) used by the specified program. Supports pagination.")
public class GhidraListImportsTool implements IGhidraMcpSpecification {
	public GhidraListImportsTool() {
	}

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		String schema = parseSchema(schema()).orElse(null);
		if (schema == null) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
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
						.description("The name of the program file."));
		schemaRoot.requiredProperty("fileName");
		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			SymbolTable symbolTable = program.getSymbolTable();
			String cursor = getOptionalStringArgument(args, "cursor").orElse(null);
			final String finalCursor = cursor; // Effectively final for lambda

			// Stream external symbols, sort, paginate, and map results
			List<Symbol> limitedSymbols = StreamSupport
					.stream(symbolTable.getExternalSymbols().spliterator(), false)
					.sorted(Comparator.comparing(Symbol::getName)) // Sort by name
					.dropWhile(symbol -> finalCursor != null && symbol.getName().compareTo(finalCursor) <= 0)
					.limit(DEFAULT_PAGE_LIMIT + 1)
					.collect(Collectors.toList());

			// Determine if there are more pages
			boolean hasMore = limitedSymbols.size() > DEFAULT_PAGE_LIMIT;

			// Get the actual symbols for the current page
			List<Symbol> pageSymbols = limitedSymbols.subList(0, Math.min(limitedSymbols.size(), DEFAULT_PAGE_LIMIT));

			// Map to POJOs
			List<GhidraSymbolInfo> pageResults = pageSymbols.stream()
					.map(GhidraSymbolInfo::new)
					.collect(Collectors.toList());

			// Determine the next cursor
			String nextCursor = null;
			if (hasMore && !pageResults.isEmpty()) {
				nextCursor = pageResults.get(pageResults.size() - 1).getName();
			}

			// Create paginated result and return success
			PaginatedResult<GhidraSymbolInfo> paginatedResult = new PaginatedResult<>(pageResults, nextCursor);
			return createSuccessResult(paginatedResult);

		}).onErrorResume(e -> {
			// Catch errors from getProgram, setup, or unexpected issues
			return createErrorResult(e);
		});
	}

}
