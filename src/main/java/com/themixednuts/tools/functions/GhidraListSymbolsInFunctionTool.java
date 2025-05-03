package com.themixednuts.tools.functions;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraHighSymbolInfo;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.PaginatedResult;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "List Symbols In Function", category = "Functions", description = "Lists local variables and parameters within a function using decompiler analysis.", mcpName = "list_symbols_in_function", mcpDescription = "Returns a list of symbols (local variables, parameters) defined within the specified function, based on decompiler analysis. Supports pagination.")
public class GhidraListSymbolsInFunctionTool implements IGhidraMcpSpecification {
	public GhidraListSymbolsInFunctionTool() {
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
		schemaRoot.property("functionName",
				JsonSchemaBuilder.string(mapper)
						.description("Optional name of the function to list symbols from."));
		schemaRoot.property("functionAddress",
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional entry point address of the function (e.g., '0x1004010'). Preferred over name if both provided."));
		// Pagination arguments (cursor, limit) are handled implicitly by MCP

		schemaRoot.requiredProperty("fileName");
		// Logic requires functionName OR functionAddress

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		// Initialize resource before the chain
		DecompInterface decomp = new DecompInterface();

		return getProgram(args, tool).flatMap(program -> {
			// Argument parsing - errors caught by onErrorResume
			Optional<String> functionNameOpt = getOptionalStringArgument(args, "functionName");
			Optional<String> functionAddressOpt = getOptionalStringArgument(args, "functionAddress");
			String cursor = getOptionalStringArgument(args, "cursor").orElse(null);

			if (functionNameOpt.isEmpty() && functionAddressOpt.isEmpty()) {
				return createErrorResult("Error: Either functionName or functionAddress must be provided.");
			}

			// Find the function
			Function targetFunction = null;
			if (functionAddressOpt.isPresent()) {
				Address addr = program.getAddressFactory().getAddress(functionAddressOpt.get());
				if (addr == null) {
					return createErrorResult("Invalid function address format: " + functionAddressOpt.get());
				}
				targetFunction = program.getFunctionManager().getFunctionAt(addr);
				if (targetFunction == null) {
					return createErrorResult("Error: Function not found at address '" + functionAddressOpt.get() + "'.");
				}
			} else { // functionNameOpt must be present
				targetFunction = StreamSupport.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
						.filter(f -> f.getName().equals(functionNameOpt.get()))
						.findFirst().orElse(null);
				if (targetFunction == null) {
					return createErrorResult("Error: Function '" + functionNameOpt.get() + "' not found.");
				}
			}

			// Decompile to get HighSymbols - decompilation errors caught by onErrorResume
			// DecompInterface setup/dispose handled outside/via doFinally
			decomp.openProgram(program);
			DecompileResults result = decomp.decompileFunction(targetFunction, 30, new ConsoleTaskMonitor());

			if (result == null || !result.decompileCompleted()) {
				String errorMsg = result != null ? result.getErrorMessage() : "Unknown decompiler error";
				return createErrorResult("Error: Decompilation failed: " + errorMsg);
			}
			HighFunction highFunction = result.getHighFunction();
			if (highFunction == null) {
				return createErrorResult("Error: Decompilation failed (no high function)");
			}

			LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
			final String finalCursor = cursor; // For lambda capture

			// Collect symbols from iterator into a list first
			List<HighSymbol> allSymbols = new ArrayList<>();
			localSymbolMap.getSymbols().forEachRemaining(allSymbols::add);

			// Stream the collected list, SORT by name, dropWhile, limit, and collect
			List<HighSymbol> limitedSymbols = allSymbols.stream()
					.sorted(Comparator.comparing(HighSymbol::getName))
					.dropWhile(symbol -> finalCursor != null && symbol.getName().compareTo(finalCursor) <= 0)
					.limit(DEFAULT_PAGE_LIMIT + 1)
					.collect(Collectors.toList());

			// Determine if there are more pages
			boolean hasMore = limitedSymbols.size() > DEFAULT_PAGE_LIMIT;

			// Get the actual symbols for the current page
			List<HighSymbol> pageSymbols = limitedSymbols.subList(0, Math.min(limitedSymbols.size(), DEFAULT_PAGE_LIMIT));

			// Map to POJOs
			List<GhidraHighSymbolInfo> pageResults = pageSymbols.stream()
					.map(GhidraHighSymbolInfo::new)
					.collect(Collectors.toList());

			// Determine the next cursor
			String nextCursor = null;
			if (hasMore && !pageResults.isEmpty()) {
				nextCursor = pageResults.get(pageResults.size() - 1).getName();
			}

			// Create paginated result and return success
			PaginatedResult<GhidraHighSymbolInfo> paginatedResult = new PaginatedResult<>(pageResults, nextCursor);
			return createSuccessResult(paginatedResult);

		}).onErrorResume(e -> {
			// Catch errors from getProgram, setup, decompilation, or unexpected issues
			return createErrorResult(e);
		}).doFinally(signalType -> { // Ensure resource cleanup
			if (decomp != null) {
				decomp.dispose();
			}
		});
	}
}
