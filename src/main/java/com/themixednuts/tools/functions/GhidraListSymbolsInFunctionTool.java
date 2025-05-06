package com.themixednuts.tools.functions;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Arrays;

import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.tools.ToolCategory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import com.themixednuts.models.SymbolInfo;
import ghidra.program.model.listing.FunctionManager;

@GhidraMcpTool(name = "List Symbols in Function", category = ToolCategory.FUNCTIONS, description = "Lists all symbols (variables and parameters) within a specific function.", mcpName = "list_symbols_in_function", mcpDescription = "Returns a list of local variables and parameters defined within a specified function.")
public class GhidraListSymbolsInFunctionTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("Optional name of the function to list symbols from."));
		schemaRoot.property(ARG_FUNCTION_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional entry point address of the function (e.g., '0x1004010'). Preferred over name if both provided.")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			Optional<String> funcAddressOpt = getOptionalStringArgument(args, ARG_FUNCTION_ADDRESS);
			Optional<String> funcNameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);
			Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

			if (funcAddressOpt.isEmpty() && funcNameOpt.isEmpty()) {
				throw new IllegalArgumentException("Either function address ('" + ARG_FUNCTION_ADDRESS
						+ "') or function name ('" + ARG_FUNCTION_NAME + "') must be provided.");
			}

			Function function = null;
			FunctionManager functionManager = program.getFunctionManager();

			if (funcAddressOpt.isPresent()) {
				String addressString = funcAddressOpt.get();
				Address entryPointAddress = program.getAddressFactory().getAddress(addressString);
				if (entryPointAddress != null) {
					function = functionManager.getFunctionAt(entryPointAddress);
					if (function == null && funcNameOpt.isEmpty()) {
						throw new IllegalArgumentException("Function not found at address: " + addressString);
					}
				} else {
					if (funcNameOpt.isEmpty()) {
						throw new IllegalArgumentException("Invalid address format: " + addressString);
					}
				}
			}

			if (function == null && funcNameOpt.isPresent()) {
				String functionName = funcNameOpt.get();
				function = StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
						.filter(f -> f.getName(true).equals(functionName))
						.findFirst()
						.orElse(null);
				if (function == null) {
					throw new IllegalArgumentException("Function not found with name: " + functionName);
				}
			}

			if (function == null) {
				throw new IllegalStateException("Could not identify function from the provided arguments.");
			}

			List<SymbolInfo> allSymbolsInFunction = new ArrayList<>();
			allSymbolsInFunction.addAll(Arrays.stream(function.getParameters())
					.map(param -> new SymbolInfo(param.getSymbol()))
					.collect(Collectors.toList()));

			allSymbolsInFunction.addAll(Arrays.stream(function.getLocalVariables())
					.map(var -> new SymbolInfo(var.getSymbol()))
					.collect(Collectors.toList()));

			allSymbolsInFunction.sort(Comparator.comparing(SymbolInfo::getAddress).thenComparing(SymbolInfo::getName));

			final String finalCursorStr = cursorOpt.orElse(null);

			List<SymbolInfo> paginatedSymbols = allSymbolsInFunction.stream()
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

			boolean hasMore = paginatedSymbols.size() > DEFAULT_PAGE_LIMIT;
			List<SymbolInfo> resultsForPage = paginatedSymbols.subList(0,
					Math.min(paginatedSymbols.size(), DEFAULT_PAGE_LIMIT));
			String nextCursor = null;
			if (hasMore && !resultsForPage.isEmpty()) {
				SymbolInfo lastItem = resultsForPage.get(resultsForPage.size() - 1);
				nextCursor = lastItem.getAddress() + ":" + lastItem.getName();
			}

			return new PaginatedResult<>(resultsForPage, nextCursor);
		});
	}
}
