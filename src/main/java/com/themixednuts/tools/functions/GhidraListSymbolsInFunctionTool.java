package com.themixednuts.tools.functions;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.models.HighSymbolInfo;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
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

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		JsonSchema schemaObject = schema();
		Optional<String> schemaStringOpt = parseSchema(schemaObject);
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to serialize schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}
		String schemaJson = schemaStringOpt.get();

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public JsonSchema schema() {
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

		schemaRoot.requiredProperty("fileName");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		DecompInterface decomp = new DecompInterface();

		return getProgram(args, tool).flatMap(program -> {
			Optional<String> functionNameOpt = getOptionalStringArgument(args, "functionName");
			Optional<String> functionAddressOpt = getOptionalStringArgument(args, "functionAddress");
			String cursor = getOptionalStringArgument(args, "cursor").orElse(null);

			if (functionNameOpt.isEmpty() && functionAddressOpt.isEmpty()) {
				return createErrorResult("Error: Either functionName or functionAddress must be provided.");
			}

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
			} else {
				targetFunction = StreamSupport.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
						.filter(f -> f.getName().equals(functionNameOpt.get()))
						.findFirst().orElse(null);
				if (targetFunction == null) {
					return createErrorResult("Error: Function '" + functionNameOpt.get() + "' not found.");
				}
			}

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
			final String finalCursor = cursor;

			List<HighSymbol> allSymbols = new ArrayList<>();
			localSymbolMap.getSymbols().forEachRemaining(allSymbols::add);

			List<HighSymbol> limitedSymbols = allSymbols.stream()
					.sorted(Comparator.comparing(HighSymbol::getName))
					.dropWhile(symbol -> finalCursor != null && symbol.getName().compareTo(finalCursor) <= 0)
					.limit(DEFAULT_PAGE_LIMIT + 1)
					.collect(Collectors.toList());

			boolean hasMore = limitedSymbols.size() > DEFAULT_PAGE_LIMIT;

			List<HighSymbol> pageSymbols = limitedSymbols.subList(0, Math.min(limitedSymbols.size(), DEFAULT_PAGE_LIMIT));

			List<HighSymbolInfo> pageResults = pageSymbols.stream()
					.map(HighSymbolInfo::new)
					.collect(Collectors.toList());

			String nextCursor = null;
			if (hasMore && !pageResults.isEmpty()) {
				nextCursor = pageResults.get(pageResults.size() - 1).getName();
			}

			PaginatedResult<HighSymbolInfo> paginatedResult = new PaginatedResult<>(pageResults, nextCursor);
			return createSuccessResult(paginatedResult);

		}).onErrorResume(e -> {
			return createErrorResult(e);
		}).doFinally(signalType -> {
			if (decomp != null) {
				decomp.dispose();
			}
		});
	}
}
