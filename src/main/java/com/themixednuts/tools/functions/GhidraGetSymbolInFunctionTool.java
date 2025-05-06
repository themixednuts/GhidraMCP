package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;
import java.util.stream.StreamSupport;

import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.models.HighSymbolInfo;
import com.themixednuts.tools.ToolCategory;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.listing.VariableStorage;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get Symbol in Function", category = ToolCategory.FUNCTIONS, description = "Gets details about a symbol (variable or parameter) within a specific function by its name or storage address.", mcpName = "get_symbol_in_function", mcpDescription = "Retrieves details of a local variable or parameter by its name or storage address within a specific function.")
public class GhidraGetSymbolInFunctionTool implements IGhidraMcpSpecification {

	public static final String ARG_SYMBOL_ADDRESS = "symbolAddress";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the function containing the symbol."));
		schemaRoot.property(ARG_NAME,
				JsonSchemaBuilder.string(mapper)
						.description(
								"The name of the symbol (local variable or parameter) to retrieve. Provide this or symbolAddress."));
		schemaRoot.property(ARG_SYMBOL_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description(
								"The storage address of the symbol (e.g., stack offset as absolute address). Provide this or symbol name.")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_FUNCTION_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		DecompInterface decomp = new DecompInterface();

		return getProgram(args, tool).flatMap(program -> {
			return Mono.fromCallable(() -> {
				String functionName = getRequiredStringArgument(args, ARG_FUNCTION_NAME);
				Optional<String> symbolNameOpt = getOptionalStringArgument(args, ARG_NAME);
				Optional<String> symbolAddressOpt = getOptionalStringArgument(args, ARG_SYMBOL_ADDRESS);

				if (symbolNameOpt.isEmpty() && symbolAddressOpt.isEmpty()) {
					throw new IllegalArgumentException("Either symbol name ('" + ARG_NAME + "') or symbol address ('"
							+ ARG_SYMBOL_ADDRESS + "') must be provided.");
				}

				Function function = StreamSupport.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
						.filter(f -> f.getName().equals(functionName))
						.findFirst()
						.orElse(null);

				if (function == null) {
					throw new IllegalArgumentException("Function not found: " + functionName);
				}

				decomp.openProgram(program);
				GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex, this.getClass().getSimpleName());
				DecompileResults result = decomp.decompileFunction(function, 30, monitor);

				if (result == null || !result.decompileCompleted()) {
					String errorMsg = result != null ? result.getErrorMessage() : "Unknown decompiler error";
					throw new RuntimeException("Decompilation failed: " + errorMsg);
				}
				HighFunction highFunction = result.getHighFunction();
				if (highFunction == null) {
					throw new RuntimeException("Decompilation failed (no high function)");
				}

				LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
				HighSymbol highSymbol = null;
				String identifierInfo = "";

				if (symbolNameOpt.isPresent()) {
					String symbolName = symbolNameOpt.get();
					identifierInfo = "name '" + symbolName + "'";
					java.util.Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
					while (symbols.hasNext()) {
						HighSymbol sym = symbols.next();
						if (sym.getName().equals(symbolName)) {
							highSymbol = sym;
							break;
						}
					}
				} else if (symbolAddressOpt.isPresent()) {
					String symbolAddressStr = symbolAddressOpt.get();
					identifierInfo = "address '" + symbolAddressStr + "'";
					Address symAddress = program.getAddressFactory().getAddress(symbolAddressStr);
					if (symAddress == null) {
						throw new IllegalArgumentException("Invalid symbol address format: " + symbolAddressStr);
					}
					java.util.Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
					while (symbols.hasNext()) {
						HighSymbol sym = symbols.next();
						VariableStorage storage = sym.getStorage();
						if (storage != null && !storage.isBadStorage() && storage.contains(symAddress)) {
							highSymbol = sym;
							break;
						}
					}
				}

				if (highSymbol == null) {
					throw new IllegalArgumentException(
							"Symbol with " + identifierInfo + " not found in function '" + functionName + "'");
				}

				return new HighSymbolInfo(highSymbol);
			});
		}).doFinally(signalType -> {
			if (decomp != null) {
				decomp.dispose();
			}
		});
	}
}