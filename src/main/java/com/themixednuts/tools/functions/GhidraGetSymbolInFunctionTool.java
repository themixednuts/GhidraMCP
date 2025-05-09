package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;

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
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.listing.VariableStorage;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get Symbol in Function", category = ToolCategory.FUNCTIONS, description = "Gets details about a symbol (variable or parameter) within a specific function by its name or storage address.", mcpName = "get_symbol_in_function", mcpDescription = "Retrieves details of a local variable or parameter by its name or storage address within a specific function.")
public class GhidraGetSymbolInFunctionTool implements IGhidraMcpSpecification {

	public static final String ARG_FILE_NAME = "fileName";
	public static final String ARG_FUNCTION_SYMBOL_ID = "functionSymbolId";
	public static final String ARG_FUNCTION_ADDRESS = "functionAddress";
	public static final String ARG_FUNCTION_NAME = "functionName";
	public static final String ARG_VARIABLE_SYMBOL_ID = "variableSymbolId";
	public static final String ARG_ADDRESS = "address";
	public static final String ARG_STORAGE_STRING = "storageString";
	public static final String ARG_NAME = "name";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));

		// Function Identification
		schemaRoot.property(ARG_FUNCTION_SYMBOL_ID,
				JsonSchemaBuilder.integer(mapper)
						.description("Optional: Symbol ID of the function. Preferred identifier."))
				.property(ARG_FUNCTION_ADDRESS,
						JsonSchemaBuilder.string(mapper)
								.description(
										"Optional: Entry point address of the function (e.g., '0x1004010'). Used if Symbol ID is not provided or not found.")
								.pattern("^(0x)?[0-9a-fA-F]+$"))
				.property(ARG_FUNCTION_NAME,
						JsonSchemaBuilder.string(mapper)
								.description(
										"Optional: Name of the function. Used if Symbol ID and Address are not provided or not found."));

		// Symbol Identification in Function
		schemaRoot.property(ARG_VARIABLE_SYMBOL_ID,
				JsonSchemaBuilder.integer(mapper)
						.description(
								"Optional: The unique ID of the symbol (variable/parameter) to retrieve. Preferred identifier for the symbol."))
				.property(ARG_ADDRESS,
						JsonSchemaBuilder.string(mapper)
								.description(
										"Optional: An address contained within the symbol's storage (e.g., a specific byte within a multi-byte stack variable, or a register name).")
								.pattern("^(0x)?[0-9a-fA-F]+$|^[a-zA-Z0-9_]+$"))
				.property(ARG_STORAGE_STRING,
						JsonSchemaBuilder.string(mapper)
								.description(
										"Optional: The exact storage string of the symbol (e.g., 'Stack[-0x10]', 'EAX', 'AddressSpace:Offset')."))
				.property(ARG_NAME,
						JsonSchemaBuilder.string(mapper)
								.description(
										"Optional: The name of the symbol (local variable or parameter) to retrieve."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		// At least one function identifier and one symbol identifier will be checked in
		// execute()

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		DecompInterface decomp = new DecompInterface();

		return getProgram(args, tool).flatMap(program -> {
			return Mono.fromCallable(() -> {
				// Function Identifiers
				Optional<Long> funcSymbolIdOpt = getOptionalLongArgument(args, ARG_FUNCTION_SYMBOL_ID);
				Optional<String> funcAddressOpt = getOptionalStringArgument(args, ARG_FUNCTION_ADDRESS);
				Optional<String> funcNameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);

				// Target Symbol in Function Identifiers
				Optional<Long> varSymbolIdOpt = getOptionalLongArgument(args, ARG_VARIABLE_SYMBOL_ID);
				Optional<String> symbolAddressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
				Optional<String> symbolStorageStringOpt = getOptionalStringArgument(args, ARG_STORAGE_STRING);
				Optional<String> symbolNameOpt = getOptionalStringArgument(args, ARG_NAME);

				if (funcSymbolIdOpt.isEmpty() && funcAddressOpt.isEmpty() && funcNameOpt.isEmpty()) {
					throw new IllegalArgumentException(
							"At least one function identifier (functionSymbolId, functionAddress, or functionName) must be provided.");
				}
				if (varSymbolIdOpt.isEmpty() && symbolAddressOpt.isEmpty() && symbolStorageStringOpt.isEmpty()
						&& symbolNameOpt.isEmpty()) {
					throw new IllegalArgumentException(
							"At least one symbol identifier must be provided: variableSymbolId, address, storageString, or name.");
				}

				Function function = resolveFunction(program, funcSymbolIdOpt, funcAddressOpt, funcNameOpt);

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

				HighSymbol foundHighSymbol = resolveHighSymbolInFunction(program, highFunction,
						varSymbolIdOpt, symbolAddressOpt, symbolStorageStringOpt, symbolNameOpt);

				return new HighSymbolInfo(foundHighSymbol);
			});
		}).doFinally(signalType -> {
			if (decomp != null) {
				decomp.dispose();
			}
		});
	}

	// Helper method to resolve function by Symbol ID, Address, or Name
	private Function resolveFunction(Program program, Optional<Long> funcSymbolIdOpt, Optional<String> funcAddressOpt,
			Optional<String> funcNameOpt) {
		ghidra.program.model.listing.FunctionManager funcMan = program.getFunctionManager();
		Function function = null;

		// Attempt 1: Resolve by Symbol ID
		if (funcSymbolIdOpt.isPresent()) {
			long symbolID = funcSymbolIdOpt.get();
			ghidra.program.model.symbol.Symbol symbol = program.getSymbolTable().getSymbol(symbolID);
			if (symbol != null && symbol.getSymbolType() == ghidra.program.model.symbol.SymbolType.FUNCTION) {
				function = funcMan.getFunctionAt(symbol.getAddress());
				if (function != null) {
					return function; // Successfully found by Symbol ID
				}
			}
		}

		// Attempt 2: Resolve by Address
		if (funcAddressOpt.isPresent()) {
			ghidra.program.model.address.Address funcAddr = program.getAddressFactory().getAddress(funcAddressOpt.get());
			if (funcAddr == null) {
				ghidra.util.Msg.warn(this, "Invalid function address format or address not found: " + funcAddressOpt.get());
			}
			if (funcAddr != null) {
				function = funcMan.getFunctionAt(funcAddr);
				if (function != null) {
					return function; // Successfully found by address
				}
			}
		}

		// Attempt 3: Resolve by Name
		if (funcNameOpt.isPresent()) {
			String functionName = funcNameOpt.get();
			java.util.List<Function> foundFunctionsByName = java.util.stream.StreamSupport
					.stream(funcMan.getFunctions(true).spliterator(), false)
					.filter(f -> f.getName().equals(functionName))
					.collect(java.util.stream.Collectors.toList());

			if (foundFunctionsByName.size() == 1) {
				return foundFunctionsByName.get(0); // Found unique function by name
			} else if (foundFunctionsByName.size() > 1) {
				throw new IllegalArgumentException(
						"Multiple functions found with name: '" + functionName +
								"'. Please use a more specific identifier like address or symbol ID.");
			}
		}

		// If not found by any means
		StringBuilder errorMessage = new StringBuilder("Function not found using any of the provided identifiers: ");
		funcSymbolIdOpt.ifPresent(id -> errorMessage.append("functionSymbolId='").append(id).append("' "));
		funcAddressOpt.ifPresent(addr -> errorMessage.append("functionAddress='").append(addr).append("' "));
		funcNameOpt.ifPresent(name -> errorMessage.append("functionName='").append(name).append("' "));
		throw new IllegalArgumentException(errorMessage.toString().trim());
	}

	private HighSymbol resolveHighSymbolInFunction(
			Program program,
			HighFunction highFunction,
			Optional<Long> varSymbolIdOpt,
			Optional<String> symbolAddressOpt,
			Optional<String> symbolStorageStringOpt,
			Optional<String> symbolNameOpt) {
		LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
		java.util.Iterator<HighSymbol> symbolsIterator;

		// 1. Try by Symbol ID
		if (varSymbolIdOpt.isPresent()) {
			long targetId = varSymbolIdOpt.get();
			symbolsIterator = localSymbolMap.getSymbols();
			while (symbolsIterator.hasNext()) {
				HighSymbol currentSym = symbolsIterator.next();
				if (currentSym.getSymbol() != null && currentSym.getSymbol().getID() == targetId) {
					return currentSym;
				}
			}
		}

		// 2. Try by Address / Register Name (symbolAddressOpt)
		if (symbolAddressOpt.isPresent()) {
			String addressOrReg = symbolAddressOpt.get();
			Address symAddress = program.getAddressFactory().getAddress(addressOrReg);
			symbolsIterator = localSymbolMap.getSymbols();
			while (symbolsIterator.hasNext()) {
				HighSymbol currentSym = symbolsIterator.next();
				VariableStorage storage = currentSym.getStorage();
				if (storage != null && !storage.isBadStorage()) {
					if (symAddress != null) {
						if (storage.contains(symAddress))
							return currentSym;
					} else {
						if (storage.isRegisterStorage() && storage.getRegister().getName().equalsIgnoreCase(addressOrReg)) {
							return currentSym;
						}
					}
				}
			}
		}

		// 3. Try by Storage String
		if (symbolStorageStringOpt.isPresent()) {
			String targetStorageStr = symbolStorageStringOpt.get();
			symbolsIterator = localSymbolMap.getSymbols();
			while (symbolsIterator.hasNext()) {
				HighSymbol currentSym = symbolsIterator.next();
				VariableStorage storage = currentSym.getStorage();
				if (storage != null && !storage.isBadStorage() && storage.toString().equalsIgnoreCase(targetStorageStr)) {
					return currentSym;
				}
			}
		}

		// 4. Try by Name
		if (symbolNameOpt.isPresent()) {
			String targetName = symbolNameOpt.get();
			symbolsIterator = localSymbolMap.getSymbols();
			while (symbolsIterator.hasNext()) {
				HighSymbol currentSym = symbolsIterator.next();
				if (currentSym.getName().equals(targetName)) {
					return currentSym;
				}
			}
		}

		StringBuilder criteria = new StringBuilder();
		varSymbolIdOpt.ifPresent(id -> criteria.append("ID='").append(id).append("', "));
		symbolAddressOpt.ifPresent(addr -> criteria.append("Address/Reg='").append(addr).append("', "));
		symbolStorageStringOpt.ifPresent(stor -> criteria.append("Storage='").append(stor).append("', "));
		symbolNameOpt.ifPresent(name -> criteria.append("Name='").append(name).append("', "));
		if (criteria.length() > 0) {
			criteria.setLength(criteria.length() - 2);
		} else {
			criteria.append(
					"No valid criteria ancountered during processing (this should not happen if initial validation passed).");
		}
		throw new IllegalArgumentException(
				"Symbol not found in function '" + highFunction.getFunction().getName() + "' using criteria: "
						+ criteria.toString());
	}
}