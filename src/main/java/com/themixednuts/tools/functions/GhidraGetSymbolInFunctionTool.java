package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;
import java.util.List;
import java.util.stream.StreamSupport;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.models.HighSymbolInfo;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get Symbol in Function", category = ToolCategory.FUNCTIONS, description = "Gets details about a symbol (variable or parameter) within a specific function by its name or storage address.", mcpName = "get_symbol_in_function", mcpDescription = """
		<use_case>
		Get detailed information about a specific symbol within a function using decompiler analysis. Retrieves variables and parameters with full storage and type information.
		</use_case>

		<important_notes>
		- Requires successful function decompilation
		- Uses high-level symbol information from decompiler
		- Function identified by Symbol ID (preferred), address, or name
		- Symbol identified by Variable Symbol ID (preferred), storage string, address, or name
		</important_notes>

		<example>
		To find parameter details: provide function address and parameter name. To find local variable: provide function name and storage location like 'Stack[-0x8]'.
		</example>

		<workflow>
		1. Identify target function using provided identifiers
		2. Decompile function to access high-level symbol information
		3. Locate specific symbol using provided criteria
		4. Return complete symbol details including storage and type information
		</workflow>
		""")
public class GhidraGetSymbolInFunctionTool implements IGhidraMcpSpecification {

	public static final String ARG_FILE_NAME = "fileName";
	public static final String ARG_FUNCTION_SYMBOL_ID = "functionSymbolId";
	public static final String ARG_FUNCTION_ADDRESS = "functionAddress";
	public static final String ARG_FUNCTION_NAME = "functionName";
	public static final String ARG_VARIABLE_SYMBOL_ID = "variableSymbolId";
	public static final String ARG_ADDRESS = "address";
	public static final String ARG_STORAGE_STRING = "storageString";
	public static final String ARG_NAME = "name";

	/**
	 * Helper method to get MCP tool name from annotation for error suggestions.
	 */
	private String getRelatedToolMcpName(Class<? extends IGhidraMcpSpecification> toolClass) {
		GhidraMcpTool annotation = toolClass.getAnnotation(GhidraMcpTool.class);
		return annotation != null ? annotation.mcpName() : toolClass.getSimpleName();
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));

		// Function Identification Properties
		schemaRoot.property(ARG_FUNCTION_SYMBOL_ID,
				JsonSchemaBuilder.integer(mapper)
						.description("The Symbol ID of the function. Preferred identifier."))
				.property(ARG_ADDRESS,
						JsonSchemaBuilder.string(mapper)
								.description("The entry point address of the function. Used if Symbol ID is not provided.")
								.pattern("^(0x)?[0-9a-fA-F]+$"))
				.property(ARG_FUNCTION_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("The name of the function. Used if Symbol ID and Address are not provided."));

		// Symbol Identification Properties
		schemaRoot.property(ARG_VARIABLE_SYMBOL_ID,
				JsonSchemaBuilder.integer(mapper)
						.description("The Symbol ID of the variable or parameter. Preferred identifier."))
				.property(ARG_ADDRESS,
						JsonSchemaBuilder.string(mapper)
								.description("The address or register name where the symbol is stored."))
				.property(ARG_STORAGE_STRING,
						JsonSchemaBuilder.string(mapper)
								.description("The storage string of the symbol (e.g., 'Stack[-0x8]', 'EAX')."))
				.property(ARG_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("The name of the symbol to retrieve."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		DecompInterface decomp = new DecompInterface();

		return getProgram(args, tool).flatMap(program -> {
			return Mono.fromCallable(() -> {
				// Function Identifiers
				Optional<Long> funcSymbolIdOpt = getOptionalLongArgument(args, ARG_FUNCTION_SYMBOL_ID);
				Optional<String> funcAddressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
				Optional<String> funcNameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);

				// Target Symbol in Function Identifiers
				Optional<Long> varSymbolIdOpt = getOptionalLongArgument(args, ARG_VARIABLE_SYMBOL_ID);
				Optional<String> symbolAddressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
				Optional<String> symbolStorageStringOpt = getOptionalStringArgument(args, ARG_STORAGE_STRING);
				Optional<String> symbolNameOpt = getOptionalStringArgument(args, ARG_NAME);

				// Validate function identifiers
				if (funcSymbolIdOpt.isEmpty() && funcAddressOpt.isEmpty() && funcNameOpt.isEmpty()) {
					Map<String, Object> providedIdentifiers = Map.of(
							ARG_FUNCTION_SYMBOL_ID, "not provided",
							ARG_ADDRESS, "not provided",
							ARG_FUNCTION_NAME, "not provided");

					GhidraMcpError error = GhidraMcpError.validation()
							.errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
							.message("At least one function identifier must be provided")
							.context(new GhidraMcpError.ErrorContext(
									annotation.mcpName(),
									"function identifier validation",
									args,
									providedIdentifiers,
									Map.of("identifiersProvided", 0, "minimumRequired", 1)))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
											"Provide at least one function identifier",
											"Include at least one of: " + ARG_FUNCTION_SYMBOL_ID + ", " + ARG_ADDRESS + ", or "
													+ ARG_FUNCTION_NAME,
											List.of(
													"\"" + ARG_FUNCTION_SYMBOL_ID + "\": 12345",
													"\"" + ARG_ADDRESS + "\": \"0x401000\"",
													"\"" + ARG_FUNCTION_NAME + "\": \"main\""),
											null)))
							.build();
					throw new GhidraMcpException(error);
				}

				// Validate symbol identifiers
				if (varSymbolIdOpt.isEmpty() && symbolAddressOpt.isEmpty() && symbolStorageStringOpt.isEmpty()
						&& symbolNameOpt.isEmpty()) {
					Map<String, Object> providedIdentifiers = Map.of(
							ARG_VARIABLE_SYMBOL_ID, "not provided",
							ARG_ADDRESS, "not provided",
							ARG_STORAGE_STRING, "not provided",
							ARG_NAME, "not provided");

					GhidraMcpError error = GhidraMcpError.validation()
							.errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
							.message("At least one symbol identifier must be provided")
							.context(new GhidraMcpError.ErrorContext(
									annotation.mcpName(),
									"symbol identifier validation",
									args,
									providedIdentifiers,
									Map.of("identifiersProvided", 0, "minimumRequired", 1)))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
											"Provide at least one symbol identifier",
											"Include at least one of: " + ARG_VARIABLE_SYMBOL_ID + ", " + ARG_ADDRESS + ", "
													+ ARG_STORAGE_STRING + ", or " + ARG_NAME,
											List.of(
													"\"" + ARG_VARIABLE_SYMBOL_ID + "\": 12345",
													"\"" + ARG_ADDRESS + "\": \"EAX\"",
													"\"" + ARG_STORAGE_STRING + "\": \"Stack[-0x8]\"",
													"\"" + ARG_NAME + "\": \"param1\""),
											List.of(getRelatedToolMcpName(
													com.themixednuts.tools.functions.GhidraListFunctionVariablesTool.class)))))
							.build();
					throw new GhidraMcpException(error);
				}

				Function function = resolveFunction(program, funcSymbolIdOpt, funcAddressOpt, funcNameOpt);

				decomp.openProgram(program);
				GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex, this.getClass().getSimpleName());
				DecompileResults result = decomp.decompileFunction(function, 30, monitor);

				if (result == null || !result.decompileCompleted()) {
					String errorMsg = result != null ? result.getErrorMessage() : "Unknown decompiler error";
					GhidraMcpError error = GhidraMcpError.execution()
							.errorCode(GhidraMcpError.ErrorCode.DECOMPILATION_FAILED)
							.message("Decompilation failed: " + errorMsg)
							.context(new GhidraMcpError.ErrorContext(
									annotation.mcpName(),
									"function decompilation",
									Map.of(ARG_FUNCTION_NAME, function.getName()),
									Map.of("decompileError", errorMsg),
									Map.of("decompileCompleted", false)))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.ALTERNATIVE_APPROACH,
											"Try using listing variables instead",
											"Use tools that work with listing variables rather than decompiler symbols",
											null,
											List.of(getRelatedToolMcpName(
													com.themixednuts.tools.functions.GhidraListFunctionVariablesTool.class))),
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
											"Verify function can be decompiled",
											"Ensure the function is properly analyzed and not corrupted",
											null,
											null)))
							.build();
					throw new GhidraMcpException(error);
				}

				HighFunction highFunction = result.getHighFunction();
				if (highFunction == null) {
					GhidraMcpError error = GhidraMcpError.execution()
							.errorCode(GhidraMcpError.ErrorCode.DECOMPILATION_FAILED)
							.message("Decompilation failed (no high function)")
							.context(new GhidraMcpError.ErrorContext(
									annotation.mcpName(),
									"high function extraction",
									Map.of(ARG_FUNCTION_NAME, function.getName()),
									Map.of("highFunctionAvailable", false),
									Map.of("decompileCompleted", true, "highFunction", false)))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.ALTERNATIVE_APPROACH,
											"Use listing-based variable tools instead",
											"Try accessing variables through the function listing rather than decompiler",
											null,
											List.of(getRelatedToolMcpName(
													com.themixednuts.tools.functions.GhidraListFunctionVariablesTool.class)))))
							.build();
					throw new GhidraMcpException(error);
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

	// Helper method to resolve function by Symbol ID, Address, or Name with
	// structured error handling
	private Function resolveFunction(Program program, Optional<Long> funcSymbolIdOpt, Optional<String> funcAddressOpt,
			Optional<String> funcNameOpt) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		FunctionManager funcMan = program.getFunctionManager();
		SymbolTable symbolTable = program.getSymbolTable();
		Function function = null;

		// Try to find function by symbol ID first
		if (funcSymbolIdOpt.isPresent()) {
			long symId = funcSymbolIdOpt.get();
			Symbol symbol = symbolTable.getSymbol(symId);
			if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
				function = funcMan.getFunctionAt(symbol.getAddress());
			}
		}

		// Try to find function by address if not found by symbol ID
		if (function == null && funcAddressOpt.isPresent()) {
			String addressString = funcAddressOpt.get();
			try {
				Address entryPointAddress = program.getAddressFactory().getAddress(addressString);
				if (entryPointAddress != null) {
					function = funcMan.getFunctionAt(entryPointAddress);
				} else {
					// Only throw error if this is the only identifier provided
					if (funcNameOpt.isEmpty() && funcSymbolIdOpt.isEmpty()) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Invalid address format")
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"address parsing",
										Map.of(ARG_ADDRESS, addressString),
										Map.of(ARG_ADDRESS, addressString),
										Map.of("expectedFormat", "hexadecimal address", "providedValue", addressString)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use valid hexadecimal address format",
												"Provide address as hexadecimal value",
												List.of("0x401000", "401000", "0x00401000"),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}
				}
			} catch (Exception e) {
				if (e instanceof GhidraMcpException) {
					throw e; // Re-throw structured error
				}
				// Only throw error if this is the only identifier provided
				if (funcNameOpt.isEmpty() && funcSymbolIdOpt.isEmpty()) {
					GhidraMcpError error = GhidraMcpError.validation()
							.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
							.message("Failed to parse address: " + e.getMessage())
							.context(new GhidraMcpError.ErrorContext(
									annotation.mcpName(),
									"address parsing",
									Map.of(ARG_ADDRESS, addressString),
									Map.of(ARG_ADDRESS, addressString),
									Map.of("parseError", e.getMessage(), "providedValue", addressString)))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
											"Use valid address format for the current program",
											"Ensure address exists in the program's address space",
											List.of("0x401000", "401000"),
											null)))
							.build();
					throw new GhidraMcpException(error);
				}
			}
		}

		// Try to find function by name if not found by other methods
		if (function == null && funcNameOpt.isPresent()) {
			String functionName = funcNameOpt.get();
			function = StreamSupport.stream(funcMan.getFunctions(true).spliterator(), false)
					.filter(f -> f.getName(true).equals(functionName))
					.findFirst()
					.orElse(null);
		}

		// If still not found, create structured error
		if (function == null) {
			Map<String, Object> searchCriteria = Map.of(
					ARG_FUNCTION_SYMBOL_ID, funcSymbolIdOpt.map(Object::toString).orElse("not provided"),
					ARG_ADDRESS, funcAddressOpt.orElse("not provided"),
					ARG_FUNCTION_NAME, funcNameOpt.orElse("not provided"));

			GhidraMcpError error = GhidraMcpError.resourceNotFound()
					.errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
					.message("Function not found using any of the provided identifiers")
					.context(new GhidraMcpError.ErrorContext(
							annotation.mcpName(),
							"function lookup",
							Map.of("requestedOperation", "get symbol"),
							searchCriteria,
							Map.of("searchAttempted", true, "functionFound", false)))
					.suggestions(List.of(
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
									"Verify the function exists with provided identifiers",
									"Use function listing tools to verify function existence",
									null,
									List.of(getRelatedToolMcpName(com.themixednuts.tools.functions.GhidraListFunctionNamesTool.class))),
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
									"Double-check identifier values",
									"Ensure symbol ID, address, or name are correct and current",
									null,
									null)))
					.build();
			throw new GhidraMcpException(error);
		}

		return function;
	}

	private HighSymbol resolveHighSymbolInFunction(
			Program program,
			HighFunction highFunction,
			Optional<Long> varSymbolIdOpt,
			Optional<String> symbolAddressOpt,
			Optional<String> symbolStorageStringOpt,
			Optional<String> symbolNameOpt) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
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

		// If symbol not found, create structured error
		Map<String, Object> searchCriteria = Map.of(
				ARG_VARIABLE_SYMBOL_ID, varSymbolIdOpt.map(Object::toString).orElse("not provided"),
				ARG_ADDRESS, symbolAddressOpt.orElse("not provided"),
				ARG_STORAGE_STRING, symbolStorageStringOpt.orElse("not provided"),
				ARG_NAME, symbolNameOpt.orElse("not provided"));

		GhidraMcpError error = GhidraMcpError.resourceNotFound()
				.errorCode(GhidraMcpError.ErrorCode.SYMBOL_NOT_FOUND)
				.message("Symbol not found in function '" + highFunction.getFunction().getName() + "'")
				.context(new GhidraMcpError.ErrorContext(
						annotation.mcpName(),
						"symbol lookup in function: " + highFunction.getFunction().getName(),
						Map.of("requestedOperation", "get symbol"),
						searchCriteria,
						Map.of("searchAttempted", true, "functionFound", true, "symbolFound", false)))
				.suggestions(List.of(
						new GhidraMcpError.ErrorSuggestion(
								GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
								"Verify the symbol exists in the specified function",
								"Use function variable listing tools to see available symbols",
								null,
								List.of(getRelatedToolMcpName(com.themixednuts.tools.functions.GhidraListFunctionVariablesTool.class))),
						new GhidraMcpError.ErrorSuggestion(
								GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
								"Double-check symbol identifier values",
								"Ensure symbol ID, address, storage string, or name are correct for this function",
								null,
								null)))
				.build();
		throw new GhidraMcpException(error);
	}
}