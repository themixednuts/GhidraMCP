package com.themixednuts.tools.functions;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.GhidraMcpErrorUtils;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get Function", category = ToolCategory.FUNCTIONS, description = "Gets details about a function specified either by its name or entry point address.", mcpName = "get_function", mcpDescription = "Get detailed information about a function in a Ghidra program. Use symbol ID, address, or function name to identify the function.")
public class GhidraGetFunctionTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_FUNCTION_SYMBOL_ID,
				JsonSchemaBuilder.integer(mapper)
						.description("The Symbol ID of the function to retrieve. Preferred identifier."));
		schemaRoot.property(ARG_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the function. Used if Symbol ID and Address are not provided or not found."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional entry point address of the function (e.g., '0x1004010'). Used if Symbol ID is not provided or not found.")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		return getProgram(args, tool)
				.flatMap(program -> executeInTransaction(program, annotation.mcpName(), () -> {
					FunctionManager functionManager = program.getFunctionManager();

					// Check for function symbol ID
					Optional<Long> symbolIdOpt = getOptionalLongArgument(args, ARG_FUNCTION_SYMBOL_ID);
					if (symbolIdOpt.isPresent()) {
						return handleFunctionBySymbolId(symbolIdOpt.get(), functionManager, program, annotation).block();
					}

					// Check for address
					Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
					if (addressOpt.isPresent()) {
						return handleFunctionByAddress(addressOpt.get(), functionManager, program, annotation).block();
					}

					// Check for function name
					Optional<String> functionNameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);
					if (functionNameOpt.isPresent()) {
						return handleFunctionByName(functionNameOpt.get(), functionManager, annotation).block();
					}

					// No valid search criteria provided - use structured error handling
					Map<String, Object> providedIdentifiers = Map.of(
							ARG_FUNCTION_SYMBOL_ID, "not provided",
							ARG_ADDRESS, "not provided",
							ARG_FUNCTION_NAME, "not provided");

					GhidraMcpError error = GhidraMcpError.validation()
							.errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
							.message("At least one identifier must be provided")
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
											null),
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
											"Explore available functions",
											"Use related tools to discover functions in the program",
											null,
											getRelatedFunctionToolNames() // Get tool names from annotations
					)))
							.build();

					throw new GhidraMcpException(error);
				}));
	}

	/**
	 * Retrieves all available function names from the FunctionManager.
	 * This method collects ALL functions to ensure fuzzy matching can consider
	 * the complete set, not just a limited subset.
	 * 
	 * @param functionManager The Ghidra FunctionManager
	 * @return A list of all function names in the program
	 */
	private List<String> getAllAvailableFunctionNames(FunctionManager functionManager) {
		return StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
				.map(f -> f.getName(true))
				.collect(Collectors.toList());
	}

	/**
	 * Retrieves a limited sample of function names for display in error messages.
	 * This provides a reasonable preview without overwhelming the user.
	 * 
	 * @param functionManager The Ghidra FunctionManager
	 * @param maxSamples      Maximum number of sample names to return
	 * @return A list of up to maxSamples function names
	 */
	private List<String> getSampleFunctionNames(FunctionManager functionManager, int maxSamples) {
		return StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
				.map(f -> f.getName(true))
				.limit(maxSamples)
				.collect(Collectors.toList());
	}

	/**
	 * Handles function lookup by name with enhanced error reporting.
	 * Uses ALL available functions for fuzzy matching to provide the best
	 * suggestions.
	 */
	private Mono<Object> handleFunctionByName(String functionName, FunctionManager functionManager,
			GhidraMcpTool annotation) {
		// Search for function by name across all functions
		FunctionIterator functions = functionManager.getFunctions(true);
		Function foundFunction = null;

		for (Function function : functions) {
			if (function.getName().equals(functionName)) {
				foundFunction = function;
				break;
			}
		}

		if (foundFunction != null) {
			return Mono.just(new FunctionInfo(foundFunction));
		}

		// Function not found - collect ALL function names for comprehensive fuzzy
		// matching
		List<String> allFunctionNames = getAllAvailableFunctionNames(functionManager);

		// Create search criteria for structured error
		Map<String, Object> searchCriteria = Map.of(
				ARG_FUNCTION_NAME, functionName);

		GhidraMcpError structuredError = GhidraMcpErrorUtils.functionNotFound(
				searchCriteria,
				annotation.mcpName(),
				allFunctionNames // Pass ALL function names for best fuzzy matching
		);

		return Mono.error(new GhidraMcpException(structuredError));
	}

	/**
	 * Handles function lookup by symbol ID with enhanced error reporting.
	 */
	private Mono<Object> handleFunctionBySymbolId(long symbolId, FunctionManager functionManager, Program program,
			GhidraMcpTool annotation) {
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol symbol = symbolTable.getSymbol(symbolId);

		if (symbol == null) {
			Map<String, Object> searchCriteria = Map.of(
					ARG_FUNCTION_SYMBOL_ID, symbolId);

			// Get sample function names for display (limited for performance)
			List<String> sampleFunctionNames = getSampleFunctionNames(functionManager, 50);

			GhidraMcpError structuredError = GhidraMcpErrorUtils.functionNotFound(
					searchCriteria,
					annotation.mcpName(),
					sampleFunctionNames);

			return Mono.error(new GhidraMcpException(structuredError));
		}

		Function function = functionManager.getFunctionAt(symbol.getAddress());
		if (function == null) {
			Map<String, Object> searchCriteria = Map.of(
					ARG_FUNCTION_SYMBOL_ID, symbolId,
					"symbolAddress", symbol.getAddress().toString(),
					"symbolName", symbol.getName());

			List<String> sampleFunctionNames = getSampleFunctionNames(functionManager, 50);

			GhidraMcpError structuredError = GhidraMcpErrorUtils.functionNotFound(
					searchCriteria,
					annotation.mcpName(),
					sampleFunctionNames);

			return Mono.error(new GhidraMcpException(structuredError));
		}

		return Mono.just(new FunctionInfo(function));
	}

	/**
	 * Handles function lookup by address with enhanced error reporting.
	 */
	private Mono<Object> handleFunctionByAddress(String addressStr, FunctionManager functionManager, Program program,
			GhidraMcpTool annotation) {
		try {
			Address address = program.getAddressFactory().getAddress(addressStr);
			Function function = functionManager.getFunctionAt(address);

			if (function != null) {
				return Mono.just(new FunctionInfo(function));
			}

			Map<String, Object> searchCriteria = Map.of(
					ARG_ADDRESS, addressStr);

			// Get sample function names for display (limited for performance)
			List<String> sampleFunctionNames = getSampleFunctionNames(functionManager, 50);

			GhidraMcpError structuredError = GhidraMcpErrorUtils.functionNotFound(
					searchCriteria,
					annotation.mcpName(),
					sampleFunctionNames);

			return Mono.error(new GhidraMcpException(structuredError));

		} catch (Exception e) {
			GhidraMcpError structuredError = GhidraMcpErrorUtils.addressParseError(
					addressStr,
					annotation.mcpName(),
					e);

			return Mono.error(new GhidraMcpException(structuredError));
		}
	}

	/**
	 * Gets MCP tool names from class annotations for related function tools.
	 * This avoids magic strings by dynamically reading annotation values.
	 */
	private List<String> getRelatedFunctionToolNames() {
		List<String> toolNames = new java.util.ArrayList<>();

		// Get MCP name for list function names tool
		GhidraMcpTool listNamesAnnotation = GhidraListFunctionNamesTool.class.getAnnotation(GhidraMcpTool.class);
		if (listNamesAnnotation != null && !listNamesAnnotation.mcpName().isBlank()) {
			toolNames.add(listNamesAnnotation.mcpName());
		}

		// Get MCP name for search functions by name tool
		GhidraMcpTool searchAnnotation = GhidraSearchFunctionsByNameTool.class.getAnnotation(GhidraMcpTool.class);
		if (searchAnnotation != null && !searchAnnotation.mcpName().isBlank()) {
			toolNames.add(searchAnnotation.mcpName());
		}

		return toolNames;
	}
}