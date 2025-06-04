package com.themixednuts.tools.functions;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.models.FunctionVariableInfo;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.util.task.ConsoleTaskMonitor;

@GhidraMcpTool(name = "List Function Variables", category = ToolCategory.FUNCTIONS, description = "Lists variables (listing and decompiler-generated) within a function, providing detailed information.", mcpName = "list_function_variables", mcpDescription = "List all variables within a specified function with detailed attributes. Includes parameters, local variables, and decompiler-generated symbols with pagination support.")
public class GhidraListFunctionVariablesTool implements IGhidraMcpSpecification {

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

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		return getProgram(args, tool).flatMap(program -> {
			Optional<Long> funcSymbolIdOpt = getOptionalLongArgument(args, ARG_FUNCTION_SYMBOL_ID);
			Optional<String> funcAddressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
			Optional<String> funcNameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);
			Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

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
				return Mono.error(new GhidraMcpException(error));
			}

			Function function = resolveFunction(program, funcSymbolIdOpt, funcAddressOpt, funcNameOpt);

			final Function finalFunction = function;
			final Program finalProgram = program;

			return Mono.fromCallable(() -> {
				Stream<FunctionVariableInfo> listingVarStream = Arrays.stream(finalFunction.getAllVariables())
						.map(FunctionVariableInfo::new);

				Stream<FunctionVariableInfo> decompilerVarStream = Stream.empty();
				DecompInterface decomplib = new DecompInterface();
				try {
					decomplib.setOptions(new DecompileOptions());
					decomplib.openProgram(finalProgram);
					DecompileResults results = decomplib.decompileFunction(finalFunction,
							decomplib.getOptions().getDefaultTimeout(), new ConsoleTaskMonitor());

					if (results == null) {
						// Decompiler failed but continue with listing variables only
						ghidra.util.Msg.warn(this, "Decompiler returned null results for function: " + finalFunction.getName());
					} else {
						HighFunction hf = results.getHighFunction();
						if (hf != null) {
							LocalSymbolMap localSymbolMap = hf.getLocalSymbolMap();
							if (localSymbolMap != null) {
								java.util.Iterator<HighSymbol> highSymbolIterator = localSymbolMap.getSymbols();
								decompilerVarStream = StreamSupport.stream(
										Spliterators.spliteratorUnknownSize(highSymbolIterator, Spliterator.ORDERED), false)
										.map(HighSymbol::getHighVariable)
										.filter(java.util.Objects::nonNull)
										.map(hv -> new FunctionVariableInfo(hv, finalProgram));
							}
						} else {
							ghidra.util.Msg.warn(this,
									"Decompilation did not yield a HighFunction for function: " + finalFunction.getName());
						}
					}
				} catch (Exception e) {
					// Log the error but continue with listing variables
					ghidra.util.Msg.error(this,
							"Error during decompilation for ListFunctionVariables: " + e.getMessage(), e);
				} finally {
					if (decomplib != null) {
						decomplib.dispose();
					}
				}

				List<FunctionVariableInfo> variablesToList = Stream.concat(listingVarStream, decompilerVarStream)
						.sorted(Comparator.comparing(FunctionVariableInfo::getStorage)
								.thenComparing(FunctionVariableInfo::getEffectiveName))
						.collect(Collectors.toList());

				final String finalCursorStr = cursorOpt.orElse(null);

				List<FunctionVariableInfo> paginatedVariables = variablesToList.stream()
						.dropWhile(varInfo -> {
							if (finalCursorStr == null)
								return false;

							String[] parts = finalCursorStr.split(":", 2);
							String cursorStorage = parts[0];
							String cursorName = parts.length > 1 ? parts[1] : "";

							int storageCompare = varInfo.getStorage().compareTo(cursorStorage);
							if (storageCompare < 0)
								return true;
							if (storageCompare == 0) {
								return varInfo.getEffectiveName().compareTo(cursorName) <= 0;
							}
							return false;
						})
						.limit(DEFAULT_PAGE_LIMIT + 1)
						.collect(Collectors.toList());

				boolean hasMore = paginatedVariables.size() > DEFAULT_PAGE_LIMIT;
				List<FunctionVariableInfo> resultsForPage = paginatedVariables.subList(0,
						Math.min(paginatedVariables.size(), DEFAULT_PAGE_LIMIT));
				String nextCursor = null;
				if (hasMore && !resultsForPage.isEmpty()) {
					FunctionVariableInfo lastItem = resultsForPage.get(resultsForPage.size() - 1);
					nextCursor = lastItem.getStorage() + ":" + lastItem.getEffectiveName();
				}

				return new PaginatedResult<>(resultsForPage, nextCursor);
			}).subscribeOn(reactor.core.scheduler.Schedulers.boundedElastic());
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
							Map.of("requestedOperation", "list variables"),
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
}