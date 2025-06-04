package com.themixednuts.tools.functions;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.StreamSupport;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get Function Prototype", category = ToolCategory.FUNCTIONS, description = "Retrieves the full signature string for a function.", mcpName = "get_function_prototype", mcpDescription = "Get the complete function signature including return type, name, parameters, and calling convention. Returns the current function prototype in Ghidra's standard format.")
public class GhidraGetFunctionPrototypeTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_FUNCTION_SYMBOL_ID,
				JsonSchemaBuilder.integer(mapper)
						.description("The Symbol ID of the function. Preferred identifier."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("Optional entry point address of the function. Used if Symbol ID is not provided.")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the function. Used if Symbol ID and Address are not provided."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		return getProgram(args, tool).map(program -> {
			Optional<Long> funcSymbolIdOpt = getOptionalLongArgument(args, ARG_FUNCTION_SYMBOL_ID);
			Optional<String> funcAddressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
			Optional<String> funcNameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);

			// Check if at least one identifier is provided
			if (funcSymbolIdOpt.isEmpty() && funcAddressOpt.isEmpty() && funcNameOpt.isEmpty()) {
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
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			Function functionToReturn = null;
			FunctionManager functionManager = program.getFunctionManager();
			SymbolTable symbolTable = program.getSymbolTable();

			// Try to find function by symbol ID first
			if (funcSymbolIdOpt.isPresent()) {
				long symId = funcSymbolIdOpt.get();
				Symbol symbol = symbolTable.getSymbol(symId);
				if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
					functionToReturn = functionManager.getFunctionAt(symbol.getAddress());
				}
			}

			// Try to find function by address if not found by symbol ID
			if (functionToReturn == null && funcAddressOpt.isPresent()) {
				String addressString = funcAddressOpt.get();
				try {
					Address entryPointAddress = program.getAddressFactory().getAddress(addressString);
					if (entryPointAddress != null) {
						functionToReturn = functionManager.getFunctionAt(entryPointAddress);
					} else {
						// Only throw error if this is the only identifier provided
						if (funcNameOpt.isEmpty() && funcSymbolIdOpt.isEmpty()) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
									.message("Invalid address format")
									.context(new GhidraMcpError.ErrorContext(
											annotation.mcpName(),
											"address parsing",
											args,
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
										args,
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
			if (functionToReturn == null && funcNameOpt.isPresent()) {
				String functionName = funcNameOpt.get();
				functionToReturn = StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
						.filter(f -> f.getName(true).equals(functionName))
						.findFirst()
						.orElse(null);
			}

			// If still not found, create structured error
			if (functionToReturn == null) {
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
								args,
								searchCriteria,
								Map.of("searchAttempted", true, "functionFound", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Verify the function exists with provided identifiers",
										"Use function listing tools to verify function existence",
										null,
										null),
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Double-check identifier values",
										"Ensure symbol ID, address, or name are correct and current",
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			return functionToReturn.getSignature(true).getPrototypeString();
		});
	}
}