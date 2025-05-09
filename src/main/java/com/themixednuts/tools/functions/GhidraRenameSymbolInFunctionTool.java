package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;
import java.util.Arrays;

import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import io.modelcontextprotocol.server.McpAsyncServerExchange;

import reactor.core.publisher.Mono;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

@GhidraMcpTool(name = "Update Symbol in Function", category = ToolCategory.FUNCTIONS, description = "Renames a symbol (variable or parameter) within a specific function.", mcpName = "update_symbol_in_function", mcpDescription = "Renames a local variable or parameter within a function.")
public class GhidraRenameSymbolInFunctionTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));

		schemaRoot.property(ARG_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("Optional: Name of the function containing the symbol."))
				.property(ARG_FUNCTION_ADDRESS,
						JsonSchemaBuilder.string(mapper)
								.description("Optional: Entry point address of the function (e.g., '0x1004010').")
								.pattern("^(0x)?[0-9a-fA-F]+$"))
				.property(ARG_FUNCTION_SYMBOL_ID,
						JsonSchemaBuilder.integer(mapper)
								.description(
										"Optional: Symbol ID of the function. Preferred if other function identifiers are also provided."));

		schemaRoot.property(ARG_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("Optional: Current name of the local variable or parameter to rename."))
				.property("symbolAddress",
						JsonSchemaBuilder.string(mapper)
								.description(
										"Optional: Address of the symbol (variable/parameter) to rename. Useful if name is not unique or known.")
								.pattern("^(0x)?[0-9a-fA-F]+$"))
				.property(ARG_VARIABLE_SYMBOL_ID,
						JsonSchemaBuilder.integer(mapper)
								.description(
										"Optional: Symbol ID of the variable or parameter to rename. Preferred if other symbol identifiers are also provided."));

		schemaRoot.property(ARG_NEW_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The desired new name for the symbol."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_NEW_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			Optional<String> funcNameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);
			Optional<String> funcAddressOpt = getOptionalStringArgument(args, ARG_FUNCTION_ADDRESS);
			Optional<Long> funcSymbolIdOpt = getOptionalLongArgument(args, ARG_FUNCTION_SYMBOL_ID);

			Optional<String> symbolNameOpt = getOptionalStringArgument(args, ARG_NAME);
			Optional<String> symbolAddressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
			Optional<Long> symbolIdOpt = getOptionalLongArgument(args, ARG_VARIABLE_SYMBOL_ID);

			String newName = getRequiredStringArgument(args, ARG_NEW_NAME);

			if (funcNameOpt.isEmpty() && funcAddressOpt.isEmpty() && funcSymbolIdOpt.isEmpty()) {
				return Mono.error(new IllegalArgumentException(
						"At least one function identifier (functionName, functionAddress, or functionSymbolId) must be provided."));
			}
			if (symbolNameOpt.isEmpty() && symbolAddressOpt.isEmpty() && symbolIdOpt.isEmpty()) {
				return Mono.error(new IllegalArgumentException(
						"At least one target symbol identifier (name, symbolAddress, or symbolId) must be provided."));
			}

			return Mono.fromCallable(() -> {
				Function function = resolveFunction(program, funcSymbolIdOpt, funcAddressOpt, funcNameOpt);

				Symbol symbolToRename = resolveSymbolInFunction(program, function, symbolIdOpt, symbolAddressOpt,
						symbolNameOpt);

				return Map.entry(symbolToRename, newName);
			})
					.flatMap(entry -> {
						Symbol symbol = entry.getKey();
						String nameToSet = entry.getValue();
						String originalName = symbol.getName();
						return executeInTransaction(program, "MCP - Rename Symbol " + originalName, () -> {
							symbol.setName(nameToSet, SourceType.USER_DEFINED);
							return "Successfully renamed symbol '" + originalName + "' to '" + nameToSet + "'";
						});
					});
		});
	}

	// Adapted from GhidraUpdateFunctionVariableNameTool
	private Function resolveFunction(Program program, Optional<Long> funcSymbolIdOpt, Optional<String> funcAddressOpt,
			Optional<String> funcNameOpt) {
		FunctionManager funcMan = program.getFunctionManager();
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

	private Symbol resolveSymbolInFunction(Program program, Function function,
			Optional<Long> symbolIdOpt,
			Optional<String> symbolAddressOpt,
			Optional<String> symbolNameOpt) {
		// 1. Try by Symbol ID
		if (symbolIdOpt.isPresent()) {
			long id = symbolIdOpt.get();
			Symbol symbol = program.getSymbolTable().getSymbol(id);
			if (symbol != null) {
				// Check if this symbol is actually a parameter or local variable of *this*
				// function
				if (Arrays.stream(function.getParameters()).anyMatch(p -> p.getSymbol().equals(symbol)) ||
						Arrays.stream(function.getLocalVariables()).anyMatch(v -> v.getSymbol().equals(symbol))) {
					return symbol;
				} else {
					ghidra.util.Msg.warn(this,
							"Symbol with ID " + id + " found, but it does not belong to function " + function.getName());
				}
			}
		}

		// 2. Try by Symbol Address
		if (symbolAddressOpt.isPresent()) {
			Address symAddr = program.getAddressFactory().getAddress(symbolAddressOpt.get());
			if (symAddr != null) {
				Symbol[] symbolsAtAddr = program.getSymbolTable().getSymbols(symAddr);
				for (Symbol candidateSymbol : symbolsAtAddr) {
					if (Arrays.stream(function.getParameters()).anyMatch(p -> p.getSymbol().equals(candidateSymbol))) {
						if (symbolNameOpt.isEmpty() || candidateSymbol.getName().equals(symbolNameOpt.get())) {
							return candidateSymbol;
						}
					}
					if (Arrays.stream(function.getLocalVariables()).anyMatch(v -> v.getSymbol().equals(candidateSymbol))) {
						if (symbolNameOpt.isEmpty() || candidateSymbol.getName().equals(symbolNameOpt.get())) {
							return candidateSymbol;
						}
					}
				}
			} else {
				ghidra.util.Msg.warn(this, "Invalid symbolAddress format: " + symbolAddressOpt.get());
			}
		}

		// 3. Try by Name
		if (symbolNameOpt.isPresent()) {
			String currentName = symbolNameOpt.get();
			Optional<Parameter> paramOpt = Arrays.stream(function.getParameters())
					.filter(p -> p.getName().equals(currentName))
					.findFirst();
			if (paramOpt.isPresent()) {
				return paramOpt.get().getSymbol();
			}

			Optional<Variable> varOpt = Arrays.stream(function.getLocalVariables())
					.filter(v -> v.getName().equals(currentName))
					.findFirst();
			if (varOpt.isPresent()) {
				return varOpt.get().getSymbol();
			}
		}

		StringBuilder errorMessage = new StringBuilder("Symbol to rename not found in function '")
				.append(function.getName())
				.append("' using identifiers: ");
		symbolIdOpt.ifPresent(id -> errorMessage.append("symbolId='").append(id).append("' "));
		symbolAddressOpt.ifPresent(addr -> errorMessage.append("symbolAddress='").append(addr).append("' "));
		symbolNameOpt.ifPresent(name -> errorMessage.append("name='").append(name).append("' "));
		throw new IllegalArgumentException(errorMessage.toString().trim());
	}
}
