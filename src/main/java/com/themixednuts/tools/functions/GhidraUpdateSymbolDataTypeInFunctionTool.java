package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.cmd.function.SetVariableDataTypeCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.data.DataTypeParser;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuples;

@GhidraMcpTool(name = "Update Symbol Data Type In Function", category = ToolCategory.FUNCTIONS, description = "Changes the data type of a local variable or parameter within a specific function.", mcpName = "update_symbol_data_type_in_function", mcpDescription = "Changes the data type of a local variable or parameter within a function.")
public class GhidraUpdateSymbolDataTypeInFunctionTool implements IGhidraMcpSpecification {

	// Removed local constants: ARG_VARIABLE_NAME, ARG_VARIABLE_SYMBOL_ID,
	// ARG_VARIABLE_STORAGE_STRING

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));

		// Function Identification Properties (Optional, at least one required)
		schemaRoot.property(ARG_FUNCTION_SYMBOL_ID,
				JsonSchemaBuilder.integer(mapper)
						.description("Optional: Symbol ID of the function. Preferred identifier."))
				.property(ARG_ADDRESS, // For function address
						JsonSchemaBuilder.string(mapper)
								.description(
										"Optional: Entry point address of the function (e.g., '0x1004010'). Used if Symbol ID is not provided or not found.")
								.pattern("^(0x)?[0-9a-fA-F]+$"))
				.property(ARG_FUNCTION_NAME, // Now optional
						JsonSchemaBuilder.string(mapper)
								.description(
										"Optional: Name of the function. Used if Symbol ID and Address are not provided or not found."));

		// Variable Identification Properties (Optional, at least one required)
		schemaRoot.property(ARG_VARIABLE_SYMBOL_ID, // Use interface constant
				JsonSchemaBuilder.integer(mapper)
						.description(
								"Optional: The Symbol ID of the local variable or parameter. Preferred identifier for the variable."))
				.property(ARG_STORAGE_STRING, // Use interface constant
						JsonSchemaBuilder.string(mapper)
								.description("Optional: The storage string of the variable (e.g., 'Stack[-0x8]', 'EAX')."))
				.property(ARG_NAME, // Use interface constant for variable name
						JsonSchemaBuilder.string(mapper)
								.description("Optional: The current name of the local variable or parameter."));

		schemaRoot.property(ARG_DATA_TYPE_PATH, // Required
				JsonSchemaBuilder.string(mapper)
						.description("The name of the new data type to apply (e.g., 'int', 'char*', 'MyStruct')."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				// .requiredProperty(ARG_FUNCTION_NAME) // No longer required, checked in
				// execute
				.requiredProperty(ARG_DATA_TYPE_PATH);
		// Validation for at least one func id and one var id done in execute

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					// Function Identifiers
					Optional<Long> funcSymbolIdOpt = getOptionalLongArgument(args, ARG_FUNCTION_SYMBOL_ID);
					Optional<String> funcAddressOpt = getOptionalStringArgument(args, ARG_ADDRESS); // For function address
					Optional<String> funcNameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);

					// Variable Identifiers
					Optional<Long> varSymbolIdOpt = getOptionalLongArgument(args, ARG_VARIABLE_SYMBOL_ID); // Was symbolIdOpt
					Optional<String> varStorageOpt = getOptionalStringArgument(args, ARG_STORAGE_STRING); // Was storageStringOpt
					Optional<String> varNameOpt = getOptionalStringArgument(args, ARG_NAME); // Was variableNameOpt

					String newDataTypePath = getRequiredStringArgument(args, ARG_DATA_TYPE_PATH);

					if (funcSymbolIdOpt.isEmpty() && funcAddressOpt.isEmpty() && funcNameOpt.isEmpty()) {
						throw new IllegalArgumentException(
								"At least one function identifier (functionSymbolId, address, or functionName) must be provided.");
					}
					if (varNameOpt.isEmpty() && varSymbolIdOpt.isEmpty() && varStorageOpt.isEmpty()) {
						throw new IllegalArgumentException(
								"At least one variable identifier must be provided: '" + ARG_NAME + "', '"
										+ ARG_VARIABLE_SYMBOL_ID + "', or '" + ARG_STORAGE_STRING + "'.");
					}

					Function function = resolveFunction(program, funcSymbolIdOpt, funcAddressOpt, funcNameOpt); // To be added

					Variable variableToUpdate = resolveVariable(program, function, varSymbolIdOpt, varStorageOpt,
							varNameOpt);
					DataType newDataType = parseDataType(program, newDataTypePath);

					return Tuples.of(program, variableToUpdate, newDataType);
				})
				.flatMap(tuple -> {
					Program program = tuple.getT1();
					Variable variable = tuple.getT2();
					DataType dataType = tuple.getT3();
					String varName = variable.getName();
					String dtName = dataType.getName();

					return executeInTransaction(program, "MCP - Update Symbol Data Type: " + varName,
							() -> {
								SetVariableDataTypeCmd cmd = new SetVariableDataTypeCmd(variable, dataType, SourceType.USER_DEFINED);
								if (!cmd.applyTo(program)) {
									throw new RuntimeException("Failed to apply data type change: " + cmd.getStatusMsg());
								}
								return "Successfully updated data type for symbol '" + varName + "' to '" + dtName + "'";
							});
				});
	}

	private Variable resolveVariable(Program program, Function function,
			Optional<Long> varSymbolIdOpt, Optional<String> varStorageOpt, Optional<String> varNameOpt) { // Signature updated
																																																		// to match call

		// 1. Try by Symbol ID
		if (varSymbolIdOpt.isPresent()) { // Using varSymbolIdOpt
			long targetId = varSymbolIdOpt.get();
			for (Variable var : function.getVariables(null)) {
				if (var.getSymbol().getID() == targetId) {
					return var;
				}
			}
		}

		// 2. Try by storage string representation
		if (varStorageOpt.isPresent()) { // Using varStorageOpt
			String targetStorage = varStorageOpt.get();
			for (Variable var : function.getVariables(null)) {
				if (var.getVariableStorage().toString().equalsIgnoreCase(targetStorage)) {
					return var;
				}
			}
		}

		// 3. Try by name
		if (varNameOpt.isPresent()) { // Using varNameOpt
			String targetName = varNameOpt.get();
			for (Variable var : function.getVariables(null)) {
				if (var.getName().equals(targetName)) {
					return var;
				}
			}
		}

		// Build a comprehensive error message
		StringBuilder attemptedCriteria = new StringBuilder();
		if (varSymbolIdOpt.isPresent()) // Using varSymbolIdOpt
			attemptedCriteria.append("ID '").append(varSymbolIdOpt.get()).append("', ");
		if (varStorageOpt.isPresent()) // Using varStorageOpt
			attemptedCriteria.append("Storage String '").append(varStorageOpt.get()).append("', ");
		if (varNameOpt.isPresent()) // Using varNameOpt
			attemptedCriteria.append("Name '").append(varNameOpt.get()).append("', ");
		if (attemptedCriteria.length() > 0) {
			attemptedCriteria.setLength(attemptedCriteria.length() - 2); // Remove last ", "
		} else {
			attemptedCriteria.append("any provided criteria (this should not happen if initial check passed)");
		}

		throw new IllegalArgumentException(
				"Variable not found in function '" + function.getName() + "' using criteria: " + attemptedCriteria.toString());
	}

	private DataType parseDataType(Program program, String newDataTypePath) {
		DataTypeManager dtm = program.getDataTypeManager();
		try {
			DataTypeParser parser = new DataTypeParser(dtm, dtm, null, DataTypeParser.AllowedDataTypes.ALL);
			DataType newDataType = parser.parse(newDataTypePath);
			if (newDataType == null) {
				throw new IllegalArgumentException("Data type not found or invalid: " + newDataTypePath);
			}
			return newDataType;
		} catch (Exception e) {
			throw new IllegalArgumentException("Failed to parse data type '" + newDataTypePath + "': " + e.getMessage(), e);
		}
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
		funcAddressOpt.ifPresent(addr -> errorMessage.append("address='").append(addr).append("' "));
		funcNameOpt.ifPresent(name -> errorMessage.append("functionName='").append(name).append("' "));
		throw new IllegalArgumentException(errorMessage.toString().trim());
	}
}
