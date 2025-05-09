package com.themixednuts.tools.functions;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.Varnode;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.CategoryPath;

@GhidraMcpTool(name = "Update Function Variable Name", description = "Sets or changes the name and optionally the data type of a local variable (e.g., stack variable, parameter) within a function.", category = ToolCategory.FUNCTIONS, mcpName = "update_function_variable_name", mcpDescription = "Sets or updates the name and optionally data type of a local variable within a specific function.")
public class GhidraUpdateFunctionVariableNameTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."),
				true);

		schemaRoot.property(ARG_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("Optional: Name of the function containing the variable."),
				false);
		schemaRoot.property(ARG_FUNCTION_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("Optional: Entry point address of the function (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"),
				false);
		schemaRoot.property(ARG_FUNCTION_SYMBOL_ID,
				JsonSchemaBuilder.integer(mapper)
						.description(
								"Optional: Symbol ID of the function. Preferred if other function identifiers are also provided."),
				false);

		schemaRoot.property(ARG_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("Optional: Current name of the variable to be renamed."),
				false);
		schemaRoot.property(ARG_STORAGE_STRING,
				JsonSchemaBuilder.string(mapper)
						.description("Optional: Storage string of the variable (e.g., 'Stack[-0x8]', 'EAX')."),
				false);
		schemaRoot.property(ARG_VARIABLE_SYMBOL_ID,
				JsonSchemaBuilder.integer(mapper)
						.description(
								"Optional: Symbol ID of the variable. Preferred if other variable identifiers are also provided."),
				false);

		schemaRoot.property(ARG_DATA_TYPE,
				JsonSchemaBuilder.string(mapper)
						.description("Optional: New data type for the variable (e.g., 'int', 'char *', '/Category/MyStruct')."),
				false);

		schemaRoot.property(ARG_NEW_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The new desired name for the variable."),
				true);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		Mono<Program> programMono = getProgram(args, tool);

		return programMono.flatMap(program -> {
			Optional<String> funcNameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);
			Optional<String> funcAddressOpt = getOptionalStringArgument(args, ARG_FUNCTION_ADDRESS);
			Optional<Long> funcSymbolIdOpt = getOptionalLongArgument(args, ARG_FUNCTION_SYMBOL_ID);

			Optional<String> varCurrentNameOpt = getOptionalStringArgument(args, ARG_NAME);
			Optional<String> varStorageOpt = getOptionalStringArgument(args, ARG_STORAGE_STRING);
			Optional<Long> varSymbolIdOpt = getOptionalLongArgument(args, ARG_VARIABLE_SYMBOL_ID);
			Optional<String> newDataTypeStrOpt = getOptionalStringArgument(args, ARG_DATA_TYPE);

			String newVarName = getRequiredStringArgument(args, ARG_NEW_NAME);

			if (funcNameOpt.isEmpty() && funcAddressOpt.isEmpty() && funcSymbolIdOpt.isEmpty()) {
				return Mono.error(new IllegalArgumentException(
						"At least one function identifier (functionName, functionAddress, or functionSymbolId) must be provided."));
			}
			if (varCurrentNameOpt.isEmpty() && varStorageOpt.isEmpty() && varSymbolIdOpt.isEmpty()) {
				return Mono.error(new IllegalArgumentException(
						"At least one variable identifier (name, storageString, or variableSymbolId) must be provided."));
			}

			Function function;
			try {
				function = resolveFunction(program, funcSymbolIdOpt, funcAddressOpt, funcNameOpt);
			} catch (IllegalArgumentException e) {
				return Mono.error(e);
			}

			String originalIdentifierForMsg = varCurrentNameOpt
					.orElse(varStorageOpt.orElse(varSymbolIdOpt.map(String::valueOf).orElse("unknown")));

			try {
				validateVariableNameSyntax(newVarName);
			} catch (InvalidInputException e) {
				return Mono.error(new IllegalArgumentException("Invalid new variable name: " + e.getMessage(), e));
			}

			DataType newDataType = null;
			if (newDataTypeStrOpt.isPresent() && !newDataTypeStrOpt.get().isBlank()) {
				DataTypeManager dtm = program.getDataTypeManager();
				newDataType = dtm.getDataType(newDataTypeStrOpt.get());
				if (newDataType == null) {
					newDataType = dtm.getDataType(new CategoryPath(newDataTypeStrOpt.get()),
							newDataTypeStrOpt.get().substring(newDataTypeStrOpt.get().lastIndexOf("/") + 1));
				}
				if (newDataType == null) {
					return Mono.error(new IllegalArgumentException("Data type not found: " + newDataTypeStrOpt.get()));
				}
			}
			final DataType finalNewDataType = newDataType;

			Optional<Variable> listingVarOpt = resolveListingVariable(function, varSymbolIdOpt, varStorageOpt,
					varCurrentNameOpt);

			if (listingVarOpt.isPresent()) {
				return renameExistingListingVariable(program, function, listingVarOpt.get(), newVarName, finalNewDataType,
						originalIdentifierForMsg);
			} else {
				DecompInterface decomp = null;
				try {
					decomp = new DecompInterface();
					decomp.setOptions(new DecompileOptions());
					decomp.openProgram(program);
					GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex,
							this.getClass().getSimpleName() + " (UpdateVariableName)");

					DecompileResults results = decomp.decompileFunction(function, decomp.getOptions().getDefaultTimeout(),
							monitor);
					HighFunction hf = results.getHighFunction();

					if (hf == null) {
						return Mono.error(new IllegalStateException(
								"Decompilation did not yield a HighFunction for: " + function.getName()
										+ ", cannot check decompiler for variable: " + originalIdentifierForMsg));
					}

					Optional<HighSymbol> hsOpt = resolveHighSymbolRepresentation(hf, varSymbolIdOpt, varStorageOpt,
							varCurrentNameOpt);

					if (hsOpt.isPresent()) {
						HighSymbol highSymbol = hsOpt.get();
						ghidra.program.model.symbol.Symbol backingSymbol = highSymbol.getSymbol();

						if (backingSymbol instanceof Variable) {
							Msg.info(this, "Variable '" + originalIdentifierForMsg +
									"' found via decompiler, mapping to existing listing variable. Proceeding with rename/retype.");
							return renameExistingListingVariable(program, function, (Variable) backingSymbol, newVarName,
									finalNewDataType, originalIdentifierForMsg);
						} else if (backingSymbol == null) {
							Msg.info(this, "Variable '" + originalIdentifierForMsg +
									"' identified as a decompiler-only symbol. Attempting to rename/retype using HighFunctionDBUtil.updateDBVariable.");

							final String finalNewName = newVarName;
							final HighSymbol finalHighSymbol = highSymbol;
							final String finalOriginalIdentifier = originalIdentifierForMsg;
							final Function finalFunction = function;

							try {
								validateVariableNameSyntax(finalNewName);
							} catch (InvalidInputException e) {
								return Mono
										.error(new IllegalArgumentException("Invalid new variable name syntax: " + e.getMessage(), e));
							}

							return executeInTransaction(program,
									"Update Decompiler Symbol in DB: " + finalOriginalIdentifier + " to " + finalNewName + " in function "
											+ finalFunction.getName(),
									() -> {
										String oldNameForMessage = finalHighSymbol.getName();
										try {
											HighFunctionDBUtil.updateDBVariable(finalHighSymbol, finalNewName, finalNewDataType,
													SourceType.USER_DEFINED);
										} catch (DuplicateNameException | InvalidInputException e) {
											Msg.error(this,
													"Failed to update decompiler symbol DB entry for '" + oldNameForMessage + "': "
															+ e.getMessage(),
													e);
											throw e;
										} catch (Exception e) {
											Msg.error(this,
													"Unexpected error updating decompiler symbol DB entry for '" + oldNameForMessage + "': "
															+ e.getMessage(),
													e);
											throw new RuntimeException(
													"Unexpected error during DB update for decompiler symbol: " + e.getMessage(), e);
										}

										String currentNameForMsg = finalNewName;
										String storageString = "N/A";
										HighVariable hv = finalHighSymbol.getHighVariable();
										if (hv != null) {
											Varnode representativeVn = hv.getRepresentative();
											if (representativeVn != null) {
												storageString = representativeVn.toString();
											}
										}
										String typeString = finalNewDataType != null ? finalNewDataType.getDisplayName() : "(unchanged)";
										String msg = String.format(
												"Decompiler symbol (originally identified as '%s', internal name was '%s', storage '%s') in function '%s' was updated to name '%s' and type '%s'. This change should reflect in subsequent decompiler views.",
												finalOriginalIdentifier,
												oldNameForMessage,
												storageString,
												finalFunction.getName(),
												currentNameForMsg,
												typeString);
										return (Object) Collections.singletonMap("message", msg);
									});
						} else {
							return Mono.error(new IllegalStateException(
									"Cannot rename/retype '" + originalIdentifierForMsg
											+ "'. It is a decompiler symbol backed by a non-variable symbol type: "
											+ backingSymbol.getSymbolType().toString()));
						}
					} else {
						return Mono.error(new IllegalStateException(
								"Variable not found in function '" + function.getName() +
										"' using either listing or decompiler view for identifiers: " + originalIdentifierForMsg));
					}
				} finally {
					if (decomp != null) {
						decomp.dispose();
					}
				}
			}
		});
	}

	private Optional<Variable> resolveListingVariable(Function function, Optional<Long> varSymbolIdOpt,
			Optional<String> varStorageOpt, Optional<String> varNameOpt) {

		Variable[] allVars = function.getAllVariables();

		if (varSymbolIdOpt.isPresent()) {
			long targetId = varSymbolIdOpt.get();
			Optional<Variable> byId = Arrays.stream(allVars)
					.filter(var -> var.getSymbol() != null && var.getSymbol().getID() == targetId)
					.findFirst();
			if (byId.isPresent())
				return byId;
		}

		if (varNameOpt.isPresent()) {
			String targetName = varNameOpt.get();
			Optional<Variable> byName = Arrays.stream(allVars)
					.filter(var -> var.getName().equals(targetName))
					.findFirst();
			if (byName.isPresent())
				return byName;
		}

		if (varStorageOpt.isPresent()) {
			String targetStorage = varStorageOpt.get();
			Optional<Variable> byStorage = Arrays.stream(allVars)
					.filter(var -> var.getVariableStorage().toString().equals(targetStorage))
					.findFirst();
			if (byStorage.isPresent())
				return byStorage;
		}

		return Optional.empty();
	}

	private Optional<HighSymbol> resolveHighSymbolRepresentation(HighFunction hf, Optional<Long> varSymbolIdOpt,
			Optional<String> varStorageOpt, Optional<String> varNameOpt) {

		LocalSymbolMap localSymbolMap = hf.getLocalSymbolMap();
		if (localSymbolMap == null) {
			return Optional.empty();
		}

		HighSymbol byId = null, byName = null, byStorage = null;
		boolean foundById = false, foundByName = false, foundByStorage = false;

		java.util.Iterator<HighSymbol> symbolsIterator = localSymbolMap.getSymbols();
		while (symbolsIterator.hasNext()) {
			HighSymbol hs = symbolsIterator.next();

			if (varSymbolIdOpt.isPresent() && !foundById) {
				if (hs.getSymbol() != null && hs.getSymbol().getID() == varSymbolIdOpt.get()) {
					byId = hs;
					foundById = true;
				}
			}
			if (varNameOpt.isPresent() && !foundByName) {
				if (hs.getName() != null && hs.getName().equals(varNameOpt.get())) {
					byName = hs;
					foundByName = true;
				}
			}
			if (varStorageOpt.isPresent() && !foundByStorage) {
				HighVariable hv = hs.getHighVariable();
				if (hv != null) {
					Varnode vn = hv.getRepresentative();
					if (vn != null && vn.toString().equals(varStorageOpt.get())) {
						byStorage = hs;
						foundByStorage = true;
					}
				}
			}
		}

		if (byId != null)
			return Optional.of(byId);
		if (byName != null)
			return Optional.of(byName);
		if (byStorage != null)
			return Optional.of(byStorage);

		return Optional.empty();
	}

	private Mono<? extends Object> renameExistingListingVariable(Program program, Function function,
			Variable variableToRename, String newName, DataType newDataType, String originalIdentifier) {

		try {
			validateVariableNameSyntax(newName);
		} catch (InvalidInputException e) {
			return Mono.error(new IllegalArgumentException("Invalid new variable name syntax: " + e.getMessage(), e));
		}

		return executeInTransaction(program,
				"Rename/Retype Listing Variable: " + originalIdentifier + " to " + newName + " in " + function.getName(),
				() -> {
					String oldNameForMessage = variableToRename.getName();
					String oldDataTypeName = variableToRename.getDataType().getDisplayName();
					try {
						variableToRename.setName(newName, SourceType.USER_DEFINED);
						if (newDataType != null) {
							try {
								variableToRename.setDataType(newDataType, true, false, SourceType.USER_DEFINED);
							} catch (InvalidInputException e) {
								Msg.error(this, "Failed to set new data type '" + newDataType.getDisplayName() + "' for variable '"
										+ newName + "': " + e.getMessage(), e);
							}
						}
					} catch (DuplicateNameException | InvalidInputException e) {
						Msg.error(this, "Failed to set name on listing variable '" + oldNameForMessage + "': " + e.getMessage(), e);
						throw e;
					}
					String actualNewName = variableToRename.getName();
					String actualNewDataTypeName = variableToRename.getDataType().getDisplayName();

					if (!actualNewName.equals(newName)) {
						Msg.warn(this, "Variable name was set to '" + actualNewName
								+ "' after requesting '" + newName + "' due to normalization.");
					}
					String typeChangeMsg = (newDataType != null && !actualNewDataTypeName.equals(oldDataTypeName))
							? String.format(", and type changed from '%s' to '%s'", oldDataTypeName, actualNewDataTypeName)
							: (newDataType != null ? ", type '" + actualNewDataTypeName + "' was reaffirmed/unchanged."
									: ", type was not changed from '" + oldDataTypeName + "'.");

					return (Object) Collections.singletonMap("message",
							"Listing variable (originally '" + originalIdentifier + "', previously '" + oldNameForMessage + "' at "
									+ variableToRename.getVariableStorage().toString() +
									") in function '" + function.getName() +
									"' renamed to '" + actualNewName + "'" + typeChangeMsg + ".");
				});
	}

	private void validateVariableNameSyntax(String newName) throws InvalidInputException {
		if (newName == null || newName.isBlank()) {
			throw new InvalidInputException("New variable name cannot be null or blank.");
		}
		SymbolUtilities.validateName(newName);
	}

	private Function resolveFunction(Program program, Optional<Long> funcSymbolIdOpt, Optional<String> funcAddressOpt,
			Optional<String> funcNameOpt) {
		FunctionManager funcMan = program.getFunctionManager();

		if (funcSymbolIdOpt.isPresent()) {
			long symbolID = funcSymbolIdOpt.get();
			ghidra.program.model.symbol.Symbol symbol = program.getSymbolTable().getSymbol(symbolID);
			if (symbol != null && symbol.getSymbolType() == ghidra.program.model.symbol.SymbolType.FUNCTION) {
				Function function = funcMan.getFunctionAt(symbol.getAddress());
				if (function != null)
					return function;
			}
		}

		if (funcAddressOpt.isPresent() && !funcAddressOpt.get().isBlank()) {
			Address funcAddr = program.getAddressFactory().getAddress(funcAddressOpt.get());
			Function function = funcMan.getFunctionAt(funcAddr);
			if (function != null)
				return function;
		}

		if (funcNameOpt.isPresent() && !funcNameOpt.get().isBlank()) {
			String functionName = funcNameOpt.get();
			List<Function> foundFunctionsByName = StreamSupport.stream(funcMan.getFunctions(true).spliterator(), false)
					.filter(f -> f.getName().equals(functionName))
					.collect(Collectors.toList());

			if (foundFunctionsByName.size() == 1)
				return foundFunctionsByName.get(0);
			if (foundFunctionsByName.size() > 1) {
				throw new IllegalArgumentException("Multiple functions found with name: '" + functionName
						+ "'. Please use a more specific identifier (address or symbol ID).");
			}
		}

		StringBuilder errorMessage = new StringBuilder("Function not found using identifiers: ");
		funcSymbolIdOpt.ifPresent(id -> errorMessage.append("SymbolID='").append(id).append("' "));
		funcAddressOpt.ifPresent(addr -> {
			if (!addr.isBlank())
				errorMessage.append("Address='").append(addr).append("' ");
		});
		funcNameOpt.ifPresent(name -> {
			if (!name.isBlank())
				errorMessage.append("Name='").append(name).append("' ");
		});
		throw new IllegalArgumentException(errorMessage.toString().trim());
	}
}