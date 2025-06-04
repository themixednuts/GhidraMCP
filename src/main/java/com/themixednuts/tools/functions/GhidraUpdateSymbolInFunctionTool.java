package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;
import java.util.List;
import java.util.ArrayList;
import java.util.stream.StreamSupport;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.DataTypeUtils;

import ghidra.app.cmd.function.SetVariableDataTypeCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

// Imports for decompiler access
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.address.Address;

@GhidraMcpTool(name = "Update Symbol In Function", category = ToolCategory.FUNCTIONS, description = "Updates the data type and/or name of a local variable, parameter, or decompiler symbol within a specific function.", mcpName = "update_symbol_in_function", mcpDescription = """
		<use_case>
		Update the data type and/or name of a local variable, parameter, or decompiler symbol within a function. Supports both listing variables and decompiler-generated high symbols.
		</use_case>

		<important_notes>
		- Function identified by Symbol ID (preferred), address, or name
		- Variable identified by Variable Symbol ID (preferred), storage string, or name
		- Changes immediately affect decompiler output quality
		- Supports pointer and array notation in data types
		</important_notes>

		<example>
		To rename a stack variable: provide function name, storage string 'Stack[-0x8]', and new name. To change parameter type: provide function address, parameter name, and new data type.
		</example>

		<workflow>
		1. Identify target function using provided identifiers
		2. Locate specific variable using provided criteria
		3. Apply data type and/or name changes
		4. Update function signature if parameters are modified
		</workflow>
		""")
public class GhidraUpdateSymbolInFunctionTool implements IGhidraMcpSpecification {

	/**
	 * Helper method to get MCP tool name from annotation for error suggestions.
	 */
	private String getRelatedToolMcpName(Class<? extends IGhidraMcpSpecification> toolClass) {
		GhidraMcpTool annotation = toolClass.getAnnotation(GhidraMcpTool.class);
		return annotation != null ? annotation.mcpName() : toolClass.getSimpleName();
	}

	private static record UpdateSymbolConfirmation(
			String originalSymbolName,
			List<String> changesMade,
			String finalMessage) {
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

		// Variable Identification Properties
		schemaRoot.property(ARG_VARIABLE_SYMBOL_ID,
				JsonSchemaBuilder.integer(mapper)
						.description("The Symbol ID of the local variable or parameter. Preferred identifier."))
				.property(ARG_STORAGE_STRING,
						JsonSchemaBuilder.string(mapper)
								.description("The storage string of the variable (e.g., 'Stack[-0x8]', 'EAX')."))
				.property(ARG_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("The current name of the local variable or parameter."));

		// Update Properties
		schemaRoot.property(ARG_DATA_TYPE_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the new data type to apply. Array and pointer notations are supported."))
				.property(ARG_NEW_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("The new name for the symbol."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);

		return schemaRoot.build();
	}

	// Context record for passing data to transaction
	private static record SymbolUpdateContext(
			Program program,
			Optional<Variable> variable, // If a listing variable is the target
			Optional<HighSymbol> highSymbol, // If a high symbol is the target
			Optional<DataType> newDataType,
			Optional<String> newSymbolName) {
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		DecompInterface decompInterface = new DecompInterface(); // Resource needing cleanup

		return getProgram(args, tool)
				.map(program -> {
					// Setup decompiler
					DecompileOptions options = new DecompileOptions();
					decompInterface.setOptions(options);
					decompInterface.openProgram(program);

					// Function Identifiers
					Optional<Long> funcSymbolIdOpt = getOptionalLongArgument(args, ARG_FUNCTION_SYMBOL_ID);
					Optional<String> funcAddressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
					Optional<String> funcNameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);

					// Variable Identifiers for lookup
					Optional<Long> varLookupSymbolIdOpt = getOptionalLongArgument(args, ARG_VARIABLE_SYMBOL_ID);
					Optional<String> varLookupNameOpt = getOptionalStringArgument(args, ARG_NAME);
					Optional<String> varLookupStorageOpt = getOptionalStringArgument(args, ARG_STORAGE_STRING);

					// Update Parameters
					Optional<String> newDataTypePathOpt = getOptionalStringArgument(args, ARG_DATA_TYPE_PATH);
					Optional<String> newSymbolNameOpt = getOptionalStringArgument(args, ARG_NEW_NAME);

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

					// Validate variable identifiers
					if (varLookupNameOpt.isEmpty() && varLookupSymbolIdOpt.isEmpty() && varLookupStorageOpt.isEmpty()) {
						Map<String, Object> providedIdentifiers = Map.of(
								ARG_VARIABLE_SYMBOL_ID, "not provided",
								ARG_STORAGE_STRING, "not provided",
								ARG_NAME, "not provided");

						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
								.message("At least one variable identifier must be provided")
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"variable identifier validation",
										args,
										providedIdentifiers,
										Map.of("identifiersProvided", 0, "minimumRequired", 1)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Provide at least one variable identifier",
												"Include at least one of: " + ARG_VARIABLE_SYMBOL_ID + ", " + ARG_STORAGE_STRING + ", or "
														+ ARG_NAME,
												List.of(
														"\"" + ARG_VARIABLE_SYMBOL_ID + "\": 12345",
														"\"" + ARG_STORAGE_STRING + "\": \"Stack[-0x8]\"",
														"\"" + ARG_NAME + "\": \"param1\""),
												List.of(getRelatedToolMcpName(
														com.themixednuts.tools.functions.GhidraListFunctionVariablesTool.class)))))
								.build();
						throw new GhidraMcpException(error);
					}

					// Validate update operations
					if (newDataTypePathOpt.isEmpty() && newSymbolNameOpt.isEmpty()) {
						Map<String, Object> providedUpdates = Map.of(
								ARG_DATA_TYPE_PATH, "not provided",
								ARG_NEW_NAME, "not provided");

						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
								.message("At least one update operation must be specified")
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"update operation validation",
										args,
										providedUpdates,
										Map.of("updatesProvided", 0, "minimumRequired", 1)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Specify at least one update operation",
												"Include either new data type or new name for the symbol",
												List.of(
														"\"" + ARG_DATA_TYPE_PATH + "\": \"int\"",
														"\"" + ARG_NEW_NAME + "\": \"newVariableName\""),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					Function function = resolveFunction(program, funcSymbolIdOpt, funcAddressOpt, funcNameOpt);

					// Enhanced Symbol Resolution
					Optional<Variable> resolvedVariableOpt = Optional.empty();
					Optional<HighSymbol> resolvedHighSymbolOpt = Optional.empty();

					// Try to resolve as a listing Variable first by Symbol ID
					if (varLookupSymbolIdOpt.isPresent()) {
						long targetId = varLookupSymbolIdOpt.get();
						for (Variable var : function.getAllVariables()) {
							Symbol varSymbol = var.getSymbol();
							if (varSymbol != null && varSymbol.getID() == targetId) {
								resolvedVariableOpt = Optional.of(var);
								break;
							}
						}
					}

					// Try by Storage String and/or Name in Listing if not found by ID
					if (resolvedVariableOpt.isEmpty() && (varLookupStorageOpt.isPresent() || varLookupNameOpt.isPresent())) {
						for (Variable var : function.getAllVariables()) {
							boolean nameMatch = varLookupNameOpt.map(name -> var.getName().equals(name)).orElse(true);
							boolean storageMatch = varLookupStorageOpt
									.map(stor -> var.getVariableStorage().toString().equalsIgnoreCase(stor)).orElse(true);
							if (nameMatch && storageMatch) {
								resolvedVariableOpt = Optional.of(var);
								break;
							}
						}
					}

					// If no listing Variable found, attempt to resolve as a HighSymbol
					if (resolvedVariableOpt.isEmpty() && (varLookupNameOpt.isPresent() || varLookupStorageOpt.isPresent())) {
						DecompileResults decompileResults = decompInterface.decompileFunction(function,
								decompInterface.getOptions().getDefaultTimeout(), new ConsoleTaskMonitor());
						if (decompileResults != null && decompileResults.getHighFunction() != null) {
							HighFunction hf = decompileResults.getHighFunction();
							LocalSymbolMap localSymbolMap = hf.getLocalSymbolMap();
							if (localSymbolMap != null) {
								java.util.Iterator<HighSymbol> highSymbolIterator = localSymbolMap.getSymbols();
								while (highSymbolIterator.hasNext()) {
									HighSymbol currentHighSymbol = highSymbolIterator.next();
									HighVariable highVar = currentHighSymbol.getHighVariable();

									// Name matching for HighSymbol
									String currentSymbolName = (highVar != null) ? highVar.getName() : currentHighSymbol.getName();
									boolean nameMatch = varLookupNameOpt.map(name -> name.equals(currentSymbolName)).orElse(true);

									// Storage matching for HighSymbol
									boolean storageMatch = varLookupStorageOpt
											.map(stor -> stor.equalsIgnoreCase(currentHighSymbol.getStorage().toString()))
											.orElse(true);

									if (nameMatch && storageMatch) {
										resolvedHighSymbolOpt = Optional.of(currentHighSymbol);
										break;
									}
								}
							}
						}
					}

					// Check if symbol was found
					if (resolvedVariableOpt.isEmpty() && resolvedHighSymbolOpt.isEmpty()) {
						Map<String, Object> searchCriteria = Map.of(
								ARG_VARIABLE_SYMBOL_ID, varLookupSymbolIdOpt.map(Object::toString).orElse("not provided"),
								ARG_STORAGE_STRING, varLookupStorageOpt.orElse("not provided"),
								ARG_NAME, varLookupNameOpt.orElse("not provided"));

						GhidraMcpError error = GhidraMcpError.resourceNotFound()
								.errorCode(GhidraMcpError.ErrorCode.SYMBOL_NOT_FOUND)
								.message("Variable or Symbol not found in function '" + function.getName() + "'")
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"variable lookup in function: " + function.getName(),
										args,
										searchCriteria,
										Map.of("searchAttempted", true, "functionFound", true, "variableFound", false)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"Verify the variable exists in the specified function",
												"Use function variable listing tools to see available variables",
												null,
												List.of(getRelatedToolMcpName(
														com.themixednuts.tools.functions.GhidraListFunctionVariablesTool.class))),
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Double-check variable identifier values",
												"Ensure symbol ID, storage string, or name are correct for this function",
												null,
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					// Parse new data type if provided
					Optional<DataType> newDataTypeOpt = newDataTypePathOpt
							.map(path -> {
								try {
									return DataTypeUtils.parseDataTypeString(program, path, tool);
								} catch (InvalidDataTypeException e) {
									GhidraMcpError error = GhidraMcpError.dataTypeParsing()
											.errorCode(GhidraMcpError.ErrorCode.INVALID_TYPE_PATH)
											.message("Invalid data type format: " + e.getMessage())
											.context(new GhidraMcpError.ErrorContext(
													annotation.mcpName(),
													"data type parsing",
													args,
													Map.of(ARG_DATA_TYPE_PATH, path),
													Map.of("parseError", e.getMessage())))
											.suggestions(List.of(
													new GhidraMcpError.ErrorSuggestion(
															GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
															"Check data type syntax",
															"Ensure data type name and notation are correct",
															List.of("int", "char*", "byte[16]", "MyStruct"),
															null)))
											.build();
									throw new GhidraMcpException(error);
								} catch (CancelledException e) {
									GhidraMcpError error = GhidraMcpError.execution()
											.errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
											.message("Data type parsing was cancelled: " + e.getMessage())
											.context(new GhidraMcpError.ErrorContext(
													annotation.mcpName(),
													"data type parsing",
													args,
													Map.of(ARG_DATA_TYPE_PATH, path),
													Map.of("operationCancelled", true)))
											.suggestions(List.of(
													new GhidraMcpError.ErrorSuggestion(
															GhidraMcpError.ErrorSuggestion.SuggestionType.ALTERNATIVE_APPROACH,
															"Retry the operation",
															"Try parsing the data type again",
															null,
															null)))
											.build();
									throw new GhidraMcpException(error);
								} catch (RuntimeException e) {
									GhidraMcpError error = GhidraMcpError.dataTypeParsing()
											.errorCode(GhidraMcpError.ErrorCode.INVALID_TYPE_PATH)
											.message("Unexpected error parsing data type: " + e.getMessage())
											.context(new GhidraMcpError.ErrorContext(
													annotation.mcpName(),
													"data type parsing",
													args,
													Map.of(ARG_DATA_TYPE_PATH, path),
													Map.of("runtimeError", e.getMessage())))
											.suggestions(List.of(
													new GhidraMcpError.ErrorSuggestion(
															GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
															"Verify data type specification",
															"Check if the data type is properly defined in the program",
															null,
															null)))
											.build();
									throw new GhidraMcpException(error);
								}
							});

					return new SymbolUpdateContext(program, resolvedVariableOpt, resolvedHighSymbolOpt,
							newDataTypeOpt, newSymbolNameOpt);
				})
				.flatMap(context -> {
					Program program = context.program();
					Optional<Variable> variableOpt = context.variable();
					Optional<HighSymbol> highSymbolOpt = context.highSymbol();
					Optional<DataType> newDataTypeOpt = context.newDataType();
					Optional<String> newSymbolNameOpt = context.newSymbolName();

					List<String> changesMade = new ArrayList<>();
					String originalSymbolName;

					if (variableOpt.isPresent()) {
						originalSymbolName = variableOpt.get().getName();
					} else if (highSymbolOpt.isPresent()) {
						HighSymbol highSymbol = highSymbolOpt.get();
						HighVariable highVar = highSymbol.getHighVariable();
						originalSymbolName = (highVar != null) ? highVar.getName() : highSymbol.getName();
					} else {
						return Mono.error(new IllegalStateException("No variable or symbol to update."));
					}

					return executeInTransaction(program, "MCP - Update Symbol: " + originalSymbolName,
							() -> {
								if (variableOpt.isPresent()) {
									Variable variable = variableOpt.get();
									// Handle Listing Variable updates
									newSymbolNameOpt.ifPresent(newName -> {
										if (!newName.equals(variable.getName())) {
											try {
												variable.setName(newName, SourceType.USER_DEFINED);
												changesMade.add("listing variable name to '" + newName + "'");
											} catch (ghidra.util.exception.DuplicateNameException e) {
												GhidraMcpError error = GhidraMcpError.validation()
														.errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
														.message("Variable name already exists in function: " + newName)
														.context(new GhidraMcpError.ErrorContext(
																annotation.mcpName(),
																"variable name update",
																Map.of(ARG_NEW_NAME, newName),
																Map.of("conflictingName", newName),
																Map.of("nameConflict", true)))
														.suggestions(List.of(
																new GhidraMcpError.ErrorSuggestion(
																		GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
																		"Choose a different variable name",
																		"Use a unique name within the function scope",
																		null,
																		null)))
														.build();
												throw new GhidraMcpException(error);
											} catch (InvalidInputException e) {
												GhidraMcpError error = GhidraMcpError.validation()
														.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
														.message("Invalid variable name: " + e.getMessage())
														.context(new GhidraMcpError.ErrorContext(
																annotation.mcpName(),
																"variable name validation",
																Map.of(ARG_NEW_NAME, newName),
																Map.of("validationError", e.getMessage()),
																Map.of("nameValid", false)))
														.suggestions(List.of(
																new GhidraMcpError.ErrorSuggestion(
																		GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
																		"Use a valid variable name",
																		"Follow standard variable naming conventions",
																		List.of("param1", "localVar", "buffer_ptr"),
																		null)))
														.build();
												throw new GhidraMcpException(error);
											}
										}
									});

									newDataTypeOpt.ifPresent(newDataType -> {
										if (!variable.getDataType().isEquivalent(newDataType)) {
											SetVariableDataTypeCmd cmd = new SetVariableDataTypeCmd(variable, newDataType,
													SourceType.USER_DEFINED);
											if (!cmd.applyTo(program)) {
												String cmdStatus = cmd.getStatusMsg() != null ? cmd.getStatusMsg() : "Unknown error";
												GhidraMcpError error = GhidraMcpError.execution()
														.errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
														.message("Failed to apply data type change: " + cmdStatus)
														.context(new GhidraMcpError.ErrorContext(
																annotation.mcpName(),
																"variable data type update command",
																Map.of(ARG_DATA_TYPE_PATH, newDataType.getDisplayName()),
																Map.of("commandStatus", cmdStatus),
																Map.of("commandSuccess", false)))
														.suggestions(List.of(
																new GhidraMcpError.ErrorSuggestion(
																		GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
																		"Verify data type compatibility",
																		"Ensure the data type is compatible with the variable storage",
																		null,
																		null)))
														.build();
												throw new GhidraMcpException(error);
											}
											changesMade.add("listing variable data type to '" + newDataType.getDisplayName() + "'");
										}
									});

								} else if (highSymbolOpt.isPresent()) {
									HighSymbol highSymbol = highSymbolOpt.get();
									HighVariable highVar = highSymbol.getHighVariable();

									// Determine current effective name and type for comparison
									String currentEffectiveName = (highVar != null) ? highVar.getName() : highSymbol.getName();
									DataType currentEffectiveDataType = (highVar != null) ? highVar.getDataType() : null;

									// Check if any change is requested
									boolean nameChanged = newSymbolNameOpt
											.map(newName -> !newName.equals(currentEffectiveName))
											.orElse(false);
									boolean typeChanged = newDataTypeOpt
											.map(newDataType -> {
												if (currentEffectiveDataType == null && highVar != null)
													return true;
												if (currentEffectiveDataType != null)
													return !newDataType.isEquivalent(currentEffectiveDataType);
												return false;
											})
											.orElse(false);

									if (nameChanged || typeChanged) {
										try {
											HighFunctionDBUtil.updateDBVariable(highSymbol,
													newSymbolNameOpt.orElse(null),
													newDataTypeOpt.orElse(null),
													SourceType.USER_DEFINED);

											if (nameChanged) {
												changesMade.add("HighSymbol name to '" + newSymbolNameOpt.get() + "'");
											}
											if (typeChanged) {
												changesMade.add("HighSymbol data type to '" + newDataTypeOpt.get().getDisplayName() + "'");
											}
										} catch (InvalidInputException | ghidra.util.exception.DuplicateNameException e) {
											GhidraMcpError error = GhidraMcpError.execution()
													.errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
													.message("Failed to update HighSymbol: " + e.getMessage())
													.context(new GhidraMcpError.ErrorContext(
															annotation.mcpName(),
															"HighSymbol database update",
															Map.of(
																	ARG_NEW_NAME, newSymbolNameOpt.orElse("not changed"),
																	ARG_DATA_TYPE_PATH,
																	newDataTypeOpt.map(DataType::getDisplayName).orElse("not changed")),
															Map.of("updateError", e.getMessage()),
															Map.of("updateSuccess", false)))
													.suggestions(List.of(
															new GhidraMcpError.ErrorSuggestion(
																	GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
																	"Check name uniqueness and validity",
																	"Ensure the new name is unique and follows naming conventions",
																	null,
																	null)))
													.build();
											throw new GhidraMcpException(error);
										}
									}
								}

								String summaryMessage;
								if (changesMade.isEmpty()) {
									summaryMessage = "No effective changes applied to symbol '" + originalSymbolName + "'.";
								} else {
									summaryMessage = "Successfully updated symbol '" + originalSymbolName + "'.";
								}

								return new UpdateSymbolConfirmation(originalSymbolName, changesMade, summaryMessage);
							});
				})
				.doFinally(signalType -> {
					if (decompInterface != null) {
						decompInterface.dispose();
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
							Map.of("updateRequested", true),
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
