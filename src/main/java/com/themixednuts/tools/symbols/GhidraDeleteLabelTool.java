package com.themixednuts.tools.symbols;

import java.util.Map;
import java.util.Optional;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.cmd.label.DeleteLabelCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SymbolIterator;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Delete Label", category = ToolCategory.SYMBOLS, description = "Removes a label at a specified address, optionally verifying the name.", mcpName = "delete_label", mcpDescription = "Delete a label from a Ghidra program. Use symbol ID, address, or name to identify the label to remove.")
public class GhidraDeleteLabelTool implements IGhidraMcpSpecification {

	private static record DeleteLabelContext(
			Program program,
			Address address,
			String actualSymbolName // Pass the confirmed name to delete
	) {
	}

	/**
	 * Creates search criteria map for error reporting.
	 */
	private Map<String, Object> createSearchCriteriaMap(Optional<Long> symbolIdOpt, Optional<String> addressOpt,
			Optional<String> nameOpt) {
		Map<String, Object> criteria = new java.util.HashMap<>();
		symbolIdOpt.ifPresent(id -> criteria.put(ARG_SYMBOL_ID, id));
		addressOpt.ifPresent(addr -> criteria.put(ARG_ADDRESS, addr));
		nameOpt.ifPresent(name -> criteria.put(ARG_NAME, name));
		return criteria;
	}

	/**
	 * Gets available label names for error suggestions.
	 */
	private List<String> getAvailableLabelNames(SymbolTable symbolTable) {
		return StreamSupport.stream(symbolTable.getAllSymbols(true).spliterator(), false)
				.filter(s -> s.getSymbolType() == SymbolType.LABEL)
				.map(s -> s.getName() + " at " + s.getAddress())
				.limit(50)
				.collect(Collectors.toList());
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address of the label to remove (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_NAME,
				JsonSchemaBuilder.string(mapper)
						.description(
								"The name of the label. Used for verification if address/ID provided, or for finding a global label."));
		schemaRoot.property(ARG_SYMBOL_ID,
				JsonSchemaBuilder.integer(mapper)
						.description("The unique Symbol ID of the label to remove."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
					Optional<String> nameOpt = getOptionalStringArgument(args, ARG_NAME);
					Optional<Long> symbolIdOpt = getOptionalLongArgument(args, ARG_SYMBOL_ID);

					if (symbolIdOpt.isEmpty() && addressOpt.isEmpty() && nameOpt.isEmpty()) {
						Map<String, Object> providedIdentifiers = Map.of(
								ARG_SYMBOL_ID, "not provided",
								ARG_ADDRESS, "not provided",
								ARG_NAME, "not provided");

						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
								.message("At least one identifier must be provided")
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"identifier validation",
										args,
										providedIdentifiers,
										Map.of("identifiersProvided", 0, "minimumRequired", 1)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Provide at least one identifier",
												"Include at least one required argument",
												List.of(
														"\"" + ARG_SYMBOL_ID + "\": 12345",
														"\"" + ARG_ADDRESS + "\": \"0x401000\"",
														"\"" + ARG_NAME + "\": \"myLabel\""),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					SymbolTable symbolTable = program.getSymbolTable();
					Symbol symbolToDelete = null;
					String criteriaInfo = "";

					if (symbolIdOpt.isPresent()) {
						long symId = symbolIdOpt.get();
						criteriaInfo = "ID '" + symId + "'";
						symbolToDelete = symbolTable.getSymbol(symId);
						if (symbolToDelete != null) {
							if (nameOpt.isPresent() && !symbolToDelete.getName().equals(nameOpt.get())) {
								GhidraMcpError error = GhidraMcpError.validation()
										.errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
										.message("Symbol name mismatch")
										.context(new GhidraMcpError.ErrorContext(
												getMcpName(),
												"name verification",
												args,
												Map.of(
														ARG_SYMBOL_ID, symId,
														ARG_NAME, nameOpt.get()),
												Map.of(
														"expectedName", nameOpt.get(),
														"actualName", symbolToDelete.getName(),
														"symbolId", symId)))
										.suggestions(List.of(
												new GhidraMcpError.ErrorSuggestion(
														GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
														"Use correct symbol name or remove name verification",
														"Correct the name or omit the name argument",
														List.of(
																"\"" + ARG_NAME + "\": \"" + symbolToDelete.getName() + "\"",
																"Omit \"" + ARG_NAME + "\" argument entirely"),
														List.of(getMcpName(GhidraGetSymbolAtAddressTool.class)))))
										.build();
								throw new GhidraMcpException(error);
							}
							if (addressOpt.isPresent()) {
								try {
									Address parsedAddressForVerification = program.getAddressFactory().getAddress(addressOpt.get());
									if (parsedAddressForVerification != null
											&& !symbolToDelete.getAddress().equals(parsedAddressForVerification)) {
										GhidraMcpError error = GhidraMcpError.validation()
												.errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
												.message("Symbol address mismatch")
												.context(new GhidraMcpError.ErrorContext(
														getMcpName(),
														"address verification",
														args,
														Map.of(
																ARG_SYMBOL_ID, symId,
																ARG_ADDRESS, addressOpt.get()),
														Map.of(
																"expectedAddress", addressOpt.get(),
																"actualAddress", symbolToDelete.getAddress().toString(),
																"symbolId", symId)))
												.suggestions(List.of(
														new GhidraMcpError.ErrorSuggestion(
																GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
																"Use correct address or remove address verification",
																"Correct the address or omit the address argument",
																List.of(
																		"\"" + ARG_ADDRESS + "\": \"" + symbolToDelete.getAddress().toString() + "\"",
																		"Omit \"" + ARG_ADDRESS + "\" argument entirely"),
																List.of(getMcpName(GhidraGetSymbolAtAddressTool.class)))))
												.build();
										throw new GhidraMcpException(error);
									}
								} catch (Exception e) {
									GhidraMcpError error = GhidraMcpError.validation()
											.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
											.message("Failed to parse verification address: " + e.getMessage())
											.context(new GhidraMcpError.ErrorContext(
													getMcpName(),
													"address parsing for verification",
													args,
													Map.of(ARG_ADDRESS, addressOpt.get()),
													Map.of("parseException", e.getClass().getSimpleName())))
											.suggestions(List.of(
													new GhidraMcpError.ErrorSuggestion(
															GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
															"Use valid hexadecimal address format",
															"Provide address in correct hexadecimal format",
															List.of(
																	"\"" + ARG_ADDRESS + "\": \"0x401000\"",
																	"\"" + ARG_ADDRESS + "\": \"401000\""),
															null)))
											.build();
									throw new GhidraMcpException(error);
								}
							}
						}
					} else if (addressOpt.isPresent()) {
						String addressStr = addressOpt.get();
						criteriaInfo = "address '" + addressStr + "'";
						Address targetAddress;
						try {
							targetAddress = program.getAddressFactory().getAddress(addressStr);
							if (targetAddress == null) {
								GhidraMcpError error = GhidraMcpError.validation()
										.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
										.message("Invalid address format")
										.context(new GhidraMcpError.ErrorContext(
												getMcpName(),
												"address parsing",
												args,
												Map.of(ARG_ADDRESS, addressStr),
												Map.of("isValidFormat", false)))
										.suggestions(List.of(
												new GhidraMcpError.ErrorSuggestion(
														GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
														"Use valid hexadecimal address format",
														"Provide address in hexadecimal format",
														List.of(
																"\"" + ARG_ADDRESS + "\": \"0x401000\"",
																"\"" + ARG_ADDRESS + "\": \"401000\""),
														null)))
										.build();
								throw new GhidraMcpException(error);
							}
						} catch (Exception e) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
									.message("Failed to parse address: " + e.getMessage())
									.context(new GhidraMcpError.ErrorContext(
											getMcpName(),
											"address parsing",
											args,
											Map.of(ARG_ADDRESS, addressStr),
											Map.of("parseException", e.getClass().getSimpleName())))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Use valid hexadecimal address format",
													"Provide address in correct hexadecimal format",
													List.of(
															"\"" + ARG_ADDRESS + "\": \"0x401000\"",
															"\"" + ARG_ADDRESS + "\": \"401000\""),
													null)))
									.build();
							throw new GhidraMcpException(error);
						}

						if (nameOpt.isPresent()) {
							// If name is also provided, iterate to find the specific named symbol at the
							// address
							String targetName = nameOpt.get();
							criteriaInfo += " and name '" + targetName + "'";
							Symbol[] symbolsAtAddr = symbolTable.getSymbols(targetAddress);
							for (Symbol sym : symbolsAtAddr) {
								if (sym.getName().equals(targetName)) {
									symbolToDelete = sym;
									break;
								}
							}
							if (symbolToDelete == null) {
								List<String> availableSymbolsAtAddress = java.util.Arrays.stream(symbolsAtAddr)
										.map(s -> s.getName() + " (" + s.getSymbolType() + ")")
										.collect(Collectors.toList());

								GhidraMcpError error = GhidraMcpError.resourceNotFound()
										.errorCode(GhidraMcpError.ErrorCode.SYMBOL_NOT_FOUND)
										.message("Label with name '" + targetName + "' not found at address '" + addressStr + "'")
										.context(new GhidraMcpError.ErrorContext(
												getMcpName(),
												"symbol lookup by name and address",
												args,
												Map.of(
														ARG_ADDRESS, addressStr,
														ARG_NAME, targetName),
												Map.of(
														"symbolsAtAddress", availableSymbolsAtAddress.size(),
														"targetName", targetName,
														"targetAddress", addressStr)))
										.suggestions(List.of(
												new GhidraMcpError.ErrorSuggestion(
														GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
														"Check available symbols at this address",
														"Verify correct symbol name or address",
														availableSymbolsAtAddress.stream().limit(10).collect(Collectors.toList()),
														List.of(getMcpName(GhidraGetSymbolAtAddressTool.class)))))
										.relatedResources(availableSymbolsAtAddress)
										.build();
								throw new GhidraMcpException(error);
							}
						} else {
							// Only address provided, try primary then first symbol
							symbolToDelete = symbolTable.getPrimarySymbol(targetAddress);
							if (symbolToDelete == null) {
								Symbol[] symbolsAtAddr = symbolTable.getSymbols(targetAddress);
								if (symbolsAtAddr.length > 0) {
									symbolToDelete = symbolsAtAddr[0];
								}
							}
						}
					} else if (nameOpt.isPresent()) { // Only name provided
						String labelName = nameOpt.get();
						criteriaInfo = "name '" + labelName + "'";
						SymbolIterator symIter = symbolTable.getSymbolIterator(labelName, true); // Global symbols
						Symbol firstMatch = null;
						int count = 0;
						while (symIter.hasNext()) {
							Symbol currentSym = symIter.next();
							if (currentSym.getSymbolType() == SymbolType.LABEL) {
								if (count == 0)
									firstMatch = currentSym;
								count++;
							}
						}
						if (count == 1) {
							symbolToDelete = firstMatch;
						} else if (count > 1) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
									.message("Multiple global labels found with name: " + labelName)
									.context(new GhidraMcpError.ErrorContext(
											getMcpName(),
											"symbol lookup by name",
											args,
											Map.of(ARG_NAME, labelName),
											Map.of("matchCount", count, "isAmbiguous", true, "type", "global labels")))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Use address or symbol ID for unambiguous identification",
													"Specify either address or symbol ID",
													List.of(
															"\"" + ARG_ADDRESS + "\": \"0x401000\"",
															"\"" + ARG_SYMBOL_ID + "\": 12345"),
													List.of(getMcpName(GhidraGetSymbolAtAddressTool.class),
															getMcpName(GhidraListAllSymbolsTool.class)))))
									.build();
							throw new GhidraMcpException(error);
						}
					}

					if (symbolToDelete == null) {
						Map<String, Object> searchCriteria = createSearchCriteriaMap(symbolIdOpt, addressOpt, nameOpt);
						List<String> availableLabels = getAvailableLabelNames(symbolTable);

						GhidraMcpError error = GhidraMcpError.resourceNotFound()
								.errorCode(GhidraMcpError.ErrorCode.SYMBOL_NOT_FOUND)
								.message("Label not found using criteria: " + criteriaInfo)
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"label lookup",
										args,
										searchCriteria,
										Map.of("searchAttempted", true, "criteriaInfo", criteriaInfo)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"Verify label exists and check available labels",
												"Use tools to list available labels",
												availableLabels.stream().limit(10).collect(Collectors.toList()),
												List.of(getMcpName(GhidraGetSymbolAtAddressTool.class)))))
								.relatedResources(availableLabels)
								.build();
						throw new GhidraMcpException(error);
					}

					if (symbolToDelete.getSymbolType() != SymbolType.LABEL) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Symbol is not a label")
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"symbol type validation",
										args,
										createSearchCriteriaMap(symbolIdOpt, addressOpt, nameOpt),
										Map.of(
												"foundSymbolType", symbolToDelete.getSymbolType().toString(),
												"expectedSymbolType", "LABEL",
												"symbolName", symbolToDelete.getName(),
												"symbolAddress", symbolToDelete.getAddress().toString())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.USE_DIFFERENT_TOOL,
												"Use appropriate tool for this symbol type",
												"Different symbol types require different deletion tools",
												List.of("Symbol type is " + symbolToDelete.getSymbolType()),
												List.of("rename_symbol", "list_all_symbols"))))
								.build();
						throw new GhidraMcpException(error);
					}

					// --- Modification Phase (Pass needed context) ---
					return new DeleteLabelContext(program, symbolToDelete.getAddress(), symbolToDelete.getName());

				})
				.flatMap(context -> {
					String identifier = context.actualSymbolName() + "@" + context.address().toString();

					return executeInTransaction(context.program(), "MCP - Delete Label " + identifier, () -> {
						// Use DeleteLabelCmd - requires address and name.
						DeleteLabelCmd cmd = new DeleteLabelCmd(context.address(), context.actualSymbolName());
						if (cmd.applyTo(context.program())) {
							return "Successfully removed label: " + identifier;
						} else {
							GhidraMcpError error = GhidraMcpError.execution()
									.errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
									.message("Failed to remove label: " + cmd.getStatusMsg())
									.context(new GhidraMcpError.ErrorContext(
											getMcpName(),
											"label deletion operation",
											Map.of(
													ARG_ADDRESS, context.address().toString(),
													ARG_NAME, context.actualSymbolName()),
											Map.of(
													"labelIdentifier", identifier,
													"commandStatus", cmd.getStatusMsg()),
											Map.of("commandFailed", true)))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
													"Verify label still exists and is not read-only",
													"Check label status and program permissions",
													List.of("Verify label exists at " + context.address()),
													List.of(getMcpName(GhidraGetSymbolAtAddressTool.class)))))
									.build();
							throw new GhidraMcpException(error);
						}
					});
				});
	}
}