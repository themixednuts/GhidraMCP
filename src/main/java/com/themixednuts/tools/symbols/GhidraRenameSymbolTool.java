package com.themixednuts.tools.symbols;

import java.util.Map;
import java.util.Optional;
import java.util.stream.StreamSupport;
import java.util.List;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.tools.datatypes.GhidraListNamespacesTool;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.Namespace;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Rename Symbol", category = ToolCategory.SYMBOLS, description = "Renames a symbol (function or data label) identified by its address or a function name.", mcpName = "rename_symbol", mcpDescription = "Rename a symbol in a Ghidra program. Use symbol ID, address, or current name to identify the symbol to rename.")
public class GhidraRenameSymbolTool implements IGhidraMcpSpecification {

	private static final String ARG_TARGET_NAMESPACE = "targetNamespace";

	private static record RenameSymbolContext(
			Program program,
			Symbol symbol,
			String simpleNewName,
			Optional<String> targetNamespacePathOpt) {
	}

	/**
	 * Creates search criteria map for error reporting.
	 */
	private Map<String, Object> createSearchCriteriaMap(Optional<Long> symbolIdOpt, Optional<String> addressOpt,
			Optional<String> currentNameOpt) {
		Map<String, Object> criteria = new java.util.HashMap<>();
		symbolIdOpt.ifPresent(id -> criteria.put(ARG_SYMBOL_ID, id));
		addressOpt.ifPresent(addr -> criteria.put(ARG_ADDRESS, addr));
		currentNameOpt.ifPresent(name -> criteria.put(ARG_CURRENT_NAME, name));
		return criteria;
	}

	/**
	 * Gets available symbol names for error suggestions.
	 */
	private List<String> getAvailableSymbolNames(SymbolTable symbolTable) {
		return StreamSupport.stream(symbolTable.getAllSymbols(true).spliterator(), false)
				.map(s -> s.getName(true))
				.limit(50)
				.collect(Collectors.toList());
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_NEW_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The desired new simple name for the symbol (without namespace path)."));
		schemaRoot.property(ARG_TARGET_NAMESPACE,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional: The target namespace path for the symbol (e.g., 'MyNamespace', 'MyNamespace::Inner', or 'Global'). If omitted, empty, 'Global', or if the path does not exist, it will be created (if possible)."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description(
								"The address of the symbol (function entry or data) to rename (e.g., '0x1004010'). Preferred over currentName if provided.")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_CURRENT_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The current name of the symbol to rename. If ambiguous, use address or ID."));
		schemaRoot.property(ARG_SYMBOL_ID,
				JsonSchemaBuilder.integer(mapper)
						.description("The unique ID of the symbol to rename. Preferred identifier."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_NEW_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {

			Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
			Optional<String> currentNameOpt = getOptionalStringArgument(args, ARG_CURRENT_NAME);
			Optional<Long> symbolIdOpt = getOptionalLongArgument(args, ARG_SYMBOL_ID);
			String simpleNewName = getRequiredStringArgument(args, ARG_NEW_NAME);
			Optional<String> targetNamespacePathOpt = getOptionalStringArgument(args, ARG_TARGET_NAMESPACE);

			if (addressOpt.isEmpty() && currentNameOpt.isEmpty() && symbolIdOpt.isEmpty()) {
				Map<String, Object> providedIdentifiers = Map.of(
						ARG_SYMBOL_ID, "not provided",
						ARG_ADDRESS, "not provided",
						ARG_CURRENT_NAME, "not provided");

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
												"\"" + ARG_CURRENT_NAME + "\": \"main\""),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			if (simpleNewName.isBlank()) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
						.message("New simple name cannot be empty or blank")
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"name validation",
								args,
								Map.of(ARG_NEW_NAME, simpleNewName),
								Map.of("isEmpty", simpleNewName.isEmpty(), "isBlank", simpleNewName.isBlank())))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Provide a non-empty symbol name",
										"Specify a valid symbol name",
										List.of(
												"\"" + ARG_NEW_NAME + "\": \"MyFunction\"",
												"\"" + ARG_NEW_NAME + "\": \"myVariable\"",
												"\"" + ARG_NEW_NAME + "\": \"dataLabel\""),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			if (simpleNewName.contains("::")) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
						.message("Simple name should not contain namespace separators")
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"name format validation",
								args,
								Map.of(ARG_NEW_NAME, simpleNewName),
								Map.of("containsNamespaceSeparator", true, "invalidCharacter", "::")))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Use simple name without namespace separators",
										"Use the '" + ARG_TARGET_NAMESPACE + "' argument for namespace specification",
										List.of(
												"\"" + ARG_NEW_NAME + "\": \"" + simpleNewName.replaceAll("::", "_") + "\"",
												"\"" + ARG_TARGET_NAMESPACE + "\": \"MyNamespace\""),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			Symbol symbolToRename = null;
			SymbolTable symbolTable = program.getSymbolTable();
			FunctionManager functionManager = program.getFunctionManager();
			String identifierInfo = "";

			if (symbolIdOpt.isPresent()) {
				long symId = symbolIdOpt.get();
				identifierInfo = "symbolId '" + symId + "'";
				symbolToRename = symbolTable.getSymbol(symId);
			} else if (addressOpt.isPresent()) {
				String addressString = addressOpt.get();
				identifierInfo = "address '" + addressString + "'";
				try {
					Address symbolAddress = program.getAddressFactory().getAddress(addressString);
					if (symbolAddress != null) {
						symbolToRename = symbolTable.getPrimarySymbol(symbolAddress);
						if (symbolToRename == null) {
							Symbol[] symbolsAtAddr = symbolTable.getSymbols(symbolAddress);
							if (symbolsAtAddr.length > 0) {
								symbolToRename = symbolsAtAddr[0];
							}
						}
					} else {
						if (currentNameOpt.isEmpty() && symbolIdOpt.isEmpty()) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
									.message("Invalid address format")
									.context(new GhidraMcpError.ErrorContext(
											getMcpName(),
											"address parsing",
											args,
											Map.of(ARG_ADDRESS, addressString),
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
					}
				} catch (Exception e) {
					if (currentNameOpt.isEmpty() && symbolIdOpt.isEmpty()) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
								.message("Failed to parse address: " + e.getMessage())
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"address parsing",
										args,
										Map.of(ARG_ADDRESS, addressString),
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
			} else if (currentNameOpt.isPresent()) {
				String name = currentNameOpt.get();
				identifierInfo = "name '" + name + "'";
				java.util.List<Function> foundFunctions = StreamSupport
						.stream(functionManager.getFunctions(true).spliterator(), false)
						.filter(f -> f.getName(true).equals(name))
						.collect(java.util.stream.Collectors.toList());

				Function function = null;
				if (foundFunctions.size() == 1) {
					function = foundFunctions.get(0);
				} else if (foundFunctions.size() > 1) {
					List<String> ambiguousFunctions = foundFunctions.stream()
							.map(f -> f.getName(true) + " at " + f.getEntryPoint())
							.collect(Collectors.toList());

					GhidraMcpError error = GhidraMcpError.validation()
							.errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
							.message("Multiple functions found with name: " + name)
							.context(new GhidraMcpError.ErrorContext(
									getMcpName(),
									"symbol lookup by name",
									args,
									Map.of(ARG_CURRENT_NAME, name),
									Map.of("matchCount", foundFunctions.size(), "isAmbiguous", true)))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
											"Use address or symbol ID for unambiguous identification",
											"Specify either address or symbol ID",
											ambiguousFunctions.stream()
													.map(f -> {
														String[] parts = f.split(" at ");
														return "\"" + ARG_ADDRESS + "\": \"" + parts[1] + "\"";
													})
													.collect(Collectors.toList()),
											List.of(getMcpName(GhidraGetSymbolAtAddressTool.class)))))
							.build();
					throw new GhidraMcpException(error);
				}

				if (function != null) {
					symbolToRename = function.getSymbol();
				} else {
					SymbolIterator symIter = symbolTable.getSymbolIterator(name, true);
					if (symIter.hasNext()) {
						symbolToRename = symIter.next();
						if (symIter.hasNext()) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
									.message("Multiple global symbols found with name: " + name)
									.context(new GhidraMcpError.ErrorContext(
											getMcpName(),
											"symbol lookup by name",
											args,
											Map.of(ARG_CURRENT_NAME, name),
											Map.of("isAmbiguous", true, "type", "global symbols")))
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
				}
			}

			if (symbolToRename == null) {
				Map<String, Object> searchCriteria = createSearchCriteriaMap(symbolIdOpt, addressOpt, currentNameOpt);
				List<String> availableSymbols = getAvailableSymbolNames(symbolTable);

				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.SYMBOL_NOT_FOUND)
						.message("Symbol not found using provided identifier(s): " + identifierInfo)
						.context(new GhidraMcpError.ErrorContext(
								getMcpName(),
								"symbol lookup",
								args,
								searchCriteria,
								Map.of("searchAttempted", true, "identifierInfo", identifierInfo)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Verify symbol exists and check available symbols",
										"Use tools to list available symbols",
										availableSymbols.stream().limit(10).collect(Collectors.toList()),
										List.of(getMcpName(GhidraListAllSymbolsTool.class),
												getMcpName(GhidraGetSymbolAtAddressTool.class)))))
						.build();
				throw new GhidraMcpException(error);
			}

			return new RenameSymbolContext(program, symbolToRename, simpleNewName, targetNamespacePathOpt);

		}).flatMap(context -> {
			String originalName = context.symbol().getName();
			Address symAddress = context.symbol().getAddress();
			String originalNamespaceName = context.symbol().getParentNamespace().getName(true);

			return executeInTransaction(context.program(),
					"MCP - Rename Symbol " + originalName + " in " + originalNamespaceName + " at " + symAddress,
					() -> {
						SymbolTable transactionSymbolTable = context.program().getSymbolTable();
						Namespace namespaceForCmd;
						String targetNsPathUserStr = context.targetNamespacePathOpt().orElse(null);

						if (targetNsPathUserStr == null || targetNsPathUserStr.isBlank()
								|| targetNsPathUserStr.equalsIgnoreCase("Global")) {
							namespaceForCmd = context.program().getGlobalNamespace();
						} else {
							// Attempt to retrieve the namespace.
							// If targetNsPathUserStr does not exist, getNamespace will return null.
							namespaceForCmd = transactionSymbolTable.getNamespace(targetNsPathUserStr, null);
							// If namespaceForCmd is null here, it means the user specified a path
							// that doesn't exist, and we will pass this null to RenameLabelCmd.
						}

						RenameLabelCmd cmd = new RenameLabelCmd(context.symbol(), context.simpleNewName(),
								namespaceForCmd, // This could be null
								SourceType.USER_DEFINED);

						if (!cmd.applyTo(context.program())) {
							String attemptedNsMsg;
							if (namespaceForCmd == null) {
								attemptedNsMsg = "non-existent namespace path: '" + targetNsPathUserStr + "'";
							} else {
								attemptedNsMsg = "'" + namespaceForCmd.getName(true) + "'";
							}

							GhidraMcpError error = GhidraMcpError.execution()
									.errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
									.message("Failed to rename symbol: " + cmd.getStatusMsg())
									.context(new GhidraMcpError.ErrorContext(
											getMcpName(),
											"symbol rename operation",
											Map.of(
													ARG_NEW_NAME, context.simpleNewName(),
													ARG_TARGET_NAMESPACE, targetNsPathUserStr != null ? targetNsPathUserStr : "global"),
											Map.of(
													"originalName", originalName,
													"symbolAddress", symAddress.toString(),
													"targetNamespace", attemptedNsMsg,
													"commandStatus", cmd.getStatusMsg()),
											Map.of("commandFailed", true, "namespaceExists", namespaceForCmd != null)))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Check if namespace exists or use different name",
													"Verify namespace exists or use global namespace",
													List.of(
															"\"" + ARG_TARGET_NAMESPACE + "\": \"Global\"",
															"\"" + ARG_NEW_NAME + "\": \"" + context.simpleNewName() + "_alt\""),
													List.of(getMcpName(GhidraListNamespacesTool.class)))))
									.build();
							throw new GhidraMcpException(error);
						}

						// For success message, reflect the actual new parent namespace
						Symbol updatedSymbol = transactionSymbolTable.getSymbol(context.symbol().getID()); // Re-fetch
						String finalActualNamespaceName;
						if (updatedSymbol != null) {
							finalActualNamespaceName = updatedSymbol.getParentNamespace().isGlobal()
									? "global namespace"
									: "'" + updatedSymbol.getParentNamespace().getName(true) + "'";
						} else {
							// Fallback if symbol somehow couldn't be re-fetched (should not happen)
							finalActualNamespaceName = (namespaceForCmd == null)
									? "unknown (original path: " + targetNsPathUserStr + " not found)"
									: (namespaceForCmd.isGlobal() ? "global namespace"
											: "'" + namespaceForCmd.getName(true) + "'");
						}

						return "Successfully renamed symbol '" + originalName + "' (was in "
								+ (originalNamespaceName.isEmpty() ? "global namespace" : "'" + originalNamespaceName + "'")
								+ ") to '" + context.simpleNewName() + "' in " + finalActualNamespaceName
								+ " at address " + symAddress;
					});
		});
	}
}