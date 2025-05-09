package com.themixednuts.tools.symbols;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
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

@GhidraMcpTool(name = "Delete Label", category = ToolCategory.SYMBOLS, description = "Removes a label at a specified address, optionally verifying the name.", mcpName = "delete_label", mcpDescription = "Removes the symbol label at a specific address. Optionally checks the label name before removal.")
public class GhidraDeleteLabelTool implements IGhidraMcpSpecification {

	private static record DeleteLabelContext(
			Program program,
			Address address,
			String actualSymbolName // Pass the confirmed name to delete
	) {
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
						throw new IllegalArgumentException(
								"At least one identifier (symbolId, address, or name) must be provided to delete a label.");
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
								throw new IllegalArgumentException("Symbol with ID '" + symId + "' found, but name mismatch. Expected '"
										+ nameOpt.get() + "' but was '" + symbolToDelete.getName() + "'.");
							}
							Address parsedAddressForVerification = addressOpt.map(program.getAddressFactory()::getAddress)
									.orElse(null);
							if (parsedAddressForVerification != null
									&& !symbolToDelete.getAddress().equals(parsedAddressForVerification)) {
								throw new IllegalArgumentException(
										"Symbol with ID '" + symId + "' found, but address mismatch. Expected '"
												+ addressOpt.get() + "' but was '" + symbolToDelete.getAddress().toString() + "'.");
							}
						}
					} else if (addressOpt.isPresent()) {
						String addressStr = addressOpt.get();
						criteriaInfo = "address '" + addressStr + "'";
						Address targetAddress = program.getAddressFactory().getAddress(addressStr);
						if (targetAddress == null) {
							throw new IllegalArgumentException("Invalid address string: " + addressStr);
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
								throw new IllegalArgumentException(
										"Label with name '" + targetName + "' not found at address '" + addressStr + "'.");
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
							throw new IllegalArgumentException(
									"Multiple global labels found with name: '" + labelName + "'. Please use address or symbol ID.");
						}
					}

					if (symbolToDelete == null) {
						throw new IllegalArgumentException("Label not found using criteria: " + criteriaInfo);
					}

					if (symbolToDelete.getSymbolType() != SymbolType.LABEL) {
						throw new IllegalArgumentException(
								"Symbol found by " + criteriaInfo + " is a " + symbolToDelete.getSymbolType()
										+ ", not a Label. Cannot delete.");
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
							// Get specific error message from the command
							throw new RuntimeException("Failed to remove label: " + identifier + ". " + cmd.getStatusMsg());
						}
					});
				});
	}
}