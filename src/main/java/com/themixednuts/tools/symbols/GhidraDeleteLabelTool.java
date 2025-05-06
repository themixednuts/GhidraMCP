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
						.description("Optional name of the label to verify before removing."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
					Optional<String> labelNameOpt = getOptionalStringArgument(args, ARG_NAME);

					Address targetAddress = program.getAddressFactory().getAddress(addressStr);
					if (targetAddress == null) {
						throw new IllegalArgumentException("Invalid address string (resolved to null): " + addressStr);
					}

					SymbolTable symbolTable = program.getSymbolTable();
					Symbol primarySymbol = symbolTable.getPrimarySymbol(targetAddress);

					// Validate symbol exists
					if (primarySymbol == null) {
						throw new IllegalArgumentException("No primary symbol found at address: " + addressStr);
					}

					// Validate symbol is a LABEL
					// DeleteLabelCmd handles various symbol types implicitly, so type check might
					// be redundant,
					// but we keep it for clearer error messages if user specifically targets a
					// non-label.
					if (primarySymbol.getSymbolType() != SymbolType.LABEL) {
						throw new IllegalArgumentException(
								"Symbol at address " + addressStr + " is a " + primarySymbol.getSymbolType() + ", not a Label.");
					}

					final String actualSymbolName = primarySymbol.getName();

					// Validate name if provided
					if (labelNameOpt.isPresent() && !actualSymbolName.equals(labelNameOpt.get())) {
						throw new IllegalArgumentException("Label name mismatch at address " + addressStr + ". Expected '"
								+ labelNameOpt.get() + "' but found '" + actualSymbolName + "'.");
					}

					// --- Modification Phase (Pass needed context) ---
					return new DeleteLabelContext(program, targetAddress, actualSymbolName);

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