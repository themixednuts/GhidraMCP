package com.themixednuts.tools.symbols;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;

import java.util.Map;

@GhidraMcpTool(key = "Clear Symbol", category = "Symbols", description = "Clears a symbol at a specific address.", mcpName = "clear_symbol_at_address", mcpDescription = "Removes the user-defined symbol at the specified address.")
public class GhidraClearSymbolTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		String schema = parseSchema(schema()).orElse(null);
		if (schema == null) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schema),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public ObjectNode schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property("address",
				JsonSchemaBuilder.string(mapper)
						.description("The address of the symbol to clear (e.g., '0x1004010')."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("address");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String addressString = getRequiredStringArgument(args, "address");
			Address address = program.getAddressFactory().getAddress(addressString);

			if (address == null) {
				return createErrorResult("Invalid address provided: " + addressString);
			}

			SymbolTable symbolTable = program.getSymbolTable();
			Listing listing = program.getListing();

			return executeInTransaction(program, "MCP - Clear Symbol", () -> {
				boolean symbolRemoved = false;
				boolean dataCleared = false;
				Symbol primarySymbol = null;

				primarySymbol = symbolTable.getPrimarySymbol(address);
				if (primarySymbol != null && primarySymbol.getSource() != SourceType.DEFAULT) {
					symbolRemoved = symbolTable.removeSymbolSpecial(primarySymbol);
					if (!symbolRemoved) {
						Msg.warn(this, "Failed to remove symbol: " + primarySymbol.getName() + " at " + address);
					}
				} else {
					symbolRemoved = true;
				}

				listing.clearCodeUnits(address, address, false);
				dataCleared = true;

				if (symbolRemoved && dataCleared) {
					return createSuccessResult("Symbol at " + address + " successfully cleared.");
				} else {
					String errorMsg = "Failed to fully clear symbol at " + address + ".";
					if (!symbolRemoved && primarySymbol != null) {
						errorMsg += " Could not remove symbol name ('" + primarySymbol.getName() + "').";
					}
					return createErrorResult(errorMsg);
				}
			});
		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}
}