package com.themixednuts.tools.symbols;

import java.util.Map;
import java.util.Optional;
import java.util.stream.StreamSupport;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
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
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Rename Symbol", category = ToolCategory.SYMBOLS, description = "Renames a symbol (function or data label) identified by its address or a function name.", mcpName = "rename_symbol", mcpDescription = "Sets a new name for a symbol (function label or data label) specified by address or function name.")
public class GhidraRenameSymbolTool implements IGhidraMcpSpecification {

	private static record RenameSymbolContext(
			Program program,
			Symbol symbol,
			String newName) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_NEW_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The desired new name for the symbol."));
		schemaRoot.property(ARG_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The current name of the function whose symbol should be renamed. Provide this or address."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description(
								"The address of the symbol (function entry or data) to rename (e.g., '0x1004010'). Preferred over functionName if provided.")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_NEW_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
			Optional<String> nameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);
			String newName = getRequiredStringArgument(args, ARG_NEW_NAME);

			if (addressOpt.isEmpty() && nameOpt.isEmpty()) {
				throw new IllegalArgumentException("Either symbol address ('" + ARG_ADDRESS + "') or function name ('"
						+ ARG_FUNCTION_NAME + "') must be provided.");
			}

			Symbol symbolToRename = null;
			SymbolTable symbolTable = program.getSymbolTable();
			FunctionManager functionManager = program.getFunctionManager();
			String identifier = "";

			if (addressOpt.isPresent()) {
				String addressString = addressOpt.get();
				identifier = addressString;
				Address symbolAddress = program.getAddressFactory().getAddress(addressString);
				if (symbolAddress != null) {
					symbolToRename = symbolTable.getPrimarySymbol(symbolAddress);
				} else {
					if (nameOpt.isEmpty()) {
						throw new IllegalArgumentException("Invalid address format: " + addressString);
					}
				}
			}

			if (symbolToRename == null && nameOpt.isPresent()) {
				String functionName = nameOpt.get();
				identifier = functionName;
				Function function = StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
						.filter(f -> f.getName(true).equals(functionName))
						.findFirst()
						.orElse(null);
				if (function != null) {
					symbolToRename = function.getSymbol();
				}
			}

			// Check if we found a symbol by either means
			if (symbolToRename == null) {
				throw new IllegalArgumentException("Symbol not found using identifier: " + identifier);
			}

			// Pass program, symbol, and new name to the transaction phase
			return new RenameSymbolContext(program, symbolToRename, newName);

		}).flatMap(context -> {
			String originalName = context.symbol().getName();
			Address symAddress = context.symbol().getAddress();

			// Use executeInTransaction with RenameLabelCmd
			return executeInTransaction(context.program(), "MCP - Rename Symbol " + originalName + " at " + symAddress,
					() -> {
						RenameLabelCmd cmd = new RenameLabelCmd(context.symbol(), context.newName(), SourceType.USER_DEFINED);
						if (!cmd.applyTo(context.program())) {
							throw new RuntimeException("Failed to rename symbol '" + originalName + "' at address "
									+ symAddress + ": " + cmd.getStatusMsg());
						}
						return "Successfully renamed symbol '" + originalName + "' to '" + context.newName() + "' at address "
								+ symAddress;
					});
		});
	}

}