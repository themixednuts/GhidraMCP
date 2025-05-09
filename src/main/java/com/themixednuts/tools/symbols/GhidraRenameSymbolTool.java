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
import ghidra.program.model.symbol.SymbolIterator;
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
			String newName = getRequiredStringArgument(args, ARG_NEW_NAME);

			if (addressOpt.isEmpty() && currentNameOpt.isEmpty() && symbolIdOpt.isEmpty()) {
				throw new IllegalArgumentException(
						"At least one symbol identifier must be provided: '" + ARG_ADDRESS + "', '"
								+ ARG_CURRENT_NAME + "', or '" + ARG_SYMBOL_ID + "'.");
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
						throw new IllegalArgumentException("Invalid address format: " + addressString);
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
					throw new IllegalArgumentException(
							"Multiple functions found with name: '" + name
									+ "'. Please use address or symbol ID for unambiguous identification.");
				}

				if (function != null) {
					symbolToRename = function.getSymbol();
				} else {
					SymbolIterator symIter = symbolTable.getSymbolIterator(name, true);
					if (symIter.hasNext()) {
						symbolToRename = symIter.next();
						if (symIter.hasNext()) {
							throw new IllegalArgumentException(
									"Multiple global symbols found with name: '" + name
											+ "'. Please use address or symbol ID for unambiguous identification.");
						}
					}
				}
			}

			if (symbolToRename == null) {
				throw new IllegalArgumentException("Symbol not found using provided identifier(s): " + identifierInfo
						+ (identifierInfo.isEmpty() ? "(no valid identifier provided or symbol does not exist)" : ""));
			}

			return new RenameSymbolContext(program, symbolToRename, newName);

		}).flatMap(context -> {
			String originalName = context.symbol().getName();
			Address symAddress = context.symbol().getAddress();

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