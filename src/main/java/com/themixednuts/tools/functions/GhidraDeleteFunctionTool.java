package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;
import java.util.stream.StreamSupport;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Delete Function", category = ToolCategory.FUNCTIONS, description = "Removes a function specified either by its name or entry point address.", mcpName = "delete_function", mcpDescription = "Removes a function specified either by its name or entry point address.")
public class GhidraDeleteFunctionTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_FUNCTION_SYMBOL_ID,
				JsonSchemaBuilder.integer(mapper)
						.description("The Symbol ID of the function to delete. Preferred identifier."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional entry point address of the function to remove (e.g., '0x1004010'). Used if Symbol ID is not provided or not found.")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description(
								"The name of the function to remove. Used if Symbol ID and Address are not provided or not found."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);

		return schemaRoot.build();
	}

	private static record DeleteFunctionContext(
			Program program,
			Address addressToDelete) {
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			Optional<Long> funcSymbolIdOpt = getOptionalLongArgument(args, ARG_FUNCTION_SYMBOL_ID);
			Optional<String> funcAddressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
			Optional<String> funcNameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);

			if (funcSymbolIdOpt.isEmpty() && funcAddressOpt.isEmpty() && funcNameOpt.isEmpty()) {
				throw new IllegalArgumentException(
						"At least one identifier (functionSymbolId, address, or functionName) must be provided.");
			}

			Function functionToDelete = null;
			FunctionManager functionManager = program.getFunctionManager();
			SymbolTable symbolTable = program.getSymbolTable();

			if (funcSymbolIdOpt.isPresent()) {
				long symId = funcSymbolIdOpt.get();
				Symbol symbol = symbolTable.getSymbol(symId);
				if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
					functionToDelete = functionManager.getFunctionAt(symbol.getAddress());
				}
			}

			if (functionToDelete == null && funcAddressOpt.isPresent()) {
				String addressString = funcAddressOpt.get();
				Address entryPointAddress = program.getAddressFactory().getAddress(addressString);
				if (entryPointAddress != null) {
					functionToDelete = functionManager.getFunctionAt(entryPointAddress);
				} else {
					if (funcNameOpt.isEmpty() && funcSymbolIdOpt.isEmpty()) {
						throw new IllegalArgumentException("Invalid address format: " + addressString);
					}
				}
			} else if (funcNameOpt.isPresent()) {
				String functionName = funcNameOpt.get();
				functionToDelete = StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
						.filter(f -> f.getName(true).equals(functionName))
						.findFirst()
						.orElse(null);
			}

			if (functionToDelete == null) {
				StringBuilder errorMsgBuilder = new StringBuilder(
						"Function not found using any of the provided valid identifiers. Attempted with: ");
				boolean first = true;
				if (funcSymbolIdOpt.isPresent()) {
					errorMsgBuilder.append("functionSymbolId='").append(funcSymbolIdOpt.get()).append("'");
					first = false;
				}
				if (funcAddressOpt.isPresent()) {
					if (!first)
						errorMsgBuilder.append(", ");
					errorMsgBuilder.append("address='").append(funcAddressOpt.get()).append("'");
					first = false;
				}
				if (funcNameOpt.isPresent()) {
					if (!first)
						errorMsgBuilder.append(", ");
					errorMsgBuilder.append("functionName='").append(funcNameOpt.get()).append("'");
				}
				if (errorMsgBuilder.toString().endsWith("Attempted with: ")) {
					errorMsgBuilder.append("(no valid identifiers led to a function)");
				}
				throw new IllegalArgumentException(errorMsgBuilder.toString());
			}

			return new DeleteFunctionContext(program, functionToDelete.getEntryPoint());

		}).flatMap(context -> {
			final String entryPointStr = context.addressToDelete().toString();

			return executeInTransaction(context.program(), "MCP - Delete Function at " + entryPointStr, () -> {
				DeleteFunctionCmd cmd = new DeleteFunctionCmd(context.addressToDelete());
				if (!cmd.applyTo(context.program())) {
					throw new RuntimeException("Failed to delete function at " + entryPointStr + ": " + cmd.getStatusMsg());
				}
				return "Successfully deleted function at address " + entryPointStr;
			});
		});
	}
}