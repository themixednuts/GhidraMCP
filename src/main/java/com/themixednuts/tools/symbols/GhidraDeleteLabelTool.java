package com.themixednuts.tools.symbols;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Remove Label", category = ToolCategory.SYMBOLS, description = "Removes a label at a specified address, optionally verifying the name.", mcpName = "remove_label", mcpDescription = "Removes the symbol label at a specific address. Optionally checks the label name before removal.")
public class GhidraDeleteLabelTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		Optional<String> schemaStringOpt = parseSchema(schema());
		if (schemaStringOpt.isEmpty()) {
			return null;
		}
		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaStringOpt.get()),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(IGhidraMcpSpecification.ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(IGhidraMcpSpecification.ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address of the label to remove (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("Optional name of the label to verify before removing."));

		schemaRoot.requiredProperty(IGhidraMcpSpecification.ARG_FILE_NAME)
				.requiredProperty(IGhidraMcpSpecification.ARG_ADDRESS);

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					// --- Setup Phase ---
					String addressStr = getRequiredStringArgument(args, IGhidraMcpSpecification.ARG_ADDRESS);
					Optional<String> labelNameOpt = getOptionalStringArgument(args, ARG_NAME);

					Address targetAddress = program.getAddressFactory().getAddress(addressStr);
					if (targetAddress == null) {
						return createErrorResult("Invalid address string (resolved to null): " + addressStr);
					}

					SymbolTable symbolTable = program.getSymbolTable();
					Symbol primarySymbol = symbolTable.getPrimarySymbol(targetAddress);

					// Validate symbol exists
					if (primarySymbol == null) {
						return createErrorResult("No primary symbol found at address: " + addressStr);
					}

					// Validate symbol is a LABEL
					if (primarySymbol.getSymbolType() != SymbolType.LABEL) {
						return createErrorResult(
								"Symbol at address " + addressStr + " is a " + primarySymbol.getSymbolType() + ", not a Label.");
					}

					// Validate name if provided
					if (labelNameOpt.isPresent() && !primarySymbol.getName().equals(labelNameOpt.get())) {
						return createErrorResult("Label name mismatch at address " + addressStr + ". Expected '"
								+ labelNameOpt.get() + "' but found '" + primarySymbol.getName() + "'.");
					}

					final Symbol symbolToRemove = primarySymbol; // Effectively final for lambda
					final String finalIdentifier = symbolToRemove.getName() + "@" + addressStr;

					// --- Modification Phase ---
					return executeInTransaction(program, "Remove Label " + finalIdentifier, () -> {
						boolean removed = symbolTable.removeSymbolSpecial(symbolToRemove);
						if (removed) {
							return createSuccessResult("Successfully removed label: " + finalIdentifier);
						} else {
							return createErrorResult("Failed to remove label: " + finalIdentifier
									+ ". It might have been removed already or removal failed.");
						}
					});
				})
				.onErrorResume(e -> createErrorResult(e)); // Handles runtime exceptions from setup or errors from transaction
	}
}