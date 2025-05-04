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
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Add Label", category = ToolCategory.SYMBOLS, description = "Adds a label at a specified address.", mcpName = "add_label", mcpDescription = "Creates a new symbol label at a specific address.")
public class GhidraCreateLabelTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		Optional<String> schemaStringOpt = parseSchema(schema());
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}
		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaStringOpt.get()),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address where the label should be added (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name for the new label."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS)
				.requiredProperty(ARG_NAME);

		return schemaRoot.build();
	}

	// Helper class to hold validated setup results
	private static class ValidatedInput {
		final Address address;
		final String labelName;

		ValidatedInput(Address address, String labelName) {
			this.address = address;
			this.labelName = labelName;
		}
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					// Perform setup and validation within a callable to handle checked exceptions
					String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
					String labelName = getRequiredStringArgument(args, ARG_NAME);

					// Validate label name format (throws InvalidInputException)
					try {
						SymbolUtilities.validateName(labelName);
					} catch (InvalidInputException e) {
						return createErrorResult(e);
					}

					// Parse address (throws AddressFormatException)
					Address targetAddress = program.getAddressFactory().getAddress(addressStr);
					if (targetAddress == null) {
						return createErrorResult("Invalid address string (resolved to null): " + addressStr);
					}

					SymbolTable symbolTable = program.getSymbolTable();
					Symbol existingSymbol = symbolTable.getPrimarySymbol(targetAddress);
					if (existingSymbol != null) {
						return createErrorResult("Symbol '" + existingSymbol.getName() + "' already exists at address ");
					}

					ValidatedInput validatedInput = new ValidatedInput(targetAddress, labelName);
					return executeInTransaction(program, "Add Label " + validatedInput.labelName + " at " + addressStr,
							() -> {
								Symbol newSymbol = symbolTable.createLabel(validatedInput.address, validatedInput.labelName,
										SourceType.USER_DEFINED);
								if (newSymbol != null) {
									return createSuccessResult(validatedInput);
								} else {
									return createErrorResult("Failed to create label '" + validatedInput.labelName + "' at "
											+ addressStr + ", createLabel returned null.");
								}
							});
				})
				.onErrorResume(e -> createErrorResult(e));
	}
}