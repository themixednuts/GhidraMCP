package com.themixednuts.tools.symbols;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.InvalidInputException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Label", category = ToolCategory.SYMBOLS, description = "Adds a label at a specified address.", mcpName = "create_label", mcpDescription = "Creates a new symbol label at a specific address.")
public class GhidraCreateLabelTool implements IGhidraMcpSpecification {

	// Define nested record for context
	private static record CreateLabelContext(
			Program program,
			Address address,
			String labelName) {
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

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					// --- Setup Phase (Synchronous) ---
					String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
					String labelName = getRequiredStringArgument(args, ARG_NAME);
					Address targetAddress;

					// Validate label name format
					try {
						SymbolUtilities.validateName(labelName);
					} catch (InvalidInputException e) {
						throw new IllegalArgumentException("Invalid label name: " + e.getMessage(), e);
					}

					// Parse address
					targetAddress = program.getAddressFactory().getAddress(addressStr);
					if (targetAddress == null) {
						throw new IllegalArgumentException("Invalid address string: " + addressStr);
					}

					// Pass program and validated inputs to transaction
					return new CreateLabelContext(program, targetAddress, labelName);

				})
				.flatMap(context -> {
					// Use context record fields
					return executeInTransaction(context.program(),
							"MCP - Add Label " + context.labelName() + " at " + context.address(), () -> {
								// Use AddLabelCmd
								AddLabelCmd cmd = new AddLabelCmd(context.address(), context.labelName(), SourceType.USER_DEFINED);
								if (cmd.applyTo(context.program())) {
									return "Successfully created label '" + context.labelName() + "' at " + context.address().toString();
								} else {
									// Throw exception with status message from command
									throw new RuntimeException("Failed to create label: " + cmd.getStatusMsg());
								}
							});
				});
	}
}