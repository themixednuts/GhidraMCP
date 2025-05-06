package com.themixednuts.tools.memory;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get Assembly at Address", category = ToolCategory.MEMORY, description = "Retrieves the assembly instruction at a specific memory address.", mcpName = "get_assembly_at_address", mcpDescription = "Get the assembly instruction string and details at a given memory address.")
public class GhidraGetAssemblyAtAddressTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(IGhidraMcpSpecification.ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper).description("The name of the program file."));
		schemaRoot.property(IGhidraMcpSpecification.ARG_ADDRESS, JsonSchemaBuilder.string(mapper)
				.description("The memory address of the instruction (e.g., '0x1004010').")
				.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(IGhidraMcpSpecification.ARG_FILE_NAME)
				.requiredProperty(IGhidraMcpSpecification.ARG_ADDRESS);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String addressStr = getRequiredStringArgument(args, IGhidraMcpSpecification.ARG_ADDRESS);
			Address address = program.getAddressFactory().getAddress(addressStr);
			if (address == null) {
				throw new IllegalArgumentException("Invalid address format: " + addressStr);
			}

			Listing listing = program.getListing();
			Instruction instruction = listing.getInstructionAt(address);

			if (instruction == null) {
				return null;
			}

			return instruction.getAddressString(false, true) + ": " + instruction.toString();
		});
	}
}