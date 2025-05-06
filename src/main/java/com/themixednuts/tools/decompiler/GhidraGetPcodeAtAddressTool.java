package com.themixednuts.tools.decompiler;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.RawPcodeOpInfo;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get PCode at Address", category = ToolCategory.DECOMPILER, description = "Retrieves the PCode representation for the instruction at a specific address.", mcpName = "get_pcode_at_address", mcpDescription = "Get the PCode intermediate representation for the instruction at a specific address.")
public class GhidraGetPcodeAtAddressTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address to retrieve PCode from (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
					Address targetAddress = program.getAddressFactory().getAddress(addressStr);

					Listing listing = program.getListing();
					Instruction instruction = listing.getInstructionAt(targetAddress);

					if (instruction == null) {
						throw new IllegalArgumentException("No instruction found at address: " + addressStr);
					}

					PcodeOp[] pcodeOps = instruction.getPcode();

					List<RawPcodeOpInfo> pcodeList = Arrays.stream(pcodeOps)
							.map(RawPcodeOpInfo::fromPcodeOp)
							.collect(Collectors.toList());

					return pcodeList;
				});
	}
}