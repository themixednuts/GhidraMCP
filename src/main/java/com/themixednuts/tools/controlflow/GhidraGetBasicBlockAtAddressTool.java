package com.themixednuts.tools.controlflow;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.BasicBlockInfo;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.GhidraMcpTaskMonitor;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get Basic Block at Address", category = ToolCategory.CONTROL_FLOW, description = "Retrieves information about the basic block containing the specified address.", mcpName = "get_basic_block_at_address", mcpDescription = "Gets information about the basic block containing a given address.")
public class GhidraGetBasicBlockAtAddressTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address contained within the desired basic block (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
			Address address = program.getAddressFactory().getAddress(addressStr);

			CodeBlockModel blockModel = new SimpleBlockModel(program);
			TaskMonitor monitor = new GhidraMcpTaskMonitor(ex, "Get Block At Address");
			CodeBlock block;
			try {
				block = blockModel.getFirstCodeBlockContaining(address, monitor);
			} catch (CancelledException e) {
				throw new RuntimeException("Operation cancelled while getting basic block: " + e.getMessage(), e);
			}

			if (block == null) {
				throw new IllegalArgumentException("No basic block found containing address: " + addressStr);
			}

			return new BasicBlockInfo(block);
		});
	}
}