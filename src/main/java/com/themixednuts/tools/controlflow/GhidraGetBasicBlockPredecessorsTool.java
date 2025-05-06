package com.themixednuts.tools.controlflow;

import java.util.List;
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
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get Basic Block Predecessors", category = ToolCategory.CONTROL_FLOW, description = "Retrieves information about the predecessor basic blocks of the block containing the specified address.", mcpName = "get_basic_block_predecessors", mcpDescription = "Gets a list of basic blocks that flow into the block containing a given address.")
public class GhidraGetBasicBlockPredecessorsTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("An address within the target basic block (e.g., '0x1004010').")
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
			TaskMonitor monitor = new GhidraMcpTaskMonitor(ex, "Get Predecessors");
			CodeBlock block;
			CodeBlockReferenceIterator predIter;

			try {
				block = blockModel.getFirstCodeBlockContaining(address, monitor);
				if (block == null) {
					throw new IllegalArgumentException("No basic block found containing address: " + addressStr);
				}
				predIter = block.getSources(monitor);
			} catch (CancelledException e) {
				throw new RuntimeException("Operation cancelled while getting basic block predecessors: " + e.getMessage(), e);
			}

			List<BasicBlockInfo> predecessors = new java.util.ArrayList<>();
			try {
				while (predIter.hasNext()) {
					CodeBlockReference ref = predIter.next();
					predecessors.add(new BasicBlockInfo(ref.getSourceBlock()));
				}
			} catch (CancelledException e) {
				throw new RuntimeException("Operation cancelled while getting basic block predecessors: " + e.getMessage(), e);
			}
			return predecessors;
		});
	}
}