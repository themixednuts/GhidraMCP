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
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuples;

@GhidraMcpTool(name = "Patch Instruction at Address", category = ToolCategory.MEMORY, description = "Patches the instruction at a given address, e.g., by NOPing it.", mcpName = "patch_instruction_at_address", mcpDescription = "Modify bytes corresponding to a single instruction (potentially safer/more abstract than raw byte writes).")
public class GhidraPatchInstructionAtAddressTool implements IGhidraMcpSpecification {

	private static final String ARG_PATCH_TYPE = "patchType";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address of the instruction to patch (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_PATCH_TYPE,
				JsonSchemaBuilder.string(mapper)
						.description("The type of patch to apply. Currently supported: 'NOP'.")
						.enumValues("NOP"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS)
				.requiredProperty(ARG_PATCH_TYPE);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> { // .map for setup
					String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
					String patchType = getRequiredStringArgument(args, ARG_PATCH_TYPE);

					Address targetAddress = program.getAddressFactory().getAddress(addressStr);
					if (targetAddress == null) {
						throw new IllegalArgumentException("Invalid address format: " + addressStr);
					}

					Listing listing = program.getListing();
					Instruction instruction = listing.getInstructionAt(targetAddress);
					if (instruction == null) {
						throw new IllegalArgumentException("No instruction found at address: " + addressStr);
					}
					// Return context
					return Tuples.of(program, targetAddress, instruction, patchType);
				})
				.flatMap(context -> { // flatMap for transaction
					Program program = context.getT1();
					Address targetAddress = context.getT2();
					Instruction instruction = context.getT3();
					String patchType = context.getT4();
					String addressStr = targetAddress.toString(); // Get string rep here

					return executeInTransaction(program, "Patch Instruction at " + addressStr, () -> {
						Memory memory = program.getMemory();
						int instructionLength = instruction.getLength();

						if ("NOP".equalsIgnoreCase(patchType)) {
							// Note: 0x90 is x86/x64 specific. A better impl would use language properties.
							byte nopByte = (byte) 0x90;
							byte[] nopBytes = new byte[instructionLength];
							for (int i = 0; i < instructionLength; i++) {
								nopBytes[i] = nopByte;
							}
							try {
								memory.setBytes(targetAddress, nopBytes);
								return "Successfully NOPed instruction (" + instructionLength + " bytes) at " + addressStr;
							} catch (MemoryAccessException e) {
								throw new RuntimeException("Memory error patching at " + addressStr + ": " + e.getMessage(), e);
							}
						} else {
							throw new IllegalArgumentException("Unsupported patch type: " + patchType);
						}
					});
				});
	}
}