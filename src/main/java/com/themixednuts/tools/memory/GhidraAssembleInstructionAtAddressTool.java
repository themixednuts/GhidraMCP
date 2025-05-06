package com.themixednuts.tools.memory;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblyException;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuples;

@GhidraMcpTool(name = "Assemble Instruction at Address", category = ToolCategory.MEMORY, description = "Assembles an instruction at a given address.", mcpName = "assemble_instruction_at_address", mcpDescription = "Assemble an instruction at a specific memory address.")
public class GhidraAssembleInstructionAtAddressTool implements IGhidraMcpSpecification {

	public static final String ARG_INSTRUCTION = "instruction";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper).description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS, JsonSchemaBuilder.string(mapper)
				.description("The memory address where the instruction will be assembled (e.g., '0x1004010').")
				.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_INSTRUCTION, JsonSchemaBuilder.string(mapper)
				.description("The assembly instruction string (e.g., 'MOV EAX, EBX')."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS)
				.requiredProperty(ARG_INSTRUCTION);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> { // Setup phase
					String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
					String instructionStr = getRequiredStringArgument(args, ARG_INSTRUCTION);
					Address address = program.getAddressFactory().getAddress(addressStr);
					if (address == null) {
						throw new IllegalArgumentException("Invalid address format: " + addressStr);
					}
					return Tuples.of(program, address, instructionStr);
				})
				.flatMap(context -> { // Transaction phase
					Program program = context.getT1();
					Address address = context.getT2();
					String instructionStr = context.getT3();
					String addressStr = address.toString(); // For messages

					return executeInTransaction(program, "Assemble Instruction at " + addressStr, () -> {
						Assembler assembler = Assemblers.getAssembler(program);
						Instruction existingInstruction = program.getListing().getInstructionAt(address);
						if (existingInstruction != null) {
							program.getListing().clearCodeUnits(address, address.add(existingInstruction.getLength() - 1), false);
						}
						try {
							assembler.assemble(address, instructionStr);
							return "Instruction '" + instructionStr + "' assembled successfully at " + addressStr;
						} catch (AssemblyException e) {
							throw new RuntimeException("Assembly failed at " + addressStr + ": " + e.getMessage(), e);
						}
					});
				});
	}
}