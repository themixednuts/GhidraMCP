package com.themixednuts.tools.memory;

import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
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

@GhidraMcpTool(name = "Assemble Instruction at Address", category = ToolCategory.MEMORY, description = "Assembles an instruction at a given address.", mcpName = "assemble_instruction_at_address", mcpDescription = """
		<use_case>Assemble and insert a new instruction at a specific memory address, replacing any existing instruction at that location.</use_case>

		<important_notes>
		• Modifies program memory and instruction listing permanently
		• Replaces existing instructions - clears code units before assembly
		• Uses architecture-specific assembler syntax and opcodes
		• Assembly must be valid for the target processor architecture
		• Changes affect disassembly flow and may break analysis
		</important_notes>

		<example>
		{
		  "fileName": "target.exe",
		  "address": "0x401020",
		  "instruction": "MOV EAX, EBX"
		}
		// Assembles x86 MOV instruction at specified address
		</example>

		<workflow>
		1. Parse and validate target address
		2. Clear any existing instruction at address
		3. Assemble instruction using program's assembler
		4. Insert new instruction into program listing
		</workflow>
		""")
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
					Address targetAddress = program.getAddressFactory().getAddress(addressStr);
					if (targetAddress == null) {
						GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
								.message("Invalid address format: " + addressStr)
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"address parsing",
										Map.of(ARG_ADDRESS, addressStr),
										Map.of(ARG_ADDRESS, addressStr),
										Map.of("expectedFormat", "hexadecimal address", "providedValue", addressStr)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use valid hexadecimal address format",
												"Provide address as hexadecimal value",
												List.of("0x401000", "401000", "0x00401000"),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}
					return Tuples.of(program, targetAddress, instructionStr);
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