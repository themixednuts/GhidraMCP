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

@GhidraMcpTool(name = "Patch Instruction at Address", category = ToolCategory.MEMORY, description = "Patches the instruction at a given address, e.g., by NOPing it.", mcpName = "patch_instruction_at_address", mcpDescription = """
		<use_case>Patch an instruction at a specific address by replacing it with alternative bytes while respecting instruction boundaries.</use_case>

		<important_notes>
		• Currently supports only NOP patching (replacing with 0x90 bytes)
		• Safer than raw byte writes as it respects instruction boundaries
		• Replaces entire instruction length with NOP bytes
		• Permanently modifies program memory and affects execution flow
		• Changes may impact analysis results and control flow graphs
		</important_notes>

		<example>
		{
		  "fileName": "malware.exe",
		  "address": "0x401030",
		  "patchType": "NOP"
		}
		// NOPs out the instruction at 0x401030
		</example>

		<workflow>
		1. Validate address and locate target instruction
		2. Determine instruction length from disassembly
		3. Generate appropriate patch bytes (e.g., 0x90 for NOP)
		4. Replace instruction bytes maintaining length alignment
		</workflow>
		""")
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
					GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
					String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
					String patchType = getRequiredStringArgument(args, ARG_PATCH_TYPE);

					Address targetAddress = program.getAddressFactory().getAddress(addressStr);
					if (targetAddress == null) {
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

					Listing listing = program.getListing();
					Instruction instruction = listing.getInstructionAt(targetAddress);
					if (instruction == null) {
						GhidraMcpError error = GhidraMcpError.resourceNotFound()
								.errorCode(GhidraMcpError.ErrorCode.ADDRESS_NOT_FOUND)
								.message("No instruction found at address: " + addressStr)
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"instruction lookup",
										Map.of(ARG_ADDRESS, addressStr),
										Map.of("targetAddress", addressStr),
										Map.of("hasInstruction", false)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"Verify address contains an instruction",
												"Use an address that contains a valid instruction",
												null,
												List.of(getMcpName(GhidraGetAssemblyAtAddressTool.class))),
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Try a different address",
												"Use an address in the program's instruction range",
												null,
												null)))
								.build();
						throw new GhidraMcpException(error);
					}
					// Return context
					return Tuples.of(program, targetAddress, instruction, patchType);
				})
				.flatMap(tuple -> executeInTransaction(tuple.getT1(), "Patch Instruction",
						() -> {
							Program program = tuple.getT1();
							Address targetAddress = tuple.getT2();
							Instruction instruction = tuple.getT3();
							String patchType = tuple.getT4();

							if (!"NOP".equalsIgnoreCase(patchType)) {
								GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
								GhidraMcpError error = GhidraMcpError.validation()
										.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
										.message("Unsupported patch type: " + patchType)
										.context(new GhidraMcpError.ErrorContext(
												annotation.mcpName(),
												"patch type validation",
												Map.of(ARG_PATCH_TYPE, patchType),
												Map.of("requestedPatchType", patchType),
												Map.of("supportedTypes", List.of("NOP"))))
										.suggestions(List.of(
												new GhidraMcpError.ErrorSuggestion(
														GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
														"Use supported patch type",
														"Currently only 'NOP' patch type is supported",
														List.of("NOP"),
														null)))
										.build();
								throw new GhidraMcpException(error);
							}

							Memory memory = program.getMemory();
							int instructionLength = instruction.getLength();

							byte nopByte = (byte) 0x90;
							byte[] nopBytes = new byte[instructionLength];
							for (int i = 0; i < instructionLength; i++) {
								nopBytes[i] = nopByte;
							}
							try {
								memory.setBytes(targetAddress, nopBytes);
								return "Successfully NOPed instruction (" + instructionLength + " bytes) at "
										+ targetAddress.toString();
							} catch (MemoryAccessException e) {
								throw new RuntimeException(
										"Memory error patching at " + targetAddress.toString() + ": " + e.getMessage(), e);
							}
						}));
	}
}