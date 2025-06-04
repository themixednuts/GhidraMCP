package com.themixednuts.tools.memory;

import java.util.HexFormat;
import java.util.Map;
import java.util.List;

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
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuples;

@GhidraMcpTool(name = "Write Memory Bytes", category = ToolCategory.MEMORY, description = "Writes a sequence of bytes to a specific memory address.", mcpName = "write_memory_bytes", mcpDescription = """
		<use_case>Write raw bytes to program memory at a specified address for patching instructions, modifying data structures, or injecting analysis markers.</use_case>

		<important_notes>
		• Modifies program memory permanently and transactionally
		• Requires writable memory regions - read-only memory will fail
		• All bytes must be written atomically or operation fails completely
		• Hex string must have even number of characters (case-insensitive)
		• Changes affect disassembly, analysis results, and program behavior
		</important_notes>

		<example>
		{
		  "fileName": "malware.exe",
		  "address": "0x401000",
		  "bytesHex": "90909090"
		}
		// Patches 4 NOP instructions at entry point
		</example>

		<workflow>
		1. Validate hex format and parse target address
		2. Convert hex string to byte array
		3. Write bytes atomically within transaction
		4. Return success with bytes written count
		</workflow>
		""")
public class GhidraWriteMemoryBytesTool implements IGhidraMcpSpecification {

	public static final String ARG_BYTES_HEX = "bytesHex";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The starting memory address to write to (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_BYTES_HEX,
				JsonSchemaBuilder.string(mapper)
						.description("The byte sequence as a hexadecimal string (e.g., '4889e5').")
						.pattern("^[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS)
				.requiredProperty(ARG_BYTES_HEX);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		return getProgram(args, tool)
				.map(program -> {
					String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
					String bytesHex = getRequiredStringArgument(args, ARG_BYTES_HEX);

					// Parse and validate address
					Address address;
					try {
						address = program.getAddressFactory().getAddress(addressStr);
					} catch (Exception e) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
								.message("Failed to parse address: " + e.getMessage())
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"address parsing",
										Map.of(ARG_ADDRESS, addressStr),
										Map.of(ARG_ADDRESS, addressStr),
										Map.of("parseError", e.getMessage(), "providedValue", addressStr)))
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

					if (address == null) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Invalid address format")
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"address validation",
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

					// Validate and parse hex bytes
					if (bytesHex.length() % 2 != 0) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Invalid hex format: odd number of characters")
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"hex format validation",
										Map.of(ARG_BYTES_HEX, bytesHex),
										Map.of(ARG_BYTES_HEX, bytesHex),
										Map.of("expectedFormat", "even number of hex characters", "providedLength", bytesHex.length())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use even number of hex characters",
												"Provide hex string with even length",
												List.of("deadbeef", "41424344", "90"),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					byte[] bytesToWrite;
					try {
						bytesToWrite = HexFormat.of().parseHex(bytesHex);
					} catch (IllegalArgumentException e) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Invalid hex string format: " + e.getMessage())
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"hex string parsing",
										Map.of(ARG_BYTES_HEX, bytesHex),
										Map.of("parseError", e.getMessage()),
										Map.of("providedValue", bytesHex)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use valid hexadecimal characters only",
												"Provide hex string with valid characters (0-9, A-F)",
												List.of("deadbeef", "41424344", "4889e5"),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					return Tuples.of(program, address, bytesToWrite);
				})
				.flatMap(context -> {
					Program program = context.getT1();
					Address address = context.getT2();
					byte[] bytesToWrite = context.getT3();
					String addressStr = address.toString();

					return executeInTransaction(program, "Write Memory Bytes to " + addressStr, () -> {
						Memory memory = program.getMemory();
						try {
							memory.setBytes(address, bytesToWrite);
							return "Successfully wrote " + bytesToWrite.length + " bytes to " + addressStr;
						} catch (MemoryAccessException e) {
							GhidraMcpError error = GhidraMcpError.execution()
									.errorCode(GhidraMcpError.ErrorCode.MEMORY_ACCESS_FAILED)
									.message("Memory access error writing to address: " + e.getMessage())
									.context(new GhidraMcpError.ErrorContext(
											annotation.mcpName(),
											"memory write access",
											Map.of(ARG_ADDRESS, addressStr, "bytesLength", bytesToWrite.length),
											Map.of("memoryError", e.getMessage()),
											Map.of("targetAddress", addressStr, "bytesToWrite", bytesToWrite.length)))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
													"Verify address is in writable memory",
													"Ensure the target address is within a writable memory region",
													List.of("Check memory permissions", "Verify address is not in read-only section"),
													null),
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Try a different address",
													"Use an address known to be in writable memory",
													null,
													null)))
									.build();
							throw new GhidraMcpException(error);
						}
					});
				});
	}
}