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
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Read Memory Bytes", category = ToolCategory.MEMORY, description = "Reads raw bytes from memory at a specific address.", mcpName = "read_memory_bytes", mcpDescription = "Read raw bytes from program memory at a specified address and return them as hexadecimal data with ASCII interpretation. Supports reading 1-4096 bytes from any mapped memory region.")
public class GhidraReadMemoryBytesTool implements IGhidraMcpSpecification {

	private static final int MAX_READ_LENGTH = 4096;

	/**
	 * POJO for memory read results
	 */
	public static class MemoryReadResult {
		private final String address;
		private final int length;
		private final String hexData;
		private final String readable;

		public MemoryReadResult(String address, int length, String hexData, String readable) {
			this.address = address;
			this.length = length;
			this.hexData = hexData;
			this.readable = readable;
		}

		public String getAddress() {
			return address;
		}

		public int getLength() {
			return length;
		}

		public String getHexData() {
			return hexData;
		}

		public String getReadable() {
			return readable;
		}
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The starting memory address to read from (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_LENGTH,
				JsonSchemaBuilder.integer(mapper)
						.description("The number of bytes to read.")
						.minimum(1)
						.maximum(MAX_READ_LENGTH));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS)
				.requiredProperty(ARG_LENGTH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		return getProgram(args, tool).map(program -> {
			String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
			int length = getRequiredIntArgument(args, ARG_LENGTH);

			// Validate length parameter
			if (length <= 0 || length > MAX_READ_LENGTH) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
						.message("Invalid length parameter")
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"length validation",
								Map.of(ARG_LENGTH, length),
								Map.of(ARG_LENGTH, length),
								Map.of("expectedRange", "1 to " + MAX_READ_LENGTH, "providedValue", length)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Use valid length range",
										"Provide length between 1 and " + MAX_READ_LENGTH + " bytes",
										List.of("16", "64", "256", "1024"),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

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

			Memory memory = program.getMemory();
			byte[] bytesRead = new byte[length];
			int actualBytesRead;

			try {
				actualBytesRead = memory.getBytes(address, bytesRead);
			} catch (MemoryAccessException e) {
				GhidraMcpError error = GhidraMcpError.execution()
						.errorCode(GhidraMcpError.ErrorCode.MEMORY_ACCESS_FAILED)
						.message("Memory access error reading from address: " + e.getMessage())
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"memory access",
								Map.of(ARG_ADDRESS, addressStr, ARG_LENGTH, length),
								Map.of("memoryError", e.getMessage()),
								Map.of("addressRequested", addressStr, "lengthRequested", length)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Verify address is in mapped memory",
										"Ensure the address is within a valid memory region",
										List.of("Check program memory map", "Verify address is initialized"),
										null),
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Try a different address or length",
										"Use an address known to be in mapped memory",
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			// Handle partial reads - trim array to actual bytes read
			if (actualBytesRead < length) {
				byte[] trimmedBytes = new byte[actualBytesRead];
				System.arraycopy(bytesRead, 0, trimmedBytes, 0, actualBytesRead);
				bytesRead = trimmedBytes;
			}

			// Generate hex data and readable ASCII representation
			String hexData = HexFormat.of().formatHex(bytesRead);
			String readable = generateReadableString(bytesRead);

			return new MemoryReadResult(address.toString(), actualBytesRead, hexData, readable);
		});
	}

	/**
	 * Generate ASCII-readable representation of bytes, replacing non-printable
	 * characters with dots.
	 */
	private String generateReadableString(byte[] bytes) {
		StringBuilder readable = new StringBuilder();
		for (byte b : bytes) {
			// ASCII printable range: 32-126
			if (b >= 32 && b <= 126) {
				readable.append((char) b);
			} else {
				readable.append('.');
			}
		}
		return readable.toString();
	}
}