package com.themixednuts.tools.memory;

import java.util.HexFormat;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Read Memory Bytes", category = ToolCategory.MEMORY, description = "Reads a sequence of bytes from a specific memory address.", mcpName = "read_memory_bytes", mcpDescription = "Read a sequence of bytes from a given memory address, returned as a hexadecimal string.")
public class GhidraReadMemoryBytesTool implements IGhidraMcpSpecification {

	private static final int MAX_READ_LENGTH = 4096;

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper).description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS, JsonSchemaBuilder.string(mapper)
				.description("The starting memory address to read from (e.g., '0x1004010').")
				.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_LENGTH, JsonSchemaBuilder.integer(mapper)
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
		return getProgram(args, tool).map(program -> {
			String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
			int length = getRequiredIntArgument(args, ARG_LENGTH);

			Address address = program.getAddressFactory().getAddress(addressStr);
			if (address == null) {
				throw new IllegalArgumentException("Invalid address format: " + addressStr);
			}

			if (length <= 0 || length > MAX_READ_LENGTH) {
				throw new IllegalArgumentException("Invalid length: Must be between 1 and " + MAX_READ_LENGTH);
			}

			Memory memory = program.getMemory();
			byte[] bytesRead = new byte[length];

			try {
				int bytesActuallyRead = memory.getBytes(address, bytesRead);
				if (bytesActuallyRead < length) {
					Msg.warn(this, "Partial read at " + addressStr + ": requested " + length + " bytes, got "
							+ bytesActuallyRead);
					// Return partially read data if read didn't complete fully
					byte[] partialBytes = new byte[bytesActuallyRead];
					System.arraycopy(bytesRead, 0, partialBytes, 0, bytesActuallyRead);
					bytesRead = partialBytes;
				}
			} catch (MemoryAccessException e) {
				throw new RuntimeException("Memory access error reading from " + addressStr + ": " + e.getMessage(), e);
			}

			return HexFormat.of().formatHex(bytesRead);
		});
	}
}